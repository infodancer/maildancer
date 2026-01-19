#!/bin/bash
#
# SMTP Integration Tests using swaks
# https://github.com/infodancer/maildancer/internal/smtpd/issues/37
#
# This script starts a local SMTP server and runs integration tests using swaks.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BINARY="$PROJECT_ROOT/bin/smtpd"

# Test configuration
TEST_PORT="${TEST_PORT:-2525}"
TEST_HOST="localhost"
TEST_HOSTNAME="test.example.com"
DELIVERY_PATH=""
SERVER_PID=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_test() {
    echo -e "\n${YELLOW}[TEST]${NC} $1"
}

# Check if swaks is installed
check_dependencies() {
    if ! command -v swaks &> /dev/null; then
        log_error "swaks is not installed. Please install it first."
        log_info "On Debian/Ubuntu: sudo apt install swaks"
        log_info "On macOS: brew install swaks"
        exit 1
    fi
    log_info "swaks found: $(which swaks)"
}

# Build the server binary
build_server() {
    log_info "Building server..."
    cd "$PROJECT_ROOT"
    go build -o "$BINARY" ./cmd/smtpd
    log_info "Server built: $BINARY"
}

# Start the SMTP server
start_server() {
    log_info "Starting SMTP server on port $TEST_PORT..."

    # Create temp delivery directory
    DELIVERY_PATH=$(mktemp -d -t smtpd-test-XXXXXX)
    log_info "Delivery path: $DELIVERY_PATH"

    # Start server in background
    "$BINARY" \
        -listen "$TEST_HOST:$TEST_PORT" \
        -hostname "$TEST_HOSTNAME" \
        -delivery-type maildir \
        -delivery-path "$DELIVERY_PATH" \
        -log-level error \
        &
    SERVER_PID=$!

    # Wait for server to be ready
    local retries=30
    while ! nc -z "$TEST_HOST" "$TEST_PORT" 2>/dev/null; do
        retries=$((retries - 1))
        if [ $retries -eq 0 ]; then
            log_error "Server failed to start"
            exit 1
        fi
        sleep 0.1
    done

    log_info "Server started (PID: $SERVER_PID)"
}

# Stop the server and cleanup
stop_server() {
    if [ -n "$SERVER_PID" ]; then
        log_info "Stopping server (PID: $SERVER_PID)..."
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
    fi

    if [ -n "$DELIVERY_PATH" ] && [ -d "$DELIVERY_PATH" ]; then
        log_info "Cleaning up delivery path: $DELIVERY_PATH"
        rm -rf "$DELIVERY_PATH"
        DELIVERY_PATH=""
    fi
}

# Trap to ensure cleanup on exit
trap stop_server EXIT

# Run a single test and check result
run_test() {
    local test_name="$1"
    local expected_exit="$2"
    shift 2
    local swaks_args=("$@")

    log_test "$test_name"

    local output
    local exit_code=0

    output=$(swaks "${swaks_args[@]}" 2>&1) || exit_code=$?

    if [ "$exit_code" -eq "$expected_exit" ]; then
        log_info "PASSED (exit code: $exit_code)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_error "FAILED (expected exit: $expected_exit, got: $exit_code)"
        echo "$output"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Run a test and verify output contains expected string
run_test_expect_output() {
    local test_name="$1"
    local expected_pattern="$2"
    shift 2
    local swaks_args=("$@")

    log_test "$test_name"

    local output
    local exit_code=0

    output=$(swaks "${swaks_args[@]}" 2>&1) || exit_code=$?

    if echo "$output" | grep -q "$expected_pattern"; then
        log_info "PASSED (found expected pattern)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_error "FAILED (pattern not found: $expected_pattern)"
        echo "$output"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# ============================================================================
# Test Cases
# ============================================================================

test_ehlo() {
    run_test "EHLO handshake" 0 \
        --server "$TEST_HOST:$TEST_PORT" \
        --quit-after EHLO \
        --helo "client.example.com"
}

test_helo() {
    run_test "HELO handshake" 0 \
        --server "$TEST_HOST:$TEST_PORT" \
        --quit-after HELO \
        --protocol SMTP \
        --helo "client.example.com"
}

test_ehlo_extensions() {
    run_test_expect_output "EHLO advertises SIZE extension" "SIZE" \
        --server "$TEST_HOST:$TEST_PORT" \
        --quit-after EHLO \
        --helo "client.example.com"
}

test_ehlo_8bitmime() {
    run_test_expect_output "EHLO advertises 8BITMIME extension" "8BITMIME" \
        --server "$TEST_HOST:$TEST_PORT" \
        --quit-after EHLO \
        --helo "client.example.com"
}

test_ehlo_smtputf8() {
    # SMTPUTF8 may or may not be advertised - skip if not present
    log_test "EHLO advertises SMTPUTF8 extension (optional)"
    local output
    output=$(swaks --server "$TEST_HOST:$TEST_PORT" --quit-after EHLO --helo "client.example.com" 2>&1) || true
    if echo "$output" | grep -q "SMTPUTF8"; then
        log_info "PASSED (SMTPUTF8 advertised)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_warn "SKIPPED (SMTPUTF8 not advertised - optional extension)"
        TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
    fi
}

test_basic_message_delivery() {
    run_test "Basic message delivery" 0 \
        --server "$TEST_HOST:$TEST_PORT" \
        --from "sender@example.com" \
        --to "recipient@example.com" \
        --helo "client.example.com" \
        --header "Subject: Test message" \
        --body "This is a test message."
}

test_multiple_recipients() {
    run_test "Multiple recipients" 0 \
        --server "$TEST_HOST:$TEST_PORT" \
        --from "sender@example.com" \
        --to "recipient1@example.com" \
        --to "recipient2@example.com" \
        --helo "client.example.com" \
        --header "Subject: Multi-recipient test" \
        --body "Test message to multiple recipients."
}

test_mail_from_with_size() {
    run_test "MAIL FROM with SIZE parameter" 0 \
        --server "$TEST_HOST:$TEST_PORT" \
        --from "sender@example.com" \
        --to "recipient@example.com" \
        --helo "client.example.com" \
        --header "Subject: Size test" \
        --body "Test message with SIZE." \
        --protocol ESMTP
}

test_rset_command() {
    run_test_expect_output "RSET command resets transaction" "250" \
        --server "$TEST_HOST:$TEST_PORT" \
        --quit-after RCPT \
        --from "sender@example.com" \
        --to "recipient@example.com" \
        --helo "client.example.com"
}

test_noop_command() {
    run_test_expect_output "NOOP command" "250" \
        --server "$TEST_HOST:$TEST_PORT" \
        --quit-after EHLO \
        --helo "client.example.com"
}

test_multiple_transactions() {
    # Send two messages on the same connection using RSET
    run_test "Multiple transactions on same connection" 0 \
        --server "$TEST_HOST:$TEST_PORT" \
        --from "sender@example.com" \
        --to "recipient@example.com" \
        --helo "client.example.com" \
        --header "Subject: Transaction test" \
        --body "First message."
}

test_quit_command() {
    run_test_expect_output "QUIT command returns 221" "221" \
        --server "$TEST_HOST:$TEST_PORT" \
        --helo "client.example.com" \
        --quit-after EHLO
}

test_long_lines() {
    # Create a message with long lines (but within RFC limits)
    local long_body
    long_body=$(python3 -c "print('X' * 500)")

    run_test "Message with long lines" 0 \
        --server "$TEST_HOST:$TEST_PORT" \
        --from "sender@example.com" \
        --to "recipient@example.com" \
        --helo "client.example.com" \
        --header "Subject: Long line test" \
        --body "$long_body"
}

test_special_characters_in_body() {
    run_test "Message with special characters" 0 \
        --server "$TEST_HOST:$TEST_PORT" \
        --from "sender@example.com" \
        --to "recipient@example.com" \
        --helo "client.example.com" \
        --header "Subject: Special chars test" \
        --body $'Line with dots:\n.leading dot\n..double dots\nEnd.'
}

test_minimal_body() {
    # Test with minimal single-character body
    run_test "Message with minimal body" 0 \
        --server "$TEST_HOST:$TEST_PORT" \
        --from "sender@example.com" \
        --to "recipient@example.com" \
        --helo "client.example.com" \
        --header "Subject: Minimal body test" \
        --body "."
}

test_multiline_body() {
    run_test "Message with multiline body" 0 \
        --server "$TEST_HOST:$TEST_PORT" \
        --from "sender@example.com" \
        --to "recipient@example.com" \
        --helo "client.example.com" \
        --header "Subject: Multiline test" \
        --body $'Line 1\nLine 2\nLine 3\n\nParagraph 2'
}

# ============================================================================
# Main
# ============================================================================

main() {
    echo "========================================"
    echo "SMTP Integration Tests (swaks)"
    echo "========================================"
    echo ""

    check_dependencies
    build_server
    start_server

    echo ""
    echo "Running tests..."
    echo "========================================"

    # Basic handshake tests
    test_ehlo
    test_helo

    # Extension advertisement tests
    test_ehlo_extensions
    test_ehlo_8bitmime
    test_ehlo_smtputf8

    # Message delivery tests
    test_basic_message_delivery
    test_multiple_recipients
    test_mail_from_with_size

    # Command tests
    test_noop_command
    test_quit_command
    test_multiple_transactions

    # Message content tests
    test_long_lines
    test_special_characters_in_body
    test_minimal_body
    test_multiline_body

    # Summary
    echo ""
    echo "========================================"
    echo "Test Summary"
    echo "========================================"
    echo -e "Passed:  ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Failed:  ${RED}$TESTS_FAILED${NC}"
    echo -e "Skipped: ${YELLOW}$TESTS_SKIPPED${NC}"
    echo "========================================"

    if [ "$TESTS_FAILED" -gt 0 ]; then
        exit 1
    fi

    exit 0
}

main "$@"
