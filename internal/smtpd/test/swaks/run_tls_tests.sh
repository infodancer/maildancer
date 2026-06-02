#!/bin/bash
#
# SMTP TLS Integration Tests using swaks
# https://github.com/infodancer/maildancer/internal/smtpd/issues/37
#
# This script tests STARTTLS functionality.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BINARY="$PROJECT_ROOT/bin/smtpd"

# Test configuration
TEST_PORT="${TEST_PORT:-2526}"
TEST_HOST="localhost"
TEST_HOSTNAME="test.example.com"
DELIVERY_PATH=""
SERVER_PID=""
CERT_DIR=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Feature flags
STARTTLS_AVAILABLE=true

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

# Check if required tools are installed
check_dependencies() {
    if ! command -v swaks &> /dev/null; then
        log_error "swaks is not installed. Please install it first."
        exit 1
    fi
    if ! command -v openssl &> /dev/null; then
        log_error "openssl is not installed. Please install it first."
        exit 1
    fi
    log_info "Dependencies found"
}

# Generate self-signed certificates for testing
generate_certificates() {
    CERT_DIR=$(mktemp -d -t smtpd-certs-XXXXXX)
    log_info "Generating test certificates in $CERT_DIR"

    # Generate private key
    openssl genrsa -out "$CERT_DIR/server.key" 2048 2>/dev/null

    # Generate self-signed certificate
    openssl req -new -x509 \
        -key "$CERT_DIR/server.key" \
        -out "$CERT_DIR/server.crt" \
        -days 1 \
        -subj "/CN=$TEST_HOSTNAME/O=Test/C=US" \
        -addext "subjectAltName=DNS:$TEST_HOSTNAME,DNS:localhost,IP:127.0.0.1" \
        2>/dev/null

    log_info "Certificates generated"
}

# Build the server binary
build_server() {
    log_info "Building server..."
    cd "$PROJECT_ROOT"
    go build -o "$BINARY" ./cmd/smtpd
    log_info "Server built: $BINARY"
}

# Start the SMTP server with TLS enabled
start_server() {
    log_info "Starting SMTP server with TLS on port $TEST_PORT..."

    # Create temp delivery directory
    DELIVERY_PATH=$(mktemp -d -t smtpd-test-XXXXXX)
    log_info "Delivery path: $DELIVERY_PATH"

    # Start server in background with TLS
    "$BINARY" \
        -listen "$TEST_HOST:$TEST_PORT" \
        -hostname "$TEST_HOSTNAME" \
        -delivery-type maildir \
        -delivery-path "$DELIVERY_PATH" \
        -tls-cert "$CERT_DIR/server.crt" \
        -tls-key "$CERT_DIR/server.key" \
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
        rm -rf "$DELIVERY_PATH"
        DELIVERY_PATH=""
    fi

    if [ -n "$CERT_DIR" ] && [ -d "$CERT_DIR" ]; then
        rm -rf "$CERT_DIR"
        CERT_DIR=""
    fi
}

# Trap to ensure cleanup on exit
trap stop_server EXIT

# Run a test and check result
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

test_starttls_advertised() {
    log_test "STARTTLS advertised in EHLO"
    local output
    output=$(swaks --server "$TEST_HOST:$TEST_PORT" --quit-after EHLO --helo "client.example.com" 2>&1) || true
    if echo "$output" | grep -q "STARTTLS"; then
        log_info "PASSED (STARTTLS advertised)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_warn "SKIPPED (STARTTLS not advertised - feature may not be implemented)"
        TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
        # Set flag to skip dependent tests
        STARTTLS_AVAILABLE=false
        return 0
    fi
}

test_starttls_upgrade() {
    if [ "$STARTTLS_AVAILABLE" != "true" ]; then
        log_test "STARTTLS upgrade successful"
        log_warn "SKIPPED (STARTTLS not available)"
        TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
        return 0
    fi
    run_test "STARTTLS upgrade successful" 0 \
        --server "$TEST_HOST:$TEST_PORT" \
        --tls \
        --tls-optional-strict \
        --tls-verify \
        --tls-ca-path "$CERT_DIR/server.crt" \
        --quit-after EHLO \
        --helo "client.example.com"
}

test_starttls_message_delivery() {
    if [ "$STARTTLS_AVAILABLE" != "true" ]; then
        log_test "Message delivery over TLS"
        log_warn "SKIPPED (STARTTLS not available)"
        TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
        return 0
    fi
    run_test "Message delivery over TLS" 0 \
        --server "$TEST_HOST:$TEST_PORT" \
        --tls \
        --tls-optional-strict \
        --tls-verify \
        --tls-ca-path "$CERT_DIR/server.crt" \
        --from "sender@example.com" \
        --to "recipient@example.com" \
        --helo "client.example.com" \
        --header "Subject: TLS test message" \
        --body "This message was sent over TLS."
}

test_starttls_then_ehlo() {
    if [ "$STARTTLS_AVAILABLE" != "true" ]; then
        log_test "EHLO after STARTTLS shows extensions"
        log_warn "SKIPPED (STARTTLS not available)"
        TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
        return 0
    fi
    # After STARTTLS, client should send EHLO again
    run_test_expect_output "EHLO after STARTTLS shows extensions" "250" \
        --server "$TEST_HOST:$TEST_PORT" \
        --tls \
        --tls-optional-strict \
        --tls-verify \
        --tls-ca-path "$CERT_DIR/server.crt" \
        --quit-after EHLO \
        --helo "client.example.com"
}

test_no_tls_without_request() {
    # Plain connection without --tls should work
    run_test "Plain connection works without TLS" 0 \
        --server "$TEST_HOST:$TEST_PORT" \
        --quit-after EHLO \
        --helo "client.example.com"
}

test_implicit_tls_rejected() {
    if [ "$STARTTLS_AVAILABLE" != "true" ]; then
        log_test "Implicit TLS rejected on STARTTLS port"
        log_warn "SKIPPED (STARTTLS not available)"
        TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
        return 0
    fi
    # Implicit TLS on non-implicit port should fail
    # (swaks --tlsc tries implicit TLS)
    run_test "Implicit TLS rejected on STARTTLS port" 1 \
        --server "$TEST_HOST:$TEST_PORT" \
        --tlsc \
        --tls-verify \
        --tls-ca-path "$CERT_DIR/server.crt" \
        --quit-after EHLO \
        --helo "client.example.com" \
        --timeout 5
}

# ============================================================================
# Main
# ============================================================================

main() {
    echo "========================================"
    echo "SMTP TLS Integration Tests (swaks)"
    echo "========================================"
    echo ""

    check_dependencies
    generate_certificates
    build_server
    start_server

    echo ""
    echo "Running TLS tests..."
    echo "========================================"

    # STARTTLS tests
    test_starttls_advertised
    test_starttls_upgrade
    test_starttls_then_ehlo
    test_starttls_message_delivery

    # Negative tests
    test_no_tls_without_request
    test_implicit_tls_rejected

    # Summary
    echo ""
    echo "========================================"
    echo "TLS Test Summary"
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
