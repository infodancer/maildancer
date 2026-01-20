# TODO

## Phase 1: Core Protocol Compliance (Critical) - COMPLETE

### Transaction State Commands
- [x] STAT - Get mailbox status (message count and total size)
- [x] LIST - List messages with sizes (with optional message number argument)
- [x] RETR - Retrieve full message (with dot-stuffing)
- [x] DELE - Mark message for deletion
- [x] RSET - Reset/undo deletion flags
- [x] NOOP - Keep-alive command

### Session Enhancements
- [x] Add MessageStore interface field to Session
- [x] Add deletion tracking (map or slice of message IDs)
- [x] Implement deletion commit logic in UPDATE state
- [x] Store Mailbox reference in session after successful PASS

## Phase 2: MessageStore Integration - COMPLETE

- [x] Define/import MessageStore interface from msgstore repo
- [x] Initialize MessageStore in main.go from config.Maildir
- [x] Pass MessageStore to Handler/Session
- [x] Load message count for STAT command
- [x] Load message list with sizes for LIST command
- [x] Load message content for RETR command
- [x] Commit deletions to MessageStore in UPDATE state

## Phase 3: Optional Extensions (RFC 2449)

- [x] TOP - Retrieve headers plus n lines of body
- [x] UIDL - Unique message ID listing
- [ ] APOP - MD5 challenge-response authentication (RFC 1939 optional)
- [ ] AUTH/SASL mechanisms (RFC 5034)

## Phase 4: Observability & Operations - COMPLETE

### Metrics - COMPLETE
- [x] Initialize Prometheus metrics endpoint
- [x] Add command execution counters (by type)
- [x] Add authentication success/failure metrics
- [x] Add message retrieval statistics
- [x] Add active connection gauge

### Connection Management - COMPLETE
- [x] Implement connection counter
- [x] Enforce MaxConnections limit
- [x] Start IdleMonitor goroutine in handler
- [x] Enforce idle timeout disconnection

## Phase 5: Testing

### Transaction Commands - COMPLETE
- [x] Create `transaction_commands_test.go`
- [x] Test STAT in different states
- [x] Test LIST with/without arguments
- [x] Test RETR with valid/invalid message IDs
- [x] Test DELE tracking
- [x] Test RSET clearing deletions
- [x] Test NOOP

### Integration Tests
- [ ] Create `handler_test.go` for command dispatch
- [ ] Create `integration_test.go` for full client-server interaction
- [ ] Test AUTHORIZATION -> TRANSACTION -> UPDATE flow
- [ ] Test concurrent connections

### Server Infrastructure
- [ ] Create `listener_test.go`
- [ ] Create `connection_test.go`
- [ ] Test timeout handling

## Phase 6: Production Readiness

### Error Handling
- [ ] Review error messages for information leakage
- [ ] Improve error messages for debugging

### Documentation
- [ ] Update README with current implementation status
- [ ] Document MessageStore integration requirements
- [ ] Add example client session flows

### Security
- [ ] Security audit of command input handling
- [ ] Verify session isolation between connections
- [ ] Review TLS requirements for transaction commands
