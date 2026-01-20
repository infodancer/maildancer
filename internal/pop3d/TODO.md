# TODO

## Phase 1: Core Protocol Compliance (Critical)

### Transaction State Commands
- [ ] STAT - Get mailbox status (message count and total size)
- [ ] LIST - List messages with sizes (with optional message number argument)
- [ ] RETR - Retrieve full message (with dot-stuffing)
- [ ] DELE - Mark message for deletion
- [ ] RSET - Reset/undo deletion flags
- [ ] NOOP - Keep-alive command

### Session Enhancements
- [ ] Add MessageStore interface field to Session
- [ ] Add deletion tracking (map or slice of message IDs)
- [ ] Implement deletion commit logic in UPDATE state
- [ ] Store Mailbox reference in session after successful PASS

## Phase 2: MessageStore Integration

- [ ] Define/import MessageStore interface from msgstore repo
- [ ] Initialize MessageStore in main.go from config.Maildir
- [ ] Pass MessageStore to Handler/Session
- [ ] Load message count for STAT command
- [ ] Load message list with sizes for LIST command
- [ ] Load message content for RETR command
- [ ] Commit deletions to MessageStore in UPDATE state

## Phase 3: Optional Extensions (RFC 2449)

- [ ] TOP - Retrieve headers plus n lines of body (currently advertised but not implemented)
- [ ] UIDL - Unique message ID listing (currently advertised but not implemented)
- [ ] APOP - MD5 challenge-response authentication (RFC 1939 optional)
- [ ] AUTH/SASL mechanisms (RFC 5034)

## Phase 4: Observability & Operations

### Metrics
- [ ] Initialize Prometheus metrics endpoint
- [ ] Add command execution counters (by type)
- [ ] Add authentication success/failure metrics
- [ ] Add message retrieval statistics
- [ ] Add active connection gauge

### Connection Management
- [ ] Implement connection counter
- [ ] Enforce MaxConnections limit
- [ ] Start IdleMonitor goroutine in handler
- [ ] Enforce idle timeout disconnection

## Phase 5: Testing

### Transaction Commands
- [ ] Create `transaction_commands_test.go`
- [ ] Test STAT in different states
- [ ] Test LIST with/without arguments
- [ ] Test RETR with valid/invalid message IDs
- [ ] Test DELE tracking
- [ ] Test RSET clearing deletions
- [ ] Test NOOP

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
