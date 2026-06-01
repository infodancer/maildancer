# TODO: Received Header Support

## Background
RFC 5321 requires MTAs to prepend Received headers to messages during relay.
The `emersion/go-message` library provides tools for this.

## Tasks

### 1. Add Received Header During Delivery
- [ ] Parse incoming message with `go-message/mail.CreateReader()`
- [ ] Create new Received header with:
  - `from` - Client HELO/EHLO hostname and IP
  - `by` - Our server hostname
  - `with` - Protocol (ESMTP, ESMTPS, ESMTPSA)
  - `id` - Message ID
  - `for` - Recipient address (optional, privacy consideration)
  - Timestamp in RFC 5322 format
- [ ] Prepend header to message before storage
- [ ] Update EncryptingDeliveryAgent to handle header addition before encryption

### 2. Header Format
Example:
```
Received: from sender.example.com (192.0.2.1)
        by mail.example.com (smtpd)
        with ESMTPS id abc123
        for <user@example.com>;
        Mon, 20 Jan 2025 10:30:00 +0000
```

### 3. Implementation Location
- Option A: In smtpd before calling DeliveryAgent.Deliver()
- Option B: In msgstore as a HeaderInjectingDeliveryAgent wrapper
- Recommendation: Option A (smtpd has all the context)

### 4. go-message Usage
```go
import "github.com/emersion/go-message/mail"

// Read existing message
mr, _ := mail.CreateReader(msgReader)
header := mr.Header

// Create new message with prepended Received header
var buf bytes.Buffer
mw, _ := mail.CreateWriter(&buf, newHeader)
// Copy body parts...
```

### 5. Testing
- [ ] Test header format compliance
- [ ] Test with multipart messages
- [ ] Test charset handling
- [ ] Verify DKIM signatures remain valid (Received is typically excluded)
