package imap

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/mail"
	"strings"
	"time"

	"github.com/infodancer/maildancer/internal/imapd/server"
)

// fetchCommand implements the FETCH command.
type fetchCommand struct{}

func (c *fetchCommand) Name() string { return "FETCH" }

func (c *fetchCommand) Execute(ctx context.Context, tag, args string, sess *Session, conn *server.Connection) error {
	return doFetch(ctx, tag, args, sess, conn, false)
}

// doFetch handles FETCH and UID FETCH.
func doFetch(ctx context.Context, tag, args string, sess *Session, conn *server.Connection, useUID bool) error {
	w := conn.Writer()

	if sess.State() != StateSelected {
		return writeBAD(w, tag, "No mailbox selected")
	}

	// Parse: sequence items
	spaceIdx := strings.IndexByte(args, ' ')
	if spaceIdx < 0 {
		return writeBAD(w, tag, "FETCH requires sequence and items")
	}

	seqStr := args[:spaceIdx]
	itemsStr := args[spaceIdx+1:]

	seqSet, err := ParseSequenceSet(seqStr)
	if err != nil {
		return writeBAD(w, tag, fmt.Sprintf("Invalid sequence set: %s", err.Error()))
	}

	items, err := ParseFetchItems(itemsStr)
	if err != nil {
		return writeBAD(w, tag, fmt.Sprintf("Invalid fetch items: %s", err.Error()))
	}

	// If UID FETCH, ensure UID is always included
	if useUID {
		hasUID := false
		for _, item := range items {
			if item == "UID" {
				hasUID = true
				break
			}
		}
		if !hasUID {
			items = append(items, "UID")
		}
	}

	maxVal := uint32(sess.MessageCount())

	for i := 1; i <= sess.MessageCount(); i++ {
		var match bool
		if useUID {
			uid := sess.MessageUID(i)
			match = seqSet.Contains(uid, sess.UIDNext()-1)
		} else {
			match = seqSet.Contains(uint32(i), maxVal)
		}

		if !match {
			continue
		}

		msg := sess.GetMessage(i)
		if msg == nil {
			continue
		}

		resp, err := buildFetchResponse(ctx, i, msg.UID, items, sess)
		if err != nil {
			sess.Logger().Error("fetch error", "seqnum", i, "error", err.Error())
			continue
		}

		if err := writeUntagged(w, fmt.Sprintf("%d FETCH (%s)", i, resp)); err != nil {
			return err
		}

		sess.Collector().MessageFetched(sess.UserDomain(), msg.Size)
	}

	return writeOK(w, tag, "FETCH completed")
}

// buildFetchResponse builds the response data for a single message fetch.
func buildFetchResponse(ctx context.Context, seqNum int, uid string, items []string, sess *Session) (string, error) {
	var parts []string
	var needContent bool

	// Check if we need message content
	for _, item := range items {
		switch {
		case item == "RFC822", item == "RFC822.HEADER", item == "RFC822.TEXT",
			item == "BODY", item == "BODYSTRUCTURE", item == "ENVELOPE",
			strings.HasPrefix(item, "BODY["), strings.HasPrefix(item, "BODY.PEEK["):
			needContent = true
		}
	}

	var content []byte
	if needContent {
		data, err := retrieveMessage(ctx, seqNum, uid, sess)
		if err != nil {
			return "", err
		}
		content = data
	}

	for _, item := range items {
		switch {
		case item == "FLAGS":
			flags := sess.GetFlags(seqNum)
			parts = append(parts, "FLAGS "+formatFlagList(flags))

		case item == "UID":
			parts = append(parts, fmt.Sprintf("UID %d", sess.MessageUID(seqNum)))

		case item == "RFC822.SIZE":
			msg := sess.GetMessage(seqNum)
			if msg != nil {
				parts = append(parts, fmt.Sprintf("RFC822.SIZE %d", msg.Size))
			}

		case item == "INTERNALDATE":
			// Use current time as a fallback; ideally this comes from the store
			parts = append(parts, "INTERNALDATE "+formatInternalDate(time.Now()))

		case item == "RFC822":
			parts = append(parts, fmt.Sprintf("RFC822 {%d}\r\n%s", len(content), string(content)))
			// RFC822 fetch implicitly sets \Seen
			if !sess.IsReadOnly() {
				sess.AddFlags(seqNum, []string{FlagSeen})
			}

		case item == "RFC822.HEADER":
			header := extractHeader(content)
			parts = append(parts, fmt.Sprintf("RFC822.HEADER {%d}\r\n%s", len(header), header))

		case item == "RFC822.TEXT":
			body := extractBody(content)
			parts = append(parts, fmt.Sprintf("RFC822.TEXT {%d}\r\n%s", len(body), body))
			if !sess.IsReadOnly() {
				sess.AddFlags(seqNum, []string{FlagSeen})
			}

		case item == "ENVELOPE":
			env := buildEnvelope(content)
			parts = append(parts, "ENVELOPE "+env)

		case item == "BODYSTRUCTURE", item == "BODY" && !strings.HasPrefix(item, "BODY["):
			bs := buildBodyStructure(content)
			parts = append(parts, "BODYSTRUCTURE "+bs)

		case strings.HasPrefix(item, "BODY["), strings.HasPrefix(item, "BODY.PEEK["):
			peek := strings.HasPrefix(item, "BODY.PEEK[")
			section := extractSection(item)
			data := fetchSection(content, section)
			label := item
			if peek {
				// Response uses BODY[...] even for BODY.PEEK[...]
				label = "BODY[" + section + "]"
			}
			parts = append(parts, fmt.Sprintf("%s {%d}\r\n%s", label, len(data), data))
			if !peek && !sess.IsReadOnly() {
				sess.AddFlags(seqNum, []string{FlagSeen})
			}
		}
	}

	return strings.Join(parts, " "), nil
}

// retrieveMessage retrieves the full message content.
func retrieveMessage(ctx context.Context, seqNum int, uid string, sess *Session) ([]byte, error) {
	folder := mailboxToFolder(sess.SelectedMailbox())

	var reader io.ReadCloser
	var err error

	if folder == "" {
		reader, err = sess.Store().Retrieve(ctx, sess.Mailbox(), uid)
	} else if sess.FolderStore() != nil {
		reader, err = sess.FolderStore().RetrieveFromFolder(ctx, sess.Mailbox(), folder, uid)
	} else {
		return nil, fmt.Errorf("folder operations not supported")
	}

	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Close() }()

	return io.ReadAll(reader)
}

// extractHeader extracts the header portion of an RFC 5322 message.
func extractHeader(content []byte) string {
	s := string(content)
	idx := strings.Index(s, "\r\n\r\n")
	if idx >= 0 {
		return s[:idx+4]
	}
	idx = strings.Index(s, "\n\n")
	if idx >= 0 {
		return s[:idx+2]
	}
	return s
}

// extractBody extracts the body portion of an RFC 5322 message.
func extractBody(content []byte) string {
	s := string(content)
	idx := strings.Index(s, "\r\n\r\n")
	if idx >= 0 {
		return s[idx+4:]
	}
	idx = strings.Index(s, "\n\n")
	if idx >= 0 {
		return s[idx+2:]
	}
	return ""
}

// extractSection extracts the section specifier from BODY[section] or BODY.PEEK[section].
func extractSection(item string) string {
	startIdx := strings.IndexByte(item, '[')
	endIdx := strings.LastIndexByte(item, ']')
	if startIdx < 0 || endIdx < 0 || endIdx <= startIdx {
		return ""
	}
	return item[startIdx+1 : endIdx]
}

// fetchSection returns the appropriate portion of the message for a BODY[section] request.
func fetchSection(content []byte, section string) string {
	section = strings.ToUpper(strings.TrimSpace(section))

	switch {
	case section == "":
		return string(content)
	case section == "TEXT":
		return extractBody(content)
	case section == "HEADER":
		return extractHeader(content)
	case strings.HasPrefix(section, "HEADER.FIELDS"):
		return fetchHeaderFields(content, section, false)
	case strings.HasPrefix(section, "HEADER.FIELDS.NOT"):
		return fetchHeaderFields(content, section, true)
	default:
		// For MIME part numbers, return full content as fallback
		return string(content)
	}
}

// fetchHeaderFields returns specific header fields.
func fetchHeaderFields(content []byte, section string, negate bool) string {
	// Extract field names from HEADER.FIELDS (field1 field2)
	parenStart := strings.IndexByte(section, '(')
	parenEnd := strings.LastIndexByte(section, ')')
	if parenStart < 0 || parenEnd < 0 {
		return extractHeader(content)
	}

	fieldStr := section[parenStart+1 : parenEnd]
	fields := strings.Fields(fieldStr)

	// Parse headers
	headerStr := extractHeader(content)
	reader := bufio.NewReader(strings.NewReader(headerStr))

	var result strings.Builder
	var currentHeader string
	var currentValue string
	inHeader := true

	flushHeader := func() {
		if currentHeader == "" {
			return
		}
		wanted := false
		for _, f := range fields {
			if strings.EqualFold(f, currentHeader) {
				wanted = true
				break
			}
		}
		if (wanted && !negate) || (!wanted && negate) {
			result.WriteString(currentHeader + ": " + currentValue + "\r\n")
		}
		currentHeader = ""
		currentValue = ""
	}

	for inHeader {
		line, err := reader.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")

		if line == "" {
			flushHeader()
			inHeader = false
			continue
		}

		if line[0] == ' ' || line[0] == '\t' {
			// Continuation line
			currentValue += "\r\n" + line
		} else {
			flushHeader()
			colonIdx := strings.IndexByte(line, ':')
			if colonIdx > 0 {
				currentHeader = line[:colonIdx]
				currentValue = strings.TrimLeft(line[colonIdx+1:], " ")
			}
		}

		if err != nil {
			break
		}
	}
	flushHeader()
	result.WriteString("\r\n")

	return result.String()
}

// buildEnvelope builds an IMAP ENVELOPE response from message content.
func buildEnvelope(content []byte) string {
	msg, err := mail.ReadMessage(strings.NewReader(string(content)))
	if err != nil {
		return "(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)"
	}

	h := msg.Header

	date := nilOrQuote(h.Get("Date"))
	subject := nilOrQuote(h.Get("Subject"))
	from := formatAddressList(h.Get("From"))
	sender := formatAddressList(h.Get("Sender"))
	replyTo := formatAddressList(h.Get("Reply-To"))
	to := formatAddressList(h.Get("To"))
	cc := formatAddressList(h.Get("Cc"))
	bcc := formatAddressList(h.Get("Bcc"))
	inReplyTo := nilOrQuote(h.Get("In-Reply-To"))
	messageID := nilOrQuote(h.Get("Message-Id"))

	// If sender is NIL, use from
	if sender == "NIL" {
		sender = from
	}
	// If reply-to is NIL, use from
	if replyTo == "NIL" {
		replyTo = from
	}

	return fmt.Sprintf("(%s %s %s %s %s %s %s %s %s %s)",
		date, subject, from, sender, replyTo, to, cc, bcc, inReplyTo, messageID)
}

// formatAddressList formats an address header as an IMAP address list.
func formatAddressList(header string) string {
	if header == "" {
		return "NIL"
	}

	addrs, err := mail.ParseAddressList(header)
	if err != nil {
		// Fallback: return the raw value as a single address
		return fmt.Sprintf("((NIL NIL %s NIL))", quoteString(header))
	}

	var parts []string
	for _, addr := range addrs {
		name := "NIL"
		if addr.Name != "" {
			name = quoteString(addr.Name)
		}

		// Split email into local@domain
		local := addr.Address
		domain := ""
		if atIdx := strings.LastIndexByte(addr.Address, '@'); atIdx >= 0 {
			local = addr.Address[:atIdx]
			domain = addr.Address[atIdx+1:]
		}

		parts = append(parts, fmt.Sprintf("(%s NIL %s %s)", name, quoteString(local), quoteString(domain)))
	}

	return "(" + strings.Join(parts, " ") + ")"
}

// buildBodyStructure builds a simplified BODYSTRUCTURE response.
func buildBodyStructure(content []byte) string {
	msg, err := mail.ReadMessage(strings.NewReader(string(content)))
	if err != nil {
		return `("TEXT" "PLAIN" ("CHARSET" "US-ASCII") NIL NIL "7BIT" 0 0)`
	}

	ct := msg.Header.Get("Content-Type")
	if ct == "" {
		ct = "text/plain"
	}

	cte := msg.Header.Get("Content-Transfer-Encoding")
	if cte == "" {
		cte = "7BIT"
	}

	// Parse content type
	mediaType := "TEXT"
	subType := "PLAIN"
	if slashIdx := strings.IndexByte(ct, '/'); slashIdx >= 0 {
		mediaType = strings.ToUpper(ct[:slashIdx])
		sub := ct[slashIdx+1:]
		if semiIdx := strings.IndexByte(sub, ';'); semiIdx >= 0 {
			sub = sub[:semiIdx]
		}
		subType = strings.ToUpper(strings.TrimSpace(sub))
	}

	body := extractBody(content)
	bodySize := len(body)
	bodyLines := strings.Count(body, "\n")

	return fmt.Sprintf(`(%s %s ("CHARSET" "UTF-8") NIL NIL %s %d %d)`,
		quoteString(mediaType), quoteString(subType), quoteString(strings.ToUpper(cte)), bodySize, bodyLines)
}
