package imap

import (
	"context"
	"fmt"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/infodancer/maildancer/internal/imapd/server"
)

// searchCommand implements the SEARCH command.
type searchCommand struct{}

func (c *searchCommand) Name() string { return "SEARCH" }

func (c *searchCommand) Execute(ctx context.Context, tag, args string, sess *Session, conn *server.Connection) error {
	return doSearch(ctx, tag, args, sess, conn, false)
}

// doSearch handles SEARCH and UID SEARCH.
func doSearch(ctx context.Context, tag, args string, sess *Session, conn *server.Connection, useUID bool) error {
	w := conn.Writer()

	if sess.State() != StateSelected {
		return writeBAD(w, tag, "No mailbox selected")
	}

	criteria := strings.TrimSpace(args)
	if criteria == "" {
		return writeBAD(w, tag, "Missing search criteria")
	}

	var results []string

	for i := 1; i <= sess.MessageCount(); i++ {
		msg := sess.GetMessage(i)
		if msg == nil {
			continue
		}

		flags := sess.GetFlags(i)

		match, err := matchesCriteria(ctx, i, msg.UID, flags, msg.Size, criteria, sess)
		if err != nil {
			sess.Logger().Error("search error", "seqnum", i, "error", err.Error())
			continue
		}

		if match {
			if useUID {
				results = append(results, fmt.Sprintf("%d", sess.MessageUID(i)))
			} else {
				results = append(results, fmt.Sprintf("%d", i))
			}
		}
	}

	resp := "SEARCH"
	if len(results) > 0 {
		resp += " " + strings.Join(results, " ")
	}

	if err := writeUntagged(w, resp); err != nil {
		return err
	}

	return writeOK(w, tag, "SEARCH completed")
}

// matchesCriteria checks if a message matches the search criteria.
func matchesCriteria(ctx context.Context, seqNum int, uid string, flags []string, size int64, criteria string, sess *Session) (bool, error) {
	tokens := tokenizeCriteria(criteria)
	result, _, err := evalCriteria(ctx, seqNum, uid, flags, size, tokens, sess)
	return result, err
}

// tokenizeCriteria splits search criteria into tokens, respecting quoted strings and parentheses.
func tokenizeCriteria(s string) []string {
	var tokens []string
	var current strings.Builder
	inQuote := false
	depth := 0

	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '"' && !inQuote:
			inQuote = true
			current.WriteByte(ch)
		case ch == '"' && inQuote:
			inQuote = false
			current.WriteByte(ch)
		case ch == '(' && !inQuote:
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
			tokens = append(tokens, "(")
			depth++
		case ch == ')' && !inQuote:
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
			tokens = append(tokens, ")")
			depth--
		case ch == ' ' && !inQuote && depth == 0:
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(ch)
		}
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	return tokens
}

// evalCriteria evaluates search criteria tokens. Returns match result and remaining tokens.
func evalCriteria(ctx context.Context, seqNum int, uid string, flags []string, size int64, tokens []string, sess *Session) (bool, []string, error) {
	if len(tokens) == 0 {
		return true, tokens, nil
	}

	// Implicit AND: all criteria must match
	result := true
	for len(tokens) > 0 {
		if tokens[0] == ")" {
			break
		}

		match, remaining, err := evalSingleCriterion(ctx, seqNum, uid, flags, size, tokens, sess)
		if err != nil {
			return false, remaining, err
		}
		tokens = remaining
		if !match {
			result = false
		}
	}
	return result, tokens, nil
}

// evalSingleCriterion evaluates a single search criterion.
func evalSingleCriterion(ctx context.Context, seqNum int, uid string, flags []string, size int64, tokens []string, sess *Session) (bool, []string, error) {
	if len(tokens) == 0 {
		return true, tokens, nil
	}

	token := strings.ToUpper(tokens[0])
	rest := tokens[1:]

	switch token {
	case "ALL":
		return true, rest, nil

	case "ANSWERED":
		return HasFlag(flags, FlagAnswered), rest, nil

	case "DELETED":
		return HasFlag(flags, FlagDeleted), rest, nil

	case "FLAGGED":
		return HasFlag(flags, FlagFlagged), rest, nil

	case "NEW":
		return HasFlag(flags, FlagRecent) && !HasFlag(flags, FlagSeen), rest, nil

	case "OLD":
		return !HasFlag(flags, FlagRecent), rest, nil

	case "RECENT":
		return HasFlag(flags, FlagRecent), rest, nil

	case "SEEN":
		return HasFlag(flags, FlagSeen), rest, nil

	case "UNANSWERED":
		return !HasFlag(flags, FlagAnswered), rest, nil

	case "UNDELETED":
		return !HasFlag(flags, FlagDeleted), rest, nil

	case "UNFLAGGED":
		return !HasFlag(flags, FlagFlagged), rest, nil

	case "UNSEEN":
		return !HasFlag(flags, FlagSeen), rest, nil

	case "DRAFT":
		return HasFlag(flags, FlagDraft), rest, nil

	case "UNDRAFT":
		return !HasFlag(flags, FlagDraft), rest, nil

	case "NOT":
		if len(rest) == 0 {
			return false, rest, fmt.Errorf("NOT requires an argument")
		}
		match, remaining, err := evalSingleCriterion(ctx, seqNum, uid, flags, size, rest, sess)
		return !match, remaining, err

	case "OR":
		if len(rest) < 2 {
			return false, rest, fmt.Errorf("OR requires two arguments")
		}
		match1, remaining1, err := evalSingleCriterion(ctx, seqNum, uid, flags, size, rest, sess)
		if err != nil {
			return false, remaining1, err
		}
		match2, remaining2, err := evalSingleCriterion(ctx, seqNum, uid, flags, size, remaining1, sess)
		if err != nil {
			return false, remaining2, err
		}
		return match1 || match2, remaining2, nil

	case "(":
		match, remaining, err := evalCriteria(ctx, seqNum, uid, flags, size, rest, sess)
		if err != nil {
			return false, remaining, err
		}
		// Consume closing paren
		if len(remaining) > 0 && remaining[0] == ")" {
			remaining = remaining[1:]
		}
		return match, remaining, nil

	case "UID":
		if len(rest) == 0 {
			return false, rest, fmt.Errorf("UID requires a sequence set")
		}
		seqSet, err := ParseSequenceSet(rest[0])
		if err != nil {
			return false, rest[1:], err
		}
		uidVal := uidFromString(uid)
		return seqSet.Contains(uidVal, sess.UIDNext()-1), rest[1:], nil

	case "LARGER":
		if len(rest) == 0 {
			return false, rest, fmt.Errorf("LARGER requires a size")
		}
		n, err := strconv.ParseInt(rest[0], 10, 64)
		if err != nil {
			return false, rest[1:], err
		}
		return size > n, rest[1:], nil

	case "SMALLER":
		if len(rest) == 0 {
			return false, rest, fmt.Errorf("SMALLER requires a size")
		}
		n, err := strconv.ParseInt(rest[0], 10, 64)
		if err != nil {
			return false, rest[1:], err
		}
		return size < n, rest[1:], nil

	case "KEYWORD":
		if len(rest) == 0 {
			return false, rest, fmt.Errorf("KEYWORD requires a flag")
		}
		return HasFlag(flags, rest[0]), rest[1:], nil

	case "UNKEYWORD":
		if len(rest) == 0 {
			return false, rest, fmt.Errorf("UNKEYWORD requires a flag")
		}
		return !HasFlag(flags, rest[0]), rest[1:], nil

	case "SUBJECT", "FROM", "TO", "CC", "BCC", "TEXT", "BODY":
		if len(rest) == 0 {
			return false, rest, fmt.Errorf("%s requires a string argument", token)
		}
		searchStr := unquote(rest[0])
		match, err := searchInMessage(ctx, seqNum, uid, token, searchStr, sess)
		return match, rest[1:], err

	case "HEADER":
		if len(rest) < 2 {
			return false, rest, fmt.Errorf("HEADER requires field-name and string")
		}
		fieldName := rest[0]
		searchStr := unquote(rest[1])
		match, err := searchHeader(ctx, seqNum, uid, fieldName, searchStr, sess)
		return match, rest[2:], err

	case "BEFORE", "ON", "SINCE":
		if len(rest) == 0 {
			return false, rest, fmt.Errorf("%s requires a date", token)
		}
		dateStr := unquote(rest[0])
		match, err := searchByDate(ctx, seqNum, uid, token, dateStr, sess)
		return match, rest[1:], err

	case "SENTBEFORE", "SENTON", "SENTSINCE":
		if len(rest) == 0 {
			return false, rest, fmt.Errorf("%s requires a date", token)
		}
		dateStr := unquote(rest[0])
		match, err := searchBySentDate(ctx, seqNum, uid, token, dateStr, sess)
		return match, rest[1:], err

	default:
		// Try to parse as a sequence set
		seqSet, err := ParseSequenceSet(token)
		if err == nil {
			return seqSet.Contains(uint32(seqNum), uint32(sess.MessageCount())), rest, nil
		}
		// Unknown criterion - skip
		return true, rest, nil
	}
}

// searchInMessage searches for a string in message headers or body.
func searchInMessage(ctx context.Context, seqNum int, uid, field, searchStr string, sess *Session) (bool, error) {
	content, err := retrieveMessage(ctx, seqNum, uid, sess)
	if err != nil {
		return false, err
	}

	searchLower := strings.ToLower(searchStr)
	fullContent := strings.ToLower(string(content))

	switch field {
	case "TEXT":
		return strings.Contains(fullContent, searchLower), nil
	case "BODY":
		body := strings.ToLower(extractBody(content))
		return strings.Contains(body, searchLower), nil
	default:
		// Search specific header
		msg, err := mail.ReadMessage(strings.NewReader(string(content)))
		if err != nil {
			return false, nil
		}
		headerVal := strings.ToLower(msg.Header.Get(field))
		return strings.Contains(headerVal, searchLower), nil
	}
}

// searchHeader searches for a string in a specific header field.
func searchHeader(ctx context.Context, seqNum int, uid, fieldName, searchStr string, sess *Session) (bool, error) {
	content, err := retrieveMessage(ctx, seqNum, uid, sess)
	if err != nil {
		return false, err
	}

	msg, err := mail.ReadMessage(strings.NewReader(string(content)))
	if err != nil {
		return false, nil
	}

	headerVal := strings.ToLower(msg.Header.Get(fieldName))
	if searchStr == "" {
		return headerVal != "", nil
	}
	return strings.Contains(headerVal, strings.ToLower(searchStr)), nil
}

// searchByDate searches by internal date.
func searchByDate(ctx context.Context, seqNum int, uid, op, dateStr string, sess *Session) (bool, error) {
	target, err := parseIMAPDate(dateStr)
	if err != nil {
		return false, nil
	}

	// Use current time as fallback for internal date
	msgDate := time.Now()

	switch op {
	case "BEFORE":
		return msgDate.Before(target), nil
	case "ON":
		return sameDay(msgDate, target), nil
	case "SINCE":
		return !msgDate.Before(target), nil
	}
	return false, nil
}

// searchBySentDate searches by the Date header.
func searchBySentDate(ctx context.Context, seqNum int, uid, op, dateStr string, sess *Session) (bool, error) {
	target, err := parseIMAPDate(dateStr)
	if err != nil {
		return false, nil
	}

	content, err := retrieveMessage(ctx, seqNum, uid, sess)
	if err != nil {
		return false, err
	}

	msg, err := mail.ReadMessage(strings.NewReader(string(content)))
	if err != nil {
		return false, nil
	}

	sentDate, err := msg.Header.Date()
	if err != nil {
		return false, nil
	}

	switch op {
	case "SENTBEFORE":
		return sentDate.Before(target), nil
	case "SENTON":
		return sameDay(sentDate, target), nil
	case "SENTSINCE":
		return !sentDate.Before(target), nil
	}
	return false, nil
}

// parseIMAPDate parses an IMAP date string (e.g., "1-Feb-2024").
func parseIMAPDate(s string) (time.Time, error) {
	s = strings.Trim(s, `"`)
	formats := []string{
		"2-Jan-2006",
		"02-Jan-2006",
	}
	for _, format := range formats {
		t, err := time.Parse(format, s)
		if err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid date: %s", s)
}

// sameDay returns true if two times are on the same calendar day.
func sameDay(a, b time.Time) bool {
	ay, am, ad := a.Date()
	by, bm, bd := b.Date()
	return ay == by && am == bm && ad == bd
}

// unquote removes surrounding quotes from a string.
func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}
