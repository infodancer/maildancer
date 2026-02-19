package imap

import (
	"fmt"
	"strconv"
	"strings"
)

// ParsedCommand represents a parsed IMAP command line.
type ParsedCommand struct {
	Tag  string
	Name string
	Args string // raw argument string after the command name
}

// ParseCommandLine parses a raw IMAP command line into tag, command name, and arguments.
// IMAP format: "<tag> <command> [args]\r\n"
func ParseCommandLine(line string) (*ParsedCommand, error) {
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return nil, fmt.Errorf("empty command line")
	}

	// Split tag from rest
	spaceIdx := strings.IndexByte(line, ' ')
	if spaceIdx < 0 {
		return nil, fmt.Errorf("missing command after tag")
	}

	tag := line[:spaceIdx]
	rest := line[spaceIdx+1:]

	if tag == "" {
		return nil, fmt.Errorf("empty tag")
	}

	// Split command from arguments
	var name, args string
	spaceIdx = strings.IndexByte(rest, ' ')
	if spaceIdx < 0 {
		name = rest
		args = ""
	} else {
		name = rest[:spaceIdx]
		args = rest[spaceIdx+1:]
	}

	if name == "" {
		return nil, fmt.Errorf("empty command name")
	}

	return &ParsedCommand{
		Tag:  tag,
		Name: strings.ToUpper(name),
		Args: args,
	}, nil
}

// SequenceRange represents a single range in a sequence set (e.g., "5", "1:3", "7:*").
type SequenceRange struct {
	Start uint32
	End   uint32 // 0 means "*" (largest)
}

// SequenceSet is a list of sequence ranges.
type SequenceSet []SequenceRange

// ParseSequenceSet parses an IMAP sequence set string like "1:5,7,9:*".
func ParseSequenceSet(s string) (SequenceSet, error) {
	if s == "" {
		return nil, fmt.Errorf("empty sequence set")
	}

	parts := strings.Split(s, ",")
	var set SequenceSet

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		r, err := parseRange(part)
		if err != nil {
			return nil, err
		}
		set = append(set, r)
	}

	if len(set) == 0 {
		return nil, fmt.Errorf("empty sequence set")
	}

	return set, nil
}

// Contains returns true if the sequence set contains the given number.
// maxVal is used to resolve "*".
func (ss SequenceSet) Contains(num uint32, maxVal uint32) bool {
	for _, r := range ss {
		end := r.End
		if end == 0 {
			end = maxVal
		}
		start := r.Start
		if start == 0 {
			start = maxVal
		}
		lo, hi := start, end
		if lo > hi {
			lo, hi = hi, lo
		}
		if num >= lo && num <= hi {
			return true
		}
	}
	return false
}

func parseRange(s string) (SequenceRange, error) {
	colonIdx := strings.IndexByte(s, ':')
	if colonIdx < 0 {
		// Single number or *
		n, err := parseSeqNum(s)
		if err != nil {
			return SequenceRange{}, err
		}
		return SequenceRange{Start: n, End: n}, nil
	}

	start, err := parseSeqNum(s[:colonIdx])
	if err != nil {
		return SequenceRange{}, err
	}
	end, err := parseSeqNum(s[colonIdx+1:])
	if err != nil {
		return SequenceRange{}, err
	}
	return SequenceRange{Start: start, End: end}, nil
}

// parseSeqNum parses a sequence number or "*" (returned as 0).
func parseSeqNum(s string) (uint32, error) {
	s = strings.TrimSpace(s)
	if s == "*" {
		return 0, nil
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid sequence number: %q", s)
	}
	if n == 0 {
		return 0, fmt.Errorf("sequence number must be positive")
	}
	return uint32(n), nil
}

// ParseParenList parses a parenthesised list like "(MESSAGES RECENT UNSEEN)".
// Returns the items inside the parentheses.
func ParseParenList(s string) ([]string, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "(") || !strings.HasSuffix(s, ")") {
		return nil, fmt.Errorf("expected parenthesised list, got %q", s)
	}
	inner := s[1 : len(s)-1]
	if inner == "" {
		return nil, nil
	}
	return strings.Fields(inner), nil
}

// ParseQuotedOrAtom parses a quoted string or atom from the beginning of s.
// Returns the parsed value and the remaining string.
func ParseQuotedOrAtom(s string) (value, remaining string) {
	s = strings.TrimLeft(s, " ")
	if s == "" {
		return "", ""
	}

	if s[0] == '"' {
		// Quoted string
		return parseQuotedString(s)
	}

	// Atom - read until space, paren, or end
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '(', ')', '{', '\r', '\n':
			return s[:i], s[i:]
		}
	}
	return s, ""
}

func parseQuotedString(s string) (value, remaining string) {
	if len(s) < 2 || s[0] != '"' {
		return s, ""
	}

	var sb strings.Builder
	escaped := false
	for i := 1; i < len(s); i++ {
		if escaped {
			sb.WriteByte(s[i])
			escaped = false
			continue
		}
		if s[i] == '\\' {
			escaped = true
			continue
		}
		if s[i] == '"' {
			return sb.String(), s[i+1:]
		}
		sb.WriteByte(s[i])
	}
	// Unterminated quote - return what we have
	return sb.String(), ""
}

// ParseFetchItems parses FETCH item specifications.
// Handles macros (ALL, FAST, FULL) and parenthesised lists.
func ParseFetchItems(args string) ([]string, error) {
	args = strings.TrimSpace(args)
	if args == "" {
		return nil, fmt.Errorf("no fetch items specified")
	}

	upper := strings.ToUpper(args)

	// Handle macros (RFC 3501 section 6.4.5)
	switch upper {
	case "ALL":
		return []string{"FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE"}, nil
	case "FAST":
		return []string{"FLAGS", "INTERNALDATE", "RFC822.SIZE"}, nil
	case "FULL":
		return []string{"FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE", "BODY"}, nil
	}

	// Parenthesised list
	if strings.HasPrefix(args, "(") {
		// Find matching close paren
		depth := 0
		for i := 0; i < len(args); i++ {
			if args[i] == '(' {
				depth++
			} else if args[i] == ')' {
				depth--
				if depth == 0 {
					inner := args[1:i]
					return parseFetchItemList(inner), nil
				}
			}
		}
		return nil, fmt.Errorf("unmatched parenthesis in fetch items")
	}

	// Single item
	return []string{strings.ToUpper(args)}, nil
}

// parseFetchItemList splits fetch items respecting brackets for BODY[...] and HEADER.FIELDS (...).
func parseFetchItemList(s string) []string {
	var items []string
	var current strings.Builder
	depth := 0

	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch ch {
		case '[':
			depth++
			current.WriteByte(ch)
		case ']':
			depth--
			current.WriteByte(ch)
		case ' ':
			if depth == 0 {
				item := strings.TrimSpace(current.String())
				if item != "" {
					items = append(items, strings.ToUpper(item))
				}
				current.Reset()
			} else {
				current.WriteByte(ch)
			}
		default:
			current.WriteByte(ch)
		}
	}

	item := strings.TrimSpace(current.String())
	if item != "" {
		items = append(items, strings.ToUpper(item))
	}

	return items
}

// ParseStoreFlags parses the flags argument of a STORE command.
// flagsStr can be "(flag1 flag2)" or "flag1 flag2" or a single flag.
func ParseStoreFlags(flagsStr string) []string {
	flagsStr = strings.TrimSpace(flagsStr)
	if strings.HasPrefix(flagsStr, "(") && strings.HasSuffix(flagsStr, ")") {
		flagsStr = flagsStr[1 : len(flagsStr)-1]
	}
	if flagsStr == "" {
		return nil
	}
	return strings.Fields(flagsStr)
}
