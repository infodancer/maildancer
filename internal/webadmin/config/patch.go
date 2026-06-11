package config

import "strings"

// PatchRspamdChecker edits content (a shared TOML config file) in-place,
// updating the url and password fields in the [[spamcheck.checkers]] block
// where type = "rspamd". All other content -- comments, whitespace, and
// unrelated sections -- is preserved exactly.
//
// If no rspamd checker block exists, one is appended at the end of the file.
// If password is empty, the password key is omitted (or removed if present).
func PatchRspamdChecker(content []byte, url, password string) []byte {
	lines := strings.Split(string(content), "\n")

	type span struct{ start, end int }

	// Identify all [[spamcheck.checkers]] blocks.
	// A block runs from its header line up to (not including) the next
	// section/array-of-tables header, or EOF.
	var blocks []span
	inBlock := false
	blockStart := 0

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if t == "[[spamcheck.checkers]]" {
			if inBlock {
				blocks = append(blocks, span{blockStart, i})
			}
			inBlock = true
			blockStart = i
		} else if inBlock && isSectionHeader(t) {
			blocks = append(blocks, span{blockStart, i})
			inBlock = false
		}
	}
	if inBlock {
		blocks = append(blocks, span{blockStart, len(lines)})
	}

	// Find the rspamd block.
	rspamdIdx := -1
	for i, b := range blocks {
		for j := b.start + 1; j < b.end; j++ {
			if matchesKV(lines[j], "type", "rspamd") {
				rspamdIdx = i
				break
			}
		}
		if rspamdIdx >= 0 {
			break
		}
	}

	if rspamdIdx < 0 {
		// No rspamd block -- append one at the end.
		joined := strings.TrimRight(strings.Join(lines, "\n"), "\n")
		var sb strings.Builder
		sb.WriteString(joined)
		sb.WriteString("\n\n[[spamcheck.checkers]]\ntype = \"rspamd\"\nurl = ")
		sb.WriteString(tomlQuote(url))
		sb.WriteString("\n")
		if password != "" {
			sb.WriteString("password = ")
			sb.WriteString(tomlQuote(password))
			sb.WriteString("\n")
		}
		return []byte(sb.String())
	}

	// Patch within the rspamd block.
	b := blocks[rspamdIdx]
	patched := make([]string, len(lines))
	copy(patched, lines)

	urlLine := -1
	passwordLine := -1
	typeLine := -1
	deleteLines := make(map[int]bool)

	for i := b.start + 1; i < b.end; i++ {
		switch {
		case matchesKV(lines[i], "type", "rspamd"):
			typeLine = i
		case matchesKey(lines[i], "url"):
			urlLine = i
			patched[i] = "url = " + tomlQuote(url)
		case matchesKey(lines[i], "password"):
			passwordLine = i
			if password != "" {
				patched[i] = "password = " + tomlQuote(password)
			} else {
				deleteLines[i] = true
			}
		}
	}

	// Insert missing keys after the type line (or the block header as fallback).
	insertAfter := b.start
	if typeLine >= 0 {
		insertAfter = typeLine
	}

	var inserts []string
	if urlLine < 0 {
		inserts = append(inserts, "url = "+tomlQuote(url))
	}
	if passwordLine < 0 && password != "" {
		inserts = append(inserts, "password = "+tomlQuote(password))
	}

	// Build the final result, inserting new lines and removing deleted ones.
	result := make([]string, 0, len(patched)+len(inserts))
	for i, line := range patched {
		if deleteLines[i] {
			continue
		}
		result = append(result, line)
		if i == insertAfter && len(inserts) > 0 {
			result = append(result, inserts...)
			inserts = nil
		}
	}

	return []byte(strings.Join(result, "\n"))
}

// QuoteString returns s as a TOML double-quoted string value.
// Use when building rawValue arguments for PatchSectionValue.
func QuoteString(s string) string { return tomlQuote(s) }

// PatchSectionValue edits content in-place, setting key = rawValue in [section].
// rawValue should be the TOML-formatted value (e.g. `"\"string\""` for strings,
// `"true"` for booleans, `"26214400"` for integers).
// All other content -- comments, whitespace, unrelated sections -- is preserved.
// If the section doesn't exist, it is appended. If rawValue is empty, the key
// line is removed.
func PatchSectionValue(content []byte, section, key, rawValue string) []byte {
	lines := strings.Split(string(content), "\n")

	sectionHeader := "[" + section + "]"

	// Find the section.
	sectionStart := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == sectionHeader {
			sectionStart = i
			break
		}
	}

	if sectionStart < 0 {
		// Section not found -- append it (only if rawValue is non-empty).
		if rawValue == "" {
			return content
		}
		joined := strings.TrimRight(strings.Join(lines, "\n"), "\n")
		var sb strings.Builder
		sb.WriteString(joined)
		sb.WriteString("\n\n")
		sb.WriteString(sectionHeader)
		sb.WriteString("\n")
		sb.WriteString(key)
		sb.WriteString(" = ")
		sb.WriteString(rawValue)
		sb.WriteString("\n")
		return []byte(sb.String())
	}

	// Determine where the section ends (next section/array-of-tables header).
	sectionEnd := len(lines)
	for i := sectionStart + 1; i < len(lines); i++ {
		if isSectionHeader(strings.TrimSpace(lines[i])) {
			sectionEnd = i
			break
		}
	}

	// Look for the key within the section.
	keyLine := -1
	for i := sectionStart + 1; i < sectionEnd; i++ {
		if matchesKey(lines[i], key) {
			keyLine = i
			break
		}
	}

	patched := make([]string, len(lines))
	copy(patched, lines)

	deleteLines := make(map[int]bool)
	var inserts []string
	insertAfter := sectionStart

	if keyLine >= 0 {
		if rawValue == "" {
			// Remove the key line.
			deleteLines[keyLine] = true
		} else {
			// Update in place.
			patched[keyLine] = key + " = " + rawValue
		}
	} else if rawValue != "" {
		// Insert after the section header.
		inserts = append(inserts, key+" = "+rawValue)
	}

	result := make([]string, 0, len(patched)+len(inserts))
	for i, line := range patched {
		if deleteLines[i] {
			continue
		}
		result = append(result, line)
		if i == insertAfter && len(inserts) > 0 {
			result = append(result, inserts...)
			inserts = nil
		}
	}

	return []byte(strings.Join(result, "\n"))
}

// isSectionHeader reports whether the trimmed line is a TOML section or
// array-of-tables header ([...] or [[...]]).
func isSectionHeader(t string) bool {
	return t != "" && !strings.HasPrefix(t, "#") && strings.HasPrefix(t, "[")
}

// matchesKey reports whether line (after trimming) sets the given TOML key,
// regardless of value. Returns false for comment lines.
func matchesKey(line, key string) bool {
	t := strings.TrimSpace(line)
	if strings.HasPrefix(t, "#") {
		return false
	}
	rest := strings.TrimPrefix(t, key)
	if len(rest) == len(t) { // key not at start
		return false
	}
	rest = strings.TrimLeft(rest, " \t")
	return strings.HasPrefix(rest, "=")
}

// matchesKV reports whether line sets key to the given unquoted string value.
func matchesKV(line, key, value string) bool {
	if !matchesKey(line, key) {
		return false
	}
	t := strings.TrimSpace(line)
	idx := strings.Index(t, "=")
	if idx < 0 {
		return false
	}
	v := strings.TrimSpace(t[idx+1:])
	// Strip inline comment if present.
	if before, _, found := strings.Cut(v, " #"); found {
		v = strings.TrimSpace(before)
	}
	// Strip surrounding double quotes.
	v = strings.Trim(v, `"`)
	return v == value
}

// tomlQuote returns s as a TOML basic double-quoted string.
func tomlQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}
