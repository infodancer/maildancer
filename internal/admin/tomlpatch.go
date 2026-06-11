package admin

import "strings"

// QuoteString returns s as a TOML basic double-quoted string value.
// Use when building rawValue arguments for PatchSectionValue.
func QuoteString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

// PatchSectionValue edits content in-place, setting key = rawValue in
// [section], or at the top level when section is empty. rawValue must be the
// TOML-formatted value (QuoteString for strings, "26214400" for integers).
// All other content -- comments, whitespace, unrelated sections -- is
// preserved. A missing section is appended; an empty rawValue removes the
// key line.
func PatchSectionValue(content []byte, section, key, rawValue string) []byte {
	lines := strings.Split(string(content), "\n")

	if section == "" {
		return patchTopLevel(lines, key, rawValue)
	}

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
		if isTOMLSectionHeader(strings.TrimSpace(lines[i])) {
			sectionEnd = i
			break
		}
	}

	// Look for the key within the section.
	keyLine := -1
	for i := sectionStart + 1; i < sectionEnd; i++ {
		if matchesTOMLKey(lines[i], key) {
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

// patchTopLevel sets key = rawValue in the top-level table, which runs from
// the start of the file to the first section header.
func patchTopLevel(lines []string, key, rawValue string) []byte {
	// The top-level table ends at the first section header.
	topEnd := len(lines)
	for i, line := range lines {
		if isTOMLSectionHeader(strings.TrimSpace(line)) {
			topEnd = i
			break
		}
	}

	keyLine := -1
	for i := range topEnd {
		if matchesTOMLKey(lines[i], key) {
			keyLine = i
			break
		}
	}

	switch {
	case keyLine >= 0 && rawValue == "":
		// Remove the key line.
		result := append([]string{}, lines[:keyLine]...)
		result = append(result, lines[keyLine+1:]...)
		return []byte(strings.Join(result, "\n"))
	case keyLine >= 0:
		patched := make([]string, len(lines))
		copy(patched, lines)
		patched[keyLine] = key + " = " + rawValue
		return []byte(strings.Join(patched, "\n"))
	case rawValue == "":
		return []byte(strings.Join(lines, "\n"))
	}

	// Insert at the end of the top-level table, before the first header.
	entry := key + " = " + rawValue
	if topEnd == len(lines) {
		joined := strings.TrimRight(strings.Join(lines, "\n"), "\n")
		if joined == "" {
			return []byte(entry + "\n")
		}
		return []byte(joined + "\n" + entry + "\n")
	}
	result := append([]string{}, lines[:topEnd]...)
	// Keep a blank line between the new entry and the following header.
	for len(result) > 0 && strings.TrimSpace(result[len(result)-1]) == "" {
		result = result[:len(result)-1]
	}
	result = append(result, entry, "")
	result = append(result, lines[topEnd:]...)
	return []byte(strings.Join(result, "\n"))
}

// isTOMLSectionHeader reports whether the trimmed line is a TOML section or
// array-of-tables header ([...] or [[...]]).
func isTOMLSectionHeader(t string) bool {
	return t != "" && !strings.HasPrefix(t, "#") && strings.HasPrefix(t, "[")
}

// matchesTOMLKey reports whether line (after trimming) sets the given TOML
// key, regardless of value. Returns false for comment lines.
func matchesTOMLKey(line, key string) bool {
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
