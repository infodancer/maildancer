package imap

import (
	"testing"
)

// --- ParseCommandLine ---

func TestParseCommandLineTaggedNoArgs(t *testing.T) {
	cmd, err := ParseCommandLine("A001 CAPABILITY")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd.Tag != "A001" {
		t.Errorf("tag = %q, want %q", cmd.Tag, "A001")
	}
	if cmd.Name != "CAPABILITY" {
		t.Errorf("name = %q, want %q", cmd.Name, "CAPABILITY")
	}
	if cmd.Args != "" {
		t.Errorf("args = %q, want empty", cmd.Args)
	}
}

func TestParseCommandLineTaggedWithArgs(t *testing.T) {
	cmd, err := ParseCommandLine("A002 LOGIN user@example.com secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd.Tag != "A002" {
		t.Errorf("tag = %q, want %q", cmd.Tag, "A002")
	}
	if cmd.Name != "LOGIN" {
		t.Errorf("name = %q, want %q", cmd.Name, "LOGIN")
	}
	if cmd.Args != "user@example.com secret" {
		t.Errorf("args = %q, want %q", cmd.Args, "user@example.com secret")
	}
}

func TestParseCommandLineNormalisesNameToUpperCase(t *testing.T) {
	cmd, err := ParseCommandLine("t1 select INBOX")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd.Name != "SELECT" {
		t.Errorf("name = %q, want %q", cmd.Name, "SELECT")
	}
}

func TestParseCommandLineStripsTrailingCRLF(t *testing.T) {
	cmd, err := ParseCommandLine("A003 NOOP\r\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd.Name != "NOOP" {
		t.Errorf("name = %q, want %q", cmd.Name, "NOOP")
	}
}

func TestParseCommandLineStarTag(t *testing.T) {
	// Servers may send untagged responses; clients send * for continuation.
	cmd, err := ParseCommandLine("* LIST () \"/\" INBOX")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd.Tag != "*" {
		t.Errorf("tag = %q, want %q", cmd.Tag, "*")
	}
}

func TestParseCommandLineErrorEmptyLine(t *testing.T) {
	_, err := ParseCommandLine("")
	if err == nil {
		t.Error("expected error for empty line, got nil")
	}
}

func TestParseCommandLineErrorMissingCommand(t *testing.T) {
	_, err := ParseCommandLine("A001")
	if err == nil {
		t.Error("expected error for line with tag only, got nil")
	}
}

func TestParseCommandLineErrorEmptyTag(t *testing.T) {
	// A line starting with a space has an empty tag.
	_, err := ParseCommandLine(" NOOP")
	if err == nil {
		t.Error("expected error for empty tag, got nil")
	}
}

func TestParseCommandLineQuotedStringInArgs(t *testing.T) {
	cmd, err := ParseCommandLine(`A004 LOGIN "user name" "p@ss"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd.Args != `"user name" "p@ss"` {
		t.Errorf("args = %q, want %q", cmd.Args, `"user name" "p@ss"`)
	}
}

// --- ParseSequenceSet ---

func TestParseSequenceSetSingleNumber(t *testing.T) {
	ss, err := ParseSequenceSet("1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ss) != 1 {
		t.Fatalf("len = %d, want 1", len(ss))
	}
	if ss[0].Start != 1 || ss[0].End != 1 {
		t.Errorf("range = [%d:%d], want [1:1]", ss[0].Start, ss[0].End)
	}
}

func TestParseSequenceSetSimpleRange(t *testing.T) {
	ss, err := ParseSequenceSet("1:5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ss) != 1 {
		t.Fatalf("len = %d, want 1", len(ss))
	}
	if ss[0].Start != 1 || ss[0].End != 5 {
		t.Errorf("range = [%d:%d], want [1:5]", ss[0].Start, ss[0].End)
	}
}

func TestParseSequenceSetCommaList(t *testing.T) {
	ss, err := ParseSequenceSet("1,3,5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ss) != 3 {
		t.Fatalf("len = %d, want 3", len(ss))
	}
}

func TestParseSequenceSetMixedRangesAndSingles(t *testing.T) {
	ss, err := ParseSequenceSet("1:3,7:9")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ss) != 2 {
		t.Fatalf("len = %d, want 2", len(ss))
	}
	if ss[0].Start != 1 || ss[0].End != 3 {
		t.Errorf("first range = [%d:%d], want [1:3]", ss[0].Start, ss[0].End)
	}
	if ss[1].Start != 7 || ss[1].End != 9 {
		t.Errorf("second range = [%d:%d], want [7:9]", ss[1].Start, ss[1].End)
	}
}

func TestParseSequenceSetStar(t *testing.T) {
	ss, err := ParseSequenceSet("*")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// * is encoded as 0
	if ss[0].Start != 0 || ss[0].End != 0 {
		t.Errorf("star range = [%d:%d], want [0:0]", ss[0].Start, ss[0].End)
	}
}

func TestParseSequenceSetOpenRange(t *testing.T) {
	ss, err := ParseSequenceSet("1:*")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ss[0].Start != 1 || ss[0].End != 0 {
		t.Errorf("open range = [%d:%d], want [1:0]", ss[0].Start, ss[0].End)
	}
}

func TestParseSequenceSetErrorEmpty(t *testing.T) {
	_, err := ParseSequenceSet("")
	if err == nil {
		t.Error("expected error for empty sequence set, got nil")
	}
}

func TestParseSequenceSetErrorZeroNumber(t *testing.T) {
	_, err := ParseSequenceSet("0")
	if err == nil {
		t.Error("expected error for sequence number 0, got nil")
	}
}

func TestParseSequenceSetErrorInvalidCharacter(t *testing.T) {
	_, err := ParseSequenceSet("abc")
	if err == nil {
		t.Error("expected error for non-numeric sequence set, got nil")
	}
}

// --- SequenceSet.Contains ---

func TestSequenceSetContainsSingleMatch(t *testing.T) {
	ss, _ := ParseSequenceSet("3")
	if !ss.Contains(3, 10) {
		t.Error("Contains(3) = false, want true")
	}
	if ss.Contains(4, 10) {
		t.Error("Contains(4) = true, want false")
	}
}

func TestSequenceSetContainsRange(t *testing.T) {
	ss, _ := ParseSequenceSet("2:5")
	for _, n := range []uint32{2, 3, 4, 5} {
		if !ss.Contains(n, 10) {
			t.Errorf("Contains(%d) = false, want true", n)
		}
	}
	if ss.Contains(1, 10) {
		t.Error("Contains(1) = true, want false")
	}
	if ss.Contains(6, 10) {
		t.Error("Contains(6) = true, want false")
	}
}

func TestSequenceSetContainsStarResolvesToMax(t *testing.T) {
	ss, _ := ParseSequenceSet("*")
	if !ss.Contains(10, 10) {
		t.Error("Contains(10) with maxVal=10 = false, want true (star)")
	}
	if ss.Contains(9, 10) {
		t.Error("Contains(9) with maxVal=10 = true, want false (star)")
	}
}

func TestSequenceSetContainsOpenRange(t *testing.T) {
	ss, _ := ParseSequenceSet("8:*")
	if !ss.Contains(8, 10) {
		t.Error("Contains(8) = false, want true")
	}
	if !ss.Contains(10, 10) {
		t.Error("Contains(10) = false, want true")
	}
	if ss.Contains(7, 10) {
		t.Error("Contains(7) = true, want false")
	}
}

// --- ParseFetchItems ---

func TestParseFetchItemsMacroALL(t *testing.T) {
	items, err := ParseFetchItems("ALL")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE"}
	if !stringSlicesEqual(items, want) {
		t.Errorf("ALL macro = %v, want %v", items, want)
	}
}

func TestParseFetchItemsMacroFAST(t *testing.T) {
	items, err := ParseFetchItems("FAST")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"FLAGS", "INTERNALDATE", "RFC822.SIZE"}
	if !stringSlicesEqual(items, want) {
		t.Errorf("FAST macro = %v, want %v", items, want)
	}
}

func TestParseFetchItemsMacroFULL(t *testing.T) {
	items, err := ParseFetchItems("FULL")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE", "BODY"}
	if !stringSlicesEqual(items, want) {
		t.Errorf("FULL macro = %v, want %v", items, want)
	}
}

func TestParseFetchItemsMacrosCaseInsensitive(t *testing.T) {
	items, err := ParseFetchItems("all")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) == 0 {
		t.Error("all (lowercase) macro returned empty items")
	}
}

func TestParseFetchItemsSingleItem(t *testing.T) {
	items, err := ParseFetchItems("FLAGS")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 1 || items[0] != "FLAGS" {
		t.Errorf("items = %v, want [FLAGS]", items)
	}
}

func TestParseFetchItemsParenList(t *testing.T) {
	items, err := ParseFetchItems("(FLAGS UID RFC822.SIZE)")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"FLAGS", "UID", "RFC822.SIZE"}
	if !stringSlicesEqual(items, want) {
		t.Errorf("items = %v, want %v", items, want)
	}
}

func TestParseFetchItemsBodySection(t *testing.T) {
	items, err := ParseFetchItems("BODY[]")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 1 || items[0] != "BODY[]" {
		t.Errorf("items = %v, want [BODY[]]", items)
	}
}

func TestParseFetchItemsBodySectionHeader(t *testing.T) {
	items, err := ParseFetchItems("BODY[HEADER]")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 1 || items[0] != "BODY[HEADER]" {
		t.Errorf("items = %v, want [BODY[HEADER]]", items)
	}
}

func TestParseFetchItemsBodyPeekSection(t *testing.T) {
	items, err := ParseFetchItems("BODY.PEEK[TEXT]")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 1 || items[0] != "BODY.PEEK[TEXT]" {
		t.Errorf("items = %v, want [BODY.PEEK[TEXT]]", items)
	}
}

func TestParseFetchItemsParenListWithBodySection(t *testing.T) {
	items, err := ParseFetchItems("(FLAGS BODY[HEADER.FIELDS (FROM TO SUBJECT)])")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("items count = %d, want 2; items = %v", len(items), items)
	}
	if items[0] != "FLAGS" {
		t.Errorf("items[0] = %q, want %q", items[0], "FLAGS")
	}
	if items[1] != "BODY[HEADER.FIELDS (FROM TO SUBJECT)]" {
		t.Errorf("items[1] = %q, want %q", items[1], "BODY[HEADER.FIELDS (FROM TO SUBJECT)]")
	}
}

func TestParseFetchItemsErrorEmpty(t *testing.T) {
	_, err := ParseFetchItems("")
	if err == nil {
		t.Error("expected error for empty fetch items, got nil")
	}
}

func TestParseFetchItemsErrorUnmatchedParen(t *testing.T) {
	_, err := ParseFetchItems("(FLAGS UID")
	if err == nil {
		t.Error("expected error for unmatched parenthesis, got nil")
	}
}

// --- ParseParenList ---

func TestParseParenListBasic(t *testing.T) {
	items, err := ParseParenList("(MESSAGES RECENT UNSEEN)")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"MESSAGES", "RECENT", "UNSEEN"}
	if !stringSlicesEqual(items, want) {
		t.Errorf("items = %v, want %v", items, want)
	}
}

func TestParseParenListEmpty(t *testing.T) {
	items, err := ParseParenList("()")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 0 {
		t.Errorf("items = %v, want nil/empty", items)
	}
}

func TestParseParenListErrorNotParenthesised(t *testing.T) {
	_, err := ParseParenList("MESSAGES RECENT")
	if err == nil {
		t.Error("expected error for non-parenthesised input, got nil")
	}
}

// --- ParseQuotedOrAtom ---

func TestParseQuotedOrAtomQuotedString(t *testing.T) {
	value, remaining := ParseQuotedOrAtom(`"hello world" rest`)
	if value != "hello world" {
		t.Errorf("value = %q, want %q", value, "hello world")
	}
	if remaining != " rest" {
		t.Errorf("remaining = %q, want %q", remaining, " rest")
	}
}

func TestParseQuotedOrAtomAtom(t *testing.T) {
	value, remaining := ParseQuotedOrAtom("INBOX rest")
	if value != "INBOX" {
		t.Errorf("value = %q, want %q", value, "INBOX")
	}
	if remaining != " rest" {
		t.Errorf("remaining = %q, want %q", remaining, " rest")
	}
}

func TestParseQuotedOrAtomEscapeInQuotedString(t *testing.T) {
	value, _ := ParseQuotedOrAtom(`"say \"hi\""`)
	if value != `say "hi"` {
		t.Errorf("value = %q, want %q", value, `say "hi"`)
	}
}

func TestParseQuotedOrAtomEmptyInput(t *testing.T) {
	value, remaining := ParseQuotedOrAtom("")
	if value != "" || remaining != "" {
		t.Errorf("ParseQuotedOrAtom(\"\") = (%q, %q), want (\"\", \"\")", value, remaining)
	}
}

// --- ParseStoreFlags ---

func TestParseStoreFlagsParenthesised(t *testing.T) {
	flags := ParseStoreFlags(`(\Seen \Flagged)`)
	want := []string{`\Seen`, `\Flagged`}
	if !stringSlicesEqual(flags, want) {
		t.Errorf("flags = %v, want %v", flags, want)
	}
}

func TestParseStoreFlagsUnparenthesised(t *testing.T) {
	flags := ParseStoreFlags(`\Seen \Deleted`)
	want := []string{`\Seen`, `\Deleted`}
	if !stringSlicesEqual(flags, want) {
		t.Errorf("flags = %v, want %v", flags, want)
	}
}

func TestParseStoreFlagsEmpty(t *testing.T) {
	flags := ParseStoreFlags("")
	if len(flags) != 0 {
		t.Errorf("flags = %v, want nil/empty", flags)
	}
}

func TestParseStoreFlagsEmptyParens(t *testing.T) {
	flags := ParseStoreFlags("()")
	if len(flags) != 0 {
		t.Errorf("flags = %v, want nil/empty", flags)
	}
}

// --- helpers ---

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
