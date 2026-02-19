package imap

import (
	"testing"
)

// --- HasFlag ---

func TestHasFlagReturnsTrueWhenFlagPresent(t *testing.T) {
	flags := []string{FlagSeen, FlagAnswered}
	if !HasFlag(flags, FlagSeen) {
		t.Errorf("HasFlag(%v, %q) = false, want true", flags, FlagSeen)
	}
}

func TestHasFlagReturnsFalseWhenFlagAbsent(t *testing.T) {
	flags := []string{FlagSeen, FlagAnswered}
	if HasFlag(flags, FlagDeleted) {
		t.Errorf("HasFlag(%v, %q) = true, want false", flags, FlagDeleted)
	}
}

func TestHasFlagReturnsFalseForEmptyList(t *testing.T) {
	if HasFlag(nil, FlagSeen) {
		t.Errorf("HasFlag(nil, %q) = true, want false", FlagSeen)
	}
}

func TestHasFlagIsCaseInsensitive(t *testing.T) {
	flags := []string{`\seen`}
	if !HasFlag(flags, `\Seen`) {
		t.Error("HasFlag with mismatched case = false, want true")
	}
}

func TestHasFlagCaseInsensitiveUpperQuery(t *testing.T) {
	flags := []string{`\Seen`}
	if !HasFlag(flags, `\SEEN`) {
		t.Error("HasFlag with uppercase query = false, want true")
	}
}

// --- AddFlag ---

func TestAddFlagAddsNewFlag(t *testing.T) {
	flags := []string{FlagSeen}
	result := AddFlag(flags, FlagDeleted)
	if !HasFlag(result, FlagDeleted) {
		t.Errorf("AddFlag: %q not found in result %v", FlagDeleted, result)
	}
	if len(result) != 2 {
		t.Errorf("AddFlag: len = %d, want 2", len(result))
	}
}

func TestAddFlagDoesNotDuplicate(t *testing.T) {
	flags := []string{FlagSeen}
	result := AddFlag(flags, FlagSeen)
	if len(result) != 1 {
		t.Errorf("AddFlag duplicate: len = %d, want 1 (no duplicate added)", len(result))
	}
}

func TestAddFlagToEmptyList(t *testing.T) {
	result := AddFlag(nil, FlagDraft)
	if len(result) != 1 || result[0] != FlagDraft {
		t.Errorf("AddFlag to nil: result = %v, want [%q]", result, FlagDraft)
	}
}

func TestAddFlagDoesNotDuplicateCaseInsensitive(t *testing.T) {
	flags := []string{`\seen`}
	result := AddFlag(flags, `\Seen`)
	if len(result) != 1 {
		t.Errorf("AddFlag case-insensitive duplicate: len = %d, want 1", len(result))
	}
}

// --- RemoveFlag ---

func TestRemoveFlagRemovesPresentFlag(t *testing.T) {
	flags := []string{FlagSeen, FlagAnswered, FlagDeleted}
	result := RemoveFlag(flags, FlagAnswered)
	if HasFlag(result, FlagAnswered) {
		t.Errorf("RemoveFlag: %q still present in %v", FlagAnswered, result)
	}
	if len(result) != 2 {
		t.Errorf("RemoveFlag: len = %d, want 2", len(result))
	}
}

func TestRemoveFlagAbsentFlagLeavesListUnchanged(t *testing.T) {
	flags := []string{FlagSeen, FlagAnswered}
	result := RemoveFlag(flags, FlagDeleted)
	if len(result) != 2 {
		t.Errorf("RemoveFlag absent: len = %d, want 2 (unchanged)", len(result))
	}
}

func TestRemoveFlagFromEmptyList(t *testing.T) {
	result := RemoveFlag(nil, FlagSeen)
	if len(result) != 0 {
		t.Errorf("RemoveFlag from nil: len = %d, want 0", len(result))
	}
}

func TestRemoveFlagIsCaseInsensitive(t *testing.T) {
	flags := []string{`\Seen`, FlagAnswered}
	result := RemoveFlag(flags, `\seen`)
	if HasFlag(result, FlagSeen) {
		t.Errorf("RemoveFlag case-insensitive: %q still present in %v", FlagSeen, result)
	}
	if len(result) != 1 {
		t.Errorf("RemoveFlag case-insensitive: len = %d, want 1", len(result))
	}
}

func TestRemoveFlagPreservesOtherFlags(t *testing.T) {
	flags := []string{FlagSeen, FlagFlagged, FlagDraft}
	result := RemoveFlag(flags, FlagFlagged)
	if !HasFlag(result, FlagSeen) {
		t.Errorf("RemoveFlag: %q was incorrectly removed", FlagSeen)
	}
	if !HasFlag(result, FlagDraft) {
		t.Errorf("RemoveFlag: %q was incorrectly removed", FlagDraft)
	}
}

// --- Standard flag constants ---

func TestFlagConstantsHaveCorrectValues(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"FlagSeen", `\Seen`},
		{"FlagAnswered", `\Answered`},
		{"FlagFlagged", `\Flagged`},
		{"FlagDeleted", `\Deleted`},
		{"FlagDraft", `\Draft`},
		{"FlagRecent", `\Recent`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Indirect check: the constant must be present in SystemFlags.
			if !HasFlag(SystemFlags, tc.value) {
				t.Errorf("%s (%q) not found in SystemFlags", tc.name, tc.value)
			}
		})
	}
}

func TestRecentFlagNotInPermanentFlags(t *testing.T) {
	if HasFlag(PermanentFlags, FlagRecent) {
		t.Error(`\Recent must not appear in PermanentFlags (it is server-managed)`)
	}
}
