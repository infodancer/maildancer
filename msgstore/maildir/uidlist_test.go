package maildir

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestReadWriteRoundTrip(t *testing.T) {
	dir := t.TempDir()

	ul := &uidList{
		version:     3,
		uidValidity: 1741824000,
		uidNext:     4,
		entries: []uidEntry{
			{uid: 1, key: "1710339422.M123456.hostname"},
			{uid: 2, key: "1710339423.M789012.hostname"},
			{uid: 3, key: "1710339424.M345678.hostname"},
		},
		keyToUID: map[string]uint32{
			"1710339422.M123456.hostname": 1,
			"1710339423.M789012.hostname": 2,
			"1710339424.M345678.hostname": 3,
		},
		uidToKey: map[uint32]string{
			1: "1710339422.M123456.hostname",
			2: "1710339423.M789012.hostname",
			3: "1710339424.M345678.hostname",
		},
	}

	if err := ul.write(dir); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := readUIDList(dir)
	if err != nil {
		t.Fatalf("readUIDList: %v", err)
	}

	if got.version != ul.version {
		t.Errorf("version: got %d, want %d", got.version, ul.version)
	}
	if got.uidValidity != ul.uidValidity {
		t.Errorf("uidValidity: got %d, want %d", got.uidValidity, ul.uidValidity)
	}
	if got.uidNext != ul.uidNext {
		t.Errorf("uidNext: got %d, want %d", got.uidNext, ul.uidNext)
	}
	if len(got.entries) != len(ul.entries) {
		t.Fatalf("entries: got %d, want %d", len(got.entries), len(ul.entries))
	}
	for i, e := range got.entries {
		if e.uid != ul.entries[i].uid || e.key != ul.entries[i].key {
			t.Errorf("entry %d: got {%d, %q}, want {%d, %q}",
				i, e.uid, e.key, ul.entries[i].uid, ul.entries[i].key)
		}
	}
	// Verify lookup maps.
	for k, v := range ul.keyToUID {
		if got.keyToUID[k] != v {
			t.Errorf("keyToUID[%q]: got %d, want %d", k, got.keyToUID[k], v)
		}
	}
	for k, v := range ul.uidToKey {
		if got.uidToKey[k] != v {
			t.Errorf("uidToKey[%d]: got %q, want %q", k, got.uidToKey[k], v)
		}
	}
}

func TestReadUIDListNotExist(t *testing.T) {
	dir := t.TempDir()
	ul, err := readUIDList(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ul != nil {
		t.Fatalf("expected nil for non-existent file, got %+v", ul)
	}
}

func TestBootstrapUIDList(t *testing.T) {
	keys := []string{
		"1710339424.M345678.hostname",
		"1710339422.M123456.hostname",
		"1710339423.M789012.hostname",
	}

	ul := bootstrapUIDList(keys)

	if ul.version != uidlistVersion {
		t.Errorf("version: got %d, want %d", ul.version, uidlistVersion)
	}
	if ul.uidValidity == 0 {
		t.Error("uidValidity should not be 0")
	}
	// Keys should be sorted, so UIDs assigned in lexicographic order.
	if len(ul.entries) != 3 {
		t.Fatalf("entries: got %d, want 3", len(ul.entries))
	}
	if ul.entries[0].key != "1710339422.M123456.hostname" || ul.entries[0].uid != 1 {
		t.Errorf("entry 0: got {%d, %q}", ul.entries[0].uid, ul.entries[0].key)
	}
	if ul.entries[1].key != "1710339423.M789012.hostname" || ul.entries[1].uid != 2 {
		t.Errorf("entry 1: got {%d, %q}", ul.entries[1].uid, ul.entries[1].key)
	}
	if ul.entries[2].key != "1710339424.M345678.hostname" || ul.entries[2].uid != 3 {
		t.Errorf("entry 2: got {%d, %q}", ul.entries[2].uid, ul.entries[2].key)
	}
	if ul.uidNext != 4 {
		t.Errorf("uidNext: got %d, want 4", ul.uidNext)
	}
}

func TestBootstrapEmpty(t *testing.T) {
	ul := bootstrapUIDList(nil)
	if len(ul.entries) != 0 {
		t.Errorf("entries: got %d, want 0", len(ul.entries))
	}
	if ul.uidNext != 1 {
		t.Errorf("uidNext: got %d, want 1", ul.uidNext)
	}
}

func TestReconcileNewKey(t *testing.T) {
	ul := &uidList{
		version:     3,
		uidValidity: 100,
		uidNext:     3,
		entries: []uidEntry{
			{uid: 1, key: "a"},
			{uid: 2, key: "b"},
		},
		keyToUID: map[string]uint32{"a": 1, "b": 2},
		uidToKey: map[uint32]string{1: "a", 2: "b"},
	}

	changed := ul.reconcile([]string{"a", "b", "c"})
	if !changed {
		t.Fatal("expected changed=true")
	}
	if ul.uidNext != 4 {
		t.Errorf("uidNext: got %d, want 4", ul.uidNext)
	}
	if uid, ok := ul.keyToUID["c"]; !ok || uid != 3 {
		t.Errorf("keyToUID[c]: got %d, ok=%v", uid, ok)
	}
	if len(ul.entries) != 3 {
		t.Errorf("entries: got %d, want 3", len(ul.entries))
	}
}

func TestReconcileKeyRemoved(t *testing.T) {
	ul := &uidList{
		version:     3,
		uidValidity: 100,
		uidNext:     4,
		entries: []uidEntry{
			{uid: 1, key: "a"},
			{uid: 2, key: "b"},
			{uid: 3, key: "c"},
		},
		keyToUID: map[string]uint32{"a": 1, "b": 2, "c": 3},
		uidToKey: map[uint32]string{1: "a", 2: "b", 3: "c"},
	}

	changed := ul.reconcile([]string{"a", "c"})
	if !changed {
		t.Fatal("expected changed=true")
	}
	// uidNext must NOT decrease.
	if ul.uidNext != 4 {
		t.Errorf("uidNext: got %d, want 4", ul.uidNext)
	}
	if len(ul.entries) != 2 {
		t.Errorf("entries: got %d, want 2", len(ul.entries))
	}
	if _, ok := ul.keyToUID["b"]; ok {
		t.Error("key 'b' should have been removed")
	}
	if _, ok := ul.uidToKey[2]; ok {
		t.Error("uid 2 should have been removed")
	}
}

func TestReconcileNoChanges(t *testing.T) {
	ul := &uidList{
		version:     3,
		uidValidity: 100,
		uidNext:     3,
		entries: []uidEntry{
			{uid: 1, key: "a"},
			{uid: 2, key: "b"},
		},
		keyToUID: map[string]uint32{"a": 1, "b": 2},
		uidToKey: map[uint32]string{1: "a", 2: "b"},
	}

	changed := ul.reconcile([]string{"a", "b"})
	if changed {
		t.Error("expected changed=false when keys match")
	}
}

func TestUIDNeverReusedAfterDeletion(t *testing.T) {
	ul := &uidList{
		version:     3,
		uidValidity: 100,
		uidNext:     4,
		entries: []uidEntry{
			{uid: 1, key: "a"},
			{uid: 2, key: "b"},
			{uid: 3, key: "c"},
		},
		keyToUID: map[string]uint32{"a": 1, "b": 2, "c": 3},
		uidToKey: map[uint32]string{1: "a", 2: "b", 3: "c"},
	}

	// Remove "b" (uid 2).
	ul.reconcile([]string{"a", "c"})

	// Add a new key -- must get uid 4, NOT uid 2.
	ul.reconcile([]string{"a", "c", "d"})
	if uid := ul.keyToUID["d"]; uid != 4 {
		t.Errorf("new key got uid %d, want 4 (uid 2 was deleted and must not be reused)", uid)
	}
	if ul.uidNext != 5 {
		t.Errorf("uidNext: got %d, want 5", ul.uidNext)
	}
}

func TestCorruptFileRecovery(t *testing.T) {
	dir := t.TempDir()
	// Create a maildir cur/ with a file.
	curDir := filepath.Join(dir, "cur")
	if err := os.MkdirAll(curDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(curDir, "1710339422.M123456.hostname:2,S"), []byte("msg"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Write garbage to .uidlist.
	if err := os.WriteFile(filepath.Join(dir, uidlistFile), []byte("garbage"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	keys, err := curDirKeys(dir)
	if err != nil {
		t.Fatalf("curDirKeys: %v", err)
	}

	ul, err := loadOrBootstrapUIDList(dir, keys)
	if err != nil {
		t.Fatalf("loadOrBootstrapUIDList: %v", err)
	}
	if ul == nil {
		t.Fatal("expected non-nil uidlist after recovery")
	}
	if len(ul.entries) != 1 {
		t.Errorf("entries: got %d, want 1", len(ul.entries))
	}
}

func TestConcurrentWriteSafety(t *testing.T) {
	dir := t.TempDir()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			lock, err := lockUIDList(dir)
			if err != nil {
				t.Errorf("lockUIDList: %v", err)
				return
			}
			defer unlockUIDList(lock)

			ul := &uidList{
				version:     3,
				uidValidity: 100,
				uidNext:     uint32(n + 1),
				keyToUID:    make(map[string]uint32),
				uidToKey:    make(map[uint32]string),
			}
			if err := ul.write(dir); err != nil {
				t.Errorf("write: %v", err)
			}
		}(i)
	}
	wg.Wait()

	// File should be valid and parseable.
	ul, err := readUIDList(dir)
	if err != nil {
		t.Fatalf("readUIDList after concurrent writes: %v", err)
	}
	if ul == nil {
		t.Fatal("expected non-nil uidlist")
	}
}

func TestCurDirKeys(t *testing.T) {
	dir := t.TempDir()
	curDir := filepath.Join(dir, "cur")
	if err := os.MkdirAll(curDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	// Create files with maildir naming: key:info
	for _, name := range []string{"1710339422.M123.host:2,S", "1710339423.M456.host:2,", "1710339424.M789.host"} {
		if err := os.WriteFile(filepath.Join(curDir, name), []byte(""), 0600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	keys, err := curDirKeys(dir)
	if err != nil {
		t.Fatalf("curDirKeys: %v", err)
	}
	if len(keys) != 3 {
		t.Fatalf("got %d keys, want 3", len(keys))
	}

	// Verify keys strip the info suffix.
	keySet := make(map[string]bool)
	for _, k := range keys {
		keySet[k] = true
	}
	for _, want := range []string{"1710339422.M123.host", "1710339423.M456.host", "1710339424.M789.host"} {
		if !keySet[want] {
			t.Errorf("missing key %q", want)
		}
	}
}

func TestParseHeaderValid(t *testing.T) {
	ul, err := parseHeader("3 V1741824000 N42")
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	if ul.version != 3 {
		t.Errorf("version: got %d, want 3", ul.version)
	}
	if ul.uidValidity != 1741824000 {
		t.Errorf("uidValidity: got %d, want 1741824000", ul.uidValidity)
	}
	if ul.uidNext != 42 {
		t.Errorf("uidNext: got %d, want 42", ul.uidNext)
	}
}

func TestParseHeaderInvalid(t *testing.T) {
	cases := []string{
		"",
		"3",
		"3 V100",
		"X V100 N42",
		"3 100 N42",
		"3 V100 42",
		"3 Vabc N42",
		"3 V100 Nabc",
	}
	for _, tc := range cases {
		_, err := parseHeader(tc)
		if err == nil {
			t.Errorf("parseHeader(%q): expected error", tc)
		}
	}
}

func TestParseEntryValid(t *testing.T) {
	e, err := parseEntry("42 1710339422.M123456.hostname")
	if err != nil {
		t.Fatalf("parseEntry: %v", err)
	}
	if e.uid != 42 {
		t.Errorf("uid: got %d, want 42", e.uid)
	}
	if e.key != "1710339422.M123456.hostname" {
		t.Errorf("key: got %q", e.key)
	}
}

func TestParseEntryInvalid(t *testing.T) {
	cases := []string{
		"",
		"42",
		"abc key",
		"42 ", // empty key after space -- tricky, but we strip to empty
	}
	for _, tc := range cases {
		_, err := parseEntry(tc)
		if err == nil {
			t.Errorf("parseEntry(%q): expected error", tc)
		}
	}
}
