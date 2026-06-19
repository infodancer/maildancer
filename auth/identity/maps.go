package identity

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// loadMap reads a flat "key" = uint map from a TOML file. A missing file is not
// an error -- it returns an empty map, so an unallocated domain/user reads as
// "no entry" rather than failing differently from an absent key.
func loadMap(path string) (map[string]uint32, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]uint32{}, nil
		}
		return nil, fmt.Errorf("read identity map %q: %w", path, err)
	}
	m := map[string]uint32{}
	if err := toml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse identity map %q: %w", path, err)
	}
	return m, nil
}

// storeMap atomically writes a flat "key" = uint map to a TOML file with the
// given header comment. Keys are emitted sorted for stable diffs; values are
// plain integers. The write is tmp-file + rename so a reader never sees a
// partial file. The file mode is 0640 (root:root by deployment); the maps are
// not secret but govern cross-user isolation, so they are not world-readable.
func storeMap(path, header string, m map[string]uint32) error {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(header, "\n"), "\n") {
		b.WriteString("# ")
		b.WriteString(line)
		b.WriteByte('\n')
	}
	b.WriteByte('\n')

	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s = %d\n", quoteKey(k), m[k])
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create identity map dir: %w", err)
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		return fmt.Errorf("open identity map tmp: %w", err)
	}
	if _, err := f.WriteString(b.String()); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("write identity map tmp: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("sync identity map tmp: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close identity map tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename identity map: %w", err)
	}
	return nil
}

// quoteKey renders a map key (domain name or localpart) as a TOML basic-string
// key. Domain names and localparts contain dots and other characters that bare
// keys disallow, so they are always quoted. strconv.Quote produces an escaping
// compatible with TOML basic strings for our ASCII key charset.
func quoteKey(k string) string {
	return strconv.Quote(k)
}

const gidMapHeader = `domain = gid. Authoritative OS group allocation for every mail domain
using the local passwd-files provider. Managed ONLY by the identity package
(via userctl / webadmin). Allocate-once; never reassign a live domain.
Do NOT hand-edit and do NOT render this from IaC.
See infodancer/docs/identity-allocation-design.md.`

const uidMapHeader = `localpart = uid. Authoritative OS user allocation for this domain
using the local passwd-files provider. Managed ONLY by the identity package
(via userctl / webadmin). Allocate-once; never reassign a live user.
See infodancer/docs/identity-allocation-design.md.`
