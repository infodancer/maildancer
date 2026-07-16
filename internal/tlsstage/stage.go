// Package tlsstage copies a daemon's TLS certificate and key from their
// configured locations (typically a read-only /etc/letsencrypt mount whose
// private key is root 0600) into a staging directory the daemon's
// unprivileged service account can read. It is run as root by the daemon's
// s6 run script immediately before dropping privileges.
package tlsstage

import (
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	toml "github.com/pelletier/go-toml/v2"
)

// Options controls a staging run.
type Options struct {
	// ConfigPath is the shared TOML config file.
	ConfigPath string
	// Section is the daemon's config section name (e.g. "pop3d").
	Section string
	// OutDir is the staging directory; the material lands there as
	// fullchain.pem and privkey.pem.
	OutDir string
	// Group is the group name given read access to the staged key.
	Group string
}

// Run stages the TLS material named by [<section>.tls] (falling back to
// [server.tls], mirroring the daemons' own config merge) into OutDir.
// When the config names no TLS material at all it writes nothing and
// returns nil so TLS-less setups keep working.
func Run(opts Options, stderr io.Writer) error {
	certFile, keyFile, err := extractTLSPaths(opts.ConfigPath, opts.Section)
	if err != nil {
		return err
	}
	if certFile == "" || keyFile == "" {
		fmt.Fprintf(stderr, "tlsstage: no TLS cert/key configured for [%s]; nothing to stage\n", opts.Section)
		return nil
	}

	if err := os.MkdirAll(opts.OutDir, 0755); err != nil {
		return fmt.Errorf("create out dir: %w", err)
	}
	// MkdirAll's mode is umask-filtered and skips pre-existing dirs; pin it.
	if err := os.Chmod(opts.OutDir, 0755); err != nil {
		return fmt.Errorf("chmod out dir: %w", err)
	}

	gid := lookupGID(opts.Group, stderr)

	if err := stageFile(certFile, filepath.Join(opts.OutDir, "fullchain.pem"), 0644, gid); err != nil {
		return fmt.Errorf("stage cert: %w", err)
	}
	if err := stageFile(keyFile, filepath.Join(opts.OutDir, "privkey.pem"), 0640, gid); err != nil {
		return fmt.Errorf("stage key: %w", err)
	}
	return nil
}

// lookupGID resolves the group to chown staged files to. It returns -1
// (meaning "skip chown") when not running as root or when the group does
// not exist; either way the copy still happens and the result is readable
// by its owner, which is the correct fallback off-root.
func lookupGID(group string, stderr io.Writer) int {
	if os.Geteuid() != 0 {
		fmt.Fprintf(stderr, "tlsstage: not running as root; skipping ownership change\n")
		return -1
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		fmt.Fprintf(stderr, "tlsstage: group %q not found; skipping ownership change\n", group)
		return -1
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		fmt.Fprintf(stderr, "tlsstage: group %q has non-numeric gid %q; skipping ownership change\n", group, g.Gid)
		return -1
	}
	return gid
}

// stageFile copies src to dst with the given mode via a temp file in the
// destination directory followed by an atomic rename, so readers never see
// a partial file. When gid >= 0 the temp file is chowned root:<gid> before
// the rename.
func stageFile(src, dst string, mode os.FileMode, gid int) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(dst), filepath.Base(dst)+".tmp*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		// Best-effort cleanup on the error paths; after a successful
		// rename the file no longer exists under this name.
		_ = os.Remove(tmpName)
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	if gid >= 0 {
		if err := os.Chown(tmpName, 0, gid); err != nil {
			return fmt.Errorf("chown: %w", err)
		}
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// extractTLSPaths reads the config file generically and returns the
// cert/key paths for the named section: [<section>.tls] when present,
// otherwise [server.tls] (the daemons merge [server] globals the same
// way). Both empty means no TLS is configured.
func extractTLSPaths(configPath, section string) (certFile, keyFile string, err error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", "", fmt.Errorf("read config: %w", err)
	}

	// Parse into a generic map so unrelated sections of any shape (arrays
	// of tables, scalars, etc.) cannot break extraction.
	var cfg map[string]any
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return "", "", fmt.Errorf("parse config: %w", err)
	}

	if cert, key, ok := tlsFromSection(cfg, section); ok {
		return cert, key, nil
	}
	if cert, key, ok := tlsFromSection(cfg, "server"); ok {
		return cert, key, nil
	}
	return "", "", nil
}

// tlsFromSection digs [<name>.tls] cert_file/key_file out of a generically
// parsed config. ok is false unless both values are present and non-empty.
func tlsFromSection(cfg map[string]any, name string) (certFile, keyFile string, ok bool) {
	sec, _ := cfg[name].(map[string]any)
	tls, _ := sec["tls"].(map[string]any)
	certFile, _ = tls["cert_file"].(string)
	keyFile, _ = tls["key_file"].(string)
	if certFile == "" || keyFile == "" {
		return "", "", false
	}
	return certFile, keyFile, true
}
