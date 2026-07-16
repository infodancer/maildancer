package tlsstage

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// writeFile writes content to dir/name and returns the full path.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func TestExtractTLSPaths_SectionTLS(t *testing.T) {
	dir := t.TempDir()
	cfg := writeFile(t, dir, "config.toml", `
[pop3d]
hostname = "mail.example.com"

[pop3d.tls]
cert_file = "/certs/fullchain.pem"
key_file = "/certs/privkey.pem"
`)

	cert, key, err := extractTLSPaths(cfg, "pop3d")
	if err != nil {
		t.Fatalf("extractTLSPaths: %v", err)
	}
	if cert != "/certs/fullchain.pem" || key != "/certs/privkey.pem" {
		t.Errorf("got cert=%q key=%q", cert, key)
	}
}

func TestExtractTLSPaths_ServerFallback(t *testing.T) {
	// The daemons merge [server.tls] into their config when the section has
	// no TLS block of its own; tlsstage must see TLS in that shape too.
	dir := t.TempDir()
	cfg := writeFile(t, dir, "config.toml", `
[server.tls]
cert_file = "/srv/fullchain.pem"
key_file = "/srv/privkey.pem"

[imapd]
hostname = "mail.example.com"
`)

	cert, key, err := extractTLSPaths(cfg, "imapd")
	if err != nil {
		t.Fatalf("extractTLSPaths: %v", err)
	}
	if cert != "/srv/fullchain.pem" || key != "/srv/privkey.pem" {
		t.Errorf("got cert=%q key=%q", cert, key)
	}
}

func TestExtractTLSPaths_SectionOverridesServer(t *testing.T) {
	dir := t.TempDir()
	cfg := writeFile(t, dir, "config.toml", `
[server.tls]
cert_file = "/srv/fullchain.pem"
key_file = "/srv/privkey.pem"

[pop3d.tls]
cert_file = "/pop/fullchain.pem"
key_file = "/pop/privkey.pem"
`)

	cert, key, err := extractTLSPaths(cfg, "pop3d")
	if err != nil {
		t.Fatalf("extractTLSPaths: %v", err)
	}
	if cert != "/pop/fullchain.pem" || key != "/pop/privkey.pem" {
		t.Errorf("got cert=%q key=%q", cert, key)
	}
}

func TestExtractTLSPaths_Absent(t *testing.T) {
	dir := t.TempDir()
	cfg := writeFile(t, dir, "config.toml", `
[pop3d]
hostname = "mail.example.com"
`)

	cert, key, err := extractTLSPaths(cfg, "pop3d")
	if err != nil {
		t.Fatalf("extractTLSPaths: %v", err)
	}
	if cert != "" || key != "" {
		t.Errorf("expected empty paths, got cert=%q key=%q", cert, key)
	}
}

func TestRun_NoTLSConfigured_IsNoop(t *testing.T) {
	dir := t.TempDir()
	cfg := writeFile(t, dir, "config.toml", `
[pop3d]
hostname = "mail.example.com"
`)
	out := filepath.Join(dir, "out")

	var stderr bytes.Buffer
	err := Run(Options{ConfigPath: cfg, Section: "pop3d", OutDir: out, Group: "mailsvc"}, &stderr)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Errorf("out dir should not be created when no TLS is configured")
	}
	if stderr.Len() == 0 {
		t.Errorf("expected a note on stderr when skipping")
	}
}

func TestRun_StagesCertAndKey(t *testing.T) {
	dir := t.TempDir()
	certSrc := writeFile(t, dir, "cert.pem", "CERT DATA\n")
	keySrc := writeFile(t, dir, "key.pem", "KEY DATA\n")
	cfg := writeFile(t, dir, "config.toml", `
[imapd.tls]
cert_file = "`+certSrc+`"
key_file = "`+keySrc+`"
`)
	out := filepath.Join(dir, "out", "imapd")

	var stderr bytes.Buffer
	if err := Run(Options{ConfigPath: cfg, Section: "imapd", OutDir: out, Group: "nosuchgroup-zz"}, &stderr); err != nil {
		t.Fatalf("Run: %v", err)
	}

	cert, err := os.ReadFile(filepath.Join(out, "fullchain.pem"))
	if err != nil {
		t.Fatalf("read staged cert: %v", err)
	}
	if string(cert) != "CERT DATA\n" {
		t.Errorf("staged cert content = %q", cert)
	}
	key, err := os.ReadFile(filepath.Join(out, "privkey.pem"))
	if err != nil {
		t.Fatalf("read staged key: %v", err)
	}
	if string(key) != "KEY DATA\n" {
		t.Errorf("staged key content = %q", key)
	}

	certInfo, err := os.Stat(filepath.Join(out, "fullchain.pem"))
	if err != nil {
		t.Fatalf("stat cert: %v", err)
	}
	if certInfo.Mode().Perm() != 0644 {
		t.Errorf("cert mode = %o, want 0644", certInfo.Mode().Perm())
	}
	keyInfo, err := os.Stat(filepath.Join(out, "privkey.pem"))
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if keyInfo.Mode().Perm() != 0640 {
		t.Errorf("key mode = %o, want 0640", keyInfo.Mode().Perm())
	}
	outInfo, err := os.Stat(out)
	if err != nil {
		t.Fatalf("stat out dir: %v", err)
	}
	if outInfo.Mode().Perm() != 0755 {
		t.Errorf("out dir mode = %o, want 0755", outInfo.Mode().Perm())
	}
	// Off-root the chown is skipped with a note; ownership is not asserted.
	if os.Geteuid() != 0 && stderr.Len() == 0 {
		t.Errorf("expected a stderr note about skipped ownership off-root")
	}
}

func TestRun_OverwritesPreviousStaging(t *testing.T) {
	dir := t.TempDir()
	certSrc := writeFile(t, dir, "cert.pem", "NEW CERT\n")
	keySrc := writeFile(t, dir, "key.pem", "NEW KEY\n")
	cfg := writeFile(t, dir, "config.toml", `
[pop3d.tls]
cert_file = "`+certSrc+`"
key_file = "`+keySrc+`"
`)
	out := filepath.Join(dir, "out")
	if err := os.MkdirAll(out, 0755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, out, "fullchain.pem", "OLD CERT\n")
	writeFile(t, out, "privkey.pem", "OLD KEY\n")

	var stderr bytes.Buffer
	if err := Run(Options{ConfigPath: cfg, Section: "pop3d", OutDir: out, Group: "mailsvc"}, &stderr); err != nil {
		t.Fatalf("Run: %v", err)
	}
	cert, err := os.ReadFile(filepath.Join(out, "fullchain.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if string(cert) != "NEW CERT\n" {
		t.Errorf("cert not replaced: %q", cert)
	}
}

func TestRun_MissingSourceFileFails(t *testing.T) {
	dir := t.TempDir()
	cfg := writeFile(t, dir, "config.toml", `
[pop3d.tls]
cert_file = "`+filepath.Join(dir, "nope.pem")+`"
key_file = "`+filepath.Join(dir, "nokey.pem")+`"
`)

	var stderr bytes.Buffer
	err := Run(Options{ConfigPath: cfg, Section: "pop3d", OutDir: filepath.Join(dir, "out"), Group: "mailsvc"}, &stderr)
	if err == nil {
		t.Fatalf("expected error for missing source files")
	}
}

func TestRun_MissingConfigFileFails(t *testing.T) {
	var stderr bytes.Buffer
	err := Run(Options{ConfigPath: "/nonexistent/config.toml", Section: "pop3d", OutDir: t.TempDir(), Group: "mailsvc"}, &stderr)
	if err == nil {
		t.Fatalf("expected error for missing config file")
	}
}
