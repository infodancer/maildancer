package tlsstage

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// stagedSetup writes a source cert/key pair, a config pointing at them, and
// performs the initial stage. It returns the options and the source paths.
func stagedSetup(t *testing.T) (Options, string, string) {
	t.Helper()
	dir := t.TempDir()
	certSrc := writeFile(t, dir, "cert.pem", "CERT V1\n")
	keySrc := writeFile(t, dir, "key.pem", "KEY V1\n")
	cfg := writeFile(t, dir, "config.toml", `
[smtpd.tls]
cert_file = "`+certSrc+`"
key_file = "`+keySrc+`"
`)
	opts := Options{
		ConfigPath: cfg,
		Section:    "smtpd",
		OutDir:     filepath.Join(dir, "out"),
		Group:      "mailsvc",
	}
	if err := Run(opts, io.Discard); err != nil {
		t.Fatalf("initial Run: %v", err)
	}
	return opts, certSrc, keySrc
}

// backdate sets a file's mtime to a fixed point in the past so a later
// rewrite is unambiguously newer regardless of filesystem mtime granularity.
func backdate(t *testing.T, path string, age time.Duration) {
	t.Helper()
	old := time.Now().Add(-age)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatalf("chtimes %s: %v", path, err)
	}
}

func TestRefreshOnce_UnchangedSourceIsNoop(t *testing.T) {
	opts, certSrc, keySrc := stagedSetup(t)
	// Sources older than the staged copies (the normal steady state).
	backdate(t, certSrc, time.Hour)
	backdate(t, keySrc, time.Hour)

	restaged, err := RefreshOnce(opts, io.Discard)
	if err != nil {
		t.Fatalf("RefreshOnce: %v", err)
	}
	if restaged {
		t.Error("RefreshOnce restaged with unchanged sources")
	}
}

func TestRefreshOnce_NewerSourceRestages(t *testing.T) {
	opts, certSrc, keySrc := stagedSetup(t)
	backdate(t, keySrc, time.Hour)
	// Renewal: new cert content, mtime newer than the staged copy.
	if err := os.WriteFile(certSrc, []byte("CERT V2\n"), 0600); err != nil {
		t.Fatalf("rewrite cert: %v", err)
	}
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(certSrc, future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	restaged, err := RefreshOnce(opts, io.Discard)
	if err != nil {
		t.Fatalf("RefreshOnce: %v", err)
	}
	if !restaged {
		t.Fatal("RefreshOnce did not restage after source changed")
	}

	got, err := os.ReadFile(filepath.Join(opts.OutDir, "fullchain.pem"))
	if err != nil {
		t.Fatalf("read staged cert: %v", err)
	}
	if string(got) != "CERT V2\n" {
		t.Errorf("staged cert = %q, want renewed content", got)
	}
}

func TestRefreshOnce_MissingStagedCopyRestages(t *testing.T) {
	opts, certSrc, keySrc := stagedSetup(t)
	backdate(t, certSrc, time.Hour)
	backdate(t, keySrc, time.Hour)
	if err := os.Remove(filepath.Join(opts.OutDir, "privkey.pem")); err != nil {
		t.Fatalf("remove staged key: %v", err)
	}

	restaged, err := RefreshOnce(opts, io.Discard)
	if err != nil {
		t.Fatalf("RefreshOnce: %v", err)
	}
	if !restaged {
		t.Error("RefreshOnce did not restage a missing staged copy")
	}
	if _, err := os.Stat(filepath.Join(opts.OutDir, "privkey.pem")); err != nil {
		t.Errorf("staged key not recreated: %v", err)
	}
}

func TestRefreshOnce_UnreadableSourceReturnsError(t *testing.T) {
	opts, certSrc, _ := stagedSetup(t)
	if err := os.Remove(certSrc); err != nil {
		t.Fatalf("remove source cert: %v", err)
	}

	_, err := RefreshOnce(opts, io.Discard)
	if err == nil {
		t.Fatal("RefreshOnce succeeded with a missing source file")
	}
}

func TestRefreshOnce_NoTLSConfiguredIsNoop(t *testing.T) {
	dir := t.TempDir()
	cfg := writeFile(t, dir, "config.toml", `
[smtpd]
hostname = "mail.example.com"
`)
	opts := Options{ConfigPath: cfg, Section: "smtpd", OutDir: filepath.Join(dir, "out"), Group: "mailsvc"}

	var stderr bytes.Buffer
	restaged, err := RefreshOnce(opts, &stderr)
	if err != nil {
		t.Fatalf("RefreshOnce: %v", err)
	}
	if restaged {
		t.Error("RefreshOnce restaged with no TLS configured")
	}
	if _, err := os.Stat(opts.OutDir); !os.IsNotExist(err) {
		t.Error("out dir should not be created when no TLS is configured")
	}
}
