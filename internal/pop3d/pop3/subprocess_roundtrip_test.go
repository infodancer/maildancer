//go:build integration

// Package pop3_test — subprocess round-trip integration tests.
//
// These tests spawn real pop3d protocol-handler and mail-session subprocesses,
// wire them together exactly as production does, and exercise all POP3
// transaction commands end-to-end without requiring root or a system user.
//
// Key design choice: the protocol-handler config has no domains_path, so
// AuthRouter has no domain provider and routes authentication to the global
// passwd fallback. result.Domain is nil, which causes passCommand to use the
// injected sessionPipeStore (not a domain-specific maildir store). This puts
// the full session-pipe protocol on the hot path: every STAT/LIST/RETR/etc.
// travels through sessionPipeStore → pipe → mail-session → maildir.
//
// Run:
//
//	go test -tags integration -v -run TestSubprocess ./internal/pop3/
//	go test -tags integration -race -v -run TestSubprocess ./internal/pop3/
package pop3_test

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// readAuthSignalLines reads the 3-line auth signal from r up to and including
// the "END" line. It returns after the END marker without closing r, so the
// caller can close r and spawn mail-session before the child's deferred
// authPipeW.Close() runs.
func readAuthSignalLines(r io.Reader) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		if strings.TrimRight(sc.Text(), "\r") == "END" {
			return
		}
	}
}

// buildPop3dBin compiles the pop3d binary into a temp dir.
// Skips the test if the Go workspace is absent or the build fails.
func buildPop3dBin(t *testing.T) string {
	t.Helper()
	wsRoot := workspaceRootForMailSession(t) // defined in sessionpipe_integration_test.go
	bin := filepath.Join(t.TempDir(), "pop3d")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/infodancer/maildancer/internal/pop3d/cmd/pop3d")
	cmd.Dir = wsRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("build pop3d failed: %v\n%s", err, out)
	}
	return bin
}

// writePop3Config writes a minimal config.toml for the protocol-handler subprocess.
//
// No TLS is configured → insecureAuth=true → USER/PASS allowed over plain TCP.
// No domains_path → AuthRouter has no domain provider → result.Domain is nil
// → the injected sessionPipeStore is used (not a domain-specific maildir).
//
// passwdPath and keysDir must be absolute paths; the subprocess resolves them
// relative to its own working directory otherwise.
func writePop3Config(t *testing.T, dir, passwdPath, keysDir string) string {
	t.Helper()
	content := fmt.Sprintf(`[pop3d]
hostname = "test.local"

[pop3d.auth]
type = "passwd"
credential_backend = %q
key_backend = %q

[[pop3d.listeners]]
address = "127.0.0.1:19110"
mode = "pop3"
`, passwdPath, keysDir)
	path := filepath.Join(dir, "pop3d.toml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write pop3d.toml: %v", err)
	}
	return path
}

// setupSubprocessEnv creates the passwd file, keys directory, and alice's
// maildir with two seeded messages. Returns absolute paths for all three.
//
// The passwd file uses "alice@test.local" as the username key because the
// global (non-domain) auth fallback receives the full user@domain string.
// The mailbox field is also "alice@test.local"; the maildir store strips the
// domain component when resolving the on-disk directory path.
func setupSubprocessEnv(t *testing.T) (maildirBase, passwdPath, keysDir string) {
	t.Helper()
	dir := t.TempDir()

	keysDir = filepath.Join(dir, "keys")
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		t.Fatalf("mkdir keys: %v", err)
	}

	// Maildir tree for alice. The maildir store strips the @domain suffix from
	// "alice@test.local" to get directory name "alice".
	maildirBase = filepath.Join(dir, "maildir")
	for _, sub := range []string{"new", "cur", "tmp"} {
		if err := os.MkdirAll(filepath.Join(maildirBase, "alice", sub), 0700); err != nil {
			t.Fatalf("mkdir alice/%s: %v", sub, err)
		}
	}

	// Seed two test messages in new/.
	for i := 1; i <= 2; i++ {
		name := fmt.Sprintf("100000000%d.%05d.testhost", i, i)
		body := fmt.Sprintf(
			"From: sender@example.com\r\nTo: alice@test.local\r\nSubject: Message %d\r\n\r\nBody line %d\r\n",
			i, i,
		)
		path := filepath.Join(maildirBase, "alice", "new", name)
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatalf("write message %d: %v", i, err)
		}
	}

	// Argon2id hash for "testpass".
	hash, err := hashPassword("testpass")
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	passwdPath = filepath.Join(dir, "passwd")
	content := fmt.Sprintf("alice@test.local:%s:alice@test.local\n", hash)
	if err := os.WriteFile(passwdPath, []byte(content), 0600); err != nil {
		t.Fatalf("write passwd: %v", err)
	}

	return maildirBase, passwdPath, keysDir
}

// runSubprocessSession wires the full subprocess pipeline and returns the
// client-side net.Conn for the test to drive.
//
// Pipeline:
//
//	client conn ↔ [TCP] ↔ pop3d protocol-handler (fd 3–6)
//	                              ↕ auth pipe (fd 4)
//	                       mini-dispatcher goroutine
//	                              ↕ session pipes (fd 5/6)
//	                       mail-session --basepath maildirBase
//
// The mini-dispatcher drains the auth pipe (waiting for the authentication
// signal), then spawns mail-session without a SysProcAttr.Credential so it
// runs as the current test user. This exercises runProtocolHandler() and
// sessionPipeStore end-to-end without requiring root or a system uid.
func runSubprocessSession(t *testing.T, pop3dPath, msPath, configPath, maildirBase string) net.Conn {
	t.Helper()

	// Listen on a random port; we hand the accepted fd to the subprocess.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	// Accept one connection in a goroutine and extract its os.File.
	connFileCh := make(chan *os.File, 1)
	go func() {
		conn, err := ln.Accept()
		_ = ln.Close()
		if err != nil {
			connFileCh <- nil
			return
		}
		tcpConn, ok := conn.(*net.TCPConn)
		if !ok {
			_ = conn.Close()
			connFileCh <- nil
			return
		}
		f, err := tcpConn.File()
		_ = tcpConn.Close() // netConn now owns the dup'd fd
		if err != nil {
			connFileCh <- nil
			return
		}
		connFileCh <- f
	}()

	// Pipe pairs (names match production subprocess.go convention):
	//   authPipeR/W  parent reads auth signal written by child (fd 4)
	//   fromSessR/W  child (fd 5) reads; mail-session writes here
	//   toSessR/W    mail-session reads; child (fd 6) writes here
	authPipeR, authPipeW, err := os.Pipe()
	if err != nil {
		t.Fatalf("auth pipe: %v", err)
	}
	fromSessR, fromSessW, err := os.Pipe()
	if err != nil {
		t.Fatalf("fromSess pipe: %v", err)
	}
	toSessR, toSessW, err := os.Pipe()
	if err != nil {
		t.Fatalf("toSess pipe: %v", err)
	}

	// Dial the listener; this unblocks the accept goroutine above.
	clientConn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	connFile := <-connFileCh
	if connFile == nil {
		_ = clientConn.Close()
		t.Fatalf("failed to dup server-side connection fd")
	}

	// Spawn the protocol-handler subprocess.
	// ExtraFiles[0..3] map to fds 3..6 in the child process.
	phCmd := exec.Command(pop3dPath, "protocol-handler", "--config", configPath)
	phCmd.ExtraFiles = []*os.File{
		connFile,  // fd 3: TCP socket
		authPipeW, // fd 4: child writes auth signal here
		fromSessR, // fd 5: child reads mail-session responses
		toSessW,   // fd 6: child writes commands to mail-session
	}
	phCmd.Env = append(os.Environ(),
		"POP3D_CLIENT_IP=127.0.0.1",
		"POP3D_LISTENER_MODE=pop3",
	)
	phCmd.Stderr = os.Stderr

	if err := phCmd.Start(); err != nil {
		_ = connFile.Close()
		_ = clientConn.Close()
		t.Fatalf("start protocol-handler: %v", err)
	}

	// Close parent copies of fds that now belong to the child.
	_ = connFile.Close()
	_ = authPipeW.Close()
	_ = fromSessR.Close()
	_ = toSessW.Close()

	// Mini-dispatcher goroutine: mirrors SubprocessServer.dispatchSession but
	// without lookupCredentials or SysProcAttr (runs as the test user).
	go func() {
		// Read exactly the 3-line auth signal (AUTH 1 / USER:... / END) without
		// waiting for pipe EOF. We cannot use io.Copy here: sessionPipeStore.handshake
		// defers authPipeW.Close(), which only runs after handshake() returns, which
		// requires mail-session to already be running — a circular dependency.
		// Reading the signal lines lets us close authPipeR and spawn mail-session
		// before the deferred close fires.
		readAuthSignalLines(authPipeR)
		_ = authPipeR.Close()

		// Spawn mail-session as the current test user (no privilege drop).
		msCmd := exec.Command(msPath, "--type", "maildir", "--basepath", maildirBase)
		msCmd.Stdin = toSessR
		msCmd.Stdout = fromSessW
		msCmd.Stderr = os.Stderr
		if err := msCmd.Start(); err != nil {
			t.Errorf("start mail-session: %v", err)
			_ = toSessR.Close()
			_ = fromSessW.Close()
			return
		}
		// Parent relinquishes child-owned pipe ends.
		_ = toSessR.Close()
		_ = fromSessW.Close()

		// Reap both subprocesses; mail-session exits on COMMIT or pipe close.
		go func() { _ = msCmd.Wait() }()
		_ = phCmd.Wait()
	}()

	return clientConn
}

// countAliceMessages returns the total file count in alice's cur/ and new/ dirs.
func countAliceMessages(t *testing.T, maildirBase string) int {
	t.Helper()
	total := 0
	for _, sub := range []string{"new", "cur"} {
		entries, err := os.ReadDir(filepath.Join(maildirBase, "alice", sub))
		if err != nil {
			t.Fatalf("readdir alice/%s: %v", sub, err)
		}
		total += len(entries)
	}
	return total
}

// TestSubprocessRoundtrip_FullSession exercises all POP3 transaction commands
// through the full subprocess pipeline:
//
//	USER / PASS → STAT → LIST → LIST 1 → UIDL → UIDL 1 →
//	RETR 1 → TOP 1 0 → TOP 1 1 → DELE 1 →
//	STAT (1 visible) → RSET → STAT (2 visible) → DELE 1 → QUIT
//
// After QUIT: asserts message 1 is deleted from disk, message 2 survives.
func TestSubprocessRoundtrip_FullSession(t *testing.T) {
	pop3dBin := buildPop3dBin(t)
	msBin := buildMailSessionBin(t)

	maildirBase, passwdPath, keysDir := setupSubprocessEnv(t)
	configPath := writePop3Config(t, t.TempDir(), passwdPath, keysDir)

	conn := runSubprocessSession(t, pop3dBin, msBin, configPath, maildirBase)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	r := bufio.NewReader(conn)

	readLine := func() string {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("readLine: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		t.Logf("S: %s", line)
		return line
	}

	// readDotList reads POP3 multi-line response lines until the terminating ".".
	readDotList := func() []string {
		var lines []string
		for {
			line := readLine()
			if line == "." {
				break
			}
			lines = append(lines, line)
		}
		return lines
	}

	send := func(s string) {
		t.Logf("C: %s", s)
		_, _ = fmt.Fprintf(conn, "%s\r\n", s)
	}

	mustOK := func(resp string) {
		t.Helper()
		if !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("expected +OK, got: %q", resp)
		}
	}

	// Greeting.
	mustOK(readLine())

	// AUTHORIZATION state.
	send("USER alice@test.local")
	mustOK(readLine())

	send("PASS testpass")
	mustOK(readLine())

	// TRANSACTION state. The PASS response triggers sessionPipeStore.handshake:
	// it writes the auth signal (unblocking the mini-dispatcher which spawns
	// mail-session), then performs the MAILBOX handshake before returning +OK.

	// STAT: 2 seeded messages.
	send("STAT")
	statResp := readLine()
	mustOK(statResp)
	var statCount, statOctets int
	if _, err := fmt.Sscanf(statResp, "+OK %d %d", &statCount, &statOctets); err != nil {
		t.Fatalf("parse STAT %q: %v", statResp, err)
	}
	if statCount != 2 {
		t.Fatalf("STAT count: want 2, got %d", statCount)
	}

	// LIST (all messages).
	send("LIST")
	mustOK(readLine())
	if entries := readDotList(); len(entries) != 2 {
		t.Fatalf("LIST: want 2 entries, got %d: %v", len(entries), entries)
	}

	// LIST 1 (single message).
	send("LIST 1")
	mustOK(readLine())

	// UIDL (all messages).
	send("UIDL")
	mustOK(readLine())
	if entries := readDotList(); len(entries) != 2 {
		t.Fatalf("UIDL: want 2 entries, got %d: %v", len(entries), entries)
	}

	// UIDL 1 (single message).
	send("UIDL 1")
	mustOK(readLine())

	// RETR 1: full message content.
	send("RETR 1")
	mustOK(readLine())
	retrLines := readDotList()
	if !strings.Contains(strings.Join(retrLines, "\n"), "From: sender@example.com") {
		t.Errorf("RETR 1: missing From header; got:\n%s", strings.Join(retrLines, "\n"))
	}

	// TOP 1 0: headers only (zero body lines).
	send("TOP 1 0")
	mustOK(readLine())
	topLines := readDotList()
	hasFrom := false
	for _, l := range topLines {
		if strings.HasPrefix(l, "From:") {
			hasFrom = true
		}
	}
	if !hasFrom {
		t.Errorf("TOP 1 0: missing From header; got:\n%s", strings.Join(topLines, "\n"))
	}

	// TOP 1 1: headers + 1 body line.
	send("TOP 1 1")
	mustOK(readLine())
	top1Lines := readDotList()
	if len(top1Lines) == 0 {
		t.Error("TOP 1 1: no content returned")
	}
	_ = top1Lines

	// DELE 1: mark message 1 for deletion (not yet committed).
	send("DELE 1")
	mustOK(readLine())

	// STAT: RFC 1939 excludes deleted messages; only message 2 visible.
	send("STAT")
	stat2Resp := readLine()
	mustOK(stat2Resp)
	var stat2Count, stat2Octets int
	if _, err := fmt.Sscanf(stat2Resp, "+OK %d %d", &stat2Count, &stat2Octets); err != nil {
		t.Fatalf("parse STAT after DELE %q: %v", stat2Resp, err)
	}
	if stat2Count != 1 {
		t.Errorf("STAT after DELE 1: want 1, got %d", stat2Count)
	}

	// RSET: cancel the pending deletion.
	send("RSET")
	mustOK(readLine())

	// STAT: back to 2.
	send("STAT")
	stat3Resp := readLine()
	mustOK(stat3Resp)
	var stat3Count, stat3Octets int
	if _, err := fmt.Sscanf(stat3Resp, "+OK %d %d", &stat3Count, &stat3Octets); err != nil {
		t.Fatalf("parse STAT after RSET %q: %v", stat3Resp, err)
	}
	if stat3Count != 2 {
		t.Errorf("STAT after RSET: want 2, got %d", stat3Count)
	}

	// DELE 1 again, then QUIT to commit.
	send("DELE 1")
	mustOK(readLine())

	send("QUIT")
	mustOK(readLine())

	// Read until EOF so we know the protocol-handler has finished committing
	// (DELETE + COMMIT via mail-session) before we inspect the maildir.
	_, _ = io.ReadAll(r)
	_ = conn.Close()

	if got := countAliceMessages(t, maildirBase); got != 1 {
		t.Errorf("after DELE+QUIT: want 1 message on disk, got %d", got)
	}
}

// TestSubprocessRoundtrip_DELE_RSET_NoCommit verifies that RSET cancels a
// pending deletion: after DELE 1, RSET, QUIT the file must still exist.
func TestSubprocessRoundtrip_DELE_RSET_NoCommit(t *testing.T) {
	pop3dBin := buildPop3dBin(t)
	msBin := buildMailSessionBin(t)

	maildirBase, passwdPath, keysDir := setupSubprocessEnv(t)
	configPath := writePop3Config(t, t.TempDir(), passwdPath, keysDir)

	conn := runSubprocessSession(t, pop3dBin, msBin, configPath, maildirBase)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	r := bufio.NewReader(conn)

	readLine := func() string {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("readLine: %v", err)
		}
		return strings.TrimRight(line, "\r\n")
	}
	mustOK := func(resp string) {
		t.Helper()
		if !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("expected +OK, got: %q", resp)
		}
	}
	send := func(s string) { _, _ = fmt.Fprintf(conn, "%s\r\n", s) }

	mustOK(readLine()) // greeting

	send("USER alice@test.local")
	mustOK(readLine())

	send("PASS testpass")
	mustOK(readLine())

	send("DELE 1")
	mustOK(readLine())

	send("RSET")
	mustOK(readLine())

	send("QUIT")
	mustOK(readLine())

	// Wait for EOF before inspecting the maildir.
	_, _ = io.ReadAll(r)
	_ = conn.Close()

	// RSET cancelled the deletion; both messages must survive.
	if got := countAliceMessages(t, maildirBase); got != 2 {
		t.Errorf("after DELE+RSET+QUIT: want 2 messages on disk, got %d", got)
	}
}
