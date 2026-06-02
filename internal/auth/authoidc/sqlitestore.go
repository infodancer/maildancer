package authoidc

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// sqliteStore is a SQLite-backed Store. It persists OIDC authorization codes,
// SSO sessions, and dynamically registered clients in a single database file
// using ACID transactions for write atomicity and a TTL column for expiry
// sweeps.
//
// ConsumeCode is atomic via DELETE ... RETURNING (SQLite 3.35+), so a single
// statement reads and removes the row.
//
// The driver is modernc.org/sqlite — pure Go, no CGO, matching the choice
// already made in infodancer/webauth so the deployment story (static binaries)
// stays consistent across the auth stack.
type sqliteStore struct {
	db  *sql.DB
	log *slog.Logger
}

// newSQLiteStore opens (or creates) a SQLite database at path, applies the
// schema, and tunes pragmas for the auth-oidc workload: WAL for concurrent
// readers, NORMAL sync for durability without per-write fsync, a generous
// busy_timeout for transient lock contention, and foreign_keys on.
func newSQLiteStore(path string, log *slog.Logger) (*sqliteStore, error) {
	if log == nil {
		log = slog.Default()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}

	dsn := path + "?_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(1)"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}
	// SQLite supports concurrent readers under WAL but only a single writer.
	// Cap the pool so we don't queue useless connections.
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(2)

	// sql.Open is lazy; the actual file open happens on first use. Ping forces
	// it now so SQLITE_CANTOPEN (bad permissions, missing parent, read-only
	// fs) surfaces with an "open" attribution and the path, instead of leaking
	// out later as a confusing "schema: out of memory (14)".
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}

	if err := initSchema(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init schema %s: %w", path, err)
	}
	return &sqliteStore{db: db, log: log}, nil
}

// initSchema applies the schema for codes, sessions, and clients tables. It is
// idempotent: a fresh database is created if needed; an existing one is left
// in place. Schema evolution beyond this initial cut can introduce a migration
// tool (goose, the choice already established by infodancer/webauth) when the
// first migration is needed.
func initSchema(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS codes (
			code           TEXT PRIMARY KEY,
			domain         TEXT NOT NULL,
			client_id      TEXT NOT NULL,
			username       TEXT NOT NULL,
			redirect_uri   TEXT NOT NULL,
			pkce_challenge TEXT NOT NULL,
			pkce_method    TEXT NOT NULL,
			nonce          TEXT NOT NULL,
			expires_at     INTEGER NOT NULL
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS idx_codes_expires_at ON codes(expires_at)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id         TEXT PRIMARY KEY,
			domain     TEXT NOT NULL,
			username   TEXT NOT NULL,
			expires_at INTEGER NOT NULL
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)`,
		`CREATE TABLE IF NOT EXISTS clients (
			domain        TEXT NOT NULL,
			client_id     TEXT NOT NULL,
			client_name   TEXT NOT NULL,
			redirect_uris TEXT NOT NULL,
			registered_at INTEGER NOT NULL,
			PRIMARY KEY (domain, client_id)
		) STRICT`,
		// Signing keys: see docs/signing-key-rotation.md. The PEM material
		// lives on the filesystem at {data_dir}/{domain}/keys/{kid}.key —
		// this table is the authoritative metadata for which kid is current,
		// which are retiring, and when retiring rows should be swept.
		`CREATE TABLE IF NOT EXISTS signing_keys (
			domain     TEXT NOT NULL,
			kid        TEXT NOT NULL,
			algorithm  TEXT NOT NULL,
			state      TEXT NOT NULL CHECK (state IN ('current', 'retiring')),
			created_at INTEGER NOT NULL,
			retired_at INTEGER,
			expires_at INTEGER,
			PRIMARY KEY (domain, kid)
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS idx_signing_keys_domain_state
			ON signing_keys(domain, state)`,
		`CREATE INDEX IF NOT EXISTS idx_signing_keys_expires_at
			ON signing_keys(expires_at) WHERE expires_at IS NOT NULL`,
		// Enforces "exactly one current key per domain" — the partial unique
		// index makes a second 'current' INSERT for the same domain fail at
		// the schema level rather than requiring application-level checking.
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_signing_keys_one_current
			ON signing_keys(domain) WHERE state = 'current'`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

// StoreCode inserts or replaces an authorization code. Errors are logged, not
// returned, matching the Store contract.
func (s *sqliteStore) StoreCode(c *authCode) {
	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO codes
		(code, domain, client_id, username, redirect_uri,
		 pkce_challenge, pkce_method, nonce, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.Code, c.Domain, c.ClientID, c.Username, c.RedirectURI,
		c.PKCEChallenge, c.PKCEMethod, c.Nonce, c.ExpiresAt.Unix())
	if err != nil {
		s.log.Warn("authoidc: StoreCode write failed", "err", err)
	}
}

// ConsumeCode atomically reads and deletes a code in a single DELETE ...
// RETURNING. Concurrent callers see exactly one winner.
func (s *sqliteStore) ConsumeCode(code string) (*authCode, error) {
	row := s.db.QueryRow(`
		DELETE FROM codes WHERE code = ?
		RETURNING code, domain, client_id, username, redirect_uri,
		          pkce_challenge, pkce_method, nonce, expires_at`,
		code)

	var c authCode
	var exp int64
	err := row.Scan(&c.Code, &c.Domain, &c.ClientID, &c.Username, &c.RedirectURI,
		&c.PKCEChallenge, &c.PKCEMethod, &c.Nonce, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("consume code: %w", err)
	}
	c.ExpiresAt = time.Unix(exp, 0)
	if time.Now().After(c.ExpiresAt) {
		return nil, ErrExpired
	}
	return &c, nil
}

func (s *sqliteStore) StoreSession(sess *ssoSession) {
	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO sessions (id, domain, username, expires_at)
		VALUES (?, ?, ?, ?)`,
		sess.ID, sess.Domain, sess.Username, sess.ExpiresAt.Unix())
	if err != nil {
		s.log.Warn("authoidc: StoreSession write failed", "err", err)
	}
}

// LookupSession returns the session if present and unexpired. Expired sessions
// are removed lazily, mirroring the other Store implementations.
func (s *sqliteStore) LookupSession(id string) (*ssoSession, bool) {
	var sess ssoSession
	var exp int64
	err := s.db.QueryRow(`
		SELECT id, domain, username, expires_at FROM sessions WHERE id = ?`,
		id).Scan(&sess.ID, &sess.Domain, &sess.Username, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false
	}
	if err != nil {
		s.log.Warn("authoidc: LookupSession failed", "err", err)
		return nil, false
	}
	sess.ExpiresAt = time.Unix(exp, 0)
	if time.Now().After(sess.ExpiresAt) {
		if _, rmErr := s.db.Exec(`DELETE FROM sessions WHERE id = ?`, id); rmErr != nil {
			s.log.Warn("authoidc: LookupSession expired delete failed", "err", rmErr)
		}
		return nil, false
	}
	return &sess, true
}

func (s *sqliteStore) DeleteSession(id string) {
	if _, err := s.db.Exec(`DELETE FROM sessions WHERE id = ?`, id); err != nil {
		s.log.Warn("authoidc: DeleteSession failed", "err", err)
	}
}

// RegisterClient persists a dynamically registered OIDC client. redirect_uris
// is stored as a JSON array — it's a list, not a set of things to query
// against, so a serialised column is simpler than a join table.
func (s *sqliteStore) RegisterClient(c *registeredClient) {
	uris, err := json.Marshal(c.RedirectURIs)
	if err != nil {
		s.log.Warn("authoidc: RegisterClient marshal failed", "err", err)
		return
	}
	_, err = s.db.Exec(`
		INSERT OR REPLACE INTO clients
		(domain, client_id, client_name, redirect_uris, registered_at)
		VALUES (?, ?, ?, ?, ?)`,
		c.Domain, c.ClientID, c.ClientName, string(uris), c.RegisteredAt.Unix())
	if err != nil {
		s.log.Warn("authoidc: RegisterClient write failed", "err", err)
	}
}

func (s *sqliteStore) LookupClient(domain, clientID string) (*registeredClient, bool) {
	var c registeredClient
	var uris string
	var registeredAt int64
	err := s.db.QueryRow(`
		SELECT domain, client_id, client_name, redirect_uris, registered_at
		FROM clients WHERE domain = ? AND client_id = ?`,
		domain, clientID).Scan(&c.Domain, &c.ClientID, &c.ClientName, &uris, &registeredAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false
	}
	if err != nil {
		s.log.Warn("authoidc: LookupClient failed", "err", err)
		return nil, false
	}
	if err := json.Unmarshal([]byte(uris), &c.RedirectURIs); err != nil {
		s.log.Warn("authoidc: LookupClient decode redirect_uris failed", "err", err)
		return nil, false
	}
	c.RegisteredAt = time.Unix(registeredAt, 0)
	return &c, true
}

// SweepExpired removes codes and sessions whose expires_at is at or before
// now. Two DELETE statements; the index on expires_at keeps it cheap.
// Signing keys are swept via SweepExpiredSigningKeys, which returns the
// deleted records so callers can unlink the corresponding files.
func (s *sqliteStore) SweepExpired(now time.Time) error {
	cutoff := now.Unix()
	if _, err := s.db.Exec(`DELETE FROM codes WHERE expires_at <= ?`, cutoff); err != nil {
		return fmt.Errorf("sweep codes: %w", err)
	}
	if _, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at <= ?`, cutoff); err != nil {
		return fmt.Errorf("sweep sessions: %w", err)
	}
	return nil
}

// --- signing keys ---

// scanSigningKey decodes one row from the signing_keys table. retired_at and
// expires_at are nullable and decode to the zero time.Time when NULL.
func scanSigningKey(scanner interface {
	Scan(dest ...any) error
}) (signingKeyRecord, error) {
	var (
		rec       signingKeyRecord
		createdAt int64
		retiredAt sql.NullInt64
		expiresAt sql.NullInt64
	)
	if err := scanner.Scan(
		&rec.Domain, &rec.KID, &rec.Algorithm, &rec.State,
		&createdAt, &retiredAt, &expiresAt,
	); err != nil {
		return rec, err
	}
	rec.CreatedAt = time.Unix(createdAt, 0)
	if retiredAt.Valid {
		rec.RetiredAt = time.Unix(retiredAt.Int64, 0)
	}
	if expiresAt.Valid {
		rec.ExpiresAt = time.Unix(expiresAt.Int64, 0)
	}
	return rec, nil
}

// signingKeyColumns is the canonical SELECT list for signing_keys, matched
// to scanSigningKey. Keep these two in sync.
const signingKeyColumns = `domain, kid, algorithm, state, created_at, retired_at, expires_at`

func (s *sqliteStore) ListSigningKeys(domain string) ([]signingKeyRecord, error) {
	rows, err := s.db.Query(
		`SELECT `+signingKeyColumns+` FROM signing_keys WHERE domain = ?`,
		domain,
	)
	if err != nil {
		return nil, fmt.Errorf("list signing keys: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []signingKeyRecord
	for rows.Next() {
		rec, err := scanSigningKey(rows)
		if err != nil {
			return nil, fmt.Errorf("scan signing key: %w", err)
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate signing keys: %w", err)
	}
	return out, nil
}

func (s *sqliteStore) InsertSigningKey(rec signingKeyRecord) error {
	_, err := s.db.Exec(
		`INSERT INTO signing_keys (domain, kid, algorithm, state, created_at)
		 VALUES (?, ?, ?, 'current', ?)`,
		rec.Domain, rec.KID, rec.Algorithm, rec.CreatedAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("insert signing key: %w", err)
	}
	return nil
}

// RotateSigningKey runs the current→retiring + new-current insertion as one
// transaction so the domain never observes "no current key" mid-rotation.
func (s *sqliteStore) RotateSigningKey(domain string, newKey signingKeyRecord, retention time.Duration) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin rotate tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit

	now := newKey.CreatedAt
	if now.IsZero() {
		now = time.Now()
	}
	expires := now.Add(retention).Unix()

	if _, err := tx.Exec(
		`UPDATE signing_keys
		   SET state = 'retiring', retired_at = ?, expires_at = ?
		 WHERE domain = ? AND state = 'current'`,
		now.Unix(), expires, domain,
	); err != nil {
		return fmt.Errorf("retire current: %w", err)
	}

	if _, err := tx.Exec(
		`INSERT INTO signing_keys (domain, kid, algorithm, state, created_at)
		 VALUES (?, ?, ?, 'current', ?)`,
		domain, newKey.KID, newKey.Algorithm, now.Unix(),
	); err != nil {
		return fmt.Errorf("insert new current: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit rotate: %w", err)
	}
	return nil
}

// RevokeSigningKey marks a key as expired immediately (expires_at = 1, a Unix
// time of "1 second past the epoch" — any positive value <= now triggers the
// sweep). The state moves to retiring so the sweep query finds it.
func (s *sqliteStore) RevokeSigningKey(domain, kid string) error {
	res, err := s.db.Exec(
		`UPDATE signing_keys
		   SET state = 'retiring', retired_at = ?, expires_at = 1
		 WHERE domain = ? AND kid = ?`,
		time.Now().Unix(), domain, kid,
	)
	if err != nil {
		return fmt.Errorf("revoke signing key: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("revoke rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("signing key %s not found for domain %s", kid, domain)
	}
	return nil
}

// SweepExpiredSigningKeys deletes retiring rows whose expires_at <= now and
// returns the deleted records so the caller can unlink files.
func (s *sqliteStore) SweepExpiredSigningKeys(now time.Time) ([]signingKeyRecord, error) {
	rows, err := s.db.Query(
		`DELETE FROM signing_keys
		   WHERE state = 'retiring' AND expires_at IS NOT NULL AND expires_at <= ?
		 RETURNING `+signingKeyColumns,
		now.Unix(),
	)
	if err != nil {
		return nil, fmt.Errorf("sweep signing keys: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []signingKeyRecord
	for rows.Next() {
		rec, err := scanSigningKey(rows)
		if err != nil {
			return nil, fmt.Errorf("scan swept signing key: %w", err)
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate swept signing keys: %w", err)
	}
	return out, nil
}

// Close closes the underlying database handle.
func (s *sqliteStore) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Compile-time assertion that sqliteStore satisfies Store.
var _ Store = (*sqliteStore)(nil)
