package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/infodancer/maildancer/internal/auth/authoidc"
)

// runKeysSubcommand dispatches the `userctl keys ...` family. args[0] is
// the action (list/rotate/revoke); remaining args are positional + flags
// for that action. dataDirFlag is the top-level --data-dir value (may be
// empty, in which case env / config file are tried).
func runKeysSubcommand(args []string, dataDirFlag string) error {
	if len(args) < 1 {
		keysUsage()
		return errors.New("keys: missing action")
	}
	action := args[0]
	rest := args[1:]

	dataDir, err := resolveDataDir(dataDirFlag)
	if err != nil {
		return err
	}
	slog.Debug("resolved auth-oidc data dir", "path", dataDir)

	km, err := authoidc.OpenKeyManager(dataDir, 0)
	if err != nil {
		return fmt.Errorf("open key manager: %w", err)
	}
	defer func() { _ = km.Close() }()

	switch action {
	case "list":
		if len(rest) != 1 {
			keysUsage()
			return errors.New("keys list: expected <domain>")
		}
		return keysList(km, rest[0])

	case "rotate":
		positional, alg, err := parseRotateArgs(rest)
		if err != nil {
			keysUsage()
			return err
		}
		return keysRotate(km, positional, alg)

	case "revoke":
		if len(rest) != 2 {
			keysUsage()
			return errors.New("keys revoke: expected <domain> <kid>")
		}
		return keysRevoke(km, rest[0], rest[1])

	default:
		keysUsage()
		return fmt.Errorf("keys: unknown action %q", action)
	}
}

func keysList(km *authoidc.KeyManager, domain string) error {
	keys, err := km.List(domain)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		fmt.Printf("no signing keys for domain %s\n", domain)
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "KID\tALGORITHM\tSTATE\tCREATED\tRETIRED\tEXPIRES"); err != nil {
		return err
	}
	for _, k := range keys {
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			k.KID, k.Algorithm, k.State,
			fmtTime(k.CreatedAt), fmtTime(k.RetiredAt), fmtTime(k.ExpiresAt),
		); err != nil {
			return err
		}
	}
	return w.Flush()
}

// parseRotateArgs accepts the args after `keys rotate` and returns the
// domain and (optionally) the --algorithm value. Either "--algorithm=X"
// or "--algorithm X" is accepted, in any position relative to the
// positional domain arg. Anything else is rejected so a typo doesn't
// silently become the domain name.
func parseRotateArgs(args []string) (domain, algorithm string, err error) {
	var positionals []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--algorithm":
			if i+1 >= len(args) {
				return "", "", errors.New("--algorithm requires a value")
			}
			algorithm = args[i+1]
			i++
		case strings.HasPrefix(a, "--algorithm="):
			algorithm = strings.TrimPrefix(a, "--algorithm=")
		case strings.HasPrefix(a, "--"):
			return "", "", fmt.Errorf("unknown flag: %s", a)
		default:
			positionals = append(positionals, a)
		}
	}
	if len(positionals) != 1 {
		return "", "", errors.New("keys rotate: expected exactly one positional <domain>")
	}
	return positionals[0], algorithm, nil
}

func keysRotate(km *authoidc.KeyManager, domain, algorithm string) error {
	newKID, err := km.Rotate(domain, algorithm)
	if err != nil {
		return err
	}
	fmt.Printf("Rotated %s: new current kid %s\n", domain, newKID)
	return nil
}

func keysRevoke(km *authoidc.KeyManager, domain, kid string) error {
	if err := km.Revoke(domain, kid); err != nil {
		return err
	}
	fmt.Printf("Revoked %s/%s — will be swept on next pass\n", domain, kid)
	return nil
}

// resolveDataDir mirrors resolveDomainsPath: flag > env > config file.
func resolveDataDir(flagValue string) (string, error) {
	if flagValue != "" {
		slog.Debug("data dir from --data-dir flag", "path", flagValue)
		return flagValue, nil
	}
	if v := os.Getenv("AUTH_OIDC_DATA_DIR"); v != "" {
		slog.Debug("data dir from AUTH_OIDC_DATA_DIR", "path", v)
		return v, nil
	}
	slog.Debug("trying auth-oidc config file", "path", defaultAuthOIDCConfigPath)
	path, err := dataDirFromConfig(defaultAuthOIDCConfigPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("data dir not set: use --data-dir, AUTH_OIDC_DATA_DIR, or ensure %s exists",
				defaultAuthOIDCConfigPath)
		}
		return "", fmt.Errorf("read %s: %w", defaultAuthOIDCConfigPath, err)
	}
	slog.Debug("data dir from config file", "path", path, "config", defaultAuthOIDCConfigPath)
	return path, nil
}

// dataDirFromConfig reads server.data_dir from the given auth-oidc config.
func dataDirFromConfig(configPath string) (string, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", err
	}
	var cfg authOIDCConfig
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return "", fmt.Errorf("parse config: %w", err)
	}
	if cfg.Server.DataDir == "" {
		return "", fmt.Errorf("server.data_dir not set in %s", configPath)
	}
	return cfg.Server.DataDir, nil
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

func keysUsage() {
	fmt.Fprintln(os.Stderr, `Usage:
  userctl [--data-dir <path>] keys list   <domain>
  userctl [--data-dir <path>] keys rotate <domain> [--algorithm=RS256|ES256|EdDSA]
  userctl [--data-dir <path>] keys revoke <domain> <kid>`)
}
