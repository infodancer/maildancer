// Command userctl is the site-level superadmin CLI for infodancer domain and
// user management. It shares its operations layer (internal/admin) with the
// webadmin UI, so the two tools cannot drift; webadmin remains the tool for
// delegated domain admins, userctl is for site operators on the host.
//
// Subcommands (noun-verb):
//
//	userctl domain  create|del|list|show|set|key ...   domain lifecycle and config
//	userctl user    add|del|list|passwd|verify|key ... user lifecycle and keys
//	userctl forward list|set|del ...                   domain forwards (1:1)
//	userctl keys    list|rotate|revoke ...             auth-oidc signing keys
//	userctl migrate uids                               allocate missing gids/uids
//
// The legacy flat forms (add, del, list, verify) remain as aliases for the
// user subcommand.
//
// Path resolution for --domains (config volume): flag >
// INFODANCER_DOMAINS_PATH env > smtpd.domains_path in
// /etc/infodancer/config.toml.
//
// Path resolution for --data (data volume: maildirs, uid counter): flag >
// INFODANCER_DOMAINS_DATA_PATH env > smtpd.domains_data_path in
// /etc/infodancer/config.toml > the domains path (single-tree layout).
//
// Path resolution for --data-dir (auth-oidc keys subcommands): flag >
// AUTH_OIDC_DATA_DIR env > server.data_dir in /etc/auth-oidc/config.toml.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"
	"golang.org/x/term"

	"github.com/infodancer/maildancer/auth/passwd"
	"github.com/infodancer/maildancer/internal/admin"
)

const (
	defaultConfigPath         = "/etc/infodancer/config.toml"
	defaultAuthOIDCConfigPath = "/etc/auth-oidc/config.toml"
)

// serverConfig is a minimal view of the shared server config for path discovery.
type serverConfig struct {
	SMTPD struct {
		DomainsPath     string `toml:"domains_path"`
		DomainsDataPath string `toml:"domains_data_path"`
	} `toml:"smtpd"`
}

// authOIDCConfig is a minimal view of the auth-oidc config for data_dir
// discovery. Only the one field we need; the daemon owns the full schema.
type authOIDCConfig struct {
	Server struct {
		DataDir string `toml:"data_dir"`
	} `toml:"server"`
}

func main() {
	fs := flag.NewFlagSet("userctl", flag.ExitOnError)
	domainsFlag := fs.String("domains", "", "path to domains config directory")
	dataFlag := fs.String("data", "", "path to domains data directory (maildirs, uid counter)")
	dataDirFlag := fs.String("data-dir", "", "path to auth-oidc data dir (for keys subcommands)")
	verboseFlag := fs.Bool("verbose", true, "enable debug logging")
	fs.Usage = usage

	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(1)
	}

	if *verboseFlag {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})))
	}

	args := fs.Args()
	if len(args) < 1 {
		usage()
		os.Exit(1)
	}

	subcmd := args[0]

	// keys is dispatched separately because it has sub-subcommands and its
	// own data-dir resolution path.
	if subcmd == "keys" {
		exitOnErr(runKeysSubcommand(args[1:], *dataDirFlag))
		return
	}

	domainsPath, err := resolveDomainsPath(*domainsFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	slog.Debug("resolved domains path", "path", domainsPath)

	dataPath := resolveDataPath(*dataFlag, domainsPath)
	slog.Debug("resolved data path", "path", dataPath)

	paths := admin.Paths{Config: domainsPath, Data: dataPath}

	switch subcmd {
	case "domain":
		exitOnErr(runDomainSubcommand(args[1:], paths, os.Stdin))

	case "user":
		exitOnErr(runUserSubcommand(args[1:], paths, os.Stdin))

	case "forward":
		exitOnErr(runForwardSubcommand(args[1:], domainsPath))

	case "migrate":
		exitOnErr(runMigrateSubcommand(args[1:], paths))

	// Legacy flat aliases for the user subcommand.
	case "add", "del", "list", "verify":
		exitOnErr(runUserSubcommand(args, paths, os.Stdin))

	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n", subcmd)
		usage()
		os.Exit(1)
	}
}

// runMigrateSubcommand handles `userctl migrate uids`.
func runMigrateSubcommand(args []string, paths admin.Paths) error {
	if len(args) != 1 || args[0] != "uids" {
		return fmt.Errorf("migrate: expected `migrate uids`")
	}
	result, err := paths.MigrateUIDs()
	if err != nil {
		return err
	}
	for _, d := range result.Details {
		fmt.Printf("allocated %s\n", d)
	}
	fmt.Printf("Migrated %d domains, %d users\n", result.DomainsMigrated, result.UsersMigrated)
	if len(result.Errors) > 0 {
		for _, e := range result.Errors {
			fmt.Fprintf(os.Stderr, "error: %s\n", e)
		}
		return fmt.Errorf("migration completed with %d errors", len(result.Errors))
	}
	return nil
}

// resolveDomainsPath returns the domains config path using the precedence:
// flag > env > /etc/infodancer/config.toml > error.
func resolveDomainsPath(flagValue string) (string, error) {
	if flagValue != "" {
		slog.Debug("domains path from --domains flag", "path", flagValue)
		return flagValue, nil
	}

	if v := os.Getenv("INFODANCER_DOMAINS_PATH"); v != "" {
		slog.Debug("domains path from INFODANCER_DOMAINS_PATH", "path", v)
		return v, nil
	}

	slog.Debug("trying config file", "path", defaultConfigPath)
	cfg, err := loadServerConfig(defaultConfigPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("domains path not set: use --domains, INFODANCER_DOMAINS_PATH, or ensure %s exists", defaultConfigPath)
		}
		return "", fmt.Errorf("read %s: %w", defaultConfigPath, err)
	}
	if cfg.SMTPD.DomainsPath == "" {
		return "", fmt.Errorf("smtpd.domains_path not set in %s", defaultConfigPath)
	}

	slog.Debug("domains path from config file", "path", cfg.SMTPD.DomainsPath, "config", defaultConfigPath)
	return cfg.SMTPD.DomainsPath, nil
}

// resolveDataPath returns the data volume path using the precedence:
// flag > env > smtpd.domains_data_path in config > domainsPath (single tree).
func resolveDataPath(flagValue, domainsPath string) string {
	if flagValue != "" {
		return flagValue
	}
	if v := os.Getenv("INFODANCER_DOMAINS_DATA_PATH"); v != "" {
		return v
	}
	if cfg, err := loadServerConfig(defaultConfigPath); err == nil && cfg.SMTPD.DomainsDataPath != "" {
		return cfg.SMTPD.DomainsDataPath
	}
	return domainsPath
}

// loadServerConfig reads the shared server config file.
func loadServerConfig(configPath string) (*serverConfig, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var cfg serverConfig
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}

func cmdVerify(domainDir, username string) error {
	passwdPath := filepath.Join(domainDir, "passwd")
	keyDir := filepath.Join(domainDir, "keys")

	slog.Debug("loading passwd agent", "passwd", passwdPath, "keys", keyDir)

	agent, err := passwd.NewAgent(passwdPath, keyDir)
	if err != nil {
		slog.Debug("NewAgent failed", "passwd", passwdPath, "error", err)
		return fmt.Errorf("load passwd: %w", err)
	}
	defer func() { _ = agent.Close() }()

	password, err := promptPassword("Password: ")
	if err != nil {
		return err
	}

	session, err := agent.Authenticate(context.Background(), username, password)
	if err != nil {
		slog.Debug("Authenticate failed", "username", username, "error", err)
		return fmt.Errorf("authentication failed: %w", err)
	}
	defer session.Clear()

	fmt.Printf("OK: %s (mailbox: %s)\n", session.User.Username, session.User.Mailbox)
	return nil
}

func promptPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	raw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr) // newline after hidden input
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	return string(raw), nil
}

func exitOnErr(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:
  Domains (site admin):
    userctl domain create <domain>                    create domain (allocates gid)
    userctl domain del    <domain> [--force]          delete domain config (mail data retained)
    userctl domain list
    userctl domain show   <domain>
    userctl domain set    <domain> <key> [<value>]    set/unset a config key
    userctl domain key    show|create|del <domain>    domain encryption keypair
    userctl domain dkim   create <domain> [--selector <s>] [--force]
    userctl domain dkim   show   <domain>             DKIM key + DNS TXT record

  Users:
    userctl user add    <user@domain> [--gen-keys] [--password-stdin]
    userctl user del    <user@domain>
    userctl user list   <domain>
    userctl user passwd <user@domain> [--password-stdin]
    userctl user verify <user@domain>
    userctl user key    show|create|del <user@domain> [--password-stdin]
    (add/del/list/verify also work without the "user" prefix)

  Forwards (1:1; *@domain for catchall):
    userctl forward list <domain>
    userctl forward set  <localpart@domain> <target>
    userctl forward del  <localpart@domain>

  Migration:
    userctl migrate uids                              allocate missing gids/uids

  Signing keys (auth-oidc operator):
    userctl [--data-dir <path>] keys list   <domain>
    userctl [--data-dir <path>] keys rotate <domain> [--algorithm=RS256|ES256|EdDSA]
    userctl [--data-dir <path>] keys revoke <domain> <kid>

Flags:
  --domains    domains config directory (flag > INFODANCER_DOMAINS_PATH > smtpd.domains_path)
  --data       domains data directory   (flag > INFODANCER_DOMAINS_DATA_PATH >
               smtpd.domains_data_path > domains path)
  --data-dir   auth-oidc data dir       (flag > AUTH_OIDC_DATA_DIR > server.data_dir)
  --verbose    enable debug logging (default: true)

Run 'userctl domain set' without arguments to list the editable config keys.
`)
}
