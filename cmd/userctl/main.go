// Command userctl manages users in infodancer auth passwd files.
//
// Usage:
//
//	userctl [--domains <path>] [--verbose] add    <user@domain>   add user (prompts for password)
//	userctl [--domains <path>] [--verbose] del    <user@domain>   remove user
//	userctl [--domains <path>] [--verbose] list   <domain>        list users and mailboxes
//	userctl [--domains <path>] [--verbose] verify <user@domain>   verify user password
//
// The domains path is resolved in order:
//  1. --domains flag
//  2. INFODANCER_DOMAINS_PATH environment variable
//  3. smtpd.domains_path from /etc/infodancer/config.toml
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/pelletier/go-toml/v2"
	"golang.org/x/term"

	"github.com/infodancer/maildancer/auth/passwd"
)

const defaultConfigPath = "/etc/infodancer/config.toml"

// serverConfig is a minimal view of the shared server config for path discovery.
type serverConfig struct {
	SMTPD struct {
		DomainsPath string `toml:"domains_path"`
	} `toml:"smtpd"`
}

func main() {
	fs := flag.NewFlagSet("userctl", flag.ExitOnError)
	domainsFlag := fs.String("domains", "", "path to domains directory")
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
	if len(args) < 2 {
		usage()
		os.Exit(1)
	}

	domainsPath, err := resolveDomainsPath(*domainsFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	slog.Debug("resolved domains path", "path", domainsPath)

	subcmd := args[0]
	target := args[1]

	switch subcmd {
	case "add":
		username, domainDir, err := parseEmailTarget(domainsPath, target)
		if err == nil {
			passwdPath := filepath.Join(domainDir, "passwd")
			slog.Debug("adding user", "username", username, "passwd", passwdPath)
			err = cmdAdd(passwdPath, username)
		}
		exitOnErr(err)

	case "del":
		username, domainDir, err := parseEmailTarget(domainsPath, target)
		if err == nil {
			passwdPath := filepath.Join(domainDir, "passwd")
			slog.Debug("deleting user", "username", username, "passwd", passwdPath)
			err = cmdDel(passwdPath, username)
		}
		exitOnErr(err)

	case "list":
		domainDir := filepath.Join(domainsPath, target)
		passwdPath := filepath.Join(domainDir, "passwd")
		slog.Debug("listing users", "domain", target, "passwd", passwdPath)
		exitOnErr(cmdList(passwdPath))

	case "verify":
		username, domainDir, err := parseEmailTarget(domainsPath, target)
		if err == nil {
			slog.Debug("verifying user", "username", username, "domain_dir", domainDir)
			err = cmdVerify(domainDir, username)
		}
		exitOnErr(err)

	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n", subcmd)
		usage()
		os.Exit(1)
	}
}

// resolveDomainsPath returns the domains path using the precedence:
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
	path, err := domainsPathFromConfig(defaultConfigPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("domains path not set: use --domains, INFODANCER_DOMAINS_PATH, or ensure %s exists", defaultConfigPath)
		}
		return "", fmt.Errorf("read %s: %w", defaultConfigPath, err)
	}

	slog.Debug("domains path from config file", "path", path, "config", defaultConfigPath)
	return path, nil
}

// domainsPathFromConfig reads smtpd.domains_path from the given config file.
func domainsPathFromConfig(configPath string) (string, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", err
	}

	var cfg serverConfig
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return "", fmt.Errorf("parse config: %w", err)
	}

	if cfg.SMTPD.DomainsPath == "" {
		return "", fmt.Errorf("smtpd.domains_path not set in %s", configPath)
	}

	return cfg.SMTPD.DomainsPath, nil
}

// parseEmailTarget splits user@domain and returns the username and domain directory path.
func parseEmailTarget(domainsPath, address string) (username, domainDir string, err error) {
	parts := strings.SplitN(address, "@", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid address %q: expected user@domain", address)
	}
	return parts[0], filepath.Join(domainsPath, parts[1]), nil
}

func cmdAdd(passwdPath, username string) error {
	password, err := promptPassword("Password: ")
	if err != nil {
		return err
	}

	confirm, err := promptPassword("Confirm password: ")
	if err != nil {
		return err
	}

	if password != confirm {
		return fmt.Errorf("passwords do not match")
	}

	if err := passwd.AddUser(passwdPath, username, password); err != nil {
		slog.Debug("AddUser failed", "passwd", passwdPath, "username", username, "error", err)
		return err
	}

	fmt.Printf("Added user %q\n", username)
	return nil
}

func cmdDel(passwdPath, username string) error {
	if err := passwd.DeleteUser(passwdPath, username); err != nil {
		slog.Debug("DeleteUser failed", "passwd", passwdPath, "username", username, "error", err)
		return err
	}
	fmt.Printf("Deleted user %q\n", username)
	return nil
}

func cmdList(passwdPath string) error {
	users, err := passwd.ListUsers(passwdPath)
	if err != nil {
		slog.Debug("ListUsers failed", "passwd", passwdPath, "error", err)
		return err
	}

	if len(users) == 0 {
		fmt.Println("no users")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "USERNAME\tMAILBOX"); err != nil {
		return err
	}
	for _, u := range users {
		if _, err := fmt.Fprintf(w, "%s\t%s\n", u.Username, u.Mailbox); err != nil {
			return err
		}
	}
	return w.Flush()
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
  userctl [--domains <path>] [--verbose] add    <user@domain>   add user (prompts for password)
  userctl [--domains <path>] [--verbose] del    <user@domain>   remove user
  userctl [--domains <path>] [--verbose] list   <domain>        list users and mailboxes
  userctl [--domains <path>] [--verbose] verify <user@domain>   verify user password

Flags:
  --domains   path to domains directory (overrides env and config)
  --verbose   enable debug logging (default: true)

Domains path resolution order:
  1. --domains flag
  2. INFODANCER_DOMAINS_PATH environment variable
  3. smtpd.domains_path from /etc/infodancer/config.toml
`)
}
