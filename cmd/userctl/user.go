package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"golang.org/x/term"

	"github.com/infodancer/maildancer/internal/admin"
)

// runUserSubcommand handles the `user` subcommand and its actions:
//
//	userctl user add    <user@domain> [--gen-keys] [--password-stdin]
//	userctl user del    <user@domain>
//	userctl user list   <domain>
//	userctl user passwd <user@domain> [--password-stdin]
//	userctl user verify <user@domain>
//	userctl user key    show|create|del <user@domain>
//
// stdin supplies passwords for --password-stdin (first line, for scripting);
// otherwise passwords are prompted interactively with confirmation.
func runUserSubcommand(args []string, paths admin.Paths, stdin io.Reader) error {
	if len(args) < 1 {
		userUsage()
		return fmt.Errorf("user: missing action")
	}

	action := args[0]
	genKeys, passwordStdin, adminReset := false, false, false
	var positional []string
	for _, a := range args[1:] {
		switch a {
		case "--gen-keys":
			genKeys = true
		case "--password-stdin":
			passwordStdin = true
		case "--reset":
			adminReset = true
		default:
			positional = append(positional, a)
		}
	}

	switch action {
	case "add":
		if len(positional) != 1 {
			userUsage()
			return fmt.Errorf("user add: expected <user@domain>")
		}
		username, domainName, err := splitAddress(positional[0])
		if err != nil {
			return err
		}
		return cmdUserAdd(paths, domainName, username, genKeys, passwordStdin, stdin)

	case "del":
		if len(positional) != 1 {
			userUsage()
			return fmt.Errorf("user del: expected <user@domain>")
		}
		username, domainName, err := splitAddress(positional[0])
		if err != nil {
			return err
		}
		if err := paths.DeleteUser(domainName, username); err != nil {
			return err
		}
		fmt.Printf("Deleted user %s@%s\n", username, domainName)
		return nil

	case "list":
		if len(positional) != 1 {
			userUsage()
			return fmt.Errorf("user list: expected <domain>")
		}
		return cmdUserList(paths, positional[0])

	case "passwd":
		if len(positional) != 1 {
			userUsage()
			return fmt.Errorf("user passwd: expected <user@domain>")
		}
		username, domainName, err := splitAddress(positional[0])
		if err != nil {
			return err
		}
		return cmdUserPasswd(paths, domainName, username, adminReset, passwordStdin, stdin)

	case "verify":
		if len(positional) != 1 {
			userUsage()
			return fmt.Errorf("user verify: expected <user@domain>")
		}
		username, domainName, err := splitAddress(positional[0])
		if err != nil {
			return err
		}
		// Reuses the legacy auth-roundtrip implementation in main.go.
		return cmdVerify(paths.DomainDir(domainName), username)

	case "key":
		return runUserKeyAction(append([]string{}, args[1:]...), paths, stdin)

	default:
		userUsage()
		return fmt.Errorf("user: unknown action %q", action)
	}
}

func cmdUserAdd(paths admin.Paths, domainName, username string, genKeys, passwordStdin bool, stdin io.Reader) error {
	password, err := readNewPassword(stdin, passwordStdin)
	if err != nil {
		return err
	}

	result, err := paths.CreateUser(domainName, username, password, genKeys)
	if err != nil {
		return err
	}
	fmt.Printf("Added user %s@%s (uid %d)\n", username, domainName, result.UID)
	if result.KeysGenerated {
		fmt.Println("Generated encryption keypair")
	}
	for _, w := range result.Warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}
	return nil
}

// cmdUserPasswd changes or resets a user's password, keeping sealed
// encryption keys consistent with the hash:
//
//   - User has keys, no --reset: re-seal flow. Requires the current password
//     (prompted, or first of two stdin lines with --password-stdin); the
//     keypair is preserved and old mail stays readable.
//   - --reset (admin flow, current password unknown): keyed users get a fresh
//     keypair sealed under the new password -- old encrypted mail becomes
//     unreadable, and the command says so. Keyless users get a plain reset.
//   - Keyless, no --reset: plain reset, same as before.
func cmdUserPasswd(paths admin.Paths, domainName, username string, adminReset, passwordStdin bool, stdin io.Reader) error {
	status, err := paths.UserKeyStatus(domainName, username)
	if err != nil {
		return err
	}
	hasKeys := status != nil && status.Exists && status.HasPrivate

	if adminReset {
		password, err := readNewPassword(stdin, passwordStdin)
		if err != nil {
			return err
		}
		if hasKeys {
			fingerprint, err := paths.ResetPasswordRegenKeys(domainName, username, password)
			if err != nil {
				return err
			}
			fmt.Printf("Password reset for %s@%s\n", username, domainName)
			fmt.Fprintf(os.Stderr, "warning: encryption keypair regenerated (new fingerprint %s); previously encrypted mail is no longer readable\n", fingerprint)
			return nil
		}
		if err := paths.ResetPassword(domainName, username, password); err != nil {
			return err
		}
		fmt.Printf("Password reset for %s@%s\n", username, domainName)
		return nil
	}

	if hasKeys {
		current, newPass, err := readPasswordChange(stdin, passwordStdin)
		if err != nil {
			return err
		}
		if err := paths.ChangePassword(domainName, username, current, newPass); err != nil {
			return err
		}
		fmt.Printf("Password updated for %s@%s (encryption key re-sealed)\n", username, domainName)
		return nil
	}

	password, err := readNewPassword(stdin, passwordStdin)
	if err != nil {
		return err
	}
	if err := paths.ResetPassword(domainName, username, password); err != nil {
		return err
	}
	fmt.Printf("Password updated for %s@%s\n", username, domainName)
	return nil
}

// readPasswordChange obtains (current, new) passwords for the re-seal flow.
// With fromStdin it reads two lines (current, then new) using one scanner --
// two readNewPassword calls would each buffer ahead and lose input.
// Interactively it prompts for the current password, then the new password
// with confirmation.
func readPasswordChange(stdin io.Reader, fromStdin bool) (current, newPass string, err error) {
	if fromStdin {
		scanner := bufio.NewScanner(stdin)
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return "", "", fmt.Errorf("read current password from stdin: %w", err)
			}
			return "", "", fmt.Errorf("read current password from stdin: empty input")
		}
		current = scanner.Text()
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return "", "", fmt.Errorf("read new password from stdin: %w", err)
			}
			return "", "", fmt.Errorf("read new password from stdin: expected a second line (current, then new)")
		}
		return current, scanner.Text(), nil
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", "", fmt.Errorf("stdin is not a terminal: use --password-stdin with two lines (current, then new)")
	}

	current, err = promptPassword("Current password: ")
	if err != nil {
		return "", "", err
	}
	newPass, err = promptPassword("New password: ")
	if err != nil {
		return "", "", err
	}
	confirm, err := promptPassword("Confirm new password: ")
	if err != nil {
		return "", "", err
	}
	if newPass != confirm {
		return "", "", fmt.Errorf("passwords do not match")
	}
	return current, newPass, nil
}

func cmdUserList(paths admin.Paths, domainName string) error {
	users, err := paths.ListUsers(domainName)
	if err != nil {
		return err
	}
	if len(users) == 0 {
		fmt.Println("no users")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "USERNAME\tMAILBOX\tUID\tKEYS"); err != nil {
		return err
	}
	for _, u := range users {
		keys := "-"
		if u.HasKeys {
			keys = "yes"
		}
		if _, err := fmt.Fprintf(w, "%s\t%s\t%d\t%s\n", u.Username, u.Mailbox, u.UID, keys); err != nil {
			return err
		}
	}
	return w.Flush()
}

// runUserKeyAction handles `user key show|create|del <user@domain>`.
func runUserKeyAction(args []string, paths admin.Paths, stdin io.Reader) error {
	if len(args) < 2 {
		userUsage()
		return fmt.Errorf("user key: expected show|create|del <user@domain>")
	}
	action := args[0]
	passwordStdin := false
	var positional []string
	for _, a := range args[1:] {
		if a == "--password-stdin" {
			passwordStdin = true
		} else {
			positional = append(positional, a)
		}
	}
	if len(positional) != 1 {
		userUsage()
		return fmt.Errorf("user key %s: expected <user@domain>", action)
	}
	username, domainName, err := splitAddress(positional[0])
	if err != nil {
		return err
	}

	switch action {
	case "show":
		status, err := paths.UserKeyStatus(domainName, username)
		if err != nil {
			return err
		}
		if !status.Exists {
			fmt.Printf("no keys for %s@%s\n", username, domainName)
			return nil
		}
		fmt.Printf("Algorithm:   x25519\n")
		fmt.Printf("Fingerprint: %s\n", status.Fingerprint)
		fmt.Printf("Private key: %v\n", status.HasPrivate)
		return nil

	case "create":
		password, err := readNewPassword(stdin, passwordStdin)
		if err != nil {
			return err
		}
		fingerprint, err := paths.CreateUserKeys(domainName, username, password)
		if err != nil {
			return err
		}
		fmt.Printf("Generated keypair for %s@%s\nFingerprint: %s\n", username, domainName, fingerprint)
		return nil

	case "del":
		if err := paths.DeleteUserKeys(domainName, username); err != nil {
			return err
		}
		fmt.Printf("Deleted keys for %s@%s\n", username, domainName)
		return nil

	default:
		userUsage()
		return fmt.Errorf("user key: unknown action %q", action)
	}
}

// readNewPassword obtains a password for a state-changing operation. With
// fromStdin it reads the first line of stdin (for scripting: pipe the secret,
// never pass it in argv where ps would expose it). Otherwise it prompts twice
// on the terminal and requires a match.
func readNewPassword(stdin io.Reader, fromStdin bool) (string, error) {
	if fromStdin {
		scanner := bufio.NewScanner(stdin)
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return "", fmt.Errorf("read password from stdin: %w", err)
			}
			return "", fmt.Errorf("read password from stdin: empty input")
		}
		return scanner.Text(), nil
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("stdin is not a terminal: use --password-stdin for non-interactive use")
	}

	password, err := promptPassword("Password: ")
	if err != nil {
		return "", err
	}
	confirm, err := promptPassword("Confirm password: ")
	if err != nil {
		return "", err
	}
	if password != confirm {
		return "", fmt.Errorf("passwords do not match")
	}
	return password, nil
}

func userUsage() {
	fmt.Fprintln(os.Stderr, `Usage:
  userctl user add    <user@domain> [--gen-keys] [--password-stdin]   add user (allocates uid)
  userctl user del    <user@domain>                                   remove user
  userctl user list   <domain>                                        list users
  userctl user passwd <user@domain> [--reset] [--password-stdin]      change/reset password
  userctl user verify <user@domain>                                   verify password
  userctl user key    show   <user@domain>                            show encryption key
  userctl user key    create <user@domain> [--password-stdin]         generate keypair
  userctl user key    del    <user@domain>                            delete keypair

--gen-keys forces an encryption keypair to be generated. Without it, a
keypair is still generated when the domain's encryption_mode is "on"
(at-rest encryption then activates for the user automatically).

--password-stdin reads the password from the first line of stdin (for
scripting); without it, userctl prompts on the terminal.

passwd on a user WITH encryption keys requires the current password (it
re-seals the key, preserving access to old mail): interactively you are
prompted; with --password-stdin supply two lines (current, then new).
passwd --reset is the admin flow when the current password is unknown:
keyed users get a regenerated keypair and old encrypted mail becomes
unreadable.`)
}
