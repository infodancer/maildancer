package tlsstage

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// RefreshOnce performs one refresh check. It re-reads the config for the
// current source paths (so a config edit changing the cert location is
// picked up) and re-runs the full stage when either source file is newer
// than its staged copy or a staged copy is missing. It reports whether a
// restage happened.
//
// This is the single iteration of the -refresh loop, factored out so the
// decision logic is testable without the loop; callers treat a returned
// error as transient (log and retry next tick).
func RefreshOnce(opts Options, stderr io.Writer) (bool, error) {
	certFile, keyFile, err := extractTLSPaths(opts.ConfigPath, opts.Section)
	if err != nil {
		return false, err
	}
	if certFile == "" || keyFile == "" {
		return false, nil
	}

	certStale, err := needsRestage(certFile, filepath.Join(opts.OutDir, "fullchain.pem"))
	if err != nil {
		return false, err
	}
	keyStale, err := needsRestage(keyFile, filepath.Join(opts.OutDir, "privkey.pem"))
	if err != nil {
		return false, err
	}
	if !certStale && !keyStale {
		return false, nil
	}

	// Certbot renews cert and key together; restage both so the staged pair
	// can never mix material from two renewals.
	if err := Run(opts, stderr); err != nil {
		return false, err
	}
	return true, nil
}

// needsRestage reports whether src must be copied over dst: dst is missing
// or src's mtime is strictly newer. A stat error on src (unreadable or
// vanished mid-renewal) is returned to the caller rather than treated as
// "no change" so the refresher can log it and retry.
func needsRestage(src, dst string) (bool, error) {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return false, fmt.Errorf("stat source: %w", err)
	}
	dstInfo, err := os.Stat(dst)
	if err != nil {
		if os.IsNotExist(err) {
			return true, nil
		}
		return false, fmt.Errorf("stat staged copy: %w", err)
	}
	return srcInfo.ModTime().After(dstInfo.ModTime()), nil
}
