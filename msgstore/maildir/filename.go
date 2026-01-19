package maildir

import (
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

var (
	// deliveryCounter ensures unique filenames even within the same microsecond.
	deliveryCounter uint64
	// cachedHostname is set once at startup.
	cachedHostname string
)

func init() {
	cachedHostname = getHostname()
}

// generateFilename creates a unique filename for maildir delivery.
// Format: timestamp.Pprocess.hostname.random
// Example: 1705678901.P12345.hostname.abc123
func generateFilename() string {
	now := time.Now()
	counter := atomic.AddUint64(&deliveryCounter, 1)
	pid := os.Getpid()

	// Generate random suffix for additional uniqueness
	randomBytes := make([]byte, 6)
	if _, err := rand.Read(randomBytes); err != nil {
		// Fallback to counter-based suffix if random fails
		return fmt.Sprintf("%d.M%dP%d.%s.%d",
			now.Unix(),
			now.Nanosecond()/1000,
			pid,
			cachedHostname,
			counter,
		)
	}

	return fmt.Sprintf("%d.M%dP%d.%s.%x",
		now.Unix(),
		now.Nanosecond()/1000,
		pid,
		cachedHostname,
		randomBytes,
	)
}

// getHostname returns the sanitized system hostname.
func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "localhost"
	}
	return sanitizeHostname(hostname)
}

// sanitizeHostname removes or replaces characters that are problematic in filenames.
func sanitizeHostname(hostname string) string {
	// Replace slashes and colons with underscores
	hostname = strings.ReplaceAll(hostname, "/", "_")
	hostname = strings.ReplaceAll(hostname, ":", "_")
	// Remove any other potentially problematic characters
	hostname = strings.ReplaceAll(hostname, "\x00", "")
	return hostname
}
