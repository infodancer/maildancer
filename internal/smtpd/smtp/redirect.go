package smtp

import "strconv"

// RedirectError indicates the delivery was redirected to other addresses.
// Callers should re-deliver the message to the specified addresses.
type RedirectError struct {
	Addresses []string
	Temporary bool
}

func (e *RedirectError) Error() string {
	return "delivery redirected to " + strconv.Itoa(len(e.Addresses)) + " address(es)"
}
