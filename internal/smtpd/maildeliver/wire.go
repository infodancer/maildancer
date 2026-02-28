// Package maildeliver defines the wire protocol between smtpd and the
// mail-deliver subprocess.
package maildeliver

// Version is the current DeliverRequest wire protocol version.
const Version = 1

// DeliverRequest is the JSON envelope written to mail-deliver's stdin on the
// first line (terminated by '\n'), followed immediately by the raw RFC 5322
// message bytes until EOF.
type DeliverRequest struct {
	Version        int      `json:"version"`
	Sender         string   `json:"sender"`
	Recipients     []string `json:"recipients"`
	ReceivedTime   string   `json:"received_time,omitempty"` // RFC3339
	ClientIP       string   `json:"client_ip,omitempty"`
	ClientHostname string   `json:"client_hostname,omitempty"`
	UID            int      `json:"uid"` // setuid target; 0 = no privilege drop
	GID            int      `json:"gid"` // setgid target; 0 = no privilege drop
}
