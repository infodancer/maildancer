package msgstore

// MsgStore combines delivery and storage operations.
// It embeds both DeliveryAgent (for smtpd message delivery) and
// MessageStore (for pop3d/imapd message retrieval).
type MsgStore interface {
	DeliveryAgent
	MessageStore
}
