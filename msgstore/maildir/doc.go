// Package maildir provides a Maildir-format message store implementation.
//
// Maildir is a widely-used format for storing email messages where each message
// is kept as a separate file. This implementation follows the Maildir specification
// with the following directory structure:
//
//	basePath/
//	└── user@example.com/
//	    ├── new/     # Newly delivered messages
//	    ├── cur/     # Messages that have been seen
//	    └── tmp/     # Temporary files during delivery
//
// The package registers itself with the msgstore registry under the name "maildir".
// Import it with a blank identifier to enable maildir support:
//
//	import _ "github.com/infodancer/maildancer/msgstore/maildir"
//
// Then open a maildir store:
//
//	store, err := msgstore.Open(msgstore.StoreConfig{
//	    Type:     "maildir",
//	    BasePath: "/var/mail",
//	})
package maildir
