module github.com/infodancer/maildancer/msgstore

go 1.24.0

toolchain go1.24.4

require (
	github.com/emersion/go-maildir v0.6.0
	github.com/infodancer/auth v0.0.0-00010101000000-000000000000
	golang.org/x/crypto v0.47.0
)

require (
	git.sr.ht/~emersion/go-sieve v0.0.0-20240926192256-cf8e1a9b5da9 // indirect
	golang.org/x/sys v0.41.0 // indirect
)

replace github.com/infodancer/auth => ../auth
