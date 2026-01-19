module github.com/infodancer/maildancer/msgstore

go 1.24.0

toolchain go1.24.4

require (
	github.com/infodancer/auth v0.0.0-00010101000000-000000000000
	golang.org/x/crypto v0.47.0
)

require golang.org/x/sys v0.40.0 // indirect

replace github.com/infodancer/auth => ../auth
