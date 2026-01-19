module github.com/infodancer/maildancer/internal/pop3d

go 1.24.0

toolchain go1.24.4

require (
	github.com/infodancer/maildancer/auth v0.0.0-00010101000000-000000000000
	github.com/pelletier/go-toml/v2 v2.2.4
)

require (
	github.com/infodancer/maildancer/msgstore v0.0.0-20260119190950-8397c0fa98ca // indirect
	golang.org/x/crypto v0.47.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
)

replace (
	github.com/infodancer/maildancer/auth => ../auth
	github.com/infodancer/maildancer/msgstore => ../msgstore
)
