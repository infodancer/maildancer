# Test Domains

This directory contains example domain configurations for use with `FilesystemDomainProvider` in tests.

## Structure

```
domains/
├── example.com/
│   ├── config.toml    # Domain configuration
│   ├── passwd         # User credentials (argon2id hashed)
│   ├── keys/          # User encryption keys
│   └── users/         # Per-user storage
│       ├── testuser/
│       │   └── Maildir/
│       │       ├── cur/
│       │       ├── new/
│       │       └── tmp/
│       └── admin/
│           └── Maildir/
└── test.org/
    ├── config.toml
    ├── passwd
    ├── keys/
    └── users/
        └── user1/
            └── Maildir/
```

## Test Users

| Domain       | Username  | Password  |
|--------------|-----------|-----------|
| example.com  | testuser  | testpass  |
| example.com  | admin     | testpass  |
| test.org     | user1     | testpass  |

## Usage in Tests

```go
import (
    "github.com/infodancer/maildancer/auth/domain"
    _ "github.com/infodancer/maildancer/auth/passwd"
    _ "github.com/infodancer/maildancer/msgstore/maildir"
)

func TestWithDomainProvider(t *testing.T) {
    provider := domain.NewFilesystemDomainProvider("test/domains", nil)
    defer provider.Close()

    d := provider.GetDomain("example.com")
    // Use domain...
}
```

## Configuration

The `config.toml` uses the `maildir_subdir` option to specify that each user's
Maildir is under a subdirectory:

```toml
[msgstore]
type = "maildir"
base_path = "users"

[msgstore.options]
maildir_subdir = "Maildir"
```

This results in paths like `users/testuser/Maildir/{cur,new,tmp}/`.
