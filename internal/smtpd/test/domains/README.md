# Test Domains

Test domain fixtures are now generated at runtime using the `testutil` package.
This avoids storing sensitive files (passwd) in version control.

## Expected Structure

When `SetupTestDomains` creates a domain fixture, it generates:

```
<tempdir>/
├── <domain>/
│   ├── config.toml    # Domain configuration
│   ├── passwd         # User credentials (argon2id hashed)
│   ├── keys/          # User encryption keys directory
│   └── users/         # Per-user storage
│       └── <user>/
│           └── Maildir/
│               ├── cur/
│               ├── new/
│               └── tmp/
```

## Default Test Domains

The `DefaultTestDomains()` function provides these test users:

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
    "github.com/infodancer/maildancer/internal/smtpd/testutil"
)

func TestWithDomainProvider(t *testing.T) {
    // Create default test domains (example.com, test.org)
    basePath := testutil.SetupDefaultTestDomains(t)

    provider := domain.NewFilesystemDomainProvider(basePath, nil)
    defer provider.Close()

    d := provider.GetDomain("example.com")
    // Use domain...
}

func TestWithCustomDomains(t *testing.T) {
    // Create custom test domains
    domains := []testutil.TestDomain{
        {
            Name: "custom.com",
            Users: []testutil.TestUser{
                {Username: "alice", Password: "testpass"},
                {Username: "bob", Password: "testpass", Mailbox: "robert"},
            },
        },
    }
    basePath := testutil.SetupTestDomains(t, domains)

    provider := domain.NewFilesystemDomainProvider(basePath, nil)
    defer provider.Close()

    d := provider.GetDomain("custom.com")
    // Use domain...
}
```

## Configuration

Each domain's `config.toml` is generated with:

```toml
[auth]
type = "passwd"
credential_backend = "passwd"
key_backend = "keys"

[msgstore]
type = "maildir"
base_path = "users"

[msgstore.options]
maildir_subdir = "Maildir"
```

This results in paths like `users/<username>/Maildir/{cur,new,tmp}/`.

## Test Password

All default test users have the password `"testpass"`. The `testutil.TestPassword`
constant provides this value for use in authentication tests.
