# Encryption Design

This document describes the encryption system used by the mail server suite for at-rest message encryption.

## Overview

Messages are encrypted per-recipient before storage, ensuring that stored messages cannot be read without the recipient's private key. The system uses modern cryptographic primitives from NaCl (Networking and Cryptography library).

```
┌─────────┐                              ┌─────────┐
│  smtpd  │                              │  pop3d  │
│         │                              │         │
│ Encrypt │──── Encrypted Message ──────▶│ Decrypt │
│  with   │                              │  with   │
│ PubKey  │                              │ PrivKey │
└─────────┘                              └─────────┘
      │                                        │
      │                                        │
      ▼                                        ▼
┌─────────────────────────────────────────────────────┐
│                     msgstore                         │
│           (stores encrypted blobs only)              │
└─────────────────────────────────────────────────────┘
```

**Key principle**: msgstore never sees plaintext message content. smtpd encrypts before delivery; pop3d decrypts after retrieval.

## Algorithms

| Purpose | Algorithm | Library |
|---------|-----------|---------|
| Key exchange | X25519 (Curve25519 ECDH) | `golang.org/x/crypto/nacl/box` |
| Message encryption | XSalsa20-Poly1305 | `golang.org/x/crypto/nacl/box` |
| Key derivation (passwords) | Argon2id | `golang.org/x/crypto/argon2` |
| Private key encryption | XSalsa20-Poly1305 | `golang.org/x/crypto/nacl/secretbox` |

## Message Encryption

### Format

Encrypted messages use the following binary format:

```
┌──────────────────────┬─────────────────┬─────────────────────────────┐
│  Ephemeral Public Key │     Nonce       │         Ciphertext          │
│       (32 bytes)      │   (24 bytes)    │   (plaintext + 16 bytes)    │
└──────────────────────┴─────────────────┴─────────────────────────────┘
```

| Field | Offset | Size | Description |
|-------|--------|------|-------------|
| Ephemeral Public Key | 0 | 32 bytes | X25519 public key, generated fresh per message |
| Nonce | 32 | 24 bytes | Random nonce for XSalsa20 |
| Ciphertext | 56 | variable | Encrypted message with Poly1305 tag |

**Overhead**: 72 bytes (32 + 24 + 16) added to each message.

### Encryption Process (smtpd)

When smtpd receives a message for a recipient with encryption enabled:

1. **Retrieve recipient's public key** via `KeyProvider.GetPublicKey()`

2. **Generate ephemeral key pair**
   ```go
   ephemeralPub, ephemeralPriv := box.GenerateKey(rand.Reader)
   ```

3. **Generate random nonce**
   ```go
   var nonce [24]byte
   rand.Read(nonce[:])
   ```

4. **Encrypt with NaCl box**
   ```go
   ciphertext := box.Seal(nil, plaintext, &nonce, &recipientPubKey, ephemeralPriv)
   ```

   Internally, this:
   - Computes shared secret: `shared = X25519(ephemeralPriv, recipientPubKey)`
   - Derives symmetric key from shared secret
   - Encrypts plaintext with XSalsa20
   - Appends Poly1305 authentication tag

5. **Assemble encrypted message**
   ```go
   result := ephemeralPub || nonce || ciphertext
   ```

6. **Deliver to msgstore** with `Encryption` metadata set

### Decryption Process (pop3d)

When pop3d retrieves a message for an authenticated user:

1. **Parse encrypted message**
   ```go
   ephemeralPub := data[0:32]
   nonce := data[32:56]
   ciphertext := data[56:]
   ```

2. **Decrypt with NaCl box**
   ```go
   plaintext, ok := box.Open(nil, ciphertext, &nonce, &ephemeralPub, &userPrivKey)
   ```

   Internally, this:
   - Computes shared secret: `shared = X25519(userPrivKey, ephemeralPub)`
   - Derives same symmetric key
   - Verifies Poly1305 tag
   - Decrypts ciphertext with XSalsa20

3. **Return plaintext** to client

## Key Storage

### Public Keys

Public keys are stored in plaintext files:

```
/etc/mail/keys/
├── alice.pub    # 32-byte X25519 public key
├── bob.pub
└── charlie.pub
```

These are readable by smtpd to encrypt incoming messages.

### Private Keys

Private keys are stored encrypted with the user's password:

```
/etc/mail/keys/
├── alice.key    # Encrypted private key
├── bob.key
└── charlie.key
```

#### Encrypted Private Key Format

```
┌─────────────┬─────────────┬─────────────────────────────┐
│    Salt     │    Nonce    │   Encrypted Private Key     │
│  (32 bytes) │  (24 bytes) │       (32 + 16 bytes)       │
└─────────────┴─────────────┴─────────────────────────────┘
```

| Field | Offset | Size | Description |
|-------|--------|------|-------------|
| Salt | 0 | 32 bytes | Random salt for Argon2id |
| Nonce | 32 | 24 bytes | Random nonce for secretbox |
| Encrypted Key | 56 | 48 bytes | Private key (32) + Poly1305 tag (16) |

**Total file size**: 104 bytes

#### Key Derivation

The encryption key is derived from the user's password using Argon2id:

```go
key := argon2.IDKey(
    []byte(password),
    salt,
    time:    3,           // iterations
    memory:  64 * 1024,   // 64 MB
    threads: 4,           // parallelism
    keyLen:  32,          // output length
)
```

These parameters provide strong resistance against:
- Brute-force attacks (time cost)
- GPU/ASIC attacks (memory cost)
- Side-channel attacks (data-independent memory access)

#### Encryption/Decryption

Private keys are encrypted using NaCl secretbox:

```go
// Encryption
ciphertext := secretbox.Seal(nil, privateKey, &nonce, &derivedKey)

// Decryption
privateKey, ok := secretbox.Open(nil, ciphertext, &nonce, &derivedKey)
```

## Password File Format

The passwd file uses an htpasswd-like format with Argon2id hashes:

```
username:$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>:mailbox_path
```

| Field | Description |
|-------|-------------|
| username | Login name |
| hash | Argon2id password hash with parameters |
| mailbox_path | Path to user's mailbox (optional, defaults to username) |

### Hash Format

```
$argon2id$v=19$m=65536,t=3,p=4$<base64_salt>$<base64_hash>
```

| Parameter | Value | Meaning |
|-----------|-------|---------|
| `v` | 19 | Argon2 version |
| `m` | 65536 | Memory cost (64 MB) |
| `t` | 3 | Time cost (iterations) |
| `p` | 4 | Parallelism (threads) |
| salt | base64 | Random salt |
| hash | base64 | Password hash |

## Security Properties

### Forward Secrecy

Each message uses a fresh ephemeral key pair. If a recipient's long-term private key is compromised:

- **Past messages**: Cannot be decrypted (attacker would need the ephemeral private keys, which were never stored)
- **Future messages**: Can be decrypted until the key is rotated

### Authenticated Encryption

Poly1305 provides:
- **Integrity**: Any modification to the ciphertext is detected
- **Authenticity**: Only someone with the correct keys could have created the ciphertext

### No Nonce Reuse

Random nonces are generated for each encryption operation. With 24-byte nonces (2^192 possible values), collision probability is negligible even for extremely high message volumes.

### Password Security

Argon2id provides defense against:
- **Dictionary attacks**: High time cost
- **GPU attacks**: High memory cost forces sequential access
- **Side-channel attacks**: Data-independent memory access pattern

## Data Flow

### Incoming Message (smtpd)

```
1. Message arrives via SMTP
2. smtpd checks: Does recipient have encryption enabled?
   │
   ├─ No  → Deliver plaintext to msgstore
   │
   └─ Yes → Get recipient's public key
            Generate ephemeral key pair
            Encrypt message with NaCl box
            Deliver encrypted message to msgstore
            (with Encryption metadata)
```

### Retrieving Message (pop3d)

```
1. User authenticates with USER/PASS
2. AuthenticationAgent validates credentials
3. AuthenticationAgent decrypts user's private key using password
4. Returns AuthSession with decrypted private key
5. Session key set on DecryptingStore
6. User requests message (RETR)
7. DecryptingStore retrieves encrypted message
8. Decrypts with session key
9. Returns plaintext to user
10. On QUIT: Session key cleared from memory
```

## Activation and Per-Domain Mode

At-rest encryption is **activated by recipient key presence**, not a global
switch. The delivery pipeline (`internal/mail-session/deliver/encrypt.go`,
stage 3.5) encrypts a message iff the recipient has a public key on file; a
recipient with no key receives plaintext. Encryption happens in mail-session
after Sieve evaluation and before any write, so every delivery path -- inbox
keep, Sieve `fileinto`, redirect `:copy` -- stores the same ciphertext. (The
older "smtpd encrypts / pop3d decrypts" framing above is historical: the
protocol daemons hold no keys and no store access; encryption and decryption
both happen in mail-session, reached over gRPC.)

**Fail-closed:** a recipient who *has* a key whose bytes are unreadable or not
a valid 32-byte key causes a temporary delivery failure -- never a silent
plaintext write. A recipient with no key is the plaintext case, not a failure.

Per domain, `encryption_mode` in the domain `config.toml` controls **key
provisioning**, which is what activates encryption for new users:

```toml
# Domain config.toml
encryption_mode = "on"   # "off" (default) | "on"
```

- `off` (default): new users are not provisioned a keypair, so their mail is
  stored as plaintext.
- `on`: `userctl user add` (and the webadmin user-create path) generate an
  X25519 keypair for each new user, so their mail is encrypted at rest.

The mode governs provisioning only -- not the runtime gate -- so setting a
domain back to `off` does not remove existing users' keys or downgrade their
stored mail to plaintext. A future `escrow` mode (recoverable via an admin
recovery key) is reserved but not yet implemented.

### Retrieval (pop3d / imapd)

```toml
[auth]
type = "passwd"
credential_backend = "/etc/mail/passwd"
key_backend = "/etc/mail/keys"
```

On login, the auth backend unseals the user's private key with their password
and session-manager passes it to the per-user mail-session over an inherited
file descriptor (fd 3). mail-session wraps the store in a `DecryptingStore`
that decrypts on retrieval; the key is zeroed and released at session end.

## Implementation Files

| File | Purpose |
|------|---------|
| `msgstore/auth_agent.go` | `AuthSession`, `AuthenticationAgent`, `KeyProvider` interfaces |
| `msgstore/auth_registry.go` | Registry pattern for auth backends |
| `msgstore/encrypting_delivery.go` | `EncryptingDeliveryAgent`, `DecryptMessage()` |
| `msgstore/passwd/passwd.go` | Passwd-file authentication backend |

## Limitations and Future Work

### Current Limitations

1. **No key rotation**: Changing a user's password requires re-encrypting the private key, but existing messages remain encrypted with the old key format.

2. **Single recipient optimization**: Messages to multiple recipients with different encryption settings result in multiple deliveries.

3. **No sender authentication**: Messages are encrypted for recipients but not signed by senders.

### Future Enhancements

1. **LDAP backend**: External credential validation with local key storage
2. **Database backend**: Centralized credential and key storage
3. **Key rotation tooling**: Utilities for password changes and key rotation
4. **Message signing**: Optional sender signatures for authenticity
