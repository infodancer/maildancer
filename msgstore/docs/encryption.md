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

## Threat model and scope

Be precise about what this protects against, because over-claiming is itself a
security defect.

**What at-rest encryption protects against:** disclosure of stored mail to an
attacker who obtains the *data at rest* but not live credentials or a running
session -- a stolen or improperly decommissioned disk, an exfiltrated backup or
snapshot, or filesystem access without the user's password. In those cases the
attacker holds ciphertext (and the sealed private key) but cannot derive the
key, so the mail stays confidential.

**What it does NOT protect against -- a live or compromised server.** With the
legacy protocols (SMTP, IMAP, POP3) the server is necessarily a plaintext point:

- **Inbound is cleartext to the server.** SMTP delivers the full RFC 5322
  message in the clear; smtpd itself encrypts it to the recipient's public key.
  The server has already seen the plaintext at delivery.
- **Retrieval requires the server to decrypt.** A standard IMAP/POP client has
  no cryptography; it authenticates with a password and expects plaintext
  bodies. The server must therefore be the decryption point, and it unseals the
  user's private key using the login password it receives at authentication.

So an attacker who controls the running server (root, or a TLS-terminating
position that logs credentials) can read mail -- by capturing it at delivery, by
harvesting the password at login and unsealing the key, or by reading the
decrypted session key from memory. At-rest encryption does not, and cannot,
prevent this for dumb clients. "The server cannot read your mail" is **false**
for the legacy path; the honest statement is "stored mail is protected against
disk and backup compromise."

**True opacity requires a crypto-capable client.** End-to-end confidentiality --
where the server never sees plaintext at delivery or retrieval -- is the job of
the next-gen protocol (SCMP), in which the client encrypts before handoff. The
only way to get server-opaque mail through a legacy IMAP/POP client is to move
the decryption point off the server into a client-controlled local bridge (a
loopback IMAP proxy that holds the keys and speaks SCMP upstream); that bridge
is a crypto-capable client wearing an IMAP costume, not a dumb client.

The client keyring / KEK work (see the keyring design doc) is the structural
on-ramp to that future -- it introduces a domain-separated keyring wrap-key and
a wrap-slot format that device-key and escrow slots plug into without a format
break -- but on the legacy path it does not change the scope above.

## Algorithms

| Purpose | Algorithm | Library |
|---------|-----------|---------|
| Key exchange | X25519 (Curve25519 ECDH) | `golang.org/x/crypto/nacl/box` |
| Message encryption | XSalsa20-Poly1305 | `golang.org/x/crypto/nacl/box` |
| Key derivation (passwords) | Argon2id | `golang.org/x/crypto/argon2` |
| Wrap-key domain separation | HKDF-SHA256 | `crypto/hkdf` |
| Keyring / KEK sealing | XChaCha20-Poly1305 | `golang.org/x/crypto/chacha20poly1305` |
| Private key encryption (legacy `.key`) | XSalsa20-Poly1305 | `golang.org/x/crypto/nacl/secretbox` |

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

Per-user keyrings live in the **writable data tree**, beside the user's
maildir, not in the read-only config tree (maildancer#82):

```
{data}/{domain}/users/{user}/
├── keyring.pub    # 32-byte X25519 public key (plaintext)
├── keyring.key    # sealed private key (see below)
└── Maildir/
```

The directory and both files are owned by the user's uid and the domain gid
(dir `0700`, `keyring.key` `0600`). This is what makes encryption work under
privilege separation: the delivery process runs as the recipient uid, so it
can read `keyring.pub` to encrypt incoming mail, and the login path (as root,
via session-manager) can read `keyring.key` to unseal the private key. Putting
the keyring in the config tree -- owned by a service uid and mounted read-only
-- left the delivery process unable to read the public key, so the encryption
gate saw "no key" and stored plaintext (the fail-open this layout fixes).

**Legacy fallback.** For unmigrated users, the old config-tree location
(`{config}/{domain}/keys/{user}.pub` / `.key`) is still read as a fallback.
New keys are only ever written to the data-tree keyring; provisioning a fresh
keypair (or `ResetPasswordRegenKeys`) migrates the user off the legacy path.

### Public keys

`keyring.pub` is a raw 32-byte X25519 public key in plaintext, read by the
delivery agent (running as the recipient) to encrypt incoming messages.

### Private keys

`keyring.key` holds the private key sealed under the user's password:

#### Sealed Keyring Format (current)

A `.key` file holds a **sealed keyring** (see the keyring design doc): a JSON
envelope the server stores but cannot read. The on-disk layout is owned by
`auth/keyring`; `auth/keyseal` is the single seam between key producers
(`internal/admin/keys`) and the consumer (`auth/passwd`).

```
Sealed keyring (JSON):
  version
  doc_version            # monotonic counter (compare-and-swap)
  kek_wrapped_blob       # XChaCha20-Poly1305(keyring, KEK), AAD = version||doc_version
  wrap_slots[]:          # how the KEK is unlocked
    slot_type            # passphrase | device | escrow
    slot_id
    wrapped_kek          # XChaCha20-Poly1305(KEK, slot_key), AAD = slot_id
    kdf                  # self-describing argon2id params (passphrase slots)
```

The keyring itself (decrypted only inside the client or inside mail-session) is
a *set* of entries, so rotated and archived private keys are retained and old
mail stays readable. The degenerate case written for a new user is a one-entry,
one-passphrase-slot keyring.

A random per-keyring **KEK** seals the keyring; the KEK is in turn wrapped to one
or more slots. This is what distinguishes the trust postures: passphrase/device
slots only -> the server cannot decrypt the keyring at rest; an additional
escrow slot wrapped to a domain recovery key -> the server can decrypt and must
disclose it. (Escrow activation -- recovery-key custody, the `escrow` mode, the
published disclosure flag -- is reserved but not yet implemented.)

#### Key Derivation (passphrase slot)

The passphrase slot's wrap-key is derived from the password with Argon2id, then
**domain-separated** with HKDF-SHA256 under a fixed info label so the keyring
wrap-key is structurally independent of the auth verifier:

```go
ikm := argon2.IDKey(password, salt, t=3, m=64*1024, p=4, keyLen=32)
wrapKey, _ := hkdf.Key(sha256.New, ikm, nil, "maildancer/keyring-wrap/v1", 32)
```

Caveat (see Threat model and scope): on the IMAP/POP path the server still
receives the password at login and unwraps server-side, so domain separation is
structural hygiene, not protection against a live server. Full protection needs
client-side derivation (SCMP / OPAQUE).

#### AEAD

The keyring and each wrapped KEK use XChaCha20-Poly1305 (24-byte nonces, AAD
binding) rather than NaCl secretbox, so associated data can bind `doc_version`
(rollback protection) and the slot id (a wrapped KEK cannot be moved between
slots).

#### Legacy single-key format (read-only, migrating)

Pre-keyring `.key` files used a fixed 104-byte layout:
`salt(32) || nonce(24) || secretbox.Seal(privKey)` keyed by Argon2id. `Open`
still reads this format, and such files migrate to the sealed-keyring format
opportunistically the next time they are re-sealed (a password change or key
regeneration).

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
key_backend = "/etc/mail/keys"   # legacy fallback only; new keyrings live in the data tree
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
