# msgstore

The shared message-storage library for maildancer. It defines the storage
interfaces every daemon depends on and ships a maildir-backed implementation.
This is a library only -- there is no `cmd/` here; the daemons import it.

## Interfaces

`msgstore` is interface-first so the backend can be swapped without touching the
daemons:

- **`DeliveryAgent`** -- delivery side, used by smtpd (via mail-deliver). Takes an
  `Envelope` + `Recipient` and writes the message.
- **`MessageStore`** -- retrieval side, used by pop3d/imapd (via mail-session) to
  list and fetch messages (`MessageInfo`).
- **`FolderStore`** -- IMAP folder management (`FolderSpec`).
- **`MsgStore`** -- the combination of delivery and retrieval.
- **`DecryptingStore` / `EncryptingDeliveryAgent`** -- the encryption wrappers:
  delivery encrypts before write, retrieval decrypts after read, so the
  underlying store only ever holds NaCl-box ciphertext.
- **`ContentSearcher` / `SieveScriptProvider`** -- optional capabilities a backend
  may implement.

## Backends

Backends register themselves and are opened by name through the registry:

```go
store, err := msgstore.Open(msgstore.StoreConfig{ /* ... */ })
// msgstore.RegisteredTypes() lists what's available
// msgstore.Register(name, factory) adds one (call from an init())
```

The bundled backend is **`maildir`** (see `maildir/`). Import it for its
registration side effect:

```go
import _ "github.com/infodancer/maildancer/msgstore/maildir"
```

## Address contract

Callers pass fully-qualified `localpart@domain` to the store. The store
normalizes internally (strips the domain, or applies its `path_template`).
Daemons must **not** pre-strip the domain or extract the localpart -- address
normalization happens once, in `auth/domain.AuthRouter`, before the address
reaches storage.

## Encryption

At-rest encryption is NaCl box (X25519 + XSalsa20-Poly1305). See
[`docs/encryption.md`](docs/encryption.md) for the key model, the passwd-line
format, and the delivery/retrieval encryption points.
