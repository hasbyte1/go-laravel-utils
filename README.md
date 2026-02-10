# go-laravel-utils / encryption

A Go package for symmetric authenticated encryption, inspired by
[Laravel's Encrypter](https://github.com/laravel/framework/blob/12.x/src/Illuminate/Encryption/Encrypter.php).

The package produces payloads that are **wire-compatible with Laravel** (same
JSON structure, same HMAC computation, same base64 conventions), making it
straightforward to share encrypted values between Go and PHP services.

---

## Features

| Feature | Details |
|---|---|
| **AES-256-CBC** (default) | PKCS#7 padding + HMAC-SHA256 authentication |
| **AES-128-CBC** | Same as above with a 128-bit key |
| **AES-256-GCM** | AEAD — authentication built-in, no separate HMAC |
| **AES-128-GCM** | Same as above with a 128-bit key |
| **Key rotation** | Register previous keys; primary key always used for encryption |
| **Interface-based** | Swap CBC for GCM (or a custom backend) without changing application code |
| **Zero extra dependencies** | Only Go's standard `crypto` library |
| **Laravel-compatible payload** | Decrypt Go-encrypted values in PHP and vice-versa |

---

## Requirements

- Go 1.21 or later
- No external dependencies

---

## Installation

```bash
go get github.com/hasbyte1/go-laravel-utils/encryption
```

---

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    "github.com/hasbyte1/go-laravel-utils/encryption"
)

func main() {
    // 1. Generate a random 32-byte key for AES-256-CBC.
    key, err := encryption.GenerateKey(encryption.AES256CBC)
    if err != nil {
        log.Fatal(err)
    }

    // 2. Persist the key (e.g. in APP_KEY environment variable).
    encoded := encryption.EncodeKey(key)
    fmt.Println("APP_KEY =", encoded)

    // 3. Later, restore and use it.
    key, _ = encryption.DecodeKey(encoded)
    enc, _ := encryption.NewEncrypter(key, encryption.AES256CBC)

    ciphertext, _ := enc.EncryptString("Hello, World!")
    plaintext,  _ := enc.DecryptString(ciphertext)
    fmt.Println(plaintext) // Hello, World!
}
```

---

## API Reference

### Constructors

```go
// AES-CBC (with HMAC-SHA256)
enc, err := encryption.NewEncrypter(key, encryption.AES256CBC)
enc, err := encryption.NewEncrypterWithOptions(key, encryption.AES256CBC,
    encryption.WithPreviousKeys(oldKey1, oldKey2),
)

// AES-GCM (AEAD)
enc, err := encryption.NewGCMEncrypter(key, encryption.AES256GCM)
enc, err := encryption.NewGCMEncrypterWithOptions(key, encryption.AES256GCM,
    encryption.WithPreviousKeys(oldKey),
)
```

### Supported Ciphers

| Constant | Value | Key Size |
|---|---|---|
| `AES128CBC` | `"aes-128-cbc"` | 16 bytes |
| `AES256CBC` | `"aes-256-cbc"` | 32 bytes |
| `AES128GCM` | `"aes-128-gcm"` | 16 bytes |
| `AES256GCM` | `"aes-256-gcm"` | 32 bytes |

### Encrypter Interface

Both `CBCEncrypter` and `GCMEncrypter` satisfy the `Encrypter` interface:

```go
type Encrypter interface {
    Encrypt(value []byte) ([]byte, error)
    EncryptString(value string) (string, error)
    Decrypt(payload []byte) ([]byte, error)
    DecryptString(payload string) (string, error)
    GetKey() []byte
    GetCipher() Cipher
}
```

This enables dependency injection: accept an `encryption.Encrypter` in your
functions and swap the concrete type in tests or configuration.

### Key Management

```go
// Generate a new random key.
key, err := encryption.GenerateKey(encryption.AES256CBC)

// Encode for storage (base64).
encoded := encryption.EncodeKey(key)  // → "base64string..."

// Decode from storage.
key, err := encryption.DecodeKey(encoded)

// Check key/cipher compatibility.
ok := encryption.Supported(key, encryption.AES256CBC) // → true/false
```

### Key Rotation

```go
enc, err := encryption.NewEncrypterWithOptions(
    newKey, encryption.AES256CBC,
    encryption.WithPreviousKeys(oldKey1, oldKey2),
)

// Encrypts with newKey.
ciphertext, _ := enc.EncryptString("new value")

// Decrypts values encrypted by newKey, oldKey1, or oldKey2.
plaintext, _ := enc.DecryptString(legacyCiphertext)
```

### Encrypting Structured Data

The package encrypts raw bytes. Use `encoding/json` (or any serialiser) to
encrypt structured values:

```go
type User struct {
    ID    int    `json:"id"`
    Email string `json:"email"`
}

user := User{ID: 42, Email: "alice@example.com"}
raw, _ := json.Marshal(user)

ciphertext, _ := enc.Encrypt(raw)

// Decrypt and unmarshal.
plainBytes, _ := enc.Decrypt(ciphertext)
var restored User
_ = json.Unmarshal(plainBytes, &restored)
```

---

## Payload Format

Every encrypted value is a **base64-encoded JSON object**:

```json
{
  "iv":    "<base64-encoded IV / nonce>",
  "value": "<base64-encoded ciphertext>",
  "mac":   "<hex HMAC-SHA256>",
  "tag":   "<base64 GCM tag>"
}
```

- **CBC payloads**: `iv`, `value`, `mac` are populated; `tag` is omitted.
- **GCM payloads**: `iv`, `value`, `tag` are populated; `mac` is `""`.

This is byte-for-byte identical to Laravel's payload format.

### HMAC Computation (CBC)

```
MAC = hex( HMAC-SHA256( key, base64(IV) || base64(ciphertext) ) )
```

Matching PHP:
```php
hash_hmac('sha256', $iv . $value, $key)  // where $iv and $value are already base64
```

---

## Laravel Interoperability

To decrypt a Go-produced CBC payload in PHP:

```php
$encrypter = new \Illuminate\Encryption\Encrypter($key, 'aes-256-cbc');
$plaintext = $encrypter->decryptString($goCiphertext);
```

To decrypt a Laravel-produced CBC payload in Go:

```go
enc, _ := encryption.NewEncrypter(key, encryption.AES256CBC)
plaintext, err := enc.DecryptString(laravelCiphertext)
```

> **Note:** Laravel serialises values with PHP's `serialize()` when `$serialize=true`
> (the default for `encrypt()`).  Use `encryptString()` / `decryptString()` on
> the PHP side for raw string values, which matches Go's behaviour exactly.

---

## Porting to Other Languages

The design is intentionally class-oriented and free of Go-specific constructs
(no goroutines, no channels, no `sync`).  The reference implementation in each
language needs only:

1. AES-CBC or AES-GCM from the standard library
2. HMAC-SHA256 (CBC only)
3. PKCS#7 padding / unpadding (CBC only)
4. Base64 encode/decode (standard alphabet)
5. JSON marshal/unmarshal

### Node.js sketch

```js
const crypto = require('crypto');

class CBCEncrypter {
    constructor(key) {
        if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error('invalid key');
        this.key = key;
    }

    encrypt(plaintext) {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', this.key, iv);
        const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
        const b64iv    = iv.toString('base64');
        const b64value = ciphertext.toString('base64');
        const mac = crypto.createHmac('sha256', this.key)
                          .update(b64iv + b64value)
                          .digest('hex');
        const payload = JSON.stringify({ iv: b64iv, value: b64value, mac });
        return Buffer.from(payload).toString('base64');
    }

    decrypt(token) {
        const payload = JSON.parse(Buffer.from(token, 'base64').toString());
        const expected = crypto.createHmac('sha256', this.key)
                               .update(payload.iv + payload.value)
                               .digest('hex');
        if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(payload.mac))) {
            throw new Error('invalid MAC');
        }
        const decipher = crypto.createDecipheriv(
            'aes-256-cbc', this.key, Buffer.from(payload.iv, 'base64'));
        return Buffer.concat([
            decipher.update(Buffer.from(payload.value, 'base64')),
            decipher.final(),
        ]);
    }
}
```

### Python sketch

```python
import base64, hashlib, hmac, json, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

class CBCEncrypter:
    def __init__(self, key: bytes):
        assert len(key) == 32, "AES-256 requires a 32-byte key"
        self.key = key

    def encrypt(self, plaintext: bytes) -> str:
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        enc = cipher.encryptor()
        ciphertext = enc.update(padded) + enc.finalize()
        b64iv    = base64.b64encode(iv).decode()
        b64value = base64.b64encode(ciphertext).decode()
        mac = hmac.new(self.key, (b64iv + b64value).encode(), hashlib.sha256).hexdigest()
        payload = json.dumps({"iv": b64iv, "value": b64value, "mac": mac})
        return base64.b64encode(payload.encode()).decode()

    def decrypt(self, token: str) -> bytes:
        payload = json.loads(base64.b64decode(token))
        expected = hmac.new(self.key,
                            (payload["iv"] + payload["value"]).encode(),
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, payload["mac"]):
            raise ValueError("invalid MAC")
        iv         = base64.b64decode(payload["iv"])
        ciphertext = base64.b64decode(payload["value"])
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        dec = cipher.decryptor()
        padded = dec.update(ciphertext) + dec.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
```

---

## Security Notes

- **Never reuse IVs.** A fresh random IV is generated for every `Encrypt` call.
- **Decrypt-then-verify is not an option.** The HMAC (CBC) or GCM tag is always
  verified before any decryption work, preventing padding-oracle and
  chosen-ciphertext attacks.
- **Constant-time MAC comparison.** `crypto/subtle.ConstantTimeCompare` is used
  to prevent timing-based MAC forgery on CBC payloads.
- **Key isolation.** Keys are cloned on ingestion; external mutations to the
  byte slice cannot affect the encrypter.
- **Key length enforcement.** Constructor calls fail immediately for mismatched
  key sizes; there is no silent truncation or zero-padding.
- **GCM nonce space.** With 96-bit random nonces the birthday probability
  becomes significant around 2^32 messages per key (~4 billion).  Rotate keys
  before reaching that threshold.
- **No serialisation.** The package does not call `serialize()` / `unserialize()`
  (as PHP does by default).  Use your own serialiser for structured data.

---

## Running Tests

```bash
# All unit tests
go test ./encryption/

# With race detector
go test -race ./encryption/

# Benchmarks
go test -bench=. -benchmem ./encryption/

# Fuzz (runs until cancelled)
go test -fuzz=FuzzCBCEncrypt  ./encryption/
go test -fuzz=FuzzCBCDecrypt  ./encryption/
go test -fuzz=FuzzGCMEncrypt  ./encryption/
go test -fuzz=FuzzGCMDecrypt  ./encryption/
```

---

## Directory Structure

```
go-laravel-utils/
├── go.mod
├── README.md
└── encryption/
    ├── cipher.go          # Cipher constants, key-size and AEAD helpers
    ├── errors.go          # Sentinel errors (ErrInvalidMAC, etc.)
    ├── interfaces.go      # Encrypter, KeyGenerator, PayloadInspector interfaces
    ├── key.go             # GenerateKey, EncodeKey, DecodeKey
    ├── padding.go         # PKCS#7 pad / unpad
    ├── payload.go         # Payload struct, marshal / unmarshal
    ├── encrypter.go       # CBCEncrypter (AES-CBC + HMAC-SHA256), Option type
    ├── gcm.go             # GCMEncrypter (AES-GCM AEAD)
    ├── encrypter_test.go  # Unit tests — CBC
    ├── gcm_test.go        # Unit tests — GCM
    ├── bench_test.go      # Benchmarks
    ├── fuzz_test.go       # Fuzz targets (Go 1.18+)
    └── example_test.go    # Godoc examples
```

---

## Design Decisions

### Why both CBC and GCM?

Laravel supports both, and each has legitimate use cases:

- **CBC + HMAC-SHA256** is the classic Encrypt-then-MAC construction and the
  most widely supported by existing infrastructure.  It is the default in
  Laravel for historical reasons.
- **AES-GCM** is faster (hardware-accelerated on modern CPUs), produces shorter
  payloads (no separate HMAC), and is preferred for new systems.

### Why identical payload to Laravel?

The primary motivation is interoperability: a Go service can safely decrypt a
value that was encrypted by a PHP/Laravel service and vice-versa, with no
additional translation layer.

### Why functional options instead of a config struct?

The `WithPreviousKeys` option is the only runtime configuration today.  A
functional option is more ergonomic for a small set of options and does not
require callers to construct an otherwise empty struct.

### Why no `io.Writer` / streaming API?

For the payload sizes typical of application-level secrets (tokens, passwords,
config values), buffering the entire plaintext in memory is the right
trade-off.  A streaming API would complicate the HMAC computation and make the
interface harder to port to other languages.

---

## License

MIT
