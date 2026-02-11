# encryption

Package `encryption` provides symmetric authenticated encryption modelled after
Laravel's `Illuminate\Encryption\Encrypter`. It supports AES-128/256 in CBC mode
(with HMAC-SHA256 authentication) and AES-128/256 in GCM mode (AEAD), and produces
payloads that are binary-compatible with Laravel's `Crypt::encrypt`.

```
go get github.com/hasbyte1/go-laravel-utils/encryption
```

---

## Table of contents

1. [Quick start](#quick-start)
2. [Ciphers](#ciphers)
3. [Key management](#key-management)
4. [CBC encryption (AES-CBC + HMAC-SHA256)](#cbc-encryption)
5. [GCM encryption (AES-GCM AEAD)](#gcm-encryption)
6. [Key rotation](#key-rotation)
7. [Interfaces](#interfaces)
8. [Payload format](#payload-format)
9. [Security notes](#security-notes)
10. [Edge cases & error handling](#edge-cases--error-handling)
11. [Porting guide](#porting-guide)
    - [Node.js / TypeScript](#nodejs--typescript)
    - [Python](#python)
12. [Laravel comparison](#laravel-comparison)

---

## Quick start

```go
import "github.com/hasbyte1/go-laravel-utils/encryption"

// 1. Generate a key
key, err := encryption.GenerateKey(encryption.AES256CBC)
if err != nil { log.Fatal(err) }

// 2. Build an encrypter
enc, err := encryption.NewEncrypter(key, encryption.AES256CBC)
if err != nil { log.Fatal(err) }

// 3. Encrypt
ciphertext, err := enc.EncryptString("hello, world")

// 4. Decrypt
plaintext, err := enc.DecryptString(ciphertext)
fmt.Println(plaintext) // hello, world
```

For AES-GCM (AEAD):

```go
key, _  := encryption.GenerateKey(encryption.AES256GCM)
enc, _  := encryption.NewGCMEncrypter(key, encryption.AES256GCM)
ct, _   := enc.EncryptString("hello")
pt, _   := enc.DecryptString(ct)
```

---

## Ciphers

| Constant | Value | Key size | Mode |
|---|---|---|---|
| `AES128CBC` | `"aes-128-cbc"` | 16 bytes | CBC + HMAC-SHA256 |
| `AES256CBC` | `"aes-256-cbc"` | 32 bytes | CBC + HMAC-SHA256 |
| `AES128GCM` | `"aes-128-gcm"` | 16 bytes | GCM (AEAD) |
| `AES256GCM` | `"aes-256-gcm"` | 32 bytes | GCM (AEAD) |

Helper functions:

```go
encryption.KeySize(encryption.AES256CBC)    // 32
encryption.IsAEAD(encryption.AES256GCM)     // true
encryption.Supported(key, encryption.AES256CBC) // true/false
encryption.ValidateCipher(encryption.AES256CBC)  // nil or error
```

---

## Key management

### `GenerateKey`

```go
func GenerateKey(c Cipher) ([]byte, error)
```

Generates a cryptographically random key of the correct length for `c`.

```go
key, err := encryption.GenerateKey(encryption.AES256CBC) // 32 random bytes
```

**Storing keys**: Base64-encode the raw bytes for configuration files or environment
variables:

```go
import "encoding/base64"

encoded := base64.StdEncoding.EncodeToString(key)
// store encoded in APP_KEY env var

decoded, _ := base64.StdEncoding.DecodeString(os.Getenv("APP_KEY"))
enc, _ := encryption.NewEncrypter(decoded, encryption.AES256CBC)
```

---

## CBC encryption

`CBCEncrypter` uses AES-CBC with PKCS#7 padding, authenticated by HMAC-SHA256.

### Constructor

```go
func NewEncrypter(key []byte, c Cipher) (*CBCEncrypter, error)
func NewEncrypterWithOptions(key []byte, c Cipher, opts ...Option) (*CBCEncrypter, error)
```

### Methods

```go
enc.Encrypt(value []byte) ([]byte, error)
enc.EncryptString(value string) (string, error)
enc.Decrypt(payload []byte) ([]byte, error)
enc.DecryptString(payload string) (string, error)
enc.GetKey() []byte
enc.GetCipher() Cipher
enc.AppearsEncrypted(payload []byte) bool  // implements PayloadInspector
```

`AppearsEncrypted` checks the structural shape without verifying the MAC or
decrypting — useful as a cheap guard before passing untrusted input to `Decrypt`.

---

## GCM encryption

`GCMEncrypter` uses AES-GCM (Galois/Counter Mode), which provides authentication
in-band via its auth tag — no separate HMAC is needed.

```go
func NewGCMEncrypter(key []byte, c Cipher) (*GCMEncrypter, error)
func NewGCMEncrypterWithOptions(key []byte, c Cipher, opts ...Option) (*GCMEncrypter, error)
```

Same method surface as `CBCEncrypter`:

```go
enc.EncryptString("secret") // → base64-JSON payload
enc.DecryptString(ct)       // → "secret"
enc.AppearsEncrypted(ct)    // true
```

**When to choose GCM over CBC:**

- GCM is slightly faster on hardware with AES-NI.
- GCM auth tags are smaller than a full HMAC-SHA256.
- CBC payloads are wire-compatible with Laravel's default `Crypt::encrypt`.
- Use CBC when you need to share encrypted values with a PHP/Laravel service.

---

## Key rotation

Provide previous keys via `WithPreviousKeys`. The primary key is tried first during
decryption; previous keys are tried in order. Previous keys are **never** used for
encryption.

```go
enc, err := encryption.NewEncrypterWithOptions(
    newKey, encryption.AES256CBC,
    encryption.WithPreviousKeys(oldKey1, oldKey2),
)

// Values encrypted with newKey or oldKey1/oldKey2 can all be decrypted.
// New encryptions always use newKey.
```

**Rotation workflow:**

1. Generate `newKey`.
2. Deploy with `WithPreviousKeys(currentKey)`.
3. Re-encrypt all stored values at your own pace.
4. Once all values are re-encrypted, remove the old key from `WithPreviousKeys`.

---

## Interfaces

### `Encrypter`

The `Encrypter` interface is the primary abstraction. Depend on it rather than on
`*CBCEncrypter` or `*GCMEncrypter` directly to make your code testable.

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

### `KeyGenerator`

```go
type KeyGenerator interface {
    GenerateKey() ([]byte, error)
}
```

Optional interface for encrypter backends that expose key generation.

### `PayloadInspector`

```go
type PayloadInspector interface {
    AppearsEncrypted(payload []byte) bool
}
```

Cheap structural check without MAC verification or decryption.

---

## Payload format

Every encrypted value is serialised as a base64-encoded JSON object. The shape is
identical to Laravel's `Crypt::encrypt` output:

```json
{
  "iv":    "<base64>",   // random IV (CBC) or nonce (GCM)
  "value": "<base64>",   // ciphertext
  "mac":   "<hex>",      // HMAC-SHA256 of base64(iv) + base64(value) — CBC only
  "tag":   "<base64>"    // AES-GCM auth tag — GCM only, omitted for CBC
}
```

This format makes it straightforward to share encrypted payloads between Go
microservices and a PHP/Laravel monolith without modification.

---

## Security notes

- **Fresh IV per call.** A unique random IV is generated for every `Encrypt` call.
  Encrypting the same plaintext twice produces different ciphertexts.
- **MAC-before-decrypt.** CBC decryption verifies the HMAC before touching the
  ciphertext, preventing padding-oracle and chosen-ciphertext attacks.
- **Constant-time comparison.** All MAC comparisons use `crypto/subtle.ConstantTimeCompare`
  to prevent timing-based MAC forgery.
- **Key isolation.** Keys are cloned on ingestion so external mutations cannot affect
  an in-use encrypter.
- **Minimum key sizes.** The constructor rejects mismatched key lengths.
- **AEAD for GCM.** GCM's in-band auth tag replaces the HMAC; the `mac` field is
  empty in GCM payloads.

---

## Edge cases & error handling

| Error | Cause |
|---|---|
| `ErrEmptyKey` | `key` slice has length 0 |
| `ErrInvalidKeyLength` | Key length does not match cipher requirement |
| `ErrUnsupportedCipher` | Unrecognised cipher string |
| `ErrInvalidPayload` | Payload is not valid base64-encoded JSON, or IV is wrong length |
| `ErrInvalidMAC` | HMAC or GCM tag verification failed (wrong key, tampered ciphertext) |
| `ErrDecryptionFailed` | AES-CBC decryption failed (e.g. bad padding) |

```go
_, err := enc.DecryptString(tampered)
if errors.Is(err, encryption.ErrInvalidMAC) {
    // payload was tampered
}
```

---

## Porting guide

### Node.js / TypeScript

```typescript
// encryption.ts — AES-256-CBC + HMAC-SHA256, Laravel-compatible
import * as crypto from "crypto";

const CIPHER = "aes-256-cbc";

function generateKey(): Buffer {
  return crypto.randomBytes(32);
}

function encrypt(plaintext: string, key: Buffer): string {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(CIPHER, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);

  const b64IV    = iv.toString("base64");
  const b64Value = ciphertext.toString("base64");

  const hmac = crypto.createHmac("sha256", key);
  hmac.update(b64IV + b64Value);
  const mac = hmac.digest("hex");

  const payload = JSON.stringify({ iv: b64IV, value: b64Value, mac });
  return Buffer.from(payload).toString("base64");
}

function decrypt(encoded: string, key: Buffer): string {
  const payload = JSON.parse(Buffer.from(encoded, "base64").toString("utf8")) as {
    iv: string; value: string; mac: string;
  };

  // Verify MAC
  const hmac = crypto.createHmac("sha256", key);
  hmac.update(payload.iv + payload.value);
  const expected = Buffer.from(hmac.digest("hex"));
  const actual   = Buffer.from(payload.mac);
  if (!crypto.timingSafeEqual(expected, actual)) throw new Error("Invalid MAC");

  const iv         = Buffer.from(payload.iv, "base64");
  const ciphertext = Buffer.from(payload.value, "base64");
  const decipher   = crypto.createDecipheriv(CIPHER, key, iv);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}

// Usage
const key = generateKey();
const ct  = encrypt("hello", key);
const pt  = decrypt(ct, key);
console.log(pt); // hello
```

### Python

```python
# encryption.py — AES-256-CBC + HMAC-SHA256, Laravel-compatible
import os, hmac, hashlib, base64, json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


def generate_key() -> bytes:
    return os.urandom(32)


def _pad(data: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()


def _unpad(data: bytes) -> bytes:
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def encrypt(plaintext: str, key: bytes) -> str:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(_pad(plaintext.encode())) + encryptor.finalize()

    b64_iv    = base64.b64encode(iv).decode()
    b64_value = base64.b64encode(ciphertext).decode()
    mac = hmac.new(key, (b64_iv + b64_value).encode(), hashlib.sha256).hexdigest()

    payload = json.dumps({"iv": b64_iv, "value": b64_value, "mac": mac})
    return base64.b64encode(payload.encode()).decode()


def decrypt(encoded: str, key: bytes) -> str:
    payload = json.loads(base64.b64decode(encoded))
    b64_iv, b64_value, stored_mac = payload["iv"], payload["value"], payload["mac"]

    # Constant-time MAC verification
    expected = hmac.new(key, (b64_iv + b64_value).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected.encode(), stored_mac.encode()):
        raise ValueError("Invalid MAC")

    iv         = base64.b64decode(b64_iv)
    ciphertext = base64.b64decode(b64_value)
    cipher     = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor  = cipher.decryptor()
    return _unpad(decryptor.update(ciphertext) + decryptor.finalize()).decode()


# Usage
key = generate_key()
ct  = encrypt("hello", key)
pt  = decrypt(ct, key)
print(pt)  # hello
```

---

## Laravel comparison

| Laravel | Go |
|---|---|
| `Crypt::encrypt($value)` | `enc.EncryptString(value)` |
| `Crypt::decrypt($payload)` | `enc.DecryptString(payload)` |
| `Crypt::encryptString($value)` | `enc.EncryptString(value)` |
| `Crypt::decryptString($payload)` | `enc.DecryptString(payload)` |
| `config('app.key')` (base64-decoded) | `key` param to `NewEncrypter` |
| `config('app.cipher')` = `"AES-256-CBC"` | `encryption.AES256CBC` |
| `Encrypter::generateKey($cipher)` | `encryption.GenerateKey(c)` |
| Previous keys array in `config/app.php` | `encryption.WithPreviousKeys(keys...)` |
| `$enc->getKey()` | `enc.GetKey()` |
| `$enc->getCipher()` | `enc.GetCipher()` |
| Payload `{iv, value, mac}` JSON | Identical — wire-compatible |
