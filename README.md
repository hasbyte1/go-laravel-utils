# go-laravel-utils

A collection of Go packages that replicate the core functionality of key
[Laravel](https://laravel.com) utilities — collections, encryption, password
hashing, and API/SPA authentication — while remaining completely framework-
and database-agnostic.

Every package follows the same design philosophy:

- **Interface-first** — depend on the interface, swap the implementation.
- **DB-agnostic** — bring your own storage; the packages provide the logic.
- **Laravel-compatible** — wire formats and API surfaces match Laravel's.
- **No magic** — pure Go with minimal external dependencies.

---

## Packages

| Package | Import path | Purpose |
|---|---|---|
| [`collections`](#collections) | `github.com/hasbyte1/go-laravel-utils/collections` | Generic, chainable `Collection[T]` type + `Map`, `GroupBy`, `Zip`, etc. |
| [`arr`](#arr) | `github.com/hasbyte1/go-laravel-utils/arr` | Standalone slice helpers and dot-notation map access |
| [`encryption`](#encryption) | `github.com/hasbyte1/go-laravel-utils/encryption` | AES-CBC / AES-GCM symmetric encryption with Laravel-compatible payloads |
| [`hashing`](#hashing) | `github.com/hasbyte1/go-laravel-utils/hashing` | Bcrypt, Argon2i, and Argon2id password hashing with a driver manager |
| [`sanctum`](#sanctum) | `github.com/hasbyte1/go-laravel-utils/sanctum` | API token and SPA cookie authentication inspired by Laravel Sanctum |
| [`sanctum/inmemory`](#sanctuminmemory) | `github.com/hasbyte1/go-laravel-utils/sanctum/inmemory` | Thread-safe in-memory reference implementation for `sanctum` interfaces |
| [`passport`](#passport) | `github.com/hasbyte1/go-laravel-utils/passport` | OAuth2/OIDC authorization server (Authorization Code + PKCE, Client Credentials, Refresh Token) inspired by Laravel Passport |
| [`passport/inmemory`](#passportinmemory) | `github.com/hasbyte1/go-laravel-utils/passport/inmemory` | Thread-safe in-memory reference implementation for `passport` storage interfaces |

---

## Requirements

- Go 1.21 or later
- [`golang.org/x/crypto`](https://pkg.go.dev/golang.org/x/crypto) — `hashing` package (bcrypt, Argon2)
- [`github.com/ory/fosite`](https://github.com/ory/fosite) — `passport` package (pulled in automatically)

---

## Installation

```bash
# Install all packages at once
go get github.com/hasbyte1/go-laravel-utils

# Or install individual packages
go get github.com/hasbyte1/go-laravel-utils/collections
go get github.com/hasbyte1/go-laravel-utils/arr
go get github.com/hasbyte1/go-laravel-utils/encryption
go get github.com/hasbyte1/go-laravel-utils/hashing
go get github.com/hasbyte1/go-laravel-utils/sanctum
go get github.com/hasbyte1/go-laravel-utils/passport
```

---

## collections

A generic, immutable-by-default `Collection[T]` type inspired by
[Laravel's Illuminate/Collections](https://github.com/laravel/framework/tree/12.x/src/Illuminate/Collections).

### Quick start

```go
import "github.com/hasbyte1/go-laravel-utils/collections"

result := collections.New(1, 2, 3, 4, 5, 6, 7, 8, 9, 10).
    Filter(func(n, _ int) bool { return n%2 == 0 }).
    SortByDesc(func(n int) float64 { return float64(n) }).
    Take(3).
    Implode(", ", strconv.Itoa) // → "10, 8, 6"
```

### Immutability

Every method returns a **new** `Collection`, leaving the original unchanged. This makes collections safe to share between goroutines and prevents accidental mutation in pipelines.

### Methods on `Collection[T]`

| Method | Description |
|---|---|
| `All() / ToSlice()` | Return a copy of the underlying slice |
| `Count()` | Number of items |
| `IsEmpty() / IsNotEmpty()` | Emptiness checks |
| `Get(i) / Has(i)` | Index-based access |
| `First(fn?) / Last(fn?)` | Get first/last (optionally filtered) |
| `FirstOrFail(fn) / LastOrFail(fn)` | Like First/Last but returns error |
| `Contains(fn)` | Predicate search |
| `Search(fn)` | Returns index or -1 |
| `Filter(fn) / Reject(fn) / Where / WhereNot` | Filtering |
| `Map(fn)` | Transform items → `Collection[any]` |
| `FlatMap(fn)` | Map + flatten → `Collection[any]` |
| `Pluck(fn)` | Extract a field → `Collection[any]` |
| `Reduce(fn, init)` | Same-type fold |
| `Unique(fn?)` | Remove duplicates |
| `Diff(other, fn) / Intersect(other, fn)` | Set operations |
| `Sort(less) / SortBy(fn) / SortByDesc(fn)` | Sorting |
| `Reverse()` | Reverse order |
| `Shuffle() / Random(n)` | Randomisation |
| `Push(...) / Prepend(...) / Append(...)` | Add items (returns new) |
| `Pop() / Shift() / Pull(i) / Forget(i)` | Remove items (returns new) |
| `Concat(other) / Merge(other)` | Concatenation |
| `Take(n) / Skip(n)` | Pagination (negative n counts from end) |
| `TakeUntil / TakeWhile / SkipUntil / SkipWhile` | Predicate-based slicing |
| `Slice(offset, length)` | Sub-slice |
| `Chunk(size)` | Split into `[][]T` |
| `Sum / Average / Min / Max` | Numeric aggregation |
| `GroupBy(fn) / KeyBy(fn)` | Grouping → `map[any]*Collection[T]` |
| `Partition(fn)` | Split into two collections |
| `Implode(sep, fn)` | Join to string |
| `Flip()` | Map value → index |
| `When / Unless / WhenEmpty / WhenNotEmpty` | Conditional pipeline |
| `Each(fn) / Tap(fn) / Dump()` | Side-effects |
| `Keys() / Values()` | Index list / clean copy |
| `ToJSON()` | JSON serialisation |
| `Macro(name, args...)` | Call a registered macro |

### Type-transforming package-level functions

Go generics don't allow methods to introduce new type parameters. Use these package-level functions when the output type differs from the input:

```go
// Map[T, U any]
doubled := collections.Map(c, func(n, _ int) string { return strconv.Itoa(n*2) })

// FlatMap[T, U any]
words := collections.FlatMap(sentences, func(s string, _ int) []string {
    return strings.Fields(s)
})

// Reduce[T, U any]
sum := collections.Reduce(c, func(acc int, n, _ int) int { return acc + n }, 0)

// Pluck[T, U any]
names := collections.Pluck(users, func(u User) string { return u.Name })

// GroupBy[T any, K comparable]
byDept := collections.GroupBy(employees, func(e Employee) string { return e.Dept })

// KeyBy[T any, K comparable]
byID := collections.KeyBy(users, func(u User) int { return u.ID })

// Zip[A, B any]
pairs := collections.Zip(keys, values) // → Collection[Pair[A, B]]

// Combine[K comparable, V any]
m, _ := collections.Combine([]string{"a", "b"}, []int{1, 2})

// Collapse[T any] / Flatten[T any]
flat := collections.Collapse(collections.New([]int{1, 2}, []int{3, 4}))

// FlattenDeep
deep := collections.FlattenDeep(nested) // recursive, Collection[any]
```

### Macros (runtime extension)

```go
// Register once (e.g. in init() or application bootstrap).
collections.RegisterMacro("evens", func(col any, _ ...any) any {
    c := col.(*collections.Collection[int])
    return c.Filter(func(n, _ int) bool { return n%2 == 0 })
})

// Call anywhere.
result, _ := collections.New(1, 2, 3, 4, 5).Macro("evens")
// result is *Collection[int]{2, 4}
```

### Portability

The Collection API maps directly to other languages:

**JavaScript (Node.js):**
```js
class Collection {
    constructor(items) { this._items = [...items]; }
    filter(fn)  { return new Collection(this._items.filter(fn)); }
    map(fn)     { return new Collection(this._items.map(fn)); }
    reduce(fn, initial) { return this._items.reduce(fn, initial); }
    first(fn)   { return fn ? this._items.find(fn) : this._items[0]; }
    // ...
}
```

**Python:**
```python
class Collection:
    def __init__(self, items): self._items = list(items)
    def filter(self, fn): return Collection(x for x in self._items if fn(x))
    def map(self, fn):    return Collection(fn(x) for x in self._items)
    def reduce(self, fn, initial):
        from functools import reduce
        return reduce(fn, self._items, initial)
    def first(self, fn=None):
        return next((x for x in self._items if fn(x)), None) if fn else self._items[0]
    # ...
```

### Directory structure

```
collections/
├── doc.go             # Package godoc
├── errors.go          # Sentinel errors
├── pair.go            # Pair[A, B] type (produced by Zip)
├── enumerable.go      # Enumerable[T] interface
├── macro.go           # RegisterMacro, HasMacro, CallMacro
├── collection.go      # Collection[T] type — all single-type methods
├── funcs.go           # Package-level type-transforming functions
├── collection_test.go # Unit tests (54 cases)
├── funcs_test.go      # Unit tests for funcs + macros (16 cases)
├── bench_test.go      # Benchmarks (10)
└── example_test.go    # Godoc examples (12)
```

---

## arr

Standalone, framework-agnostic slice helpers and dot-notation map access
functions inspired by Laravel's `Arr` facade.

### Slice helpers

```go
import "github.com/hasbyte1/go-laravel-utils/arr"

evens  := arr.Filter([]int{1,2,3,4,5}, func(n, _ int) bool { return n%2 == 0 })
chunks := arr.Chunk([]int{1,2,3,4,5}, 2)     // → [[1 2] [3 4] [5]]
names  := arr.Pluck(users, func(u User) string { return u.Name })
flat   := arr.Collapse([][]int{{1,2},{3,4}})  // → [1 2 3 4]
groups := arr.GroupBy(items, func(i Item) string { return i.Category })
keyed  := arr.KeyBy(users, func(u User) int { return u.ID })
pairs  := arr.Zip([]string{"a","b"}, []int{1,2})
unique := arr.Unique([]int{1,2,2,3,3,3})      // → [1 2 3]
sorted := arr.Sort([]int{3,1,4,1,5}, func(a,b int) bool { return a < b })
```

### Dot-notation map access

```go
m := map[string]any{
    "user": map[string]any{
        "name": "Alice",
        "address": map[string]any{"city": "London"},
    },
}

arr.Get(m, "user.address.city")          // → "London"
arr.Get(m, "missing.key", "default")     // → "default"
arr.Set(m, "user.address.postcode", "EC1")
arr.Has(m, "user.name")                  // → true
arr.HasAll(m, "user.name", "user.address.city") // → true
arr.Forget(m, "user.address.postcode")
flat := arr.Dot(m)                       // flatten to dot keys
nested := arr.Undot(flat)                // expand back
only := arr.Only(m, "user")             // keep subset
without := arr.Except(m, "user")        // remove keys
arr.Merge(dst, src)                      // deep merge
```

### Full function reference

| Function | Signature |
|---|---|
| `First` | `[T any]([]T, ...func(T) bool) (T, bool)` |
| `Last` | `[T any]([]T, ...func(T) bool) (T, bool)` |
| `Contains` | `[T any]([]T, func(T) bool) bool` |
| `ContainsValue` | `[T comparable]([]T, T) bool` |
| `IndexOf` | `[T comparable]([]T, T) int` |
| `Search` | `[T any]([]T, func(T) bool) int` |
| `Map` | `[T, U any]([]T, func(T, int) U) []U` |
| `Filter` | `[T any]([]T, func(T, int) bool) []T` |
| `Reject` | `[T any]([]T, func(T, int) bool) []T` |
| `Reduce` | `[T, U any]([]T, func(U, T, int) U, U) U` |
| `FlatMap` | `[T, U any]([]T, func(T, int) []U) []U` |
| `Pluck` | `[T, U any]([]T, func(T) U) []U` |
| `Unique` | `[T comparable]([]T) []T` |
| `UniqueBy` | `[T any, K comparable]([]T, func(T) K) []T` |
| `Diff` | `[T comparable]([]T, []T) []T` |
| `Intersect` | `[T comparable]([]T, []T) []T` |
| `Chunk` | `[T any]([]T, int) [][]T` |
| `Collapse` | `[T any]([][]T) []T` |
| `Flatten` | `(any) []any` |
| `Reverse` | `[T any]([]T) []T` |
| `Prepend` | `[T any]([]T, ...T) []T` |
| `Wrap` | `[T any](T) []T` |
| `Partition` | `[T any]([]T, func(T) bool) ([]T, []T)` |
| `Zip` | `[A, B any]([]A, []B) []Pair[A,B]` |
| `Combine` | `[K comparable, V any]([]K, []V) (map[K]V, error)` |
| `GroupBy` | `[T any, K comparable]([]T, func(T) K) map[K][]T` |
| `KeyBy` | `[T any, K comparable]([]T, func(T) K) map[K]T` |
| `Sort` | `[T any]([]T, func(T, T) bool) []T` |
| `Shuffle` | `[T any]([]T) []T` |
| `Random` | `[T any]([]T, int) []T` |
| `Sum` | `[T any]([]T, func(T) float64) float64` |
| `Min` | `[T any]([]T, func(T) float64) (T, bool)` |
| `Max` | `[T any]([]T, func(T) float64) (T, bool)` |
| `Dot` | `(map[string]any) map[string]any` |
| `Undot` | `(map[string]any) map[string]any` |
| `Get` | `(map[string]any, string, ...any) any` |
| `Set` | `(map[string]any, string, any)` |
| `Has` | `(map[string]any, string) bool` |
| `HasAll` | `(map[string]any, ...string) bool` |
| `HasAny` | `(map[string]any, ...string) bool` |
| `Forget` | `(map[string]any, string)` |
| `Only` | `(map[string]any, ...string) map[string]any` |
| `Except` | `(map[string]any, ...string) map[string]any` |
| `Merge` | `(dst, src map[string]any) map[string]any` |

### Directory structure

```
arr/
├── doc.go       # Package godoc
├── errors.go    # Internal sentinel error
├── arr.go       # Generic slice helpers
├── dot.go       # Dot-notation map functions
├── arr_test.go  # Slice helper tests (43 cases)
├── dot_test.go  # Dot notation tests (17 cases)
└── example_test.go
```

---

## encryption

Symmetric authenticated encryption modelled after
[Laravel's `Encrypter`](https://github.com/laravel/framework/blob/12.x/src/Illuminate/Encryption/Encrypter.php).
Payloads are **wire-compatible with Laravel** — a Go-encrypted value can be
decrypted by PHP and vice-versa with no additional translation.

### Supported ciphers

| Constant | OpenSSL name | Key size | Auth |
|---|---|---|---|
| `AES128CBC` | `aes-128-cbc` | 16 bytes | HMAC-SHA256 |
| `AES256CBC` | `aes-256-cbc` | 32 bytes | HMAC-SHA256 |
| `AES128GCM` | `aes-128-gcm` | 16 bytes | GCM tag (AEAD) |
| `AES256GCM` | `aes-256-gcm` | 32 bytes | GCM tag (AEAD) |

### Quick start

```go
import "github.com/hasbyte1/go-laravel-utils/encryption"

// Generate a random key.
key, err := encryption.GenerateKey(encryption.AES256CBC)

// Persist and reload the key.
encoded := encryption.EncodeKey(key)       // base64 string for storage
key, err = encryption.DecodeKey(encoded)   // restore from storage

// Create an encrypter and round-trip a value.
enc, err := encryption.NewEncrypter(key, encryption.AES256CBC)
ciphertext, _ := enc.EncryptString("Hello, World!")
plaintext,  _ := enc.DecryptString(ciphertext)
```

### AES-GCM (AEAD)

```go
enc, err := encryption.NewGCMEncrypter(key, encryption.AES256GCM)
ciphertext, _ := enc.EncryptString("Hello, World!")
plaintext,  _ := enc.DecryptString(ciphertext)
```

### Key rotation

```go
enc, err := encryption.NewEncrypterWithOptions(
    newKey, encryption.AES256CBC,
    encryption.WithPreviousKeys(oldKey1, oldKey2),
)

// All new values are encrypted with newKey.
// Values encrypted with oldKey1 or oldKey2 are still decryptable.
plaintext, _ := enc.DecryptString(legacyCiphertext)
```

### Payload format

Every encrypted value is a **base64-encoded JSON object** identical to
Laravel's:

```json
{
  "iv":    "<base64>",
  "value": "<base64 ciphertext>",
  "mac":   "<hex HMAC-SHA256>",
  "tag":   "<base64 GCM tag>"
}
```

`mac` is populated for CBC payloads; `tag` for GCM payloads.

**HMAC formula (CBC):**
```
MAC = hex( HMAC-SHA256( key, base64(IV) || base64(ciphertext) ) )
```

This matches PHP's:
```php
hash_hmac('sha256', $iv . $value, $key)  // $iv and $value are already base64
```

### Laravel interoperability

```php
// Decrypt a Go-produced payload in PHP:
$encrypter = new \Illuminate\Encryption\Encrypter($key, 'aes-256-cbc');
$plaintext = $encrypter->decryptString($goCiphertext);
```

```go
// Decrypt a Laravel-produced payload in Go:
enc, _ := encryption.NewEncrypter(key, encryption.AES256CBC)
plaintext, err := enc.DecryptString(laravelCiphertext)
```

> Laravel serialises with PHP's `serialize()` when `$serialize=true` (the
> default for `encrypt()`). Use `encryptString()` / `decryptString()` on the
> PHP side for raw strings, which matches Go's behaviour.

### `Encrypter` interface

Both `CBCEncrypter` and `GCMEncrypter` satisfy a common interface for
dependency injection:

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

### Porting to Node.js / Python

The payload format is language-agnostic. Port requirements:
1. AES-CBC or AES-GCM from the standard library
2. HMAC-SHA256 (CBC only)
3. PKCS#7 padding / unpadding (CBC only)
4. Standard base64 encode/decode
5. JSON marshal/unmarshal

**Node.js sketch (AES-256-CBC):**

```js
const crypto = require('crypto');

class CBCEncrypter {
    constructor(key) { this.key = key; }

    encrypt(plaintext) {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', this.key, iv);
        const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
        const b64iv = iv.toString('base64'), b64ct = ct.toString('base64');
        const mac = crypto.createHmac('sha256', this.key)
                          .update(b64iv + b64ct).digest('hex');
        return Buffer.from(JSON.stringify({ iv: b64iv, value: b64ct, mac }))
                     .toString('base64');
    }

    decrypt(token) {
        const p = JSON.parse(Buffer.from(token, 'base64').toString());
        const expected = crypto.createHmac('sha256', this.key)
                               .update(p.iv + p.value).digest('hex');
        if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(p.mac)))
            throw new Error('invalid MAC');
        const d = crypto.createDecipheriv('aes-256-cbc', this.key,
                                          Buffer.from(p.iv, 'base64'));
        return Buffer.concat([d.update(Buffer.from(p.value, 'base64')), d.final()]);
    }
}
```

**Python sketch (AES-256-CBC):**

```python
import base64, hashlib, hmac, json, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

class CBCEncrypter:
    def __init__(self, key: bytes):
        self.key = key

    def encrypt(self, plaintext: bytes) -> str:
        iv = os.urandom(16)
        padder = sym_padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        enc = Cipher(algorithms.AES(self.key), modes.CBC(iv)).encryptor()
        ct = enc.update(padded) + enc.finalize()
        b64iv, b64ct = base64.b64encode(iv).decode(), base64.b64encode(ct).decode()
        mac = hmac.new(self.key, (b64iv + b64ct).encode(), hashlib.sha256).hexdigest()
        return base64.b64encode(json.dumps({'iv': b64iv, 'value': b64ct, 'mac': mac}).encode()).decode()

    def decrypt(self, token: str) -> bytes:
        p = json.loads(base64.b64decode(token))
        expected = hmac.new(self.key, (p['iv'] + p['value']).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, p['mac']):
            raise ValueError('invalid MAC')
        iv, ct = base64.b64decode(p['iv']), base64.b64decode(p['value'])
        dec = Cipher(algorithms.AES(self.key), modes.CBC(iv)).decryptor()
        padded = dec.update(ct) + dec.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
```

### Security properties

| Property | Detail |
|---|---|
| Fresh IV per message | `Encrypt` generates a new random IV on every call |
| Verify before decrypt | HMAC / GCM tag is verified before any decryption work begins |
| Timing-safe comparison | `crypto/subtle.ConstantTimeCompare` for MAC checks |
| Key isolation | Keys are cloned on ingestion; external slice mutations cannot affect the encrypter |
| Key length enforcement | Constructors fail immediately on mismatched key sizes |

### Directory structure

```
encryption/
├── cipher.go          # Cipher type, key-size helpers, AEAD detection
├── errors.go          # Sentinel errors
├── interfaces.go      # Encrypter, KeyGenerator, PayloadInspector interfaces
├── key.go             # GenerateKey, EncodeKey, DecodeKey
├── padding.go         # PKCS#7 pad / unpad
├── payload.go         # Payload struct, JSON marshal / unmarshal
├── encrypter.go       # CBCEncrypter — AES-CBC + HMAC-SHA256, key rotation
├── gcm.go             # GCMEncrypter — AES-GCM AEAD
├── encrypter_test.go  # CBC unit tests (35 cases)
├── gcm_test.go        # GCM unit tests (22 cases)
├── bench_test.go      # Benchmarks (13)
├── fuzz_test.go       # Fuzz targets (4)
└── example_test.go    # Godoc examples (8)
```

---

## hashing

Secure, extensible password hashing modelled after
[Laravel's Illuminate/Hashing](https://github.com/laravel/framework/tree/12.x/src/Illuminate/Hashing).

### Algorithms

| Driver | Constant | Default parameters |
|---|---|---|
| bcrypt | `DriverBcrypt` | cost 12 |
| Argon2i | `DriverArgon2i` | m=64 MiB, t=3, p=2, key=32 B |
| Argon2id | `DriverArgon2id` (**recommended**) | m=64 MiB, t=3, p=2, key=32 B |

All defaults meet or exceed OWASP ASVS Level 2.

### Quick start

```go
import "github.com/hasbyte1/go-laravel-utils/hashing"

// Batteries-included: all three drivers, Argon2id default.
m, err := hashing.NewDefaultManager()

hash, _  := m.Make("my-secret-password")
ok, _    := m.Check("my-secret-password", hash)    // true
ok, _     = m.Check("wrong-password",     hash)    // false

// Re-hash on next login when parameters have changed.
if needs, _ := m.NeedsRehash(hash); needs {
    hash, _ = m.Make(password)
    // persist new hash
}
```

### `Hasher` interface

All drivers implement a common interface for dependency injection:

```go
type Hasher interface {
    Make(password string) (string, error)
    Check(password, hash string) (bool, error)
    NeedsRehash(hash string) (bool, error)
    Info(hash string) (HashInfo, error)
    Driver() DriverName
}
```

### Using a specific driver directly

```go
// Bcrypt with custom cost
h, err := hashing.NewBcryptHasher(hashing.BcryptOptions{Cost: 14})
hash, _ := h.Make("password")

// Argon2id with custom parameters
h, err := hashing.NewArgon2idHasher(hashing.Argon2Options{
    Memory:  128 * 1024, // 128 MiB
    Time:    4,
    Threads: 4,
    KeyLen:  32,
    SaltLen: 16,
})
```

### `HashManager` — driver registry

```go
m := hashing.NewManager(hashing.DriverArgon2id)
m.RegisterDriver(hashing.DriverBcrypt, bcryptHasher)
m.RegisterDriver(hashing.DriverArgon2id, argon2idHasher)
m.RegisterDriver("my-custom", &MyHasher{})  // custom driver

hash, _ := m.Make("password")               // uses default (Argon2id)
hash, _ = m.Driver("my-custom").Make("pw")  // explicit driver
```

### Cross-driver migration (bcrypt → Argon2id)

```go
m, _ := hashing.NewDefaultManager()
m.SetDefaultDriver(hashing.DriverArgon2id)

// On login:
ok, _ := m.CheckWithDetect(password, storedHash) // works for bcrypt or Argon2id hash
if ok {
    if needs, _ := m.NeedsRehash(storedHash); needs {
        newHash, _ := m.Make(password)
        persist(userID, newHash) // transparently upgrade to Argon2id
    }
}
```

### Hash info and driver detection

```go
// Inspect a hash without verifying it.
info, _ := m.InfoWithDetect(hash)
fmt.Println(info.Driver)            // "argon2id"
fmt.Println(info.Params["memory"])  // uint32(65536)

// Detect the driver from a hash string prefix.
driver, ok := hashing.DetectDriver(hash) // ("argon2id", true)
```

### Argon2 hash format (PHC)

Argon2 hashes use the standard
[PHC string format](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md):

```
$argon2id$v=19$m=65536,t=3,p=2$<base64-salt>$<base64-hash>
```

Parameters are self-contained in the hash string — no external state is
needed to verify a previously produced hash.

### Custom driver example

```go
type MyHasher struct{}

func (h *MyHasher) Make(password string) (string, error)      { /* ... */ }
func (h *MyHasher) Check(password, hash string) (bool, error) { /* ... */ }
func (h *MyHasher) NeedsRehash(hash string) (bool, error)     { /* ... */ }
func (h *MyHasher) Info(hash string) (hashing.HashInfo, error) { /* ... */ }
func (h *MyHasher) Driver() hashing.DriverName                { return "my-algo" }

m.RegisterDriver("my-algo", &MyHasher{})
```

### Directory structure

```
hashing/
├── hasher.go         # Hasher interface, DriverName, HashInfo, DetectDriver
├── errors.go         # Sentinel errors
├── manager.go        # Manager — driver registry and dispatcher
├── bcrypt.go         # BcryptHasher
├── argon2.go         # Argon2iHasher, Argon2idHasher, PHC encoding
├── bcrypt_test.go    # Bcrypt unit tests (18 cases)
├── argon2_test.go    # Argon2 unit tests (33 cases)
├── manager_test.go   # Manager unit tests (22 cases)
├── bench_test.go     # Benchmarks (9)
└── example_test.go   # Godoc examples (7)
```

---

## sanctum

API token and SPA cookie authentication for Go, inspired by
[Laravel Sanctum](https://laravel.com/docs/sanctum).

Completely DB-agnostic: bring your own `TokenRepository` and `UserProvider`
implementations. A thread-safe in-memory reference implementation is provided
in `sanctum/inmemory`.

### Features

| Feature | Description |
|---|---|
| **Token generation** | UUID v4 prefix + 40-byte random secret; only SHA-256(secret) stored |
| **Fast lookup** | Tokens carry an ID prefix for O(1) database retrieval |
| **Expiry** | Per-token or global default expiry; `IsExpired()` helper |
| **Abilities / scopes** | `Can`, `CanAll`, `CanAny`, wildcard `"*"` |
| **Token management** | Create, revoke (single / all), list, prune expired |
| **SPA auth** | Session-based auth via `SessionAuthenticator` interface |
| **CSRF protection** | Double-submit cookie pattern (`XSRF-TOKEN` / `X-XSRF-TOKEN`) |
| **net/http middleware** | `Authenticate`, `RequireAbilities`, `RequireAnyAbility` |
| **Customisation hooks** | `TokenValidator` for IP allow-listing, `EventListener` for observability |
| **Thread-safe** | All components safe for concurrent use |

### Quick start

```go
import (
    "github.com/hasbyte1/go-laravel-utils/sanctum"
    "github.com/hasbyte1/go-laravel-utils/sanctum/inmemory"
)

// 1. Wire up the service.
repo  := inmemory.New()           // replace with your DB implementation
users := inmemory.NewUserStore()  // replace with your user repository
svc   := sanctum.NewTokenService(repo, users, sanctum.DefaultConfig())
csrf  := sanctum.NewCSRFService(sanctum.DefaultConfig())
guard := sanctum.NewGuard(svc, csrf)

// 2. Create a token for a user.
result, err := svc.CreateToken(ctx, "user-123", sanctum.CreateTokenOptions{
    Name:      "My CLI Token",
    Abilities: []string{"servers:read", "servers:write"},
})
// result.PlainText  → send this to the user once (e.g. in an API response)
// result.Token.ID   → stored in the database

// 3. Authenticate an incoming Bearer token.
user, token, err := svc.AuthenticateToken(ctx, plainText)
if err != nil { /* ErrInvalidToken, ErrTokenExpired, ErrTokenNotFound */ }
```

### Token format

```
{uuid-v4}|{base64url(40 random bytes)}
```

Only `sha256(secret)` — the part after `|` — is stored in the database. The
full plain-text token is returned once at creation and cannot be recovered.

This mirrors Laravel Sanctum's `{id}|{plainTextToken}` format.

### Ability checking

```go
// Direct helpers
sanctum.Can(token.Abilities, "servers:read")                  // single ability
sanctum.CanAll(token.Abilities, []string{"read", "write"})    // AND
sanctum.CanAny(token.Abilities, []string{"read", "admin"})    // OR
sanctum.HasWildcard(token.Abilities)                          // has "*"
```

### net/http middleware

```go
mux := http.NewServeMux()

// Chain: authenticate → check ability → handler
protected := sanctum.Authenticate(guard)(
    sanctum.RequireAbilities("servers:write")(
        http.HandlerFunc(myHandler),
    ),
)
mux.Handle("/api/servers", protected)

// In the handler:
func myHandler(w http.ResponseWriter, r *http.Request) {
    ac := sanctum.AuthContextFromRequest(r)
    fmt.Fprintf(w, "hello %s", ac.User.GetID())
}
```

`RequireAbilities` enforces AND logic; `RequireAnyAbility` enforces OR logic.
Session-authenticated (SPA) requests bypass ability checks — they always have
full access.

### SPA authentication (cookie + CSRF)

```go
// Issue a CSRF cookie on a dedicated endpoint (e.g. GET /sanctum/csrf-cookie).
func csrfHandler(w http.ResponseWriter, r *http.Request) {
    csrf.IssueToken(w) // sets XSRF-TOKEN cookie
}

// Enable session auth on the guard.
guard := sanctum.NewGuard(svc, csrf,
    sanctum.WithSessionAuthenticator(mySessionAuth),
)

// Subsequent POST/PUT/PATCH/DELETE requests must echo the cookie value
// in the X-XSRF-TOKEN header. The guard validates this automatically.
```

### Token management

```go
// Revoke a single token (e.g. "sign out this device").
svc.RevokeToken(ctx, token.ID)

// Revoke all tokens for a user (e.g. "sign out everywhere").
svc.RevokeAllTokens(ctx, userID)

// List all tokens for a user.
tokens, _ := svc.ListTokens(ctx, userID)

// Delete expired tokens (run as a scheduled job).
n, _ := svc.PruneExpired(ctx)
```

### Customisation hooks

```go
// IP allow-listing via TokenValidator.
ipCheck := sanctum.TokenValidator(func(ctx context.Context, r *http.Request, user sanctum.User, token *sanctum.Token) error {
    if r.RemoteAddr != "10.0.0.1:*" {
        return errors.New("IP not allowed")
    }
    return nil
})

// Observability via EventListener.
logger := sanctum.EventListener(func(e sanctum.AuthEvent) {
    if e.Type == sanctum.EventFailed {
        log.Printf("auth failed: %v", e.Err)
    }
})

guard := sanctum.NewGuard(svc, csrf,
    sanctum.WithTokenValidator(ipCheck),
    sanctum.WithEventListener(logger),
)
```

### Implementing `TokenRepository`

```go
type TokenRepository interface {
    Create(ctx context.Context, token *Token) error
    FindByID(ctx context.Context, id string) (*Token, error)
    FindByHash(ctx context.Context, hash string) (*Token, error)
    UpdateLastUsedAt(ctx context.Context, id string, t time.Time) error
    Revoke(ctx context.Context, id string) error
    RevokeAll(ctx context.Context, userID string) error
    ListByUser(ctx context.Context, userID string) ([]*Token, error)
    PruneExpired(ctx context.Context) (int64, error)
}
```

Example SQL schema:

```sql
CREATE TABLE personal_access_tokens (
    id         TEXT PRIMARY KEY,
    user_id    TEXT        NOT NULL,
    name       TEXT        NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,  -- sha256 of the secret
    abilities  TEXT,                  -- JSON array, e.g. '["servers:read"]'
    created_at TIMESTAMP   NOT NULL,
    updated_at TIMESTAMP   NOT NULL,
    last_used_at TIMESTAMP,
    expires_at   TIMESTAMP,
    INDEX idx_token_hash (token_hash),
    INDEX idx_user_id    (user_id)
);
```

### Implementing `UserProvider`

```go
type UserProvider interface {
    FindByID(ctx context.Context, id string) (User, error)
}

// User is the minimal interface your user model must satisfy.
type User interface {
    GetID() string
}
```

### Directory structure

```
sanctum/
├── errors.go             # Sentinel errors
├── token.go              # Token model, NewTokenResult, generation, hashing
├── abilities.go          # Can, CanAll, CanAny, HasWildcard
├── config.go             # Config struct, DefaultConfig
├── repository.go         # TokenRepository, UserProvider, SessionAuthenticator interfaces
├── context.go            # AuthContext, WithAuthContext, AuthContextFromRequest
├── service.go            # TokenService — full token lifecycle
├── csrf.go               # CSRFService — double-submit cookie pattern
├── guard.go              # Guard — Bearer + session auth, hooks, events
├── middleware.go         # Authenticate, RequireAbilities, RequireAnyAbility
├── token_test.go         # Token unit tests (14 cases)
├── abilities_test.go     # Ability unit tests (5 cases)
├── service_test.go       # TokenService integration tests (14 cases)
├── csrf_test.go          # CSRF unit tests (10 cases)
├── guard_test.go         # Guard unit tests (12 cases)
├── middleware_test.go    # Middleware unit tests (11 cases)
└── example_test.go       # Godoc examples (8)
```

---

## sanctum/inmemory

A thread-safe in-memory implementation of `TokenRepository` and `UserProvider`
for use in **tests and prototyping**. Do not use in production.

```go
import "github.com/hasbyte1/go-laravel-utils/sanctum/inmemory"

repo  := inmemory.New()
users := inmemory.NewUserStore()
users.Add(myUser) // add a User to the store
```

All methods are safe for concurrent use. `Create` stores an independent copy
of the token to prevent external mutation of stored state.

---

## passport

An OAuth2/OIDC authorization server for Go, inspired by
[Laravel Passport](https://laravel.com/docs/passport). It wraps
[ory/fosite](https://github.com/ory/fosite) internally — consumers never
import fosite directly.

### Features

| Feature | Detail |
|---|---|
| **Grant types** | Authorization Code + PKCE (S256 enforced for public clients), Client Credentials, Refresh Token |
| **OIDC** | ID tokens (RS256), UserInfo endpoint, discovery document, JWKS endpoint |
| **DB-agnostic** | Bring your own storage; implement five small interfaces |
| **ResourceGuard** | Validate JWT access tokens in downstream services — static key or remote JWKS with cache |
| **PKCE enforcement** | S256 required for public clients; plain method disabled |
| **Replay protection** | Authorization codes are invalidated after first use; replays trigger token revocation |
| **fosite hidden** | No fosite types leak into the public API |

### Quick start

```go
import (
    "crypto/rand"
    "crypto/rsa"
    "github.com/hasbyte1/go-laravel-utils/passport"
    "github.com/hasbyte1/go-laravel-utils/passport/inmemory"
)

// 1. Generate (or load from disk) an RSA key pair.
key, _ := rsa.GenerateKey(rand.Reader, 2048)

// 2. Build your stores (use your own DB implementations; inmemory is for tests).
store := inmemory.New()
store.AddClient(&passport.OAuthClient{
    ID:           "my-app",
    SecretHash:   "$2a$10$...", // bcrypt hash of the client secret
    Name:         "My App",
    RedirectURIs: []string{"https://myapp.example.com/callback"},
    GrantTypes:   []string{"authorization_code", "refresh_token"},
    Scopes:       []string{"openid", "profile", "email"},
    Public:       false,
})

// 3. Configure the server.
cfg := passport.DefaultConfig("https://auth.example.com")
cfg.GlobalSecret = randomBytes32       // 32-byte secret from crypto/rand
cfg.LoginURL    = "https://auth.example.com/login"
cfg.ConsentURL  = "https://auth.example.com/consent"

// 4. Construct the server.
srv, err := passport.NewServer(
    cfg,
    store,       // ClientStore
    store,       // AuthorizationCodeStore
    store,       // AccessTokenStore
    store,       // RefreshTokenStore
    store,       // DeviceStore
    mySessionProvider,   // UserSessionProvider
    myConsentProvider,   // ConsentProvider
    myUserInfoProvider,  // UserInfoProvider
    myUserProvider,      // sanctum.UserProvider
    key,
)

// 5. Mount routes onto your HTTP mux.
mux := http.NewServeMux()
srv.RegisterRoutes(mux)
// Routes registered:
//   GET  /oauth/authorize
//   POST /oauth/token
//   POST /oauth/revoke
//        /oauth/userinfo          (GET + POST per RFC 9068)
//   POST /oauth/device/code       (returns 501 — device grant pending fosite update)
//   GET  /.well-known/openid-configuration
//   GET  /.well-known/jwks.json
```

### Configuration

```go
cfg := passport.DefaultConfig("https://auth.example.com")

// Required before use:
cfg.GlobalSecret = secret32Bytes   // crypto/rand, 32 bytes min
cfg.LoginURL    = "..."            // redirect when user is not logged in
cfg.ConsentURL  = "..."            // redirect when consent is not granted

// Optional overrides (defaults shown):
cfg.AccessTokenTTL  = time.Hour           // 1 h
cfg.RefreshTokenTTL = 30 * 24 * time.Hour // 30 days
cfg.AuthCodeTTL     = 10 * time.Minute    // 10 min
```

### Implementing the storage interfaces

You must implement five storage interfaces against your own database. Each
interface is intentionally small.

#### `ClientStore`

```go
type ClientStore interface {
    GetClient(ctx context.Context, id string) (*OAuthClient, error)
    // Return ErrClientNotFound when absent.
}
```

#### `AuthorizationCodeStore`

```go
type AuthorizationCodeStore interface {
    CreateAuthorizationCode(ctx context.Context, code *AuthorizationCode) error
    GetAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error)
    // Return ErrCodeNotFound when absent; ErrCodeInvalidated when Active==false.
    InvalidateAuthorizationCode(ctx context.Context, code string) error
    // Sets Active=false; record must still be returned as ErrCodeInvalidated.
    DeleteAuthorizationCode(ctx context.Context, code string) error
}
```

#### `AccessTokenStore`

```go
type AccessTokenStore interface {
    CreateAccessToken(ctx context.Context, token *AccessToken) error
    GetAccessToken(ctx context.Context, signature string) (*AccessToken, error)
    DeleteAccessToken(ctx context.Context, signature string) error
    DeleteAccessTokensBySubject(ctx context.Context, subject string) error
    // Caller-facing helper for logout/deletion flows; not called by the server.
    DeleteAccessTokensByRequestID(ctx context.Context, requestID string) error
}
```

#### `RefreshTokenStore`

```go
type RefreshTokenStore interface {
    CreateRefreshToken(ctx context.Context, token *RefreshToken) error
    GetRefreshToken(ctx context.Context, signature string) (*RefreshToken, error)
    // Return (token, ErrTokenInactive) when Active==false — record must be returned.
    DeleteRefreshToken(ctx context.Context, signature string) error
    DeleteRefreshTokensBySubject(ctx context.Context, subject string) error
    // Caller-facing helper for logout/deletion flows; not called by the server.
    RevokeRefreshTokensByRequestID(ctx context.Context, requestID string) error
    // Sets Active=false; called by the server during token rotation.
}
```

#### `DeviceStore`

```go
type DeviceStore interface {
    CreateDeviceCode(ctx context.Context, req *DeviceCode) error
    GetDeviceCode(ctx context.Context, deviceCode string) (*DeviceCode, error)
    GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error)
    UpdateDeviceCode(ctx context.Context, req *DeviceCode) error
    DeleteDeviceCode(ctx context.Context, deviceCode string) error
}
```

#### Example SQL schema

```sql
CREATE TABLE oauth_clients (
    id           TEXT PRIMARY KEY,
    secret_hash  TEXT NOT NULL,
    name         TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,  -- JSON array
    grant_types  TEXT NOT NULL,   -- JSON array
    scopes       TEXT NOT NULL,   -- JSON array
    public       BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE oauth_authorization_codes (
    code         TEXT PRIMARY KEY,
    request_id   TEXT NOT NULL,
    client_id    TEXT NOT NULL,
    user_id      TEXT NOT NULL,
    redirect_uri TEXT,
    scopes       TEXT NOT NULL,   -- JSON array
    expires_at   TIMESTAMP NOT NULL,
    active       BOOLEAN NOT NULL DEFAULT TRUE,
    session_data BLOB NOT NULL,   -- opaque, store and return unchanged
    nonce        TEXT
);

CREATE TABLE oauth_access_tokens (
    signature    TEXT PRIMARY KEY,
    request_id   TEXT NOT NULL,
    client_id    TEXT NOT NULL,
    user_id      TEXT,
    scopes       TEXT NOT NULL,
    expires_at   TIMESTAMP NOT NULL,
    session_data BLOB NOT NULL
);

CREATE TABLE oauth_refresh_tokens (
    signature    TEXT PRIMARY KEY,
    request_id   TEXT NOT NULL,
    client_id    TEXT NOT NULL,
    user_id      TEXT,
    scopes       TEXT NOT NULL,
    expires_at   TIMESTAMP NOT NULL,
    active       BOOLEAN NOT NULL DEFAULT TRUE,
    session_data BLOB NOT NULL
);
```

### Implementing the behaviour interfaces

#### `UserSessionProvider`

Resolves the currently authenticated user from an incoming HTTP request.
Used during the authorization code flow to identify who is approving the request.

```go
type UserSessionProvider interface {
    // Return (nil, nil) when no user is authenticated — the server redirects to LoginURL.
    GetUser(ctx context.Context, r *http.Request) (sanctum.User, error)
}
```

#### `ConsentProvider`

Manages user consent records so the consent screen is only shown once per
client + scope combination.

```go
type ConsentProvider interface {
    IsConsentGranted(ctx context.Context, userID, clientID string, scopes []string) (bool, error)
    SaveConsent(ctx context.Context, userID, clientID string, scopes []string) error
    RevokeConsent(ctx context.Context, userID, clientID string) error
}
```

#### `UserInfoProvider`

Returns OIDC claims for the `/oauth/userinfo` endpoint.

```go
type UserInfoProvider interface {
    // scopes is always empty in the current version — look up claims by user ID.
    GetUserInfo(ctx context.Context, user sanctum.User, scopes []string) (map[string]any, error)
}

// Example:
func (p *MyUserInfoProvider) GetUserInfo(_ context.Context, user sanctum.User, _ []string) (map[string]any, error) {
    u, err := p.db.FindUser(user.GetID())
    if err != nil {
        return nil, err
    }
    return map[string]any{
        "name":  u.Name,
        "email": u.Email,
    }, nil
}
```

### ResourceGuard — protecting downstream services

`ResourceGuard` validates JWT access tokens issued by the authorization server
in your API services, without needing access to the database.

```go
import "github.com/hasbyte1/go-laravel-utils/passport"

// Option A: static public key (key loaded from disk or shared memory).
guard := passport.NewResourceGuard("https://auth.example.com", &rsaKey.PublicKey)

// Option B: remote JWKS (fetched from /.well-known/jwks.json, cached for 1 hour).
guard := passport.NewRemoteResourceGuard(
    "https://auth.example.com",
    "https://auth.example.com/.well-known/jwks.json",
    passport.WithCacheTTL(30*time.Minute),
    passport.WithHTTPClient(myClient),
)

// Use as net/http middleware.
mux.Handle("/api/data", guard.Middleware(http.HandlerFunc(myHandler)))

// In the handler — read validated claims from context.
func myHandler(w http.ResponseWriter, r *http.Request) {
    claims := passport.ClaimsFromContext(r.Context())
    if !claims.HasScope("data:read") {
        http.Error(w, "forbidden", http.StatusForbidden)
        return
    }
    fmt.Fprintf(w, "hello %s", claims.Subject)
}

// Or validate manually without middleware.
claims, err := guard.Authenticate(r)
// errors: ErrUnauthorized, ErrInvalidToken, ErrTokenExpired
```

`TokenClaims` fields:

```go
type TokenClaims struct {
    Subject   string
    ClientID  string
    Scopes    []string
    Issuer    string
    ExpiresAt time.Time
    Extra     map[string]any // all other JWT claims
}

claims.HasScope("read", "write") // true only if both scopes are present
```

### Authorization Code flow (PKCE)

```
1. Your app redirects the user:
   GET /oauth/authorize
       ?response_type=code
       &client_id=my-app
       &redirect_uri=https://myapp.example.com/callback
       &scope=openid+profile
       &state=<random>
       &code_challenge=<base64url(sha256(verifier))>
       &code_challenge_method=S256

2. Server calls UserSessionProvider.GetUser — redirects to LoginURL if nil.

3. Server calls ConsentProvider.IsConsentGranted — redirects to ConsentURL if false.
   Your consent page calls ConsentProvider.SaveConsent, then redirects back.

4. Server redirects to redirect_uri?code=<code>&state=<state>.

5. Your app exchanges the code:
   POST /oauth/token
   Content-Type: application/x-www-form-urlencoded

   grant_type=authorization_code
   &code=<code>
   &redirect_uri=https://myapp.example.com/callback
   &client_id=my-app
   &code_verifier=<original_verifier>

6. Response:
   {
     "access_token":  "<jwt>",
     "token_type":    "bearer",
     "expires_in":    3600,
     "refresh_token": "<opaque>",
     "id_token":      "<jwt>"
   }
```

### Client Credentials flow

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=client_credentials&scope=read
```

### Refresh Token flow

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=<token>
&client_id=my-app
&client_secret=<secret>
```

### Device flow

`DeviceStore` is fully implemented and `ApproveDevice` / `DenyDevice` are
available on `Server`. The HTTP endpoint (`POST /oauth/device/code`) currently
returns 501 Not Implemented because fosite v0.49 does not ship the
`RFC8628DeviceAuthorizationGrantFactory`. Upgrade fosite to a version that
includes RFC 8628 to activate the full flow.

```go
// Approve/deny from your device verification page handler:
err := srv.ApproveDevice(ctx, userCode, loggedInUser)
err := srv.DenyDevice(ctx, userCode)
```

### Directory structure

```
passport/
├── doc.go                   # Package godoc
├── errors.go                # Sentinel errors
├── config.go                # Config, DefaultConfig
├── models.go                # OAuthClient, AuthorizationCode, AccessToken, RefreshToken, DeviceCode
├── client.go                # ClientStore interface
├── store.go                 # AuthorizationCodeStore, AccessTokenStore, RefreshTokenStore, DeviceStore
├── user.go                  # UserSessionProvider, ConsentProvider, UserInfoProvider
├── server.go                # NewServer, ApproveDevice, DenyDevice
├── handlers.go              # RegisterRoutes, HandleAuthorize, HandleToken, HandleRevoke, HandleDeviceAuthorization
├── oidc.go                  # HandleUserInfo, HandleDiscovery, HandleJWKS
├── resource.go              # ResourceGuard, NewResourceGuard, NewRemoteResourceGuard, TokenClaims, ClaimsFromContext
├── adapter.go               # internal fosite adapter (not part of public API)
├── server_test.go           # Integration tests (8 cases)
├── resource_test.go         # ResourceGuard unit tests (7 cases)
└── adapter_internal_test.go # Internal adapter regression tests (3 cases)
```

---

## passport/inmemory

Thread-safe in-memory implementations of all five passport storage interfaces
plus `UserSessionProvider` and `ConsentProvider`, for use in **tests and
prototyping**. Do not use in production.

```go
import "github.com/hasbyte1/go-laravel-utils/passport/inmemory"

store   := inmemory.New()         // implements all five storage interfaces
sessions := inmemory.NewSessionStore() // UserSessionProvider
consent  := inmemory.NewConsentStore() // ConsentProvider

// Register a client.
store.AddClient(&passport.OAuthClient{
    ID:           "test-client",
    SecretHash:   "$2a$10$...",
    GrantTypes:   []string{"authorization_code", "client_credentials"},
    Scopes:       []string{"openid", "read"},
    RedirectURIs: []string{"http://localhost/callback"},
})

// Seed a session so the authorize endpoint sees a logged-in user.
sessions.Set("session-cookie-value", myUser)
```

All methods are safe for concurrent use. Every `Get*` call returns a deep copy
of the stored record so mutations to the returned struct do not corrupt stored state.

---

## Running tests

```bash
# All packages
go test -race ./...

# Individual packages
go test -race ./collections/...
go test -race ./arr/...
go test -race ./encryption/...
go test -race ./hashing/...
go test -race ./sanctum/...
go test -race ./passport/...

# Benchmarks
go test -bench=. -benchmem ./collections/
go test -bench=. -benchmem ./encryption/
go test -bench=. -benchmem ./hashing/

# Fuzz tests (run until cancelled)
go test -fuzz=FuzzCBCEncrypt ./encryption/
go test -fuzz=FuzzCBCDecrypt ./encryption/
go test -fuzz=FuzzGCMEncrypt ./encryption/
go test -fuzz=FuzzGCMDecrypt ./encryption/
```

**Test count:**

| Package | Tests |
|---|---|
| `collections` | 70 |
| `arr` | 60 |
| `encryption` | 72 |
| `hashing` | 80 |
| `sanctum` | 66 |
| `sanctum/inmemory` | 18 |
| `passport` | 17 |
| `passport/inmemory` | 9 |
| **Total** | **392** |

---

## Security notes

### Encryption

- A unique random IV/nonce is generated for every `Encrypt` call — never reused.
- Decryption verifies the HMAC / GCM tag **before** touching the ciphertext,
  preventing padding-oracle and chosen-ciphertext attacks.
- `crypto/subtle.ConstantTimeCompare` is used for all MAC comparisons.
- Keys are cloned on ingestion; external mutations cannot affect an active encrypter.
- Constructors enforce key length and fail immediately on mismatches.

### Hashing

- All hashing defaults meet or exceed **OWASP ASVS Level 2**.
- Salts are generated internally by each algorithm — callers never manage salts.
- Bcrypt comparisons use `bcrypt.CompareHashAndPassword` which is intrinsically
  constant-time.
- Argon2 comparisons use `crypto/subtle.ConstantTimeCompare`.
- Use `NeedsRehash` on every successful login to transparently upgrade hashes
  when parameters or algorithms change.

### Sanctum

- Only `sha256(secret)` is stored — the plain-text token is irrecoverable.
- Token format includes a UUID prefix for fast database lookup without
  exposing the secret in an index.
- CSRF validation uses `crypto/subtle.ConstantTimeCompare`.
- `crypto/rand` is used for all token and CSRF secret generation.
- CSRF cookies are non-HttpOnly (so JavaScript can read them) but should
  have `Secure: true` in production (HTTPS).

### Passport

- Authorization codes are single-use; replaying an invalidated code triggers
  revocation of all associated access and refresh tokens (RFC 6749 §10.5).
- PKCE S256 is enforced for all public clients; the `plain` method is disabled.
- JWT access tokens are RS256; algorithm confusion attacks (`none`, HMAC
  downgrade) are blocked in both the server and `ResourceGuard`.
- `ResourceGuard` pins the algorithm to RS256 before signature verification.
- Concurrent JWKS refreshes are deduplicated via `singleflight` to prevent
  thundering-herd cache stampedes.
- `GlobalSecret` must be at least 32 bytes; `NewServer` fails immediately if
  shorter.

---

## Design decisions

### Why no ORM dependency?

The service and guard layers call only the repository interfaces. Users supply
their own implementation (SQL, Redis, DynamoDB, MongoDB, …) without pulling in
any ORM or query-builder. This keeps the package import graph minimal and lets
each application use its existing data layer.

### Why match Laravel's payload format exactly?

The primary goal is interoperability between Go and PHP services sharing the
same encryption key or token store. Matching the wire format means zero
translation overhead.

### Why interface-first design?

Accepting `encryption.Encrypter`, `hashing.Hasher`, or `sanctum.TokenRepository`
in function signatures rather than concrete types makes unit testing trivial
(mock the interface) and enables swapping implementations without changing
call sites.

### Why functional options (`WithPreviousKeys`, `GuardOption`)?

They allow zero-allocation configuration for the common case (no options) while
remaining extensible without breaking existing call sites — the same pattern
used by the Go standard library (`http.Server`, `sql.DB`, etc.).

---

## License

MIT
