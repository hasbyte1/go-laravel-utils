# hashing

Package `hashing` provides extensible, framework-agnostic password hashing modelled
after Laravel's `Illuminate/Hashing` module. Three algorithms ship out of the box:
bcrypt, Argon2i, and Argon2id.

```
go get github.com/hasbyte1/go-laravel-utils/hashing
```

---

## Table of contents

1. [Quick start](#quick-start)
2. [Drivers](#drivers)
   - [Bcrypt](#bcrypt)
   - [Argon2i](#argon2i)
   - [Argon2id (recommended)](#argon2id-recommended)
3. [Manager](#manager)
4. [Key rehash workflow](#key-rehash-workflow)
5. [Hash detection](#hash-detection)
6. [Custom drivers](#custom-drivers)
7. [PHC hash format](#phc-hash-format)
8. [Security defaults](#security-defaults)
9. [Edge cases & error handling](#edge-cases--error-handling)
10. [Porting guide](#porting-guide)
    - [Node.js / TypeScript](#nodejs--typescript)
    - [Python](#python)
11. [Laravel comparison](#laravel-comparison)

---

## Quick start

```go
import "github.com/hasbyte1/go-laravel-utils/hashing"

// Batteries-included Manager with all three drivers, Argon2id as default
m, err := hashing.NewDefaultManager()
if err != nil { log.Fatal(err) }

// Hash a password
hash, err := m.Make("my-secret-password")

// Verify
ok, err := m.Check("my-secret-password", hash)
// ok = true

ok, err = m.Check("wrong-password", hash)
// ok = false

// Check if the hash needs upgrading
needs, _ := m.NeedsRehash(hash)
// needs = false (hash already uses current defaults)
```

---

## Drivers

### Bcrypt

Uses Go's `golang.org/x/crypto/bcrypt`. Output format: `$2b$<cost>$<salt><hash>`.

```go
h, err := hashing.NewBcryptHasher(hashing.BcryptOptions{Cost: 12})

hash, _ := h.Make("password")
// $2b$12$...

ok, _ := h.Check("password", hash)  // true

needs, _ := h.NeedsRehash(hash)  // false (cost matches)

// Inspect parameters
info, _ := h.Info(hash)
// info.Driver = "bcrypt"
// info.Params["cost"] = 12
```

#### `BcryptOptions`

```go
type BcryptOptions struct {
    Cost int  // Default: 12 (OWASP minimum is 10)
}
```

```go
hashing.DefaultBcryptOptions() // BcryptOptions{Cost: 12}
```

---

### Argon2i

Uses data-independent memory access. More resistant to side-channel attacks, but
slightly more susceptible to TMTO attacks than Argon2id. Use Argon2id for new systems.

```go
h, err := hashing.NewArgon2iHasher(hashing.DefaultArgon2Options())

hash, _ := h.Make("password")
// $argon2i$v=19$m=65536,t=3,p=2$<salt>$<hash>

ok, _ := h.Check("password", hash) // true
```

---

### Argon2id (recommended)

Hybrid of Argon2i and Argon2d. Recommended by RFC 9106 and OWASP for password hashing.

```go
h, err := hashing.NewArgon2idHasher(hashing.DefaultArgon2Options())

hash, _ := h.Make("password")
// $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
```

#### `Argon2Options`

```go
type Argon2Options struct {
    Memory  uint32  // memory cost in KiB — default: 65536 (64 MiB)
    Time    uint32  // iterations — default: 3
    Threads uint8   // parallelism — default: 2
    KeyLen  uint32  // derived key length in bytes — default: 32
    SaltLen uint32  // random salt length in bytes — default: 16
}
```

```go
hashing.DefaultArgon2Options()
// Argon2Options{Memory: 65536, Time: 3, Threads: 2, KeyLen: 32, SaltLen: 16}
```

Custom options example:

```go
h, err := hashing.NewArgon2idHasher(hashing.Argon2Options{
    Memory:  128 * 1024, // 128 MiB
    Time:    4,
    Threads: 4,
    KeyLen:  32,
    SaltLen: 16,
})
```

---

## Manager

`Manager` is a thread-safe driver registry. Register named `Hasher` implementations,
designate one as the default, then dispatch all operations through the `Manager`.

```go
// Empty Manager with Argon2id as default
m := hashing.NewManager(hashing.DriverArgon2id)

// Register drivers
h, _ := hashing.NewArgon2idHasher(hashing.DefaultArgon2Options())
m.RegisterDriver(hashing.DriverArgon2id, h)

// Batteries-included convenience constructor
m, _ = hashing.NewDefaultManager()
```

### Manager methods

```go
m.Make(password string) (string, error)
m.Check(password, hash string) (bool, error)
m.CheckWithDetect(password, hash string) (bool, error)  // auto-detect driver
m.NeedsRehash(hash string) (bool, error)
m.Info(hash string) (HashInfo, error)
m.InfoWithDetect(hash string) (HashInfo, error)

m.Driver(name DriverName) (Hasher, error)
m.RegisterDriver(name DriverName, h Hasher) error
m.SetDefaultDriver(name DriverName) error
m.DefaultDriver() DriverName
m.HasDriver(name DriverName) bool
```

`CheckWithDetect` and `InfoWithDetect` automatically identify the algorithm that
produced the hash by inspecting its prefix. This is useful during migrations when
hashes from multiple algorithms coexist in the database.

---

## Key rehash workflow

On every successful login:

1. Verify the password with `m.Check` (or `m.CheckWithDetect`).
2. Call `m.NeedsRehash(storedHash)`.
3. If it returns `true`, call `m.Make(plainTextPassword)` and persist the new hash.

```go
func login(password, storedHash string, m *hashing.Manager) error {
    ok, err := m.CheckWithDetect(password, storedHash)
    if err != nil || !ok {
        return errors.New("invalid credentials")
    }

    if needs, _ := m.NeedsRehash(storedHash); needs {
        newHash, _ := m.Make(password)
        db.UpdatePasswordHash(userID, newHash) // persist in your store
    }

    return nil
}
```

`NeedsRehash` returns `true` when:
- The hash was produced by a **different** driver than the current default (e.g.,
  bcrypt hash while default is Argon2id), **or**
- The hash was produced by the same driver but with **weaker parameters** (e.g.,
  bcrypt cost 10 while current default is 12).

---

## Hash detection

`DetectDriver` inspects the hash prefix to identify the algorithm:

```go
driver, ok := hashing.DetectDriver(hash)
// "argon2id" / "argon2i" / "bcrypt" / ("", false)
```

| Prefix | Driver |
|---|---|
| `$argon2id$` | `DriverArgon2id` |
| `$argon2i$` | `DriverArgon2i` |
| `$2a$`, `$2b$`, `$2y$` | `DriverBcrypt` |

---

## Custom drivers

Implement the `Hasher` interface to plug in your own algorithm:

```go
type Hasher interface {
    Make(password string) (string, error)
    Check(password, hash string) (bool, error)
    NeedsRehash(hash string) (bool, error)
    Info(hash string) (HashInfo, error)
    Driver() DriverName
}
```

Example — scrypt wrapper:

```go
type ScryptHasher struct { N, R, P int }

func (h *ScryptHasher) Driver() hashing.DriverName { return "scrypt" }

func (h *ScryptHasher) Make(password string) (string, error) {
    salt := make([]byte, 16)
    rand.Read(salt)
    dk, _ := scrypt.Key([]byte(password), salt, h.N, h.R, h.P, 32)
    return fmt.Sprintf("$scrypt$n=%d,r=%d,p=%d$%s$%s",
        h.N, h.R, h.P,
        base64.RawStdEncoding.EncodeToString(salt),
        base64.RawStdEncoding.EncodeToString(dk),
    ), nil
}
// ... implement Check, NeedsRehash, Info

m.RegisterDriver("scrypt", &ScryptHasher{N: 32768, R: 8, P: 1})
m.SetDefaultDriver("scrypt")
```

---

## PHC hash format

Argon2 hashes use the [PHC string format](https://github.com/P-H-C/phc-string-format):

```
$argon2id$v=19$m=65536,t=3,p=2$<salt_b64>$<hash_b64>
   ^         ^   ^      ^   ^     ^            ^
   variant   ver mem    iter para base64(salt) base64(key)
```

- Base64 encoding uses the standard alphabet **without** padding (RFC 4648 §5 no `=`).
- This is compatible with Python's `passlib` (argon2-cffi) and Node.js's `argon2` npm package.
- Parameters are embedded in the hash string, so changing `Argon2Options` only affects
  newly created hashes — existing hashes remain verifiable forever.

---

## Security defaults

| Driver | Default parameter | Value | OWASP minimum |
|---|---|---|---|
| bcrypt | cost | 12 | 10 |
| Argon2i / Argon2id | memory | 64 MiB | 19 MiB (ASVS L2) |
| Argon2i / Argon2id | iterations | 3 | 2 |
| Argon2i / Argon2id | parallelism | 2 | 1 |
| Argon2i / Argon2id | key length | 32 bytes | — |
| Argon2i / Argon2id | salt length | 16 bytes | — |

All comparisons use `crypto/subtle.ConstantTimeCompare` to prevent timing attacks.

---

## Edge cases & error handling

| Error | Cause |
|---|---|
| `ErrInvalidHash` | Hash string is malformed or cannot be parsed |
| `ErrAlgorithmMismatch` | Hash prefix does not match the hasher's algorithm |
| `ErrDriverNotFound` | Named driver has not been registered in Manager |
| `ErrEmptyDriverName` | `RegisterDriver` called with empty name |
| `ErrNilHasher` | `RegisterDriver` called with a `nil` hasher |
| `ErrInvalidOption` | Argon2 parameter fails validation (e.g., time < 1) |

```go
_, err := h.Check("password", "not-a-valid-hash")
if errors.Is(err, hashing.ErrInvalidHash) {
    // handle gracefully
}
```

---

## Porting guide

### Node.js / TypeScript

```typescript
// hashing.ts — Argon2id + bcrypt manager port
import argon2 from "argon2";   // npm install argon2
import bcrypt from "bcrypt";   // npm install bcrypt

type DriverName = "argon2id" | "bcrypt";

interface Hasher {
  make(password: string): Promise<string>;
  check(password: string, hash: string): Promise<boolean>;
  needsRehash(hash: string): boolean;
}

class Argon2idHasher implements Hasher {
  constructor(
    private opts = { memoryCost: 65536, timeCost: 3, parallelism: 2 }
  ) {}

  async make(password: string): Promise<string> {
    return argon2.hash(password, { type: argon2.argon2id, ...this.opts });
  }

  async check(password: string, hash: string): Promise<boolean> {
    return argon2.verify(hash, password);
  }

  needsRehash(hash: string): boolean {
    return argon2.needsRehash(hash, { type: argon2.argon2id, ...this.opts });
  }
}

class BcryptHasher implements Hasher {
  constructor(private rounds = 12) {}

  async make(password: string): Promise<string> {
    return bcrypt.hash(password, this.rounds);
  }

  async check(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  needsRehash(hash: string): boolean {
    return bcrypt.getRounds(hash) < this.rounds;
  }
}

class HashManager {
  private drivers = new Map<DriverName, Hasher>();
  private defaultDriver: DriverName;

  constructor(defaultDriver: DriverName) {
    this.defaultDriver = defaultDriver;
  }

  register(name: DriverName, hasher: Hasher): this {
    this.drivers.set(name, hasher);
    return this;
  }

  async make(password: string): Promise<string> {
    return this.drivers.get(this.defaultDriver)!.make(password);
  }

  async check(password: string, hash: string): Promise<boolean> {
    return this.drivers.get(this.defaultDriver)!.check(password, hash);
  }

  needsRehash(hash: string): boolean {
    return this.drivers.get(this.defaultDriver)!.needsRehash(hash);
  }
}

// Usage
const manager = new HashManager("argon2id")
  .register("argon2id", new Argon2idHasher())
  .register("bcrypt",   new BcryptHasher(12));

const hash = await manager.make("my-password");
const ok   = await manager.check("my-password", hash); // true
```

### Python

```python
# hashing.py — Argon2id + bcrypt manager port
# pip install argon2-cffi bcrypt
from __future__ import annotations
from abc import ABC, abstractmethod

import bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError


class Hasher(ABC):
    @abstractmethod
    def make(self, password: str) -> str: ...
    @abstractmethod
    def check(self, password: str, hash: str) -> bool: ...
    @abstractmethod
    def needs_rehash(self, hash: str) -> bool: ...


class Argon2idHasher(Hasher):
    def __init__(self, time_cost=3, memory_cost=65536, parallelism=2):
        self._ph = PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
        )

    def make(self, password: str) -> str:
        return self._ph.hash(password)

    def check(self, password: str, hash: str) -> bool:
        try:
            return self._ph.verify(hash, password)
        except VerifyMismatchError:
            return False

    def needs_rehash(self, hash: str) -> bool:
        return self._ph.check_needs_rehash(hash)


class BcryptHasher(Hasher):
    def __init__(self, rounds: int = 12):
        self._rounds = rounds

    def make(self, password: str) -> str:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt(self._rounds)).decode()

    def check(self, password: str, hash: str) -> bool:
        return bcrypt.checkpw(password.encode(), hash.encode())

    def needs_rehash(self, hash: str) -> bool:
        return bcrypt.checkpw(b"", hash.encode()) and \
               bcrypt.gensalt(self._rounds).__len__() != len(hash)


class HashManager:
    def __init__(self, default: str):
        self._drivers: dict[str, Hasher] = {}
        self._default = default

    def register(self, name: str, hasher: Hasher) -> "HashManager":
        self._drivers[name] = hasher
        return self

    def make(self, password: str) -> str:
        return self._drivers[self._default].make(password)

    def check(self, password: str, hash: str) -> bool:
        return self._drivers[self._default].check(password, hash)

    def needs_rehash(self, hash: str) -> bool:
        return self._drivers[self._default].needs_rehash(hash)


# Usage
manager = (
    HashManager(default="argon2id")
    .register("argon2id", Argon2idHasher())
    .register("bcrypt", BcryptHasher(rounds=12))
)

hash_val = manager.make("my-password")
ok       = manager.check("my-password", hash_val)  # True
```

---

## Laravel comparison

| Laravel | Go |
|---|---|
| `Hash::make($password)` | `m.Make(password)` |
| `Hash::check($password, $hash)` | `m.Check(password, hash)` |
| `Hash::needsRehash($hash)` | `m.NeedsRehash(hash)` |
| `Hash::info($hash)` | `m.InfoWithDetect(hash)` |
| `config('hashing.driver')` = `"argon2id"` | `hashing.NewManager(DriverArgon2id)` |
| `config('hashing.argon')` | `hashing.Argon2Options{...}` |
| `config('hashing.bcrypt.rounds')` | `hashing.BcryptOptions{Cost: 12}` |
| `Hash::driver('bcrypt')` | `m.Driver(hashing.DriverBcrypt)` |
| Custom driver via `Hash::extend` | `m.RegisterDriver(name, hasher)` |
| `HashManager` class | `hashing.Manager` |
| `Hasher` interface | `hashing.Hasher` interface |
| PHC string `$argon2id$v=19$…` | Identical — wire-compatible |
