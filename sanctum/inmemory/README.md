# sanctum/inmemory

Package `inmemory` provides thread-safe in-memory implementations of
`sanctum.TokenRepository` and `sanctum.UserProvider`. It is intended for use in
**tests** and **local prototyping** — not for production deployments.

```
go get github.com/hasbyte1/go-laravel-utils/sanctum
```

---

## Table of contents

1. [Usage](#usage)
2. [Repository](#repository)
3. [UserStore](#userstore)
4. [Full example](#full-example)
5. [Implementing a production backend](#implementing-a-production-backend)
   - [PostgreSQL (Go)](#postgresql-go)
   - [Node.js / TypeScript](#nodejs--typescript)
   - [Python](#python)

---

## Usage

```go
import (
    "github.com/hasbyte1/go-laravel-utils/sanctum"
    "github.com/hasbyte1/go-laravel-utils/sanctum/inmemory"
)

repo  := inmemory.New()           // TokenRepository
users := inmemory.NewUserStore()  // UserProvider

cfg := sanctum.DefaultConfig()
svc := sanctum.NewTokenService(repo, users, cfg)
```

---

## Repository

`Repository` is a thread-safe in-memory `TokenRepository` backed by a `map[string]*Token`
guarded by a `sync.RWMutex`.

```go
repo := inmemory.New()
```

### Methods

```go
// Create stores a new token. Returns an error if the token ID already exists.
repo.Create(ctx, token *sanctum.Token) error

// FindByID looks up a token by its UUID.
// Returns sanctum.ErrTokenNotFound when absent.
repo.FindByID(ctx, id string) (*sanctum.Token, error)

// FindByHash looks up a token by its SHA-256 secret hash.
// Returns sanctum.ErrTokenNotFound when absent.
repo.FindByHash(ctx, hash string) (*sanctum.Token, error)

// UpdateLastUsedAt records the last authentication timestamp.
repo.UpdateLastUsedAt(ctx, id string, t time.Time) error

// Revoke removes a token by ID.
// Returns sanctum.ErrTokenNotFound when absent.
repo.Revoke(ctx, id string) error

// RevokeAll removes all tokens belonging to userID.
repo.RevokeAll(ctx, userID string) error

// ListByUser returns all tokens owned by userID.
repo.ListByUser(ctx, userID string) ([]*sanctum.Token, error)

// PruneExpired deletes all tokens past their ExpiresAt and returns the count.
repo.PruneExpired(ctx) (int64, error)
```

All methods return copies of stored tokens (shallow copy with a deep-copied
`Abilities` slice) so that callers cannot mutate internal state.

---

## UserStore

`UserStore` is a thread-safe in-memory `UserProvider`.

```go
users := inmemory.NewUserStore()
```

### Methods

```go
// Add registers a user. Overwrites any existing user with the same ID.
users.Add(u sanctum.User)

// FindByID returns the user with the given ID.
// Returns (nil, nil) when not found.
users.FindByID(ctx, id string) (sanctum.User, error)
```

---

## Full example

```go
package main

import (
    "context"
    "fmt"
    "log"
    "net/http"

    "github.com/hasbyte1/go-laravel-utils/sanctum"
    "github.com/hasbyte1/go-laravel-utils/sanctum/inmemory"
)

type AppUser struct{ ID string }
func (u *AppUser) GetID() string { return u.ID }

func main() {
    ctx := context.Background()

    // Set up in-memory stores
    repo  := inmemory.New()
    users := inmemory.NewUserStore()
    users.Add(&AppUser{ID: "user-1"})

    // Create service + guard
    cfg     := sanctum.DefaultConfig()
    svc     := sanctum.NewTokenService(repo, users, cfg)
    csrfSvc := sanctum.NewCSRFService(cfg)
    guard   := sanctum.NewGuard(svc, csrfSvc)

    // Issue a token
    result, err := svc.CreateToken(ctx, "user-1", sanctum.CreateTokenOptions{
        Name:      "Test Token",
        Abilities: []string{"read"},
    })
    if err != nil { log.Fatal(err) }
    fmt.Println("token:", result.PlainText)

    // Protected route
    mux := http.NewServeMux()
    mux.Handle("/api/me",
        sanctum.Authenticate(guard)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            ac := sanctum.AuthContextFromRequest(r)
            fmt.Fprintf(w, "hello %s\n", ac.User.GetID())
        })),
    )

    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

Test with:

```bash
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/me
# hello user-1
```

---

## Implementing a production backend

Replace `inmemory.Repository` with a real database by implementing the
`sanctum.TokenRepository` interface:

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

### PostgreSQL (Go)

Suggested schema:

```sql
CREATE TABLE personal_access_tokens (
    id          UUID        PRIMARY KEY,
    user_id     TEXT        NOT NULL,
    name        TEXT        NOT NULL,
    hash        TEXT        NOT NULL UNIQUE,
    abilities   TEXT[]      NOT NULL DEFAULT '{}',
    expires_at  TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX pat_user_id    ON personal_access_tokens (user_id);
CREATE INDEX pat_hash       ON personal_access_tokens (hash);
```

Skeleton implementation with `pgx/v5`:

```go
type PGTokenRepository struct{ db *pgxpool.Pool }

func (r *PGTokenRepository) Create(ctx context.Context, t *sanctum.Token) error {
    _, err := r.db.Exec(ctx, `
        INSERT INTO personal_access_tokens
            (id, user_id, name, hash, abilities, expires_at, created_at, updated_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        t.ID, t.UserID, t.Name, t.Hash, t.Abilities, t.ExpiresAt, t.CreatedAt, t.UpdatedAt,
    )
    return err
}

func (r *PGTokenRepository) FindByID(ctx context.Context, id string) (*sanctum.Token, error) {
    row := r.db.QueryRow(ctx,
        `SELECT id,user_id,name,hash,abilities,expires_at,last_used_at,created_at,updated_at
         FROM personal_access_tokens WHERE id=$1`, id)
    t := &sanctum.Token{}
    if err := row.Scan(&t.ID, &t.UserID, &t.Name, &t.Hash, &t.Abilities,
        &t.ExpiresAt, &t.LastUsedAt, &t.CreatedAt, &t.UpdatedAt); err != nil {
        if errors.Is(err, pgx.ErrNoRows) {
            return nil, sanctum.ErrTokenNotFound
        }
        return nil, err
    }
    return t, nil
}

func (r *PGTokenRepository) FindByHash(ctx context.Context, hash string) (*sanctum.Token, error) {
    // Same as FindByID but WHERE hash=$1
    // ...
}

func (r *PGTokenRepository) UpdateLastUsedAt(ctx context.Context, id string, t time.Time) error {
    _, err := r.db.Exec(ctx,
        `UPDATE personal_access_tokens SET last_used_at=$1, updated_at=$2 WHERE id=$3`,
        t, t, id)
    return err
}

func (r *PGTokenRepository) Revoke(ctx context.Context, id string) error {
    cmd, err := r.db.Exec(ctx, `DELETE FROM personal_access_tokens WHERE id=$1`, id)
    if err != nil { return err }
    if cmd.RowsAffected() == 0 { return sanctum.ErrTokenNotFound }
    return nil
}

func (r *PGTokenRepository) RevokeAll(ctx context.Context, userID string) error {
    _, err := r.db.Exec(ctx,
        `DELETE FROM personal_access_tokens WHERE user_id=$1`, userID)
    return err
}

func (r *PGTokenRepository) ListByUser(ctx context.Context, userID string) ([]*sanctum.Token, error) {
    rows, err := r.db.Query(ctx,
        `SELECT id,user_id,name,hash,abilities,expires_at,last_used_at,created_at,updated_at
         FROM personal_access_tokens WHERE user_id=$1 ORDER BY created_at DESC`, userID)
    if err != nil { return nil, err }
    defer rows.Close()
    var tokens []*sanctum.Token
    for rows.Next() {
        t := &sanctum.Token{}
        rows.Scan(&t.ID, &t.UserID, &t.Name, &t.Hash, &t.Abilities,
            &t.ExpiresAt, &t.LastUsedAt, &t.CreatedAt, &t.UpdatedAt)
        tokens = append(tokens, t)
    }
    return tokens, rows.Err()
}

func (r *PGTokenRepository) PruneExpired(ctx context.Context) (int64, error) {
    cmd, err := r.db.Exec(ctx,
        `DELETE FROM personal_access_tokens WHERE expires_at IS NOT NULL AND expires_at < NOW()`)
    return cmd.RowsAffected(), err
}
```

### Node.js / TypeScript

```typescript
// pg-token-repository.ts — PostgreSQL implementation (node-postgres)
import { Pool } from "pg";
import { Token, ErrTokenNotFound } from "./sanctum";

export class PGTokenRepository {
  constructor(private pool: Pool) {}

  async create(token: Token): Promise<void> {
    await this.pool.query(
      `INSERT INTO personal_access_tokens
       (id,user_id,name,hash,abilities,expires_at,created_at,updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [token.id, token.userId, token.name, token.hash,
       token.abilities, token.expiresAt, token.createdAt, token.updatedAt]
    );
  }

  async findById(id: string): Promise<Token | null> {
    const { rows } = await this.pool.query(
      `SELECT * FROM personal_access_tokens WHERE id=$1`, [id]
    );
    return rows[0] ? this._row(rows[0]) : null;
  }

  async findByHash(hash: string): Promise<Token | null> {
    const { rows } = await this.pool.query(
      `SELECT * FROM personal_access_tokens WHERE hash=$1`, [hash]
    );
    return rows[0] ? this._row(rows[0]) : null;
  }

  async revoke(id: string): Promise<void> {
    const { rowCount } = await this.pool.query(
      `DELETE FROM personal_access_tokens WHERE id=$1`, [id]
    );
    if (rowCount === 0) throw new Error(ErrTokenNotFound);
  }

  async revokeAll(userId: string): Promise<void> {
    await this.pool.query(
      `DELETE FROM personal_access_tokens WHERE user_id=$1`, [userId]
    );
  }

  async pruneExpired(): Promise<number> {
    const { rowCount } = await this.pool.query(
      `DELETE FROM personal_access_tokens WHERE expires_at IS NOT NULL AND expires_at < NOW()`
    );
    return rowCount ?? 0;
  }

  private _row(r: Record<string, unknown>): Token {
    return {
      id: r.id as string, userId: r.user_id as string, name: r.name as string,
      hash: r.hash as string, abilities: r.abilities as string[],
      expiresAt: r.expires_at ? new Date(r.expires_at as string) : undefined,
    };
  }
}
```

### Python

```python
# pg_token_repository.py — PostgreSQL implementation (asyncpg)
import asyncpg
import hashlib
from dataclasses import asdict
from sanctum import Token, ErrTokenNotFound


class PGTokenRepository:
    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool

    async def create(self, token: Token) -> None:
        await self.pool.execute(
            """INSERT INTO personal_access_tokens
               (id,user_id,name,hash,abilities,expires_at,created_at,updated_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8)""",
            token.id, token.user_id, token.name, token.hash,
            token.abilities, token.expires_at, token.created_at, token.created_at,
        )

    async def find_by_id(self, id: str) -> Token | None:
        row = await self.pool.fetchrow(
            "SELECT * FROM personal_access_tokens WHERE id=$1", id
        )
        return self._from_row(row) if row else None

    async def find_by_hash(self, hash: str) -> Token | None:
        row = await self.pool.fetchrow(
            "SELECT * FROM personal_access_tokens WHERE hash=$1", hash
        )
        return self._from_row(row) if row else None

    async def revoke(self, id: str) -> None:
        result = await self.pool.execute(
            "DELETE FROM personal_access_tokens WHERE id=$1", id
        )
        if result == "DELETE 0":
            raise ValueError(ErrTokenNotFound)

    async def revoke_all(self, user_id: str) -> None:
        await self.pool.execute(
            "DELETE FROM personal_access_tokens WHERE user_id=$1", user_id
        )

    async def prune_expired(self) -> int:
        result = await self.pool.execute(
            "DELETE FROM personal_access_tokens "
            "WHERE expires_at IS NOT NULL AND expires_at < NOW()"
        )
        return int(result.split()[-1])

    def _from_row(self, row) -> Token:
        return Token(
            id=row["id"], user_id=row["user_id"], name=row["name"],
            hash=row["hash"], abilities=list(row["abilities"]),
            expires_at=row["expires_at"],
        )
```
