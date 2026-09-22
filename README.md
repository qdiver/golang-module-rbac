# golang-module-rbac

An identity and access-control control plane for Go HTTP services: password
and session authentication, API keys, role/permission authorization, MFA
(TOTP + recovery codes), WebAuthn/passkeys, step-up re-verification, and a
configurable password policy.

It was extracted verbatim from a product's `internal/infra/auth` package, so
it ships as a working, tested unit rather than a from-scratch library. It is
deliberately ignorant of HTTP and of storage: nothing in this module reads a
cookie, writes a header, or talks to a database. You wire it to your own
router and to a persistence layer that implements this module's small store
interfaces.

## Install

```sh
go get github.com/qdiver/golang-module-rbac
```

Imported as package `auth`:

```go
import auth "github.com/qdiver/golang-module-rbac"
```

## What's in here

| Concern | Type | File |
|---|---|---|
| Roles and permissions | `Role`, `Permission`, `Role.Can` | `role.go` |
| Request identity | `Identity`, `WithIdentity`/`FromContext` | `identity.go` |
| Password hashing | `HashPassword`, `VerifyPassword` (argon2id) | `password.go` |
| Password policy | `Policy`, `Policy.Check`, `PolicyStore` | `policy.go` |
| Common-password / dictionary check | `InCommonPasswordList` | `dictionary.go` |
| Sessions & API keys | `Authenticator`, `Store` | `authenticator.go`, `store.go` |
| Bearer tokens | `NewSessionToken`, `NewAPIKey`, `HashToken` | `token.go` |
| User & role administration | `Admin`, `AdminStore` | `admin.go` |
| TOTP second factor | `MFAService`, `MFAStore`, TOTP helpers | `mfa.go`, `totp.go` |
| Recovery codes | `NewRecoveryCodes`, `NormalizeRecoveryCode` | `recovery.go` |
| WebAuthn / passkeys | `WebAuthnService`, `WebAuthnStore` | `webauthn.go` |
| Step-up re-authentication | `Authenticator.StepUp`, `StepUpStore` | `stepup.go` |
| Secret-at-rest sealing | `Sealer` (AES-GCM) | `seal.go` |
| Test fixtures | `webauthntest` package | `webauthntest/` |

## Roles and permissions

Three fixed roles — `RoleViewer`, `RoleAnalyst`, `RoleAdmin` — each mapped to
an explicit set of permissions in a table (`role.go`), not an ordered
hierarchy:

```go
const (
	PermReadReports    Permission = "reports:read"
	PermCreateReport   Permission = "reports:create"
	PermRerunReport    Permission = "reports:rerun"
	PermDeleteReport   Permission = "reports:delete"
	PermManageDisputes Permission = "disputes:manage"
	PermManageUsers    Permission = "users:manage"
)
```

Roles are a string type, not an integer, and deliberately unordered: a
hierarchy invites `if role >= Analyst`, which silently grants every future
role inserted above that comparison point whatever it was guarding. Every
authorization decision goes through `Role.Can(perm)` against the table, so
adding a role or a permission can't accidentally widen an existing check.

The permission names describe operations ("create a report"), not routes
("POST /reports"), so moving or versioning a route doesn't silently change
who may call it. The permission set above matches the product this module
was extracted from — treat it as a starting point and edit `role.go` to fit
your own domain's operations.

```go
if !actor.Can(auth.PermDeleteReport) {
	return auth.ErrNotPermitted
}
```

## Wiring it up

This module defines the store interfaces it needs; you provide the
persistence. A minimal wiring for sessions + password login:

```go
store := myPostgresIdentityStore{} // implements auth.Store
clock := realClock{}               // implements auth.Clock: Now() time.Time
ids := uuidGen{}                   // implements auth.IDGen: NewID() string

authenticator, err := auth.NewAuthenticator(store, clock, ids)
if err != nil {
	log.Fatal(err)
}

result, err := authenticator.Login(ctx, email, password)
switch {
case errors.Is(err, auth.ErrInvalidCredentials):
	// 401
case err != nil:
	// 500
case result.MFARequired():
	// prompt for the second factor, then authenticator.CompleteMFA(...)
default:
	// result.Session carries the bearer token to set as a cookie
}
```

`Authenticator` is built up with optional capabilities via `With*` methods —
`WithPasskeys`, `WithStepUp`, `WithSecondFactor`, `WithPolicies` — so a
service that doesn't need WebAuthn or MFA can skip those stores entirely.

User and role administration is a separate type, `Admin`, built from a
separate `AdminStore` interface, specifically so that request-path code
(`Authenticator`) can never reach account-management operations
(`CreateUser`, `SetRole`, `MintAPIKey`, ...) by accident — the separation is
enforced by the type system, not by convention:

```go
admin, err := auth.NewAdmin(adminStore, clock, ids)
...
user, err := admin.CreateUser(ctx, actor, email, name, auth.RoleAnalyst, password)
```

### Store interfaces to implement

| Interface | Backs | Declared in |
|---|---|---|
| `Store` | login, session/API-key verification, logout | `store.go` |
| `AdminStore` | user CRUD, role changes, API key minting | `admin.go` |
| `PolicyStore` | per-org password policy | `policy.go` |
| `MFAStore` | TOTP enrollment, MFA tokens, recovery codes | `mfa.go` |
| `WebAuthnStore` | passkey credentials and ceremony challenges | `webauthn.go` |
| `StepUpStore` | step-up timestamps | `stepup.go` |

Every lookup method is expected to return `auth.ErrNotFound` for "no live
row" — including rows that exist but are expired, revoked, or owned by a
disabled account. Filtering those states out is the store implementation's
job: this package treats "not found" and "not currently valid" as the same
thing on purpose, so a liveness decision never depends on a caller
remembering to check it.

```go
var ErrNotFound = ...  // sentinel for "no such row"
var ErrConflict = ...  // sentinel for a uniqueness violation (e.g. duplicate email)
```

These are this module's own sentinels — it has no dependency on the
consuming application's error types, so a store adapter must map its
driver-specific "no rows" error (`sql.ErrNoRows`, `pgx.ErrNoRows`, ...) to
`auth.ErrNotFound` before returning it, not to some other package's sentinel
of the same name.

### `Clock` and `IDGen`

Wall-clock time and ID generation are abstracted so use cases are
deterministic under test:

```go
type Clock interface{ Now() time.Time }
type IDGen interface{ NewID() string }
```

## Sessions and API keys

`Authenticator` issues two kinds of bearer credential, both stored only as a
salted hash (`token.go`):

- **Sessions** — cookie-carried, with an idle timeout and a hard absolute
  ceiling (`IdleTimeout`, `AbsoluteTimeout` in `authenticator.go`), so a
  forgotten tab on a shared machine times out and a stolen cookie has a
  bounded life no matter how actively it's used.
- **API keys** — long-lived, minted by an admin via `Admin.MintAPIKey`, and
  clamped to at most the minting admin's own role (`Role.AtMost`) so an
  admin can never mint a key with more authority than they hold.

## MFA and passkeys

- `MFAService` (`mfa.go`) enrolls and verifies a TOTP second factor
  (`totp.go`), issues one-time recovery codes (`recovery.go`), and seals the
  TOTP secret at rest via `Sealer` (`seal.go`, AES-GCM).
- `WebAuthnService` (`webauthn.go`) wraps `github.com/go-webauthn/webauthn`
  for passkey/security-key registration and login, including a
  passwordless flow and step-up re-verification with a passkey.
- `Authenticator.StepUp` (`stepup.go`) re-verifies a live session's owner —
  by password or by passkey — for actions that shouldn't ride on however
  old the session already is.

## Password policy

`Policy` (`policy.go`) is a per-organization, data-driven set of rules
(minimum length, character classes, history/reuse, common-password and
personal-detail dictionary checks, maximum age) rather than constants baked
into the code, so an operator can tighten or loosen it without a deploy.
`policy.Check(password, personalDetails...)` returns a `*PolicyError`
carrying every violated rule, not just the first one.

## Testing

```sh
go test ./...
```

The suite is self-contained — no database or network access required. The
`webauthntest` package provides an in-memory fake WebAuthn authenticator for
exercising registration/login ceremonies in tests without a real security
key.

## Dependencies

- `golang.org/x/crypto` — argon2id password hashing
- `github.com/go-webauthn/webauthn` — WebAuthn/passkey ceremonies
- `github.com/pquerna/otp` — TOTP
- `github.com/stretchr/testify` — test assertions
- `github.com/fxamacker/cbor/v2` — used by the `webauthntest` fixture

Nothing here pulls in an HTTP router or a database driver — those belong to
the application wiring this module in.

## What this module deliberately doesn't include

- **HTTP enforcement** (middleware that reads a request's credential,
  resolves it to an `Identity`, and denies a route the caller's role can't
  reach). That pattern is generic enough to reuse, but the concrete
  route-to-permission table is application policy, not library code —
  wire `Role.Can` / `Identity.Can` into your own router's middleware.
- **Concrete storage adapters** (Postgres, etc.) for the interfaces above.
