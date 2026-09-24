# golang-module-rbac

An identity and access-control control plane for Go HTTP services: password
and session authentication, API keys, role/permission authorization, MFA
(TOTP + recovery codes), WebAuthn/passkeys, Google Sign-In (OpenID Connect),
step-up re-verification, and a configurable password policy.

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
| Roles and permissions | `PermissionTable`, `Role`, `Permission` | `role.go` |
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
| Google Sign-In (OIDC) | `GoogleSSOService`, `GoogleSSOStore` | `google_sso.go` |
| Step-up re-authentication | `Authenticator.StepUp`, `StepUpStore` | `stepup.go` |
| Secret-at-rest sealing | `Sealer` (AES-GCM) | `seal.go` |
| Test fixtures | `webauthntest` package | `webauthntest/` |

## Roles and permissions

This module defines no roles or permissions of its own — `Role` and
`Permission` are plain string types, and your project names both however
fits its own domain:

```go
const (
	RoleViewer auth.Role = "viewer"
	RoleEditor auth.Role = "editor"
	RoleOwner  auth.Role = "owner"

	PermReadPost    auth.Permission = "posts:read"
	PermWritePost   auth.Permission = "posts:write"
	PermPublish     auth.Permission = "posts:publish"
	PermManageUsers auth.Permission = "users:manage"
)
```

You declare which role carries which permissions once, in a
`PermissionTable`, built at startup and passed to `NewAuthenticator`,
`NewAdmin` and `NewMFAService`:

```go
table, err := auth.NewPermissionTable(map[auth.Role][]auth.Permission{
	RoleViewer: {PermReadPost},
	RoleEditor: {PermReadPost, PermWritePost},
	RoleOwner:  {PermReadPost, PermWritePost, PermPublish, PermManageUsers},
}, PermManageUsers, RoleOwner)
```

Each role repeats what a weaker one grants rather than inheriting from it —
the duplication is the point, so the table reads top to bottom with no
inheritance chain to walk, and a permission can be given to one role alone
without anyone having to notice a weaker role's set feeds into it. Roles are
a string type, not an integer, and deliberately unordered: an integer
hierarchy invites `if role >= editor`, which silently grants every future
role inserted above that comparison point whatever it was guarding.

The last two arguments to `NewPermissionTable` name the two things this
module's own machinery depends on: `ManageUsers` is the permission that
gates `Admin`'s account-management operations (`CreateUser`, `SetRole`,
`MintAPIKey`, ...) and `MFAService.ClearFactorFor`, and the admin role is
who the last-enabled-administrator safety check protects — the one every
organization must keep at least one enabled instance of — and who
`SystemIdentity` acts as. Construction fails if the admin role doesn't
actually carry the `ManageUsers` permission in your table, since that
combination can never do anything useful.

Every authorization decision goes through `Can`, most often via the
`Identity` it was resolved against:

```go
if !actor.Can(PermPublish) {
	return auth.ErrNotPermitted
}
```

### How the table reaches `Can`

`identity.Can(perm)` takes no table argument — the table travels inside the
`Identity`, attached once by whichever `Authenticator`/`Admin`/etc. resolved
it, from the same `*PermissionTable` you built at startup. A zero-value or
never-authenticated `Identity` carries no table and so `Can` returns `false`
for everything, which is what makes a missed authentication step fail
closed rather than defaulting into whatever the first role in a table
happens to be.

Code outside this module that builds an `Identity` by hand — a login stub in
a test, a synthetic identity for a background job your application drives
itself — attaches the table explicitly:

```go
actor := auth.Identity{UserID: id, OrgID: orgID, Role: RoleEditor}.WithPermissions(table)
```

## Wiring it up

This module defines the store interfaces it needs; you provide the
persistence. A minimal wiring for sessions + password login:

```go
store := myPostgresIdentityStore{} // implements auth.Store
clock := realClock{}               // implements auth.Clock: Now() time.Time
ids := uuidGen{}                   // implements auth.IDGen: NewID() string

authenticator, err := auth.NewAuthenticator(store, clock, ids, table)
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
admin, err := auth.NewAdmin(adminStore, clock, ids, table)
...
user, err := admin.CreateUser(ctx, actor, email, name, RoleEditor, password)
```

### Store interfaces to implement

| Interface | Backs | Declared in |
|---|---|---|
| `Store` | login, session/API-key verification, logout | `store.go` |
| `AdminStore` | user CRUD, role changes, API key minting | `admin.go` |
| `PolicyStore` | per-org password policy | `policy.go` |
| `MFAStore` | TOTP enrollment, MFA tokens, recovery codes | `mfa.go` |
| `WebAuthnStore` | passkey credentials and ceremony challenges | `webauthn.go` |
| `GoogleSSOStore` | linked Google accounts and sign-in state | `google_sso.go` |
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
  bounded life no matter how actively it's used. Those are the defaults;
  `Authenticator.WithSessionLifetimes` takes a `func(User) (idle, absolute
  time.Duration)` so a deployment can give administrators a shorter idle
  window than agents. It's consulted at issue and on every touch.
- **API keys** — long-lived, minted by an admin via `Admin.MintAPIKey`, and
  clamped to at most the minting admin's own role (`PermissionTable.AtMost`)
  so an admin can never mint a key with more authority than they hold.

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

## Google Sign-In (SSO)

`GoogleSSOService` (`google_sso.go`) adds Google as an alternative to a
password, using standard OAuth 2.0 + OpenID Connect (authorization code
flow, with PKCE):

```go
google, err := auth.NewGoogleSSOService(ctx, auth.GoogleSSOConfig{
	ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
	ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
	RedirectURL:  "https://app.example.com/auth/google/callback",
	// HostedDomain: "example.com", // optional: restrict to a Workspace domain
}, googleStore, store, clock, ids)
if err != nil {
	log.Fatal(err)
}
authenticator = authenticator.WithGoogleSSO(google)
```

Two endpoints drive it:

```go
// GET /auth/google
start, err := authenticator.BeginGoogleLogin(ctx)
// redirect the browser to start.RedirectURL; remember nothing else — the
// state and PKCE verifier are already persisted by GoogleSSOStore.

// GET /auth/google/callback?state=...&code=...
result, err := authenticator.CompleteGoogleLogin(ctx, r.URL.Query().Get("state"), r.URL.Query().Get("code"))
// result.SessionToken is always set on success: set it as the session
// cookie. MFARequired() is never true here (see below).
```

A few decisions worth knowing about before wiring this in:

- **It completes the login on its own, without the account's second
  factor.** `CompleteGoogleLogin` does not consult `RequiresSecondFactor`,
  the same treatment `CompletePasswordlessLogin` gives a passkey: the
  second step already happened at Google, and a six-digit code on top of
  Google's own 2-Step Verification is a second prompt for the same proof.
  The trade is that a Google login here is as strong as the Google account.
  A deployment that wants every sign-in behind its own second factor should
  enforce 2-Step Verification at Google (a Workspace policy, which
  `HostedDomain` makes the relevant one) or not enable this.
- **It never creates an account.** The first time a Google account signs in,
  `GoogleSSOService` links it to an existing user by a Google-verified email
  match (`email_verified` must be true) and persists that link via
  `GoogleSSOStore.LinkGoogleAccount` for next time. If no account matches,
  it returns `auth.ErrGoogleAccountNotFound` rather than provisioning one —
  which organization a new user belongs to and what role they start with are
  deployment policy, the same reasoning that keeps `AdminStore.CreateUser`
  behind an authenticated, permitted actor. Handle that error by
  provisioning through `Admin.CreateUser` yourself, if self-service sign-up
  is what you want, and let the caller retry.
- **`HostedDomain`**, when set, refuses any Google account outside that
  Google Workspace domain (the ID token's `hd` claim) — useful for an
  internal tool that should only ever accept a company's own accounts.

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

The suite is self-contained — no database or network access required,
including for Google SSO: those tests run `GoogleSSOService` against a local
token endpoint and a self-signed test key pair rather than Google's own
infrastructure (`oidc.NewVerifier`'s documented pattern for this). The
`webauthntest` package provides an in-memory fake WebAuthn authenticator for
exercising registration/login ceremonies in tests without a real security
key.

## Dependencies

- `golang.org/x/crypto` — argon2id password hashing
- `github.com/go-webauthn/webauthn` — WebAuthn/passkey ceremonies
- `github.com/coreos/go-oidc/v3` + `golang.org/x/oauth2` — Google Sign-In
  (OpenID Connect discovery, token exchange, ID token verification)
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
  wire `Identity.Can` into your own router's middleware.
- **Concrete storage adapters** (Postgres, etc.) for the interfaces above.
