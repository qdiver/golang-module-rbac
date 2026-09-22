package auth

import (
	"context"
	"time"
)

// Scheme records which credential authenticated a request.
//
// It exists for the audit trail and for the operator, not for
// authorization: a session and an API key of the same role are exactly
// equal in what they may do (ADR-0027), and any code that branches on
// Scheme to decide permission is reintroducing the authority question in a
// second place.
type Scheme string

const (
	// SchemeSession is a logged-in person, authenticated by cookie.
	SchemeSession Scheme = "session"

	// SchemeAPIKey is a machine, authenticated by X-API-Key.
	SchemeAPIKey Scheme = "api_key"

	// SchemeSystem is the process acting on its own behalf, with no
	// caller at all: the worker running a rescore or a deep pass off the
	// job queue.
	//
	// It exists so that work with no human origin is distinguishable in
	// change_log rather than borrowing a person's name. ADR-0027 requires
	// that distinction, and the old betaActor constant could not express
	// it because it was the only value there was.
	SchemeSystem Scheme = "system"
)

// Identity is the authenticated caller, resolved once per request by the
// HTTP layer and carried on the request context.
//
// It is the thing that replaces httpapi.betaActor. Every field on it is
// server-derived — from a session or key row that was looked up, never from
// a request header or body — because build-plan.md §5's change_log is only
// worth having if what it records cannot be asserted by the caller.
type Identity struct {
	// UserID is the users row this credential belongs to. Empty for
	// SchemeSystem.
	UserID string

	// OrgID is the organization the caller acts within, and the scope every
	// report read is filtered by once report ownership lands.
	OrgID string

	// Role is the authority this credential carries. For an API key it is
	// the key's own role, already clamped to its owner's at mint time — so
	// nothing downstream needs to consult the owner to be safe.
	Role Role

	// Actor is what gets written to change_log.actor, reports.created_by
	// and disputes.created_by: a human-readable, stable identification of
	// who did it.
	Actor string

	// Email is the account's address.
	//
	// It is carried separately from Actor because Actor is the DISPLAY name
	// when one is set, and the two are not recoverable from each other.
	// Without this, /auth/me could only report an address for accounts with
	// no name — so a named user's email appeared on the settings page
	// immediately after signing in (where the login handler still had the
	// address they typed) and vanished on the next reload.
	Email string

	// Scheme records how the caller authenticated.
	Scheme Scheme

	// SessionID is the session this identity was resolved from, or empty for
	// an API key or a system actor.
	//
	// It is carried so that step-up can stamp the ONE session that was
	// re-verified rather than the account: a second factor satisfied in one
	// browser must not unlock a privileged view in another.
	SessionID string

	// SteppedUpAt is when this session was last re-verified (ADR-0028
	// step-up). Zero means never, which is the state of every session that
	// has not — including every session that existed before step-up did.
	SteppedUpAt time.Time

	// PasswordExpired is true when this session was issued to someone whose
	// password is past the policy's maximum age (ADR-0029).
	//
	// It does not weaken the identity — the credential was correct, and the
	// role is real. It is a hold: RequirePasswordChange confines such a
	// session to the endpoints needed to set a new password, so rotation
	// forces a change rather than signing someone out into a form they
	// cannot reach.
	PasswordExpired bool

	// perms is the table Can checks Role against. Unexported so nothing
	// outside this package can forge one onto an Identity it did not build
	// — WithPermissions is how a caller outside this package attaches one.
	perms *PermissionTable
}

// WithPermissions returns a copy of i that answers Can against t.
//
// identityOf, IdentityOf and SystemIdentity all call this internally, so
// anything produced by this package's own login path already carries the
// table it was configured with. This is for the other case: code outside
// this package that builds an Identity by hand — a login stub in a test, a
// synthetic identity for a background job the application drives itself —
// needs a way to attach the deployment's table too, since the field itself
// cannot be set from outside the package.
func (i Identity) WithPermissions(t *PermissionTable) Identity {
	i.perms = t
	return i
}

// Can reports whether this identity may perform the operation, against the
// PermissionTable it was built with.
//
// The zero Identity carries the zero Role and a nil table, neither of which
// matches anything in a real PermissionTable. That is the property that
// makes a missed authentication step fail closed: an unauthenticated
// request whose identity was never populated can do nothing, rather than
// defaulting into whatever the first role in a table happens to be.
func (i Identity) Can(p Permission) bool { return i.perms.Can(i.Role, p) }

// SystemIdentity returns the identity a background job acts under for a
// given organization, carrying t's AdminRole — the same role's authority an
// operator would have, since a job doing work on an organization's behalf
// needs to do anything an administrator of that organization could.
//
// The org is a parameter rather than a constant because a background job
// acts within the organization of the work it is processing — never an
// inherited caller's, and never "all of them".
//
// t must not be nil; it is the same table passed to NewAuthenticator and
// NewAdmin, and a process that reaches this without one configured has a
// wiring bug worth panicking over rather than silently granting a system
// job zero permissions.
func SystemIdentity(orgID string, t *PermissionTable) Identity {
	return Identity{
		OrgID:  orgID,
		Role:   t.AdminRole,
		Actor:  "system",
		Scheme: SchemeSystem,
	}.WithPermissions(t)
}

// identityKey is the context key for the authenticated caller. It is an
// unexported empty struct type, so no other package can collide with it or
// forge an identity into a context without going through WithIdentity.
type identityKey struct{}

// WithIdentity returns a context carrying the authenticated caller.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

// FromContext returns the authenticated caller, and whether there was one.
//
// The boolean is not decoration. A handler that ignores it gets the zero
// Identity, which can do nothing and belongs to no organization — safe, but
// it produces a 403 where the real answer was "this route was never wired
// for authentication". Callers that require an identity should treat the
// false case as a programming error rather than as an anonymous user.
func FromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(Identity)
	return id, ok
}
