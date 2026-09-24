package auth

import (
	"context"
	"time"
)

// User is a users row as this package needs it.
//
// It is a local struct rather than a domain type because identity is not
// part of the product's domain: build-plan.md's domain layer is assets,
// findings, rubrics and scores, and a password hash has no business in it
// (ADR-0002's dependency rule). Nothing here is imported by internal/domain.
type User struct {
	ID           string
	OrgID        string
	Email        string
	Name         string
	PasswordHash string
	Role         Role
	Disabled     bool
	AvatarURL    string // profile picture URL from a Google sign-in, if any

	// PasswordChangedAt is when the current password was set, or the zero
	// time for an account that predates migration 0013.
	//
	// The zero value reads as "unknown, so not expired" (Policy.IsExpired).
	// It is deliberately not backfilled: a backfill would be a lie about
	// when those passwords were chosen, and under a rotation policy it would
	// expire every account on an upgraded deployment on the same day.
	PasswordChangedAt time.Time
}

// NewSession is the row Store.InsertSession writes. The plaintext token
// never appears — only its hash — so a Store implementation has no way to
// persist the credential even by accident.
type NewSession struct {
	// PasswordExpired marks a session issued to someone whose password is
	// past the policy's maximum age. Such a session authenticates, but
	// middleware confines it to the change-password form (ADR-0029).
	PasswordExpired bool

	ID                string
	UserID            string
	TokenHash         []byte
	CreatedAt         time.Time
	ExpiresAt         time.Time
	AbsoluteExpiresAt time.Time
}

// SessionLookup is what a live-session query returns: the session's own ID,
// so it can be touched or revoked, and the identity it resolves to.
type SessionLookup struct {
	SessionID         string
	AbsoluteExpiresAt time.Time
	Identity          Identity
}

// APIKeyLookup is the key equivalent of SessionLookup.
type APIKeyLookup struct {
	KeyID    string
	Identity Identity
}

// Store is the persistence this package needs, and no more.
//
// It is declared here, beside its consumer, rather than in
// internal/app/ports — the same choice httpapi.BaselineReader records, and
// for a sharper reason: these are not use-case ports. Nothing in
// internal/app creates a session or verifies a password, and putting
// credential access in the shared port set would invite it to.
//
// Every lookup method returns ErrNotFound for "no live row", and it is
// the implementation's job to make "expired", "revoked" and "owner disabled"
// indistinguishable from "no such row" by filtering them in the query. A
// Store that returns a dead session and expects the caller to check liveness
// has moved a security decision to the least reliable place for it.
type Store interface {
	// UserByEmail backs login. Matching is case-insensitive.
	UserByEmail(ctx context.Context, email string) (User, error)

	// UserByID backs the second step of a two-step login (ADR-0028), which
	// resumes from a token carrying a user id rather than an address.
	UserByID(ctx context.Context, id string) (User, error)

	// SetPasswordHash backs the login path's transparent cost upgrade
	// (NeedsRehash) and a password change.
	SetPasswordHash(ctx context.Context, userID, hash string) error

	// InsertSession persists a freshly minted session.
	InsertSession(ctx context.Context, s NewSession) error

	// SessionByTokenHash returns the live session with this token hash as
	// of now, or ErrNotFound.
	SessionByTokenHash(ctx context.Context, hash []byte, now time.Time) (SessionLookup, error)

	// TouchSession advances the sliding idle window. Implementations clamp
	// expiresAt to the session's absolute ceiling.
	TouchSession(ctx context.Context, sessionID string, now, expiresAt time.Time) error

	// RevokeSession is logout.
	RevokeSession(ctx context.Context, sessionID string, now time.Time) error

	// RevokeSessionsByUser is logout everywhere, used on password change
	// and on disabling an account — neither of which is complete while an
	// issued cookie still works.
	RevokeSessionsByUser(ctx context.Context, userID string, now time.Time) error

	// ClearPasswordExpired lifts the rotation hold on a user's surviving
	// sessions after they change their password. Without it the session
	// that just satisfied the policy would stay confined to the form that
	// asked it to.
	ClearPasswordExpired(ctx context.Context, userID string) error

	// APIKeyByHash returns the live key with this hash, or
	// ErrNotFound.
	APIKeyByHash(ctx context.Context, hash []byte) (APIKeyLookup, error)

	// TouchAPIKey records last use, so unused keys can be found and
	// revoked.
	TouchAPIKey(ctx context.Context, keyID string, now time.Time) error
}
