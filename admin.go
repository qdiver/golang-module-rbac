package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// NewUserRecord is the row AdminStore.CreateUser writes. PasswordHash is an
// encoded argon2id string; no plaintext password reaches a Store.
type NewUserRecord struct {
	ID           string
	OrgID        string
	Email        string
	Name         string
	PasswordHash string
	Role         Role
	CreatedAt    time.Time
}

// NewAPIKeyRecord is the row AdminStore.CreateAPIKey writes. KeyHash is the
// SHA-256 of the key; the plaintext is returned to the caller once and never
// stored.
type NewAPIKeyRecord struct {
	ID        string
	UserID    string
	Name      string
	KeyHash   []byte
	Role      Role
	CreatedAt time.Time
}

// APIKeyInfo is a key as a listing shows it: everything except the hash.
type APIKeyInfo struct {
	ID         string
	UserID     string
	Name       string
	Role       Role
	CreatedAt  time.Time
	LastUsedAt time.Time
	RevokedAt  time.Time
}

// Revoked reports whether the key has been revoked.
func (k APIKeyInfo) Revoked() bool { return !k.RevokedAt.IsZero() }

// AdminStore is the persistence the management use cases need.
//
// It is separate from Store, which is the request path's read-only lookup
// surface, because the two have very different blast radii: Store resolves a
// credential on every request, while this creates users and mints keys. A
// handler holding only a Store cannot create a user by accident, and that
// separation is enforced by the type system rather than by review.
type AdminStore interface {
	CreateUser(ctx context.Context, u NewUserRecord) error
	UserByID(ctx context.Context, id string) (User, error)
	UserByEmail(ctx context.Context, email string) (User, error)
	ListUsers(ctx context.Context, orgID string) ([]User, error)
	SetDisabledAt(ctx context.Context, userID string, at time.Time) error

	// ClearDisabledAt re-enables an account. Separate from SetDisabledAt
	// with a zero time, so that "undo the disabling" cannot be expressed by
	// accident as "disabled at the beginning of time".
	ClearDisabledAt(ctx context.Context, userID string) error
	SetRole(ctx context.Context, userID string, role Role) error
	DeleteUser(ctx context.Context, userID string) error
	SetPasswordHash(ctx context.Context, userID, hash string) error
	RevokeSessionsByUser(ctx context.Context, userID string, now time.Time) error

	// ClearPasswordExpired lifts the rotation hold on the sessions a
	// password change leaves alive (ADR-0029).
	ClearPasswordExpired(ctx context.Context, userID string) error

	CreateAPIKey(ctx context.Context, k NewAPIKeyRecord) error
	APIKeyByID(ctx context.Context, keyID string) (APIKeyInfo, error)
	ListAPIKeys(ctx context.Context, userID string) ([]APIKeyInfo, error)
	RevokeAPIKey(ctx context.Context, keyID string, at time.Time) error
}

// Errors the management use cases return. The HTTP layer maps each to a
// status; none of them carries detail a caller could mine.
var (
	// ErrEmailTaken is returned when an account already exists for an
	// address. Unlike a login failure, this is safe to report: the caller
	// is an authenticated administrator who can already list every account
	// in their organization, so it tells them nothing they cannot see.
	ErrEmailTaken = errors.New("auth: an account already exists for that email")

	// ErrWeakPassword is returned when a password is below the floor.
	ErrWeakPassword = fmt.Errorf("auth: a password must be at least %d characters", MinPasswordLen)

	// ErrNotPermitted is returned when a caller may perform the operation
	// in general but not on this particular target — revoking someone
	// else's key, or disabling an account in another organization.
	ErrNotPermitted = errors.New("auth: not permitted on this target")

	// ErrLastAdmin is returned when disabling an account would leave an
	// organization with no enabled administrator.
	ErrLastAdmin = errors.New("auth: that is the last enabled administrator")
)

// MinPasswordLen is the floor on any password this package accepts.
//
// It is a length floor, not a composition policy. Length is the property
// that actually resists guessing; character-class rules push people toward
// predictable substitutions and were dropped from NIST's own guidance for
// that reason.
const MinPasswordLen = 12

// Admin is the management use cases: creating and disabling users, changing
// passwords, and minting and revoking API keys.
//
// It holds every rule that must not be re-derived in a handler — the role
// clamp, the organization boundary, the last-admin check — so that an
// endpoint added later gets them by calling this rather than by remembering
// them.
type Admin struct {
	store    AdminStore
	policies PolicyStore
	clock    Clock
	ids      IDGen
	table    *PermissionTable
}

// NewAdmin builds an Admin. Every dependency is required.
func NewAdmin(store AdminStore, clock Clock, ids IDGen, table *PermissionTable) (*Admin, error) {
	if store == nil || clock == nil || ids == nil || table == nil {
		return nil, errors.New("auth: NewAdmin requires a store, a clock, an ID generator and a permission table")
	}
	return &Admin{store: store, clock: clock, ids: ids, table: table}, nil
}

// WithPolicies attaches the per-organization password policy (ADR-0029).
//
// It is a separate call rather than a constructor parameter so that an Admin
// built without one keeps working: every password is then checked against
// DefaultPolicy, which is the same floor the product enforced before this
// existed. A missing policy store must degrade to the default, never to "no
// rules" — a nil check that skipped validation would turn a wiring mistake
// into an unenforced password policy, silently.
func (a *Admin) WithPolicies(p PolicyStore) *Admin {
	a.policies = p
	return a
}

// policyFor returns the policy governing an organization.
//
// Absent store or a read failure both fall back to DefaultPolicy rather than
// failing the operation. That is the safe direction: the default is the
// strictest thing this product ships with composition on, so a database
// hiccup makes a password change stricter than configured, never laxer.
func (a *Admin) policyFor(ctx context.Context, orgID string) Policy {
	if a.policies == nil {
		return DefaultPolicy(orgID)
	}
	p, err := a.policies.PolicyForOrg(ctx, orgID)
	if err != nil {
		return DefaultPolicy(orgID)
	}
	return p
}

// checkReuse refuses a password the user has used before.
//
// It is run only after the cheap rules have passed, because each stored hash
// costs a full argon2id comparison — 19 MiB and two passes apiece — and
// paying that for a password about to be refused for being eight characters
// long would put a measurable amount of the request budget into a wrong
// answer.
//
// The comparison cannot be a hash lookup: each stored value has its own
// salt, which is the property that stops a stolen history table being
// cracked as a batch. So it is a loop, and the loop is why HistoryDepth is
// capped at ten.
func (a *Admin) checkReuse(ctx context.Context, userID string, p Policy, next string) error {
	if a.policies == nil || p.HistoryDepth <= 0 {
		return nil
	}
	hashes, err := a.policies.RecentPasswordHashes(ctx, userID, p.HistoryDepth)
	if err != nil {
		return fmt.Errorf("auth: read password history: %w", err)
	}
	for _, h := range hashes {
		ok, verifyErr := VerifyPassword(h, next)
		if verifyErr != nil {
			// A single unparseable row must not block a password change.
			// It is a corrupt value, not a match, and refusing the change
			// would leave the user unable to rotate a password they may
			// believe is compromised.
			continue
		}
		if ok {
			return &PolicyError{Violations: []Violation{{
				Rule:    RuleReuse,
				Message: fmt.Sprintf("it repeats one of your last %d passwords", p.HistoryDepth),
			}}}
		}
	}
	return nil
}

// recordChange files the outgoing hash and stamps the change date.
//
// Failures here are returned, not swallowed: without the stamp a password
// under a rotation policy never expires, and without the history file the
// previous password can be set again immediately. Both are the silent
// non-enforcement of a control somebody switched on.
func (a *Admin) recordChange(ctx context.Context, userID, previousHash string, p Policy) error {
	if a.policies == nil {
		return nil
	}
	err := a.policies.RecordPasswordChange(
		ctx, userID, previousHash, a.ids.NewID(), a.clock.Now(), p.HistoryDepth)
	if err != nil {
		return fmt.Errorf("auth: record password change: %w", err)
	}
	return nil
}

// CreateUser adds an account to the caller's organization.
//
// The organization is taken from the caller's identity and never from the
// request: an administrator of one organization must not be able to create
// an account in another by naming it. This is the invariant that will still
// hold once reports are scoped (ADR-0027 phase 3), when an account in the
// wrong organization becomes a way to read another customer's findings.
func (a *Admin) CreateUser(ctx context.Context, actor Identity, email, name string, role Role, password string) (User, error) {
	if !actor.Can(a.table.ManageUsers) {
		return User{}, ErrNotPermitted
	}
	if !a.table.Valid(role) {
		return User{}, fmt.Errorf("auth: unknown role %q", role)
	}
	email = strings.TrimSpace(email)
	if email == "" {
		return User{}, errors.New("auth: an email address is required")
	}
	// Against the policy of the organization the account is being created
	// in, which is the caller's own — CreateUser takes the org from the
	// identity and never from the request.
	if err := a.policyFor(ctx, actor.OrgID).Check(password, email, name); err != nil {
		return User{}, err
	}

	// Checked before the write so the caller gets a sentence rather than a
	// constraint violation. The users_email_unique index is what actually
	// guarantees it against a concurrent create; this check is for the
	// message, and CreateUser below still maps ErrConflict.
	switch _, err := a.store.UserByEmail(ctx, email); {
	case err == nil:
		return User{}, ErrEmailTaken
	case !errors.Is(err, ErrNotFound):
		return User{}, fmt.Errorf("auth: check for an existing account: %w", err)
	}

	hash, err := HashPassword(password)
	if err != nil {
		return User{}, fmt.Errorf("auth: hash password: %w", err)
	}

	u := User{
		ID: a.ids.NewID(), OrgID: actor.OrgID, Email: email,
		Name: strings.TrimSpace(name), Role: role,
	}
	if err := a.store.CreateUser(ctx, NewUserRecord{
		ID: u.ID, OrgID: u.OrgID, Email: u.Email, Name: u.Name,
		PasswordHash: hash, Role: role, CreatedAt: a.clock.Now(),
	}); err != nil {
		if errors.Is(err, ErrConflict) {
			return User{}, ErrEmailTaken
		}
		return User{}, fmt.Errorf("auth: create user: %w", err)
	}
	return u, nil
}

// ListUsers returns the accounts in the caller's organization.
func (a *Admin) ListUsers(ctx context.Context, actor Identity) ([]User, error) {
	if !actor.Can(a.table.ManageUsers) {
		return nil, ErrNotPermitted
	}
	return a.store.ListUsers(ctx, actor.OrgID)
}

// DisableUser disables an account and revokes its sessions.
//
// The softer of the two removals: the account stops working and keeps
// existing, which is what you want for someone who may come back. DeleteUser
// is the other. Revoking the sessions is not optional — an account that
// cannot log in but whose existing cookie still works is not disabled.
func (a *Admin) DisableUser(ctx context.Context, actor Identity, userID string) error {
	target, err := a.manageableTarget(ctx, actor, userID)
	if err != nil {
		return err
	}
	if target.Disabled {
		return nil // already disabled; nothing to do and nothing to report
	}
	if target.Role == a.table.AdminRole {
		lastAdmin, err := a.isLastEnabledAdmin(ctx, target)
		if err != nil {
			return err
		}
		if lastAdmin {
			return ErrLastAdmin
		}
	}

	now := a.clock.Now()
	if err := a.store.SetDisabledAt(ctx, userID, now); err != nil {
		return fmt.Errorf("auth: disable user: %w", err)
	}
	if err := a.store.RevokeSessionsByUser(ctx, userID, now); err != nil {
		return fmt.Errorf("auth: revoke sessions for a disabled user: %w", err)
	}
	return nil
}

// UserByID resolves an account, for an operation that acts on somebody
// else's and needs the row to authorize against.
//
// It takes no actor and performs no authorization of its own: the caller's
// right to act is decided by the operation, against the row this returns.
// Folding a permission check in here would make the check invisible at the
// call site, which is the pattern ADR-0027 rejected for route permissions.
func (a *Admin) UserByID(ctx context.Context, userID string) (User, error) {
	return a.store.UserByID(ctx, userID)
}

// EnableUser lets a disabled account sign in again.
//
// This is the other half of DisableUser, and its absence was a real defect:
// disabling was a one-way door, so an administrator who suspended the wrong
// colleague could only delete the account and build a new one — losing its
// API keys and its id, and with it the link between that id and everything
// the person had done.
//
// It does NOT restore sessions. Disabling revoked them, and a suspension
// that ends should return the account to a signed-out state rather than
// silently reviving whatever was live when it began — which may be the
// session that prompted the suspension.
func (a *Admin) EnableUser(ctx context.Context, actor Identity, userID string) error {
	target, err := a.manageableTarget(ctx, actor, userID)
	if err != nil {
		return err
	}
	if !target.Disabled {
		return nil // already enabled; nothing to do and nothing to report
	}
	if err := a.store.ClearDisabledAt(ctx, userID); err != nil {
		return fmt.Errorf("auth: enable user: %w", err)
	}
	return nil
}

// isLastEnabledAdmin reports whether target is the only enabled admin left.
func (a *Admin) isLastEnabledAdmin(ctx context.Context, target User) (bool, error) {
	users, err := a.store.ListUsers(ctx, target.OrgID)
	if err != nil {
		return false, fmt.Errorf("auth: count administrators: %w", err)
	}
	for _, u := range users {
		if u.ID != target.ID && u.Role == a.table.AdminRole && !u.Disabled {
			return false, nil
		}
	}
	return true, nil
}

// DeleteUser removes an account permanently.
//
// Disabling is still the softer option and the one to reach for when someone
// may come back; this is for an account that should not have existed, or one
// whose owner is gone for good.
//
// It does NOT erase the audit trail, and an earlier version of this comment
// claimed it would. change_log.actor, reports.created_by and
// disputes.created_by are text columns, not foreign keys — a deleted user
// keeps their name on everything they did. What does go is what should: the
// account's sessions and API keys, which cascade.
//
// The refusals are DisableUser's, for the same reasons: not another
// organization's account, not your own, and not the last enabled
// administrator.
func (a *Admin) DeleteUser(ctx context.Context, actor Identity, userID string) error {
	target, err := a.manageableTarget(ctx, actor, userID)
	if err != nil {
		return err
	}
	if target.Role == a.table.AdminRole && !target.Disabled {
		last, err := a.isLastEnabledAdmin(ctx, target)
		if err != nil {
			return err
		}
		if last {
			return ErrLastAdmin
		}
	}
	if err := a.store.DeleteUser(ctx, target.ID); err != nil {
		return fmt.Errorf("auth: delete user: %w", err)
	}
	return nil
}

// SetRole changes what an account may do.
//
// Not on your own account: an administrator who demotes themselves cannot
// promote themselves back, and in an organization of one that is a lockout
// with no in-product way out. Not on the last enabled administrator either,
// for the same reason.
func (a *Admin) SetRole(ctx context.Context, actor Identity, userID string, role Role) error {
	if !a.table.Valid(role) {
		return fmt.Errorf("auth: unknown role %q", role)
	}
	target, err := a.manageableTarget(ctx, actor, userID)
	if err != nil {
		return err
	}
	if target.Role == role {
		return nil // already there; nothing to do and nothing to report
	}
	if target.Role == a.table.AdminRole && role != a.table.AdminRole && !target.Disabled {
		last, err := a.isLastEnabledAdmin(ctx, target)
		if err != nil {
			return err
		}
		if last {
			return ErrLastAdmin
		}
	}
	if err := a.store.SetRole(ctx, target.ID, role); err != nil {
		return fmt.Errorf("auth: set role: %w", err)
	}
	return nil
}

// manageableTarget resolves an account the caller is allowed to act on,
// applying the three checks every management operation shares: the caller
// manages users at all, the target is in their organization, and it is not
// themselves.
//
// It exists so those three cannot drift apart across the operations — the
// way they would if each one re-implemented them, and the way a fourth
// operation added later would get them for free.
func (a *Admin) manageableTarget(ctx context.Context, actor Identity, userID string) (User, error) {
	if !actor.Can(a.table.ManageUsers) {
		return User{}, ErrNotPermitted
	}
	if userID == actor.UserID {
		return User{}, ErrNotPermitted
	}
	target, err := a.store.UserByID(ctx, userID)
	if err != nil {
		return User{}, err
	}
	if target.OrgID != actor.OrgID {
		// Indistinguishable from "no such user": confirming that an id
		// exists in another organization is itself a disclosure.
		return User{}, ErrNotFound
	}
	return target, nil
}

// ChangePassword changes the caller's own password.
//
// The current password is required even though the caller is already
// authenticated. A session cookie is a bearer credential: someone at an
// unlocked machine, or holding a stolen token, must not be able to take the
// account over permanently by setting a new password.
//
// Every other session is revoked on success. A password change is what
// someone does when they think a credential is compromised, and leaving the
// attacker's session live would make it useless. The caller's own session
// survives, because logging someone out of the tab they just used is
// confusing and buys nothing.
func (a *Admin) ChangePassword(ctx context.Context, actor Identity, current, next string) error {
	if actor.UserID == "" {
		return ErrNotPermitted
	}

	u, err := a.store.UserByID(ctx, actor.UserID)
	if err != nil {
		return err
	}
	if u.PasswordHash == "" {
		return ErrInvalidCredentials
	}

	// The current password is verified BEFORE the new one is judged.
	// Reversing the two would let anyone holding the session learn which
	// passwords the policy accepts without knowing the current one — a small
	// oracle, but a free one to avoid.
	ok, err := VerifyPassword(u.PasswordHash, current)
	if err != nil {
		return fmt.Errorf("auth: verify current password: %w", err)
	}
	if !ok {
		return ErrInvalidCredentials
	}

	policy := a.policyFor(ctx, u.OrgID)
	if policyErr := policy.Check(next, u.Email, u.Name); policyErr != nil {
		return policyErr
	}
	if reuseErr := a.checkReuse(ctx, u.ID, policy, next); reuseErr != nil {
		return reuseErr
	}

	hash, err := HashPassword(next)
	if err != nil {
		return fmt.Errorf("auth: hash password: %w", err)
	}
	if setErr := a.store.SetPasswordHash(ctx, u.ID, hash); setErr != nil {
		return fmt.Errorf("auth: set password: %w", setErr)
	}
	// The hash being replaced is what goes into history, so it is read from
	// the row loaded before the write.
	if recErr := a.recordChange(ctx, u.ID, u.PasswordHash, policy); recErr != nil {
		return recErr
	}
	// Sessions are revoked after the hash is written, not before: if this
	// fails, the password has still changed, which is the half a caller
	// most needs to have taken effect.
	if err := a.store.RevokeSessionsByUser(ctx, u.ID, a.clock.Now()); err != nil {
		return fmt.Errorf("auth: revoke sessions after a password change: %w", err)
	}
	// And lift any rotation hold. The caller's own session survives the
	// revocation above by design, and it is the one that was confined to
	// this form — leaving the flag set would lock the user out with the
	// very password they just set.
	if err := a.store.ClearPasswordExpired(ctx, u.ID); err != nil {
		return fmt.Errorf("auth: lift the password-rotation hold: %w", err)
	}
	return nil
}

// ResetPassword sets another user's password, without knowing the old one.
//
// This is the recovery path a forgotten password needs, and it is
// deliberately an ADMINISTRATOR action rather than a self-service email
// flow. A reset link mailed to an address is an authentication factor in its
// own right, and adding one to a product holding breach evidence means
// deciding how long the link lives, what happens when the mailbox is the
// thing that was compromised, and who can trigger one for whom. An admin who
// can already create and disable accounts can already do everything a reset
// does; this only spares them deleting the account and making a new one.
//
// Every session the target holds is revoked. A password someone could not
// remember is one they may believe was compromised, and leaving the old
// sessions live would make the reset cosmetic.
//
// The caller cannot reset their own password here — ChangePassword is that
// path, and it asks for the current one. Routing self-service through an
// endpoint that does not would mean anyone at an unlocked admin's machine
// could take the account permanently, which is exactly what ChangePassword's
// current-password check exists to prevent.
func (a *Admin) ResetPassword(ctx context.Context, actor Identity, userID, next string) error {
	target, err := a.manageableTarget(ctx, actor, userID)
	if err != nil {
		return err
	}

	policy := a.policyFor(ctx, target.OrgID)
	if policyErr := policy.Check(next, target.Email, target.Name); policyErr != nil {
		return policyErr
	}
	// Reuse is checked here too, and the disclosure that comes with it is
	// accepted deliberately. Telling an administrator "that repeats one of
	// their last five" does reveal something about the target's history —
	// but the administrator can already set this account's password to
	// anything and sign in as them, so the marginal disclosure is small.
	// Skipping the check would be the larger harm: it would let a reset
	// reinstate a password the user rotated away from precisely because
	// they believed it was compromised.
	if reuseErr := a.checkReuse(ctx, target.ID, policy, next); reuseErr != nil {
		return reuseErr
	}

	hash, err := HashPassword(next)
	if err != nil {
		return fmt.Errorf("auth: hash password: %w", err)
	}
	if setErr := a.store.SetPasswordHash(ctx, target.ID, hash); setErr != nil {
		return fmt.Errorf("auth: set password: %w", setErr)
	}
	if recErr := a.recordChange(ctx, target.ID, target.PasswordHash, policy); recErr != nil {
		return recErr
	}
	if err := a.store.RevokeSessionsByUser(ctx, target.ID, a.clock.Now()); err != nil {
		return fmt.Errorf("auth: revoke sessions after a reset: %w", err)
	}
	return nil
}

// MintAPIKey creates a key belonging to the caller and returns it in
// plaintext exactly once.
//
// Any authenticated caller may mint their own keys — this needs no
// ManageUsers permission — because a key is not new authority, it is a
// second way to present authority the caller already has. The clamp is what
// makes that true: the requested role is reduced to the caller's own, so a
// weaker role issuing a read-only key to CI is ordinary, and a weaker role
// minting an admin key is impossible.
func (a *Admin) MintAPIKey(ctx context.Context, actor Identity, name string, requested Role) (string, APIKeyInfo, error) {
	if actor.UserID == "" {
		return "", APIKeyInfo{}, ErrNotPermitted
	}
	if !a.table.Valid(requested) {
		requested = actor.Role
	}
	granted := a.table.AtMost(requested, actor.Role)

	key, hash, err := NewAPIKey()
	if err != nil {
		return "", APIKeyInfo{}, fmt.Errorf("auth: mint key: %w", err)
	}
	info := APIKeyInfo{
		ID: a.ids.NewID(), UserID: actor.UserID,
		Name: strings.TrimSpace(name), Role: granted, CreatedAt: a.clock.Now(),
	}
	if err := a.store.CreateAPIKey(ctx, NewAPIKeyRecord{
		ID: info.ID, UserID: info.UserID, Name: info.Name,
		KeyHash: hash, Role: granted, CreatedAt: info.CreatedAt,
	}); err != nil {
		return "", APIKeyInfo{}, fmt.Errorf("auth: create key: %w", err)
	}
	return key, info, nil
}

// ListAPIKeys returns the caller's own keys, revoked ones included.
//
// Revoked keys are listed rather than hidden: "this key was revoked last
// Tuesday" is the answer someone is looking for when a CI job starts
// failing, and removing the row would replace it with silence.
func (a *Admin) ListAPIKeys(ctx context.Context, actor Identity) ([]APIKeyInfo, error) {
	if actor.UserID == "" {
		return nil, ErrNotPermitted
	}
	return a.store.ListAPIKeys(ctx, actor.UserID)
}

// RevokeAPIKey revokes one of the caller's own keys.
//
// A key belonging to someone else answers as though it does not exist, for
// the same reason a cross-organization report does: a distinct "not yours"
// confirms the ID is real.
func (a *Admin) RevokeAPIKey(ctx context.Context, actor Identity, keyID string) error {
	if actor.UserID == "" {
		return ErrNotPermitted
	}
	key, err := a.store.APIKeyByID(ctx, keyID)
	if err != nil {
		return err
	}
	if key.UserID != actor.UserID {
		return ErrNotFound
	}
	if key.Revoked() {
		return nil // already revoked; the caller's intent is satisfied
	}
	if err := a.store.RevokeAPIKey(ctx, keyID, a.clock.Now()); err != nil {
		return fmt.Errorf("auth: revoke key: %w", err)
	}
	return nil
}

// PasswordPolicy returns the policy governing the caller's organization.
//
// Readable by any authenticated caller, not just an administrator. A person
// choosing a password has to be told the rules they must satisfy, and the
// alternative — guessing until the form stops complaining — is exactly the
// behavior that produces Password1!. There is nothing to withhold: it is
// their own organization's policy, and it is enforced on them either way.
func (a *Admin) PasswordPolicy(ctx context.Context, actor Identity) (Policy, error) {
	if actor.UserID == "" && actor.OrgID == "" {
		return Policy{}, ErrNotPermitted
	}
	return a.policyFor(ctx, actor.OrgID), nil
}

// SetPasswordPolicy replaces the caller's organization's policy.
//
// The organization is taken from the caller's identity and never from the
// request, for the same reason CreateUser does: an administrator of one
// organization must not be able to weaken another's password rules by naming
// it. On a multi-tenant deployment that would be a way to attack a
// neighboring customer's accounts without touching them directly.
//
// It returns the stored policy rather than nothing, so a client renders what
// was saved instead of what it hoped was saved.
func (a *Admin) SetPasswordPolicy(ctx context.Context, actor Identity, p Policy) (Policy, error) {
	if !actor.Can(a.table.ManageUsers) {
		return Policy{}, ErrNotPermitted
	}
	if a.policies == nil {
		return Policy{}, ErrNoPolicyStore
	}

	// Server-set, never from the request: a policy's provenance is the point
	// of recording it, and a caller that could name the author could
	// attribute their own change to somebody else.
	p.OrgID = actor.OrgID
	p.UpdatedAt = a.clock.Now()
	p.UpdatedBy = actor.Actor

	if err := p.Validate(); err != nil {
		return Policy{}, err
	}
	if err := a.policies.SavePolicy(ctx, p); err != nil {
		return Policy{}, fmt.Errorf("auth: save password policy: %w", err)
	}
	return p, nil
}
