package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Session lifetime policy (ADR-0027).
//
// Two clocks, not one. IdleTimeout logs out a forgotten tab on a shared
// machine; AbsoluteTimeout puts a ceiling on a session that is used every
// day, so a stolen cookie has a bounded life no matter how actively it is
// exercised. A single sliding window would give the first property and not
// the second — which is the one that matters after a token is exfiltrated.
const (
	IdleTimeout     = 12 * time.Hour
	AbsoluteTimeout = 7 * 24 * time.Hour
)

// ErrInvalidCredentials is returned by Login for every failure a caller is
// allowed to distinguish: no such user, wrong password, disabled account.
//
// They are one error on purpose. Separating them turns the login endpoint
// into a user-enumeration oracle — "no such account" tells an attacker which
// addresses are worth a password list, and "account disabled" confirms a
// former employee's address was real. The specific reason is logged for the
// operator and never returned.
var ErrInvalidCredentials = errors.New("auth: invalid credentials")

// ErrNoCredentials is returned by Authenticate when a request carried
// nothing to authenticate with, as distinct from carrying something wrong.
//
// The HTTP layer answers both with 401, but only one of them is worth
// logging as a possible attack.
var ErrNoCredentials = errors.New("auth: no credentials presented")

// Authenticator turns credentials into an Identity.
//
// It holds the whole of the decision: password verification, session
// lifetime, and the resolution of a bearer token to a role. The HTTP layer
// below it decides only where a credential was read from and what status
// code to answer with, and the Store above it does no policy at all. That
// split is what lets the rules be tested without a server and without a
// database.
type Authenticator struct {
	store Store
	clock Clock
	ids   IDGen

	// policies supplies the per-organization password policy, for rotation
	// (ADR-0029). Optional: with none, no password ever expires, which is
	// the behavior every deployment had before this existed.
	policies PolicyStore

	// steps records step-up re-verifications (ADR-0028). Optional: with
	// none, StepUp reports that this deployment cannot record one, and any
	// route behind RequireStepUp stays closed — which is the safe direction
	// for a view that exists to show who did what.
	steps StepUpStore

	// factor is the second-factor use cases (ADR-0028). Optional: with
	// none, no account is ever asked for a second factor, which is the
	// behavior every deployment had before MFA existed.
	factor SecondFactor

	// passkeys completes a login with a security key (ADR-0031). Optional:
	// with none, an account's keys cannot finish a sign-in and TOTP is the
	// only second step.
	passkeys PasskeyAuthenticator

	// google completes a sign-in with a Google account. Optional: with
	// none, BeginGoogleLogin and CompleteGoogleLogin answer
	// ErrGoogleSSOUnavailable and password is the only first factor.
	google GoogleAuthenticator
}

// PasskeyAuthenticator is the part of the passkey use cases the login path
// needs.
//
// Two methods, not the whole service: the login path should be able to start
// and finish a ceremony, and nothing more. Registering and revoking belong to
// a caller who is already signed in.
type PasskeyAuthenticator interface {
	BeginLogin(ctx context.Context, userID string) (Ceremony, error)
	FinishLogin(ctx context.Context, challengeID string, response []byte) (string, error)

	// BeginStepUp and FinishStepUp re-verify a caller who already holds a
	// session, so a security key can prove "it is still you" and not only
	// "it is you".
	BeginStepUp(ctx context.Context, userID string) (Ceremony, error)
	FinishStepUp(ctx context.Context, userID, challengeID string, response []byte) error

	// The front door: a sign-in that names no account, answered by whichever
	// credential the browser offers.
	BeginPasswordlessLogin(ctx context.Context) (Ceremony, error)
	FinishPasswordlessLogin(ctx context.Context, challengeID string, response []byte) (userID string, err error)
}

// GoogleAuthenticator is the part of the Google sign-in use cases the login
// path needs.
//
// Two methods, mirroring PasskeyAuthenticator's front door: start a sign-in
// that names no account, and finish one. Linking, which account a fresh
// Google sign-in resolves to, and the OAuth mechanics all stay inside
// GoogleSSOService — this is only what the login path calls.
type GoogleAuthenticator interface {
	BeginLogin(ctx context.Context) (GoogleLoginStart, error)
	FinishLogin(ctx context.Context, state, code string) (userID string, err error)
}

// SecondFactor is the part of the MFA use cases the login path needs.
//
// Narrowed to four methods rather than taking *MFAService, so the
// authenticator cannot enroll, disable or reissue anything: the login path
// should be able to ASK about a factor and CHECK one, and nothing more.
type SecondFactor interface {
	// RequiresSecondFactor reports whether an account has an active factor.
	RequiresSecondFactor(ctx context.Context, userID string) bool

	// IssueMFAToken mints the token that carries a half-finished login into
	// step two.
	IssueMFAToken(ctx context.Context, userID string) (string, error)

	// ClaimMFAToken spends a step-one token and says whose login it is.
	ClaimMFAToken(ctx context.Context, token string) (MFAToken, error)

	// VerifyFactor checks a TOTP or recovery code.
	VerifyFactor(ctx context.Context, userID, code string) (FactorKind, error)

	// HasAnyFactorOtherThanPasskeys reports whether the account keeps a
	// factor VerifyFactor can actually check.
	//
	// The distinction matters because RequiresSecondFactor answers for
	// factors of either kind, and VerifyFactor only understands one of them.
	// Without this, a passkey-only account is told to produce a six-digit
	// code it has no way to generate — which is what put step-up, and the
	// audit log behind it, out of such an account's reach entirely.
	HasAnyFactorOtherThanPasskeys(ctx context.Context, userID string) bool
}

// LoginResult is the outcome of the first step of a login.
//
// Exactly one of SessionToken and MFAToken is set, and the type exists to
// make that a thing a caller has to look at. The previous signature returned
// a session token unconditionally; a second factor bolted onto it would have
// meant every existing call site kept compiling while silently skipping the
// factor. Changing the shape makes the compiler enumerate the call sites
// instead — the same reasoning ADR-0027 gives for passing org ids explicitly.
type LoginResult struct {
	// SessionToken is the plaintext session cookie value, set only when the
	// login is COMPLETE.
	SessionToken string

	// MFAToken is set instead when a second factor is required. It is not a
	// session and must never be treated as one (ADR-0028).
	MFAToken string

	// Identity is who authenticated. It is populated in both cases, because
	// the audit log must be able to name the account even for a login that
	// has not finished.
	Identity Identity

	// FactorUsed names the second-factor credential that completed the
	// login, when one did. Empty for a single-factor login.
	FactorUsed FactorKind
}

// MFARequired reports whether this login is waiting on a second factor.
func (r LoginResult) MFARequired() bool { return r.MFAToken != "" }

// NewAuthenticator builds an Authenticator. Every dependency is required;
// there is no safe default for any of them.
func NewAuthenticator(store Store, clock Clock, ids IDGen) (*Authenticator, error) {
	if store == nil || clock == nil || ids == nil {
		return nil, errors.New("auth: NewAuthenticator requires a store, a clock and an ID generator")
	}
	return &Authenticator{store: store, clock: clock, ids: ids}, nil
}

// Login verifies an email and password and mints a session.
//
// It returns the session token in plaintext exactly once, for the caller to
// put in a cookie. Nothing persists it.
//
// The password is verified even when no user matched, against a discarded
// hash. Skipping the work on a missing account makes the failure measurably
// faster than a wrong password, which hands back by timing exactly the
// user-enumeration answer ErrInvalidCredentials exists to withhold.
func (a *Authenticator) Login(ctx context.Context, email, password string) (LoginResult, error) {
	now := a.clock.Now()

	u, err := a.store.UserByEmail(ctx, strings.TrimSpace(email))
	switch {
	case errors.Is(err, ErrNotFound):
		// Burn comparable time, then fail. The hash is a real argon2id
		// encoding of a value nothing knows, so this costs what a genuine
		// verification costs.
		//nolint:errcheck // the result is deliberately discarded: this call
		// exists to spend verification time, not to decide anything.
		_, _ = VerifyPassword(dummyHash, password)
		return LoginResult{}, ErrInvalidCredentials
	case err != nil:
		return LoginResult{}, fmt.Errorf("auth: look up user: %w", err)
	}

	// A user with no password hash authenticates by some other means (an
	// OIDC account, once that exists) or by none at all. Either way, no
	// password is the right one.
	if u.PasswordHash == "" {
		//nolint:errcheck // discarded for the same reason as above.
		_, _ = VerifyPassword(dummyHash, password)
		return LoginResult{}, ErrInvalidCredentials
	}

	ok, err := VerifyPassword(u.PasswordHash, password)
	if err != nil {
		// A corrupt hash is an operational problem, not a login attempt to
		// report as such — but the caller still learns only that login
		// failed.
		return LoginResult{}, fmt.Errorf("auth: verify password for %s: %w", u.ID, err)
	}
	if !ok || u.Disabled {
		return LoginResult{}, ErrInvalidCredentials
	}

	// The one moment the plaintext is in hand, so the one moment a cost
	// upgrade is free. A failure here must not fail the login: the user
	// typed the right password, and their hash staying at the old cost for
	// another session is not worth locking them out over.
	if NeedsRehash(u.PasswordHash) {
		if rehashed, rerr := HashPassword(password); rerr == nil {
			//nolint:errcheck // a failed upgrade must not fail the login;
			// the password was correct, and the hash staying at the old
			// cost for one more session is not worth a lockout.
			_ = a.store.SetPasswordHash(ctx, u.ID, rehashed)
		}
	}

	// The password was right. If the account carries a second factor, this
	// is where the login STOPS: no session is minted, and the caller gets a
	// short-lived token that proves step one and nothing else. A session
	// issued here would be a single-factor session, and anyone stealing it
	// would have bypassed the factor entirely (ADR-0028).
	if a.factor != nil && a.factor.RequiresSecondFactor(ctx, u.ID) {
		mfaToken, mfaErr := a.factor.IssueMFAToken(ctx, u.ID)
		if mfaErr != nil {
			return LoginResult{}, fmt.Errorf("auth: begin second factor: %w", mfaErr)
		}
		return LoginResult{MFAToken: mfaToken, Identity: identityOf(u, SchemeSession)}, nil
	}

	return a.issueSession(ctx, u, now, "")
}

// issueSession mints and persists a session for an authenticated user.
//
// Shared by the single-step login and the second step of a two-step one, so
// the two cannot drift: the session lifetimes, the rotation hold and the
// identity are decided in one place rather than in two that look alike.
func (a *Authenticator) issueSession(ctx context.Context, u User, now time.Time, used FactorKind) (LoginResult, error) {
	token, hash, err := NewSessionToken()
	if err != nil {
		return LoginResult{}, fmt.Errorf("auth: mint session: %w", err)
	}

	// Computed once, here, and carried on the session row. A session IS
	// issued for an expired password — that is the grace path: rotation must
	// force a change, not sign someone out into a form they cannot reach.
	// Middleware confines the session until the password is changed.
	expired := a.passwordExpired(ctx, u, now)

	if err := a.store.InsertSession(ctx, NewSession{
		ID:                a.ids.NewID(),
		UserID:            u.ID,
		TokenHash:         hash,
		CreatedAt:         now,
		ExpiresAt:         now.Add(IdleTimeout),
		AbsoluteExpiresAt: now.Add(AbsoluteTimeout),
		PasswordExpired:   expired,
	}); err != nil {
		return LoginResult{}, fmt.Errorf("auth: persist session: %w", err)
	}

	id := identityOf(u, SchemeSession)
	id.PasswordExpired = expired
	return LoginResult{SessionToken: token, Identity: id, FactorUsed: used}, nil
}

// CompleteMFA finishes a two-step login.
//
// The order here is the security-relevant part, and it is deliberate:
//
//  1. The step-one token is CLAIMED first, which spends it. A token that
//     survived a wrong code would let whoever held it try the six digits as
//     many times as they liked; spending it on the attempt means each guess
//     costs a fresh password authentication, which the login throttle bounds.
//  2. The account is re-read, because it may have been disabled in the
//     minutes between the two steps — a suspension that only took effect at
//     the next login would be no suspension at all.
//  3. Only then is the code checked.
func (a *Authenticator) CompleteMFA(ctx context.Context, mfaToken, code string) (LoginResult, error) {
	if a.factor == nil {
		return LoginResult{}, ErrInvalidMFAToken
	}

	claimed, err := a.factor.ClaimMFAToken(ctx, mfaToken)
	if err != nil {
		return LoginResult{}, err
	}

	u, err := a.store.UserByID(ctx, claimed.UserID)
	switch {
	case errors.Is(err, ErrNotFound):
		return LoginResult{}, ErrInvalidCredentials
	case err != nil:
		return LoginResult{}, fmt.Errorf("auth: look up user: %w", err)
	case u.Disabled:
		return LoginResult{}, ErrInvalidCredentials
	}

	kind, err := a.factor.VerifyFactor(ctx, u.ID, code)
	if err != nil {
		// The identity travels with the error so the caller can audit a
		// failed second factor against the account it was attempted on —
		// without it, the log would show an anonymous failure and a
		// brute-force attempt on one account would be invisible.
		return LoginResult{Identity: identityOf(u, SchemeSession)}, err
	}

	return a.issueSession(ctx, u, a.clock.Now(), kind)
}

// WithPasskeys attaches the passkey use cases, enabling a security key to
// complete a two-step login.
func (a *Authenticator) WithPasskeys(p PasskeyAuthenticator) *Authenticator {
	a.passkeys = p
	return a
}

// BeginPasskeyLogin starts the second step with a security key.
//
// It SPENDS the mfa_token, which is ADR-0028's rule applied to a two-call
// ceremony: the attempt begins here, so a failed ceremony costs a fresh
// password authentication rather than another free go at the hardware. The
// challenge that comes back is itself single-use and two minutes long, so
// nothing is weakened by the token being gone before the key is touched.
func (a *Authenticator) BeginPasskeyLogin(ctx context.Context, mfaToken string) (Ceremony, error) {
	if a.factor == nil || a.passkeys == nil {
		return Ceremony{}, ErrInvalidMFAToken
	}
	claimed, err := a.factor.ClaimMFAToken(ctx, mfaToken)
	if err != nil {
		return Ceremony{}, err
	}
	return a.passkeys.BeginLogin(ctx, claimed.UserID)
}

// BeginPasswordlessLogin starts a sign-in with a key alone.
//
// No credential of any kind is required to call it, like login itself. It
// discloses nothing: the ceremony names no account, and the challenge it
// returns is a random id that is useless without a key that can sign it.
func (a *Authenticator) BeginPasswordlessLogin(ctx context.Context) (Ceremony, error) {
	if a.passkeys == nil {
		return Ceremony{}, ErrWebAuthnUnavailable
	}
	return a.passkeys.BeginPasswordlessLogin(ctx)
}

// CompletePasswordlessLogin verifies the key and issues the session.
//
// The account is whatever the credential turned out to belong to, and is
// re-read here for the same reason the two-step completions re-read it: it
// may have been disabled since the ceremony began, and a suspension that
// only took effect at the next login would be no suspension at all.
//
// It does NOT consult RequiresSecondFactor. A verified passkey IS the second
// factor — the ceremony required user verification, so it carries both
// possession and the PIN or biometric that unlocked it — and sending someone
// who signed in with their key to a six-digit prompt would be asking for a
// third.
func (a *Authenticator) CompletePasswordlessLogin(ctx context.Context, challengeID string, response []byte) (LoginResult, error) {
	if a.passkeys == nil {
		return LoginResult{}, ErrWebAuthnUnavailable
	}
	userID, err := a.passkeys.FinishPasswordlessLogin(ctx, challengeID, response)
	if err != nil {
		return LoginResult{}, err
	}

	u, err := a.store.UserByID(ctx, userID)
	switch {
	case errors.Is(err, ErrNotFound):
		return LoginResult{}, ErrInvalidCredentials
	case err != nil:
		return LoginResult{}, fmt.Errorf("auth: look up user: %w", err)
	case u.Disabled:
		return LoginResult{}, ErrInvalidCredentials
	}
	return a.issueSession(ctx, u, a.clock.Now(), FactorPasskey)
}

// CompletePasskeyLogin finishes the ceremony and issues the session.
//
// The account comes from the challenge, never from the request, and is
// re-read here for the same reason CompleteMFA re-reads it: it may have been
// disabled in the minutes between the two calls, and a suspension that only
// took effect at the next login would be no suspension at all.
func (a *Authenticator) CompletePasskeyLogin(ctx context.Context, challengeID string, response []byte) (LoginResult, error) {
	if a.passkeys == nil {
		return LoginResult{}, ErrWebAuthnCeremonyExpired
	}
	userID, err := a.passkeys.FinishLogin(ctx, challengeID, response)
	if err != nil {
		return LoginResult{}, err
	}

	u, err := a.store.UserByID(ctx, userID)
	switch {
	case errors.Is(err, ErrNotFound):
		return LoginResult{}, ErrInvalidCredentials
	case err != nil:
		return LoginResult{}, fmt.Errorf("auth: look up user: %w", err)
	case u.Disabled:
		return LoginResult{}, ErrInvalidCredentials
	}
	return a.issueSession(ctx, u, a.clock.Now(), FactorPasskey)
}

// WithGoogleSSO attaches the Google sign-in use cases, enabling a Google
// account to complete a login.
func (a *Authenticator) WithGoogleSSO(g GoogleAuthenticator) *Authenticator {
	a.google = g
	return a
}

// BeginGoogleLogin starts a sign-in with a Google account.
//
// Like BeginPasswordlessLogin, it takes no credential and names no account:
// which account it turns out to be is decided entirely by which Google
// account the browser authenticates as.
func (a *Authenticator) BeginGoogleLogin(ctx context.Context) (GoogleLoginStart, error) {
	if a.google == nil {
		return GoogleLoginStart{}, ErrGoogleSSOUnavailable
	}
	return a.google.BeginLogin(ctx)
}

// CompleteGoogleLogin verifies the callback and mints a session.
//
// Unlike CompletePasswordlessLogin, this DOES consult RequiresSecondFactor:
// see the package doc in google_sso.go for why a Google sign-in is treated
// as a first factor, not as proof strong enough to skip the account's own
// second one. The account is re-read here for the same reason every other
// completion re-reads it: it may have been disabled since the redirect
// began, and a suspension that only took effect at the next login would be
// no suspension at all.
func (a *Authenticator) CompleteGoogleLogin(ctx context.Context, state, code string) (LoginResult, error) {
	if a.google == nil {
		return LoginResult{}, ErrGoogleSSOUnavailable
	}
	now := a.clock.Now()

	userID, err := a.google.FinishLogin(ctx, state, code)
	if err != nil {
		return LoginResult{}, err
	}

	u, err := a.store.UserByID(ctx, userID)
	switch {
	case errors.Is(err, ErrNotFound):
		return LoginResult{}, ErrInvalidCredentials
	case err != nil:
		return LoginResult{}, fmt.Errorf("auth: look up user: %w", err)
	case u.Disabled:
		return LoginResult{}, ErrInvalidCredentials
	}

	if a.factor != nil && a.factor.RequiresSecondFactor(ctx, u.ID) {
		mfaToken, mfaErr := a.factor.IssueMFAToken(ctx, u.ID)
		if mfaErr != nil {
			return LoginResult{}, fmt.Errorf("auth: begin second factor: %w", mfaErr)
		}
		return LoginResult{MFAToken: mfaToken, Identity: identityOf(u, SchemeSession)}, nil
	}

	return a.issueSession(ctx, u, now, FactorGoogle)
}

// WithStepUp attaches the store that records step-up re-verifications.
func (a *Authenticator) WithStepUp(s StepUpStore) *Authenticator {
	a.steps = s
	return a
}

// WithSecondFactor attaches the MFA use cases, enabling the two-step login.
//
// Separate from the constructor so an Authenticator built without one keeps
// working: no account is then asked for a second factor, which is what every
// deployment did before MFA existed. Note the asymmetry with
// RequiresSecondFactor's own failure mode — a MISSING service means the
// feature is off, while a service that cannot READ answers "yes, required",
// because those are different situations and only the second one might be
// hiding a factor somebody switched on.
func (a *Authenticator) WithSecondFactor(f SecondFactor) *Authenticator {
	a.factor = f
	return a
}

// WithPolicies attaches the password policy store, enabling rotation.
//
// Separate from the constructor so an Authenticator built without one keeps
// working. The fallback here is the opposite of Admin's and deliberately so:
// Admin falls back to the STRICTEST policy because the failure mode there is
// accepting a weak password, whereas here the failure mode is locking a user
// out of their own account over a policy the process could not read. No
// policy store means nothing expires.
func (a *Authenticator) WithPolicies(p PolicyStore) *Authenticator {
	a.policies = p
	return a
}

// passwordExpired reports whether this user must change their password
// before doing anything else.
//
// A read failure returns false. An organization's rotation setting being
// briefly unreadable must not lock its users out — the password itself was
// correct, and the worst case of answering false is that a stale password
// survives until the next sign-in.
func (a *Authenticator) passwordExpired(ctx context.Context, u User, now time.Time) bool {
	if a.policies == nil {
		return false
	}
	p, err := a.policies.PolicyForOrg(ctx, u.OrgID)
	if err != nil {
		return false
	}
	return p.IsExpired(u.PasswordChangedAt, now)
}

// dummyHash is a valid argon2id encoding used only to spend verification
// time on a login for an account that does not exist. It is a hash of a
// random value generated at init; no password matches it, and nothing ever
// checks the result.
var dummyHash = mustDummyHash()

func mustDummyHash() string {
	token, _, err := NewSessionToken()
	if err != nil {
		// Unreachable short of crypto/rand failing, in which case nothing
		// in this package can work. A fixed fallback keeps the timing
		// defense functional rather than panicking at init.
		return "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2Ex$ZGlnZXN0ZGlnZXN0ZGlnZXN0ZGlnZXN0ZGln"
	}
	h, err := HashPassword(token)
	if err != nil {
		return "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2Ex$ZGlnZXN0ZGlnZXN0ZGlnZXN0ZGlnZXN0ZGln"
	}
	return h
}

// AuthenticateSession resolves a session token to an Identity and advances
// the idle window.
//
// The touch is best-effort: a failure to extend a session must not reject a
// request that was properly authenticated. The consequence of a lost touch
// is that the user is asked to log in earlier than they should have been,
// which is the right direction for this to fail in.
func (a *Authenticator) AuthenticateSession(ctx context.Context, token string) (Identity, error) {
	if token == "" {
		return Identity{}, ErrNoCredentials
	}
	hash, err := ParseSessionToken(token)
	if err != nil {
		return Identity{}, ErrInvalidCredentials
	}
	now := a.clock.Now()
	got, err := a.store.SessionByTokenHash(ctx, hash, now)
	switch {
	case errors.Is(err, ErrNotFound):
		return Identity{}, ErrInvalidCredentials
	case err != nil:
		return Identity{}, fmt.Errorf("auth: look up session: %w", err)
	}
	//nolint:errcheck // best-effort: a failure to extend the idle window
	// must not reject a request that authenticated correctly. The cost of
	// losing it is an earlier re-login, which is the safe direction.
	_ = a.store.TouchSession(ctx, got.SessionID, now, now.Add(IdleTimeout))
	return got.Identity, nil
}

// AuthenticateAPIKey resolves an X-API-Key value to an Identity.
//
// The recorded role is the key's own, clamped to its owner's when the key
// was minted, so this path never has to consult the owner to be safe.
func (a *Authenticator) AuthenticateAPIKey(ctx context.Context, key string) (Identity, error) {
	if key == "" {
		return Identity{}, ErrNoCredentials
	}
	hash, err := ParseAPIKey(key)
	if err != nil {
		return Identity{}, ErrInvalidCredentials
	}
	got, err := a.store.APIKeyByHash(ctx, hash)
	switch {
	case errors.Is(err, ErrNotFound):
		return Identity{}, ErrInvalidCredentials
	case err != nil:
		return Identity{}, fmt.Errorf("auth: look up api key: %w", err)
	}
	//nolint:errcheck // best-effort: last-used is an operational
	// convenience, and failing a valid request over it would be absurd.
	_ = a.store.TouchAPIKey(ctx, got.KeyID, a.clock.Now())
	return got.Identity, nil
}

// Logout revokes the session behind a token.
//
// An unknown or already-dead token is not an error: the caller's intent —
// that this token stop working — is satisfied either way, and reporting a
// failure would only tell whoever presented it that it had been valid.
func (a *Authenticator) Logout(ctx context.Context, token string) error {
	hash, err := ParseSessionToken(token)
	if err != nil {
		return nil
	}
	now := a.clock.Now()
	got, err := a.store.SessionByTokenHash(ctx, hash, now)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return fmt.Errorf("auth: look up session: %w", err)
	}
	if err := a.store.RevokeSession(ctx, got.SessionID, now); err != nil {
		return fmt.Errorf("auth: revoke session: %w", err)
	}
	return nil
}

// identityOf builds the Identity a user resolves to.
//
// Actor prefers the display name and falls back to the email, because
// change_log.actor is read by a person trying to work out who did
// something: "alice@example.com" always answers that, and an empty name
// must never produce an empty actor.
func identityOf(u User, scheme Scheme) Identity {
	actor := u.Name
	if strings.TrimSpace(actor) == "" {
		actor = u.Email
	}
	return Identity{
		UserID: u.ID,
		OrgID:  u.OrgID,
		Role:   u.Role,
		Actor:  actor,
		Email:  u.Email,
		Scheme: scheme,
	}
}

// IdentityOf is identityOf, exported for Store implementations, which build
// an Identity from a joined row and must produce exactly the same Actor
// fallback that Login does. Two copies of that rule would drift, and the
// symptom would be an audit trail where the same person appears under two
// names depending on how they authenticated.
func IdentityOf(u User, scheme Scheme) Identity { return identityOf(u, scheme) }
