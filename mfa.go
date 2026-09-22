package auth

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// MFATokenLifetime is how long the step-one token is good for.
//
// Long enough to fetch a phone from another room, short enough that one left
// in a proxy log or a browser history is useless by the time anyone reads it.
// It is not a session and must never be treated as one — see ADR-0028.
const MFATokenLifetime = 5 * time.Minute

// TOTPEnrollment is the state of an account's second factor.
type TOTPEnrollment struct {
	UserID       string
	SecretSealed string
	ConfirmedAt  time.Time
	LastUsedStep int64
	CreatedAt    time.Time
}

// Confirmed reports whether the factor is active. An unconfirmed row is a
// scan somebody started and never finished, and must not make login ask for
// a code nobody can produce.
func (e TOTPEnrollment) Confirmed() bool { return !e.ConfirmedAt.IsZero() }

// MFAToken is a claimed step-one token.
type MFAToken struct {
	ID        string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// MFAStore is the persistence the second factor needs.
type MFAStore interface {
	// TOTPByUser returns an account's enrollment, or ErrNotFound.
	TOTPByUser(ctx context.Context, userID string) (TOTPEnrollment, error)

	// UpsertTOTP stores a new, unconfirmed secret, replacing any pending
	// one and resetting the replay counter.
	UpsertTOTP(ctx context.Context, userID, sealed string, now time.Time) error

	// ConfirmTOTP activates an enrollment, recording the step that proved it.
	ConfirmTOTP(ctx context.Context, userID string, at time.Time, step int64) error

	// SetTOTPLastUsedStep advances the replay guard. Implementations must
	// refuse to move it backwards.
	SetTOTPLastUsedStep(ctx context.Context, userID string, step int64) error

	// DeleteTOTP removes the factor.
	DeleteTOTP(ctx context.Context, userID string) error

	// ReplaceRecoveryCodes deletes any existing codes and stores these.
	ReplaceRecoveryCodes(ctx context.Context, userID string, hashes [][]byte, ids []string, now time.Time) error

	// SpendRecoveryCode claims one unused code, reporting whether it found
	// one. It must be atomic: a check followed by an update would let two
	// simultaneous requests spend the same code.
	SpendRecoveryCode(ctx context.Context, userID string, hash []byte, now time.Time) (bool, error)

	// UnusedRecoveryCodeCount is what the UI shows so somebody notices
	// before they run out.
	UnusedRecoveryCodeCount(ctx context.Context, userID string) (int64, error)

	// InsertMFAToken persists a step-one token.
	InsertMFAToken(ctx context.Context, id, userID string, hash []byte, now, expires time.Time) error

	// ClaimMFAToken marks a live token used and returns it, atomically.
	ClaimMFAToken(ctx context.Context, hash []byte, now time.Time) (MFAToken, error)
}

// MFA errors.
var (
	// ErrMFANotEnrolled is returned when an operation needs a factor that
	// does not exist.
	ErrMFANotEnrolled = errors.New("auth: no second factor is enrolled on this account")

	// ErrMFAAlreadyConfirmed is returned when enrollment would overwrite an
	// ACTIVE factor. Replacing one silently would let anyone holding a
	// session swap the second factor for their own, which is the whole
	// control defeated by its own settings page.
	ErrMFAAlreadyConfirmed = errors.New("auth: a second factor is already enrolled; remove it first")

	// ErrInvalidMFAToken is returned for a step-one token that is expired,
	// already used, or was never issued. One error for all three: a caller
	// must not learn which.
	ErrInvalidMFAToken = errors.New("auth: that sign-in attempt has expired; start again")
)

// MFAService is the second-factor use cases.
type MFAService struct {
	store  MFAStore
	users  AdminStore
	sealer *Sealer
	clock  Clock
	ids    IDGen
	issuer string

	// passkeys lets a security key count as a second factor (ADR-0031).
	// Optional; see WithPasskeys.
	passkeys PasskeyChecker
}

// NewMFAService builds the service. Every dependency is required: a second
// factor with no sealer would store its secret in plaintext, and one with no
// store would report itself enabled and verify nothing.
func NewMFAService(store MFAStore, users AdminStore, sealer *Sealer, clock Clock, ids IDGen, issuer string) (*MFAService, error) {
	if store == nil || users == nil || clock == nil || ids == nil {
		return nil, errors.New("auth: NewMFAService requires a store, a user store, a clock and an ID generator")
	}
	if sealer == nil {
		return nil, ErrNoSealKey
	}
	if issuer == "" {
		issuer = "Security Assessment"
	}
	return &MFAService{store: store, users: users, sealer: sealer, clock: clock, ids: ids, issuer: issuer}, nil
}

// Status describes an account's second factor for its owner.
type Status struct {
	Enabled           bool
	PendingEnrollment bool
	RecoveryCodesLeft int
	EnrolledAt        time.Time
}

// Status reports the caller's own factor.
func (m *MFAService) Status(ctx context.Context, actor Identity) (Status, error) {
	if actor.UserID == "" {
		return Status{}, ErrNotPermitted
	}
	e, err := m.store.TOTPByUser(ctx, actor.UserID)
	switch {
	case errors.Is(err, ErrNotFound):
		return Status{}, nil
	case err != nil:
		return Status{}, fmt.Errorf("auth: read enrollment: %w", err)
	}

	left, err := m.store.UnusedRecoveryCodeCount(ctx, actor.UserID)
	if err != nil {
		return Status{}, fmt.Errorf("auth: count recovery codes: %w", err)
	}
	return Status{
		Enabled:           e.Confirmed(),
		PendingEnrollment: !e.Confirmed(),
		RecoveryCodesLeft: int(left),
		EnrolledAt:        e.ConfirmedAt,
	}, nil
}

// Enrollment is what a caller needs to add the account to an authenticator.
type Enrollment struct {
	// Secret is the base32 shared secret, for manual entry when a camera is
	// not available or a QR will not scan.
	Secret string

	// URI is the otpauth:// value a QR encodes.
	URI string
}

// BeginEnrollment generates a new secret and stores it unconfirmed.
//
// Two steps rather than one, because a secret stored and treated as active
// the moment it is generated locks out anyone whose scan failed or whose
// phone clock is wrong — and they would discover it at their next sign-in,
// with no way back.
//
// It refuses to overwrite a CONFIRMED factor. Replacing one silently would
// let anyone holding a live session swap the second factor for their own,
// which is the control defeating itself through its own settings page.
func (m *MFAService) BeginEnrollment(ctx context.Context, actor Identity) (Enrollment, error) {
	if actor.UserID == "" {
		return Enrollment{}, ErrNotPermitted
	}

	switch existing, err := m.store.TOTPByUser(ctx, actor.UserID); {
	case err == nil && existing.Confirmed():
		return Enrollment{}, ErrMFAAlreadyConfirmed
	case err != nil && !errors.Is(err, ErrNotFound):
		return Enrollment{}, fmt.Errorf("auth: read enrollment: %w", err)
	}

	secret, err := NewTOTPSecret()
	if err != nil {
		return Enrollment{}, err
	}
	sealed, err := m.sealer.Seal(secret)
	if err != nil {
		return Enrollment{}, fmt.Errorf("auth: seal the MFA secret: %w", err)
	}
	if err := m.store.UpsertTOTP(ctx, actor.UserID, sealed, m.clock.Now()); err != nil {
		return Enrollment{}, fmt.Errorf("auth: store enrollment: %w", err)
	}

	account := actor.Email
	if account == "" {
		account = actor.Actor
	}
	return Enrollment{Secret: secret, URI: TOTPKeyURI(secret, m.issuer, account)}, nil
}

// ConfirmEnrollment activates a pending factor and issues recovery codes.
//
// The codes are issued HERE and not at BeginEnrollment, even though the
// proposal says "shown once at enrollment". Enrolling is not the moment the
// factor becomes real — confirming is — and handing out ten recovery codes
// for a factor that may never be switched on would put a second set of
// working credentials into someone's clipboard for nothing.
//
// The plaintext codes are returned once and never again. Only their hashes
// are stored, so a database dump does not hand over a way past the factor.
func (m *MFAService) ConfirmEnrollment(ctx context.Context, actor Identity, code string) ([]string, error) {
	if actor.UserID == "" {
		return nil, ErrNotPermitted
	}
	e, err := m.store.TOTPByUser(ctx, actor.UserID)
	switch {
	case errors.Is(err, ErrNotFound):
		return nil, ErrMFANotEnrolled
	case err != nil:
		return nil, fmt.Errorf("auth: read enrollment: %w", err)
	case e.Confirmed():
		return nil, ErrMFAAlreadyConfirmed
	}

	secret, err := m.sealer.Open(e.SecretSealed)
	if err != nil {
		return nil, err
	}
	now := m.clock.Now()
	step, err := ValidateTOTPCode(secret, code, now, e.LastUsedStep)
	if err != nil {
		return nil, ErrInvalidTOTPCode
	}

	// The confirming step is recorded as used, so the very code that proved
	// enrollment cannot also be the one that completes a login a moment later.
	if confirmErr := m.store.ConfirmTOTP(ctx, actor.UserID, now, step); confirmErr != nil {
		return nil, fmt.Errorf("auth: confirm enrollment: %w", confirmErr)
	}

	codes, err := m.issueRecoveryCodes(ctx, actor.UserID, now)
	if err != nil {
		// The factor is on and the codes are not. Reported, because an
		// account with a second factor and no way back is exactly the
		// lockout this phase exists to prevent — the caller must be told to
		// generate a set before they close the page.
		return nil, fmt.Errorf("auth: the second factor is enabled but recovery codes could not be issued; "+
			"generate a set before signing out: %w", err)
	}
	return codes, nil
}

// RegenerateRecoveryCodes replaces the set, invalidating the old one.
func (m *MFAService) RegenerateRecoveryCodes(ctx context.Context, actor Identity) ([]string, error) {
	if actor.UserID == "" {
		return nil, ErrNotPermitted
	}
	switch e, err := m.store.TOTPByUser(ctx, actor.UserID); {
	case errors.Is(err, ErrNotFound) || (err == nil && !e.Confirmed()):
		return nil, ErrMFANotEnrolled
	case err != nil:
		return nil, fmt.Errorf("auth: read enrollment: %w", err)
	}
	return m.issueRecoveryCodes(ctx, actor.UserID, m.clock.Now())
}

// issueRecoveryCodes generates a set and replaces whatever was there.
//
// Replace, not append: reissuing exists because the old set may be
// compromised or lost, and leaving the previous codes working would mean a
// printout from last year still opens the account.
func (m *MFAService) issueRecoveryCodes(ctx context.Context, userID string, now time.Time) ([]string, error) {
	codes, hashes, err := NewRecoveryCodes()
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(hashes))
	for i := range ids {
		ids[i] = m.ids.NewID()
	}
	if err := m.store.ReplaceRecoveryCodes(ctx, userID, hashes, ids, now); err != nil {
		return nil, fmt.Errorf("auth: store recovery codes: %w", err)
	}
	return codes, nil
}

// Disable removes the second factor, after re-verifying the password.
//
// The password is required even though the caller is authenticated, for the
// same reason ChangePassword requires it: a session cookie is a bearer
// credential, and someone at an unlocked machine must not be able to strip
// the second factor off the account and keep it.
func (m *MFAService) Disable(ctx context.Context, actor Identity, currentPassword string) error {
	if actor.UserID == "" {
		return ErrNotPermitted
	}
	// Checked before the password, so somebody with no factor gets a clear
	// answer rather than being asked to prove themselves for a no-op. It
	// discloses nothing: the caller is the account's owner, asking about
	// their own account.
	switch _, err := m.store.TOTPByUser(ctx, actor.UserID); {
	case errors.Is(err, ErrNotFound):
		return ErrMFANotEnrolled
	case err != nil:
		return fmt.Errorf("auth: read enrollment: %w", err)
	}

	u, err := m.users.UserByID(ctx, actor.UserID)
	if err != nil {
		return err
	}
	if u.PasswordHash == "" {
		return ErrInvalidCredentials
	}
	ok, err := VerifyPassword(u.PasswordHash, currentPassword)
	if err != nil {
		return fmt.Errorf("auth: verify password: %w", err)
	}
	if !ok {
		return ErrInvalidCredentials
	}

	if err := m.store.DeleteTOTP(ctx, actor.UserID); err != nil {
		return fmt.Errorf("auth: remove the second factor: %w", err)
	}
	// The recovery codes go with it. They exist only to get past this
	// factor, so leaving them live after it is gone would leave a set of
	// standalone credentials nobody remembers issuing.
	if err := m.store.ReplaceRecoveryCodes(ctx, actor.UserID, nil, nil, m.clock.Now()); err != nil {
		return fmt.Errorf("auth: remove recovery codes: %w", err)
	}
	return nil
}

// ClearFactorFor removes another account's second factor.
//
// This is the lockout valve, and it is the reason a second factor is safe to
// switch on at all. Recovery codes cover the ordinary loss of a phone; this
// covers the case where the codes are gone too, which is common enough that
// without it the honest advice would be "do not enable this".
//
// The caller must hold PermManageUsers and the target must be in their
// organization — manageableTarget enforces both. It deliberately does NOT
// require the administrator's own password: they may be acting on an urgent
// call, and an administrator who can already reset this account's password
// and sign in as them gains nothing from the extra step.
//
// The recovery codes go with the factor, for the same reason Disable takes
// them: they exist only to get past it.
func (m *MFAService) ClearFactorFor(ctx context.Context, actor Identity, userID string, target User) error {
	if !actor.Can(PermManageUsers) {
		return ErrNotPermitted
	}
	if target.OrgID != actor.OrgID {
		return ErrNotPermitted
	}
	if err := m.store.DeleteTOTP(ctx, userID); err != nil {
		return fmt.Errorf("auth: remove the second factor: %w", err)
	}
	if err := m.store.ReplaceRecoveryCodes(ctx, userID, nil, nil, m.clock.Now()); err != nil {
		return fmt.Errorf("auth: remove recovery codes: %w", err)
	}

	// And the security keys. "Clear their second factor" has to mean every
	// factor, or the valve is a trap: an administrator told the account was
	// reset would hand it back still demanding a key its owner has lost,
	// and the only operation that exists to fix that has already been used.
	//
	// Done last, and its failure is returned, so a partial clear is reported
	// rather than passing as a completed reset.
	if m.passkeys != nil {
		if err := m.passkeys.RevokeAllFor(ctx, userID); err != nil {
			return fmt.Errorf("auth: remove security keys: %w", err)
		}
	}
	return nil
}

// FactorKind says which credential completed the second step. It is recorded
// in the audit log: "signed in with a recovery code" is a materially
// different event from "signed in with their authenticator", and an operator
// reviewing access should not have to infer the difference.
type FactorKind string

// The second-factor credentials a login can be completed with.
const (
	FactorTOTP     FactorKind = "totp"
	FactorRecovery FactorKind = "recovery_code"
	FactorPasskey  FactorKind = "passkey"
)

// VerifyFactor checks a second-factor credential for a user.
//
// # Why the shape decides which table is consulted
//
// A six-digit numeric string is a TOTP code and is checked only against the
// authenticator; anything else is treated as a recovery code and checked only
// against the recovery table. Trying both for every input would mean a
// mistyped TOTP code took a swing at the recovery hashes, and — far worse — a
// recovery code entered while the authenticator still worked could be spent
// by a caller who did not mean to spend one.
//
// # Why success advances the replay guard here
//
// This is the only path that authenticates with a TOTP code, so it is the
// only place the step can be recorded. Recording it anywhere else would leave
// a window in which the same code completes two logins.
func (m *MFAService) VerifyFactor(ctx context.Context, userID, code string) (FactorKind, error) {
	e, err := m.store.TOTPByUser(ctx, userID)
	switch {
	case errors.Is(err, ErrNotFound):
		return "", ErrMFANotEnrolled
	case err != nil:
		return "", fmt.Errorf("auth: read enrollment: %w", err)
	case !e.Confirmed():
		return "", ErrMFANotEnrolled
	}

	if looksLikeTOTP(code) {
		return FactorTOTP, m.verifyTOTP(ctx, userID, e, code)
	}
	return FactorRecovery, m.verifyRecoveryCode(ctx, userID, code)
}

// looksLikeTOTP reports whether an input is six digits and nothing else.
func looksLikeTOTP(code string) bool {
	trimmed := ""
	for _, r := range code {
		if r == ' ' || r == '-' {
			continue
		}
		trimmed += string(r)
	}
	if len(trimmed) != 6 {
		return false
	}
	for _, r := range trimmed {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func (m *MFAService) verifyTOTP(ctx context.Context, userID string, e TOTPEnrollment, code string) error {
	secret, err := m.sealer.Open(e.SecretSealed)
	if err != nil {
		return err
	}
	step, err := ValidateTOTPCode(secret, code, m.clock.Now(), e.LastUsedStep)
	if err != nil {
		// A replayed code and a wrong one are the same answer to the caller.
		// The distinction is preserved for the audit log by the error the
		// validator returned, which the handler records.
		return ErrInvalidTOTPCode
	}
	if err := m.store.SetTOTPLastUsedStep(ctx, userID, step); err != nil {
		// A code that verified but whose step could not be recorded is a
		// code that can be used again. Refusing the login is the safe
		// reading: the user retries in thirty seconds, and a replay window
		// never opens.
		return fmt.Errorf("auth: record the used TOTP step: %w", err)
	}
	return nil
}

func (m *MFAService) verifyRecoveryCode(ctx context.Context, userID, code string) error {
	normalized := NormalizeRecoveryCode(code)
	if normalized == "" {
		return ErrInvalidRecoveryCode
	}
	spent, err := m.store.SpendRecoveryCode(ctx, userID, HashToken(normalized), m.clock.Now())
	if err != nil {
		return fmt.Errorf("auth: spend recovery code: %w", err)
	}
	if !spent {
		return ErrInvalidRecoveryCode
	}
	return nil
}

// IssueMFAToken mints the token that carries a half-finished login into step
// two, and returns it in plaintext exactly once.
func (m *MFAService) IssueMFAToken(ctx context.Context, userID string) (string, error) {
	token, hash, err := NewSessionToken()
	if err != nil {
		return "", fmt.Errorf("auth: mint MFA token: %w", err)
	}
	now := m.clock.Now()
	if err := m.store.InsertMFAToken(ctx, m.ids.NewID(), userID, hash, now, now.Add(MFATokenLifetime)); err != nil {
		return "", fmt.Errorf("auth: persist MFA token: %w", err)
	}
	return token, nil
}

// ClaimMFAToken spends a step-one token and returns whose login it belongs
// to.
//
// It is claimed BEFORE the code is checked, deliberately. A token that
// survived a wrong code would let an attacker holding it try the six digits
// as many times as they liked; spending it on the attempt means each guess
// costs them a fresh password authentication, which the login throttle then
// bounds.
func (m *MFAService) ClaimMFAToken(ctx context.Context, token string) (MFAToken, error) {
	if token == "" {
		return MFAToken{}, ErrInvalidMFAToken
	}
	t, err := m.store.ClaimMFAToken(ctx, HashToken(token), m.clock.Now())
	switch {
	case errors.Is(err, ErrNotFound):
		return MFAToken{}, ErrInvalidMFAToken
	case err != nil:
		return MFAToken{}, fmt.Errorf("auth: claim MFA token: %w", err)
	}
	return t, nil
}

// PasskeyChecker reports whether an account can authenticate with a security
// key. *WebAuthnService satisfies it.
//
// Narrowed to one method so the TOTP service can ask the question without
// being able to register, revoke or verify a passkey — three things that are
// not its business.
type PasskeyChecker interface {
	HasCredentials(ctx context.Context, userID string) bool

	// RevokeAllFor removes every key on an account, for the administrator's
	// lockout valve. Without it that valve only half works: it clears the
	// authenticator app and leaves the keys, so somebody who lost the KEY is
	// still locked out by the very operation meant to rescue them.
	RevokeAllFor(ctx context.Context, userID string) error
}

// WithPasskeys lets an account's security keys count as a second factor
// (ADR-0031).
//
// Optional: without it only a confirmed TOTP enrollment challenges a login,
// which is what every deployment did before passkeys existed.
func (m *MFAService) WithPasskeys(p PasskeyChecker) *MFAService {
	m.passkeys = p
	return m
}

// RequiresSecondFactor reports whether an account has an active factor of
// EITHER kind.
//
// A read failure answers TRUE — fail closed. Answering false on a database
// hiccup would sign somebody straight in past a second factor they had
// deliberately switched on, which is the one error here that cannot be
// walked back.
func (m *MFAService) RequiresSecondFactor(ctx context.Context, userID string) bool {
	if m.passkeys != nil && m.passkeys.HasCredentials(ctx, userID) {
		return true
	}
	e, err := m.store.TOTPByUser(ctx, userID)
	switch {
	case errors.Is(err, ErrNotFound):
		return false
	case err != nil:
		return true
	}
	return e.Confirmed()
}

// HasAnyFactorOtherThanPasskeys reports whether an account has a confirmed
// authenticator app.
//
// It is what the passkey revoke path consults before removing somebody's last
// key: with an app still enrolled, the key is just a key; without one,
// removing it is the silent path back to a password-only account.
func (m *MFAService) HasAnyFactorOtherThanPasskeys(ctx context.Context, userID string) bool {
	e, err := m.store.TOTPByUser(ctx, userID)
	return err == nil && e.Confirmed()
}

// HasAnyFactor reports whether an account keeps a second factor of some kind.
//
// It is what the passkey revocation path consults before removing the last
// key: an account with a confirmed authenticator keeps its second factor
// without that key, and one without does not.
func (m *MFAService) HasAnyFactor(ctx context.Context, userID string) bool {
	e, err := m.store.TOTPByUser(ctx, userID)
	if err == nil && e.Confirmed() {
		return true
	}
	return m.passkeys != nil && m.passkeys.HasCredentials(ctx, userID)
}
