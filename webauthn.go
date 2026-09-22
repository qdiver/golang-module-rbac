package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthn covers passkeys and hardware security keys with one mechanism: a
// platform authenticator (Touch ID, Windows Hello, a phone) and a roaming one
// (a YubiKey) are the same credential with a different attachment.
//
// It ships as a SECOND FACTOR, beside TOTP, which is decision 2 of
// docs/proposals/auth-hardening.md. Passwordless is the same credential with
// the password step removed, and `users.password_hash` is already nullable
// for it; what is missing is the per-organization switch, not the mechanism.

// WebAuthnChallengeLifetime is how long a ceremony may take.
//
// Two minutes: long enough to find a key in a bag and touch it, short enough
// that a challenge left in a log or a proxy is useless by the time anyone
// reads it. The WebAuthn specification suggests a comparable timeout to the
// browser, and this is the server refusing to be the longer of the two.
const WebAuthnChallengeLifetime = 2 * time.Minute

// Ceremony purposes. A challenge issued for one must not complete the other:
// registration proves possession of a NEW key, and accepting that as a login
// would let anyone who can register sign in as somebody else.
const (
	WebAuthnPurposeRegistration = "registration"
	WebAuthnPurposeLogin        = "login"

	// WebAuthnPurposeStepUp proves it is still you on a session you already
	// hold. Distinct from login for the same reason login is distinct from
	// registration: a login assertion is produced by someone with no session
	// yet, and accepting one as a step-up would let a half-finished sign-in
	// reach an operation meant to need a second, deliberate proof.
	WebAuthnPurposeStepUp = "step_up"

	// WebAuthnPurposePasswordless signs in with the key alone, before any
	// account has been named. It is the one ceremony that starts without
	// knowing whose it is.
	WebAuthnPurposePasswordless = "passwordless"
)

// WebAuthn errors.
var (
	// ErrWebAuthnUnavailable is returned when the deployment has no relying
	// party configured. WebAuthn cannot be inferred from a request header —
	// the RP ID is what binds a credential to a site, and trusting the Host
	// header for it would let anyone who can reach the server claim to be it.
	ErrWebAuthnUnavailable = errors.New("auth: passkeys are not configured for this deployment")

	// ErrWebAuthnCeremonyExpired is returned for a challenge that is
	// expired, already used, issued for a different purpose, or never issued.
	// One error for all four: a caller must not learn which.
	ErrWebAuthnCeremonyExpired = errors.New("auth: that took too long; start again")

	// ErrWebAuthnRejected is returned when an authenticator's response does
	// not verify.
	ErrWebAuthnRejected = errors.New("auth: that security key was not accepted")

	// ErrWebAuthnNotRegistered is returned when an account has no credential
	// to verify against.
	ErrWebAuthnNotRegistered = errors.New("auth: no security key is registered on this account")
)

// WebAuthnCredential is one registered authenticator.
type WebAuthnCredential struct {
	ID           string
	UserID       string
	CredentialID []byte

	// Credential is the library's own value, and the source of truth for
	// verification. The fields below are derived from it for display.
	Credential webauthn.Credential

	Name         string
	AAGUID       []byte
	Attachment   string
	SignCount    uint32
	CloneWarning bool
	CreatedAt    time.Time
	LastUsedAt   time.Time
}

// WebAuthnStore is the persistence passkeys need.
type WebAuthnStore interface {
	InsertCredential(ctx context.Context, c WebAuthnCredential) error
	ListCredentials(ctx context.Context, userID string) ([]WebAuthnCredential, error)
	CredentialByID(ctx context.Context, id string) (WebAuthnCredential, error)
	// TouchCredential records a use. It takes the CREDENTIAL the verifier
	// left, not just the counter: the library compares an assertion against
	// the counter inside the stored credential, so one that is never
	// rewritten is compared against its registration value for ever and the
	// clone check becomes decoration.
	TouchCredential(ctx context.Context, id string, at time.Time, cred webauthn.Credential, clone bool) error
	RevokeCredential(ctx context.Context, id, userID string, at time.Time) (bool, error)
	RevokeAllCredentials(ctx context.Context, userID string, at time.Time) error

	InsertChallenge(ctx context.Context, id, userID, purpose string, session []byte, now, expires time.Time) error
	ClaimChallenge(ctx context.Context, id, userID, purpose string, now time.Time) ([]byte, error)

	// ClaimLoginChallenge matches on the challenge id alone and returns the
	// user it belongs to. A login has no session yet, so the id is the only
	// thing tying the two halves of the ceremony together.
	ClaimLoginChallenge(ctx context.Context, id string, now time.Time) (userID string, session []byte, err error)

	// ClaimPasswordlessChallenge matches on the id and purpose alone. There
	// is no user to match against: which account it turns out to be is
	// decided by the credential the browser signs with.
	ClaimPasswordlessChallenge(ctx context.Context, id string, now time.Time) (session []byte, err error)
}

// WebAuthnConfig is one deployment's relying party.
type WebAuthnConfig struct {
	// RPDisplayName is what the browser shows in its prompt.
	RPDisplayName string

	// RPID is the domain the credential is bound to. It cannot be inferred
	// from a request: the RP ID is the whole of WebAuthn's origin binding,
	// and taking it from the Host header would let anyone who can reach the
	// server claim to be the site.
	RPID string

	// RPOrigins are the exact origins a ceremony may come from.
	RPOrigins []string
}

// WebAuthnUsers is the single lookup a ceremony needs: the account a
// credential is being registered to, for the name the browser shows in its
// prompt.
//
// Deliberately one method rather than the whole AdminStore. This service
// registers and verifies security keys; it has no business holding the
// method that deletes a user or the one that mints an API key, and a narrow
// interface is what makes that true by construction rather than by review.
// AdminStore satisfies it, so the production wiring is unchanged.
type WebAuthnUsers interface {
	UserByID(ctx context.Context, id string) (User, error)
}

// WebAuthnService is the passkey use cases.
type WebAuthnService struct {
	wa    *webauthn.WebAuthn
	store WebAuthnStore
	users WebAuthnUsers
	clock Clock
	ids   IDGen
}

// NewWebAuthnService builds the service, or returns ErrWebAuthnUnavailable
// when the deployment has not configured a relying party.
func NewWebAuthnService(cfg WebAuthnConfig, store WebAuthnStore, users WebAuthnUsers, clock Clock, ids IDGen) (*WebAuthnService, error) {
	if strings.TrimSpace(cfg.RPID) == "" || len(cfg.RPOrigins) == 0 {
		return nil, ErrWebAuthnUnavailable
	}
	if strings.TrimSpace(cfg.RPDisplayName) == "" {
		return nil, errors.New("auth: NewWebAuthnService requires RPDisplayName — the name shown in the browser's passkey prompt, and there is no generic default that would be right for someone else's deployment")
	}
	if store == nil || users == nil || clock == nil || ids == nil {
		return nil, errors.New("auth: NewWebAuthnService requires a store, a user store, a clock and an ID generator")
	}

	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.RPDisplayName,
		RPID:          cfg.RPID,
		RPOrigins:     cfg.RPOrigins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			// Any authenticator: a platform one and a roaming key are the
			// same credential with a different attachment, and forcing
			// either would rule out half the hardware people already own.
			// PREFERRED, not discouraged. A credential that is not resident
			// cannot be found without being told which account to look in,
			// which is exactly what signing in with a key alone cannot do.
			// Preferred rather than required so a key with no room for one
			// still registers and still works as a second factor — it simply
			// will not appear at the front door.
			ResidentKey: protocol.ResidentKeyRequirementPreferred,
			// User verification PREFERRED, not required. Required would
			// refuse a U2F-era security key that has no PIN or biometric —
			// hardware that is still a perfectly good second factor beside a
			// password, which is what this is.
			UserVerification: protocol.VerificationPreferred,
		},
		Timeouts: webauthn.TimeoutsConfig{
			Login: webauthn.TimeoutConfig{
				Enforce: true, Timeout: WebAuthnChallengeLifetime,
				TimeoutUVD: WebAuthnChallengeLifetime,
			},
			Registration: webauthn.TimeoutConfig{
				Enforce: true, Timeout: WebAuthnChallengeLifetime,
				TimeoutUVD: WebAuthnChallengeLifetime,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("auth: configure passkeys: %w", err)
	}
	return &WebAuthnService{wa: wa, store: store, users: users, clock: clock, ids: ids}, nil
}

// waUser adapts an account to the library's User interface.
//
// WebAuthnID is the USER ID and not the email, deliberately. It is the handle
// the authenticator stores and returns, and the specification requires
// authorization decisions to be made on it — an email is a display name that
// can change, and a credential bound to one would follow the address rather
// than the account.
type waUser struct {
	user  User
	creds []webauthn.Credential
}

func (u waUser) WebAuthnID() []byte { return []byte(u.user.ID) }
func (u waUser) WebAuthnName() string {
	if u.user.Email != "" {
		return u.user.Email
	}
	return u.user.ID
}

func (u waUser) WebAuthnDisplayName() string {
	if strings.TrimSpace(u.user.Name) != "" {
		return u.user.Name
	}
	return u.WebAuthnName()
}
func (u waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// userFor assembles the library's view of an account and its credentials.
func (s *WebAuthnService) userFor(ctx context.Context, userID string) (waUser, []WebAuthnCredential, error) {
	u, err := s.users.UserByID(ctx, userID)
	if err != nil {
		return waUser{}, nil, err
	}
	stored, err := s.store.ListCredentials(ctx, userID)
	if err != nil {
		return waUser{}, nil, fmt.Errorf("auth: read credentials: %w", err)
	}
	creds := make([]webauthn.Credential, 0, len(stored))
	for _, c := range stored {
		creds = append(creds, c.Credential)
	}
	return waUser{user: u, creds: creds}, stored, nil
}

// Ceremony is the server's half of a begin call: what the browser needs, and
// the id that ties the finish back to it.
type Ceremony struct {
	// ChallengeID identifies the stored session data. The client returns it
	// with the authenticator's response.
	ChallengeID string

	// Options is the JSON the browser's navigator.credentials call takes.
	Options json.RawMessage
}

// BeginRegistration starts adding an authenticator to an account.
func (s *WebAuthnService) BeginRegistration(ctx context.Context, actor Identity) (Ceremony, error) {
	if actor.UserID == "" {
		return Ceremony{}, ErrNotPermitted
	}
	u, existing, err := s.userFor(ctx, actor.UserID)
	if err != nil {
		return Ceremony{}, err
	}

	// Excluding what is already registered is what makes the browser say
	// "you already have a key for this site" instead of silently creating a
	// second credential on the same authenticator.
	exclude := make([]protocol.CredentialDescriptor, 0, len(existing))
	for _, c := range existing {
		exclude = append(exclude, c.Credential.Descriptor())
	}

	creation, session, err := s.wa.BeginRegistration(u, webauthn.WithExclusions(exclude))
	if err != nil {
		return Ceremony{}, fmt.Errorf("auth: begin registration: %w", err)
	}
	return s.storeCeremony(ctx, actor.UserID, WebAuthnPurposeRegistration, creation, session)
}

// FinishRegistration verifies the authenticator's response and stores the
// credential.
//
// name is what the list will call it. It is taken from the caller because
// nothing in the response says "YubiKey on my keyring" — the AAGUID names a
// model at best, and three identical models are what a person actually owns.
func (s *WebAuthnService) FinishRegistration(ctx context.Context, actor Identity, challengeID, name string, response []byte) (WebAuthnCredential, error) {
	if actor.UserID == "" {
		return WebAuthnCredential{}, ErrNotPermitted
	}
	session, err := s.claim(ctx, challengeID, actor.UserID, WebAuthnPurposeRegistration)
	if err != nil {
		return WebAuthnCredential{}, err
	}
	u, _, err := s.userFor(ctx, actor.UserID)
	if err != nil {
		return WebAuthnCredential{}, err
	}

	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return WebAuthnCredential{}, ErrWebAuthnRejected
	}
	cred, err := s.wa.CreateCredential(u, session, parsed)
	if err != nil {
		return WebAuthnCredential{}, ErrWebAuthnRejected
	}

	now := s.clock.Now()
	stored := WebAuthnCredential{
		ID:           s.ids.NewID(),
		UserID:       actor.UserID,
		CredentialID: cred.ID,
		Credential:   *cred,
		Name:         strings.TrimSpace(name),
		AAGUID:       cred.Authenticator.AAGUID,
		SignCount:    cred.Authenticator.SignCount,
		CreatedAt:    now,
	}
	if stored.Name == "" {
		stored.Name = "Security key"
	}
	// platform or cross-platform: what makes "this laptop" distinguishable
	// from "the key on your keyring" in a list of three.
	stored.Attachment = string(parsed.AuthenticatorAttachment)

	if err := s.store.InsertCredential(ctx, stored); err != nil {
		return WebAuthnCredential{}, fmt.Errorf("auth: store credential: %w", err)
	}
	return stored, nil
}

// BeginLogin starts the second step of a sign-in for an account with a
// registered authenticator.
//
// The caller has already spent the account's `mfa_token` to get here, which
// is what ADR-0028's "spent on the attempt" rule requires: a failed ceremony
// costs a fresh password authentication rather than another free go at the
// hardware.
func (s *WebAuthnService) BeginLogin(ctx context.Context, userID string) (Ceremony, error) {
	u, existing, err := s.userFor(ctx, userID)
	if err != nil {
		return Ceremony{}, err
	}
	if len(existing) == 0 {
		return Ceremony{}, ErrWebAuthnNotRegistered
	}

	assertion, session, err := s.wa.BeginLogin(u)
	if err != nil {
		return Ceremony{}, fmt.Errorf("auth: begin login: %w", err)
	}
	return s.storeCeremony(ctx, userID, WebAuthnPurposeLogin, assertion, session)
}

// FinishLogin verifies an assertion, records the use, and returns whose login
// it completed.
//
// The user comes from the CHALLENGE, never from the request. A client that
// named its own user id would be choosing whose account to finish signing
// into, which is the whole ceremony defeated by its last step.
func (s *WebAuthnService) FinishLogin(ctx context.Context, challengeID string, response []byte) (string, error) {
	userID, raw, err := s.store.ClaimLoginChallenge(ctx, challengeID, s.clock.Now())
	switch {
	case errors.Is(err, ErrNotFound):
		return "", ErrWebAuthnCeremonyExpired
	case err != nil:
		return "", fmt.Errorf("auth: claim ceremony: %w", err)
	}

	var session webauthn.SessionData
	if err := json.Unmarshal(raw, &session); err != nil {
		return "", fmt.Errorf("auth: decode ceremony: %w", err)
	}

	u, existing, err := s.userFor(ctx, userID)
	if err != nil {
		return "", err
	}

	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return "", ErrWebAuthnRejected
	}
	cred, err := s.wa.ValidateLogin(u, session, parsed)
	if err != nil {
		return "", ErrWebAuthnRejected
	}

	// Find the stored row this credential belongs to, so the use — and the
	// clone warning, if the library raised one — lands on the right one.
	for _, c := range existing {
		if !bytes.Equal(c.CredentialID, cred.ID) {
			continue
		}
		// The clone warning is RECORDED, not acted on. An authenticator that
		// legitimately does not implement the counter produces it too, so
		// refusing outright would lock out working hardware; it is surfaced
		// to the user and to the audit log, and revoking is a human decision.
		if err := s.store.TouchCredential(ctx, c.ID, s.clock.Now(),
			*cred, cred.Authenticator.CloneWarning); err != nil {
			return "", fmt.Errorf("auth: record credential use: %w", err)
		}
		return userID, nil
	}

	// Verified against a credential this account does not hold. Not reachable
	// through the library, which is only offered the ones we gave it, and
	// refused rather than ignored because the alternative is a login nobody
	// can attribute.
	return "", ErrWebAuthnRejected
}

// Credentials lists an account's registered authenticators.
func (s *WebAuthnService) Credentials(ctx context.Context, actor Identity) ([]WebAuthnCredential, error) {
	if actor.UserID == "" {
		return nil, ErrNotPermitted
	}
	return s.store.ListCredentials(ctx, actor.UserID)
}

// RevokeCredential removes one authenticator from the caller's account.
//
// otherFactor reports whether the account keeps a second factor without this
// credential — a confirmed TOTP enrollment, or another key. Revoking the last
// one is refused, because it is the silent path back to a password-only
// account: the person means "I lost that key", not "turn two-factor off", and
// the two should not be the same gesture.
func (s *WebAuthnService) RevokeCredential(ctx context.Context, actor Identity, id string, otherFactor bool) error {
	if actor.UserID == "" {
		return ErrNotPermitted
	}
	existing, err := s.store.ListCredentials(ctx, actor.UserID)
	if err != nil {
		return fmt.Errorf("auth: read credentials: %w", err)
	}

	// Does this account actually hold the key being revoked? Asked FIRST,
	// because the last-credential guard below counts what is there — and
	// with nothing there, "you cannot remove your last key" is both wrong
	// and confusing for somebody who has none.
	held := false
	for _, c := range existing {
		if c.ID == id {
			held = true
			break
		}
	}
	if !held {
		return ErrNotFound
	}

	// Removing the LAST factor an account has needs a step-up, not a refusal.
	//
	// Refusing was the old behaviour and it made the first key permanent: on
	// a deployment with no MFA_SECRET_KEY there is no other factor to fall
	// back to, so nothing the owner could do would ever remove it. It was
	// also inconsistent with POST /auth/mfa/disable, which lets somebody
	// switch TOTP off entirely once they have confirmed their password —
	// the same reduction in protection, allowed there and forbidden here.
	//
	// What the guard is actually for is making sure this is deliberate and
	// recent, which is exactly what a step-up proves. The account still ends
	// up password-only; it just cannot get there by accident, or by someone
	// who found an unlocked machine.
	if len(existing) <= 1 && !otherFactor && !actor.SteppedUp(s.clock.Now()) {
		return ErrStepUpRequired
	}

	revoked, err := s.store.RevokeCredential(ctx, id, actor.UserID, s.clock.Now())
	if err != nil {
		return fmt.Errorf("auth: revoke credential: %w", err)
	}
	if !revoked {
		return ErrNotFound
	}
	return nil
}

// HasCredentials reports whether an account can authenticate with a key.
//
// A read failure answers TRUE, the same way RequiresSecondFactor does and for
// the same reason: answering false would sign somebody in past a factor they
// deliberately switched on, which is the one error here that cannot be walked
// back.
func (s *WebAuthnService) HasCredentials(ctx context.Context, userID string) bool {
	creds, err := s.store.ListCredentials(ctx, userID)
	if err != nil {
		return true
	}
	return len(creds) > 0
}

// BeginPasswordlessLogin starts a sign-in that names no account.
//
// The browser picks the credential and the credential says who it belongs
// to, so nothing here identifies anybody — which is the point. A front door
// that took an email first would confirm which addresses have accounts.
//
// User verification is REQUIRED, unlike every other ceremony in this file.
// Elsewhere a key is the SECOND factor and the password was the first, so a
// U2F-era key with no PIN or biometric is still a real second factor. Here
// there is no password, and a key that only proves possession would make
// this one factor — a found key would be a sign-in. Requiring verification
// is what keeps a passwordless login two factors: the key, and the PIN or
// biometric that unlocks it.
func (s *WebAuthnService) BeginPasswordlessLogin(ctx context.Context) (Ceremony, error) {
	assertion, session, err := s.wa.BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		return Ceremony{}, fmt.Errorf("auth: begin passwordless login: %w", err)
	}
	return s.storeCeremony(ctx, "", WebAuthnPurposePasswordless, assertion, session)
}

// FinishPasswordlessLogin verifies the assertion and says whose it was.
//
// The account comes out of the ceremony, never out of the request. The
// handler resolves the user handle the authenticator returned — which is the
// account id this service wrote at registration — and the library then
// checks the assertion against that account's own credentials.
func (s *WebAuthnService) FinishPasswordlessLogin(ctx context.Context, challengeID string, response []byte) (string, error) {
	raw, err := s.store.ClaimPasswordlessChallenge(ctx, challengeID, s.clock.Now())
	switch {
	case errors.Is(err, ErrNotFound):
		return "", ErrWebAuthnCeremonyExpired
	case err != nil:
		return "", fmt.Errorf("auth: claim ceremony: %w", err)
	}

	var session webauthn.SessionData
	if err := json.Unmarshal(raw, &session); err != nil {
		return "", fmt.Errorf("auth: decode ceremony: %w", err)
	}

	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return "", ErrWebAuthnRejected
	}

	var (
		userID   string
		existing []WebAuthnCredential
	)
	handler := func(_, userHandle []byte) (webauthn.User, error) {
		u, creds, uErr := s.userFor(ctx, string(userHandle))
		if uErr != nil {
			return nil, uErr
		}
		userID, existing = string(userHandle), creds
		return u, nil
	}

	cred, err := s.wa.ValidateDiscoverableLogin(handler, session, parsed)
	if err != nil {
		return "", ErrWebAuthnRejected
	}

	for _, c := range existing {
		if !bytes.Equal(c.CredentialID, cred.ID) {
			continue
		}
		if err := s.store.TouchCredential(ctx, c.ID, s.clock.Now(),
			*cred, cred.Authenticator.CloneWarning); err != nil {
			return "", fmt.Errorf("auth: record credential use: %w", err)
		}
		return userID, nil
	}
	return "", ErrWebAuthnRejected
}

// BeginStepUp starts a step-up ceremony for a caller who already holds a
// session.
//
// Separate from BeginLogin because the two are claimed differently: a login
// challenge is matched on its id alone, since there is no session to tie it
// to, while this one is bound to the account that asked for it. That binding
// is what stops a challenge issued to one signed-in user being answered on
// behalf of another.
func (s *WebAuthnService) BeginStepUp(ctx context.Context, userID string) (Ceremony, error) {
	u, existing, err := s.userFor(ctx, userID)
	if err != nil {
		return Ceremony{}, err
	}
	if len(existing) == 0 {
		return Ceremony{}, ErrWebAuthnNotRegistered
	}

	assertion, session, err := s.wa.BeginLogin(u)
	if err != nil {
		return Ceremony{}, fmt.Errorf("auth: begin step-up: %w", err)
	}
	return s.storeCeremony(ctx, userID, WebAuthnPurposeStepUp, assertion, session)
}

// FinishStepUp verifies the assertion against the account that began it.
//
// userID comes from the caller's session, never from the request, and the
// challenge is claimed against BOTH it and the step-up purpose — so a
// challenge belonging to someone else, or one minted for a login, is refused
// as though it had expired.
func (s *WebAuthnService) FinishStepUp(ctx context.Context, userID, challengeID string, response []byte) error {
	raw, err := s.store.ClaimChallenge(ctx, challengeID, userID, WebAuthnPurposeStepUp, s.clock.Now())
	switch {
	case errors.Is(err, ErrNotFound):
		return ErrWebAuthnCeremonyExpired
	case err != nil:
		return fmt.Errorf("auth: claim ceremony: %w", err)
	}

	var session webauthn.SessionData
	if err := json.Unmarshal(raw, &session); err != nil {
		return fmt.Errorf("auth: decode ceremony: %w", err)
	}

	u, existing, err := s.userFor(ctx, userID)
	if err != nil {
		return err
	}

	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return ErrWebAuthnRejected
	}
	cred, err := s.wa.ValidateLogin(u, session, parsed)
	if err != nil {
		return ErrWebAuthnRejected
	}

	// The counter advances here too. A step-up is a real use of the key, and
	// a use that did not move the counter would leave a gap the clone check
	// reads as a cloned authenticator later.
	for _, c := range existing {
		if !bytes.Equal(c.CredentialID, cred.ID) {
			continue
		}
		if err := s.store.TouchCredential(ctx, c.ID, s.clock.Now(),
			*cred, cred.Authenticator.CloneWarning); err != nil {
			return fmt.Errorf("auth: record credential use: %w", err)
		}
		return nil
	}
	return ErrWebAuthnRejected
}

// RevokeAllFor removes every key on an account.
//
// The administrator's lockout valve, and it takes no actor: the permission
// check belongs to the use case that calls it (MFAService.ClearFactorFor),
// which is also the one that knows the target is in the caller's
// organization. Duplicating the check here would mean two places to get it
// right and two places to get it wrong.
//
// Unlike RevokeCredential there is no last-credential guard, and there must
// not be: the whole point of the valve is to return an account that nobody
// can get into to one its owner can.
func (s *WebAuthnService) RevokeAllFor(ctx context.Context, userID string) error {
	if err := s.store.RevokeAllCredentials(ctx, userID, s.clock.Now()); err != nil {
		return fmt.Errorf("auth: revoke all credentials: %w", err)
	}
	return nil
}

// storeCeremony persists the session data and returns what the browser needs.
func (s *WebAuthnService) storeCeremony(ctx context.Context, userID, purpose string, options any, session *webauthn.SessionData) (Ceremony, error) {
	raw, err := json.Marshal(session)
	if err != nil {
		return Ceremony{}, fmt.Errorf("auth: encode ceremony: %w", err)
	}
	opts, err := json.Marshal(options)
	if err != nil {
		return Ceremony{}, fmt.Errorf("auth: encode options: %w", err)
	}

	id := s.ids.NewID()
	now := s.clock.Now()
	if err := s.store.InsertChallenge(ctx, id, userID, purpose, raw, now, now.Add(WebAuthnChallengeLifetime)); err != nil {
		return Ceremony{}, fmt.Errorf("auth: store ceremony: %w", err)
	}
	return Ceremony{ChallengeID: id, Options: opts}, nil
}

// claim spends a challenge and returns its session data.
func (s *WebAuthnService) claim(ctx context.Context, id, userID, purpose string) (webauthn.SessionData, error) {
	raw, err := s.store.ClaimChallenge(ctx, id, userID, purpose, s.clock.Now())
	switch {
	case errors.Is(err, ErrNotFound):
		return webauthn.SessionData{}, ErrWebAuthnCeremonyExpired
	case err != nil:
		return webauthn.SessionData{}, fmt.Errorf("auth: claim ceremony: %w", err)
	}
	var session webauthn.SessionData
	if err := json.Unmarshal(raw, &session); err != nil {
		return webauthn.SessionData{}, fmt.Errorf("auth: decode ceremony: %w", err)
	}
	return session, nil
}
