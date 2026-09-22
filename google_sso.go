package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Google Sign-In (OpenID Connect), as an alternative first factor beside a
// password. It ships in the same shape as passkeys and TOTP: a separate
// service, held by the Authenticator through a narrow interface, wired in
// only when a deployment configures it (WithGoogleSSO).
//
// It is deliberately NOT treated as satisfying the account's own second
// factor. A passkey ceremony proves possession of specific hardware and
// (per WebAuthnConfig) typically user verification, which is why
// CompletePasswordlessLogin skips RequiresSecondFactor. A Google sign-in
// proves only that the browser currently holds a live Google session —
// which, from this package's point of view, is a bearer credential no
// stronger than a password. So it is treated as exactly that: a stand-in
// for the password step, still gated by whatever second factor the account
// has configured here.

// GoogleChallengeLifetime is how long a sign-in may take between the
// redirect to Google and the callback.
//
// Longer than WebAuthnChallengeLifetime's two minutes: a WebAuthn ceremony
// is "find a key and touch it", while this may include Google's own
// account picker, a password prompt and its own second factor before the
// browser ever comes back.
const GoogleChallengeLifetime = 10 * time.Minute

// Google SSO errors. As with WebAuthn, failure detail is collapsed into a
// small set of sentinels: a caller must not learn WHY a token was rejected,
// only that it was.
var (
	// ErrGoogleSSOUnavailable is returned when the deployment has not
	// configured Google sign-in.
	ErrGoogleSSOUnavailable = errors.New("auth: Google sign-in is not configured for this deployment")

	// ErrGoogleCeremonyExpired is returned for a state value that is
	// expired, already used, or never issued. Same one-error-for-every-cause
	// reasoning as ErrWebAuthnCeremonyExpired.
	ErrGoogleCeremonyExpired = errors.New("auth: that took too long; start again")

	// ErrGoogleTokenRejected is returned when the authorization code could
	// not be exchanged, or the ID token that came back does not verify:
	// wrong signature, wrong audience, wrong issuer, expired, or a nonce
	// that does not match the one this sign-in started with.
	ErrGoogleTokenRejected = errors.New("auth: that Google sign-in was not accepted")

	// ErrGoogleEmailNotVerified is returned when Google's own
	// "email_verified" claim is false. This package will not link or
	// resolve an account from an email Google itself has not vouched for —
	// trusting it would let anyone who can set any address as their Google
	// profile email sign in as whoever holds it here.
	ErrGoogleEmailNotVerified = errors.New("auth: Google has not verified that email address")

	// ErrGoogleHostedDomainDenied is returned when GoogleSSOConfig.HostedDomain
	// is set and the signing-in account is not a member of it.
	ErrGoogleHostedDomainDenied = errors.New("auth: that Google account is not in an allowed organization")

	// ErrGoogleAccountNotFound is returned when the Google account is not
	// already linked to a user here, and no existing account has a matching,
	// Google-verified email to link on first sign-in.
	//
	// This package never creates an account on its own. Which organization a
	// brand-new user belongs to and which role they start with are policy
	// decisions specific to the deployment, not something an unauthenticated
	// OAuth callback should be trusted to decide — the same reasoning that
	// keeps AdminStore.CreateUser behind an authenticated, permitted actor.
	// A caller that wants self-service sign-up handles this error by
	// provisioning the account itself (through Admin.CreateUser, with
	// whatever role and org policy it chooses) and retrying.
	ErrGoogleAccountNotFound = errors.New("auth: no account is linked to that Google account")
)

// FactorGoogle names Google as the credential that completed a login, the
// same way FactorPasskey does for a passwordless one. Recorded via
// issueSession's used parameter, not through the two-step MFA path.
const FactorGoogle FactorKind = "google"

// GoogleSSOStore is the persistence Google sign-in needs, beyond the
// account lookups GoogleSSOUsers already covers.
//
// Separate from Store and AdminStore for the reason WebAuthnStore is
// separate from them: this is a distinct blast radius, and a type that only
// holds this interface cannot touch a session, a password hash or a role.
type GoogleSSOStore interface {
	// UserByGoogleSubject returns the account already linked to this
	// Google account's stable subject id, or ErrNotFound if none is linked
	// yet.
	UserByGoogleSubject(ctx context.Context, subject string) (User, error)

	// LinkGoogleAccount records that userID owns this Google subject, so
	// the next sign-in resolves by UserByGoogleSubject and does not need to
	// fall back to an email match. Called once, the first time an existing
	// account is matched by email.
	LinkGoogleAccount(ctx context.Context, userID, subject string, at time.Time) error

	// InsertGoogleChallenge persists the nonce and PKCE verifier for one
	// sign-in attempt, keyed by id.
	InsertGoogleChallenge(ctx context.Context, id, nonce, codeVerifier string, now, expires time.Time) error

	// ClaimGoogleChallenge spends the state value from the callback and
	// returns what BeginLogin stored for it, or ErrNotFound for an id that
	// is expired, already used, or was never issued. Claimed rather than
	// merely read, for the same reason WebAuthn's challenges are: a state
	// value good for more than one callback would let a leaked or replayed
	// redirect be completed twice.
	ClaimGoogleChallenge(ctx context.Context, id string, now time.Time) (nonce, codeVerifier string, err error)
}

// GoogleSSOUsers is the one lookup first-time linking needs: the account a
// verified Google email might already belong to.
//
// One method, not the whole Store or AdminStore, for the same reason
// WebAuthnUsers is narrowed: this service resolves an identity, it does not
// hold the methods that would let it create, disable or delete one.
// AdminStore and Store both satisfy it, so either can wire this in
// unchanged.
type GoogleSSOUsers interface {
	UserByEmail(ctx context.Context, email string) (User, error)
}

// GoogleSSOConfig is one deployment's Google OAuth client.
type GoogleSSOConfig struct {
	// ClientID and ClientSecret are the OAuth 2.0 credentials from Google
	// Cloud Console.
	ClientID     string
	ClientSecret string

	// RedirectURL is where Google sends the browser back to. It must match
	// a URL registered against ClientID exactly, character for character —
	// Google will not check state or origin for you, so a client-supplied
	// redirect is not a substitute for this being fixed configuration.
	RedirectURL string

	// HostedDomain, when set, restricts sign-in to Google Workspace
	// accounts in this domain (the ID token's "hd" claim). Empty allows any
	// Google account, personal or otherwise — the right default for a
	// product that is not itself scoped to one organization's Workspace.
	HostedDomain string
}

// GoogleLoginStart is the server's half of beginning a Google sign-in: the
// URL to send the browser to, and the id the callback must come back with.
//
// Named separately from webauthn.go's Ceremony, rather than reusing it,
// because Ceremony.Options is JSON meant for navigator.credentials and
// repurposing it for a redirect URL would make that field mean two
// different things depending which service returned it.
type GoogleLoginStart struct {
	// State identifies the stored nonce and PKCE verifier. The callback
	// must return it unchanged as the "state" query parameter.
	State string

	// RedirectURL is where to send the browser to begin the sign-in.
	RedirectURL string
}

// GoogleSSOService is the Google sign-in use cases: starting the redirect
// and resolving the callback to an account.
type GoogleSSOService struct {
	oauth        *oauth2.Config
	verifier     *oidc.IDTokenVerifier
	store        GoogleSSOStore
	users        GoogleSSOUsers
	clock        Clock
	ids          IDGen
	hostedDomain string
}

// NewGoogleSSOService builds the service, discovering Google's OpenID
// Connect configuration over the network. Returns ErrGoogleSSOUnavailable
// when the deployment has not configured a client.
func NewGoogleSSOService(ctx context.Context, cfg GoogleSSOConfig, store GoogleSSOStore, users GoogleSSOUsers, clock Clock, ids IDGen) (*GoogleSSOService, error) {
	if strings.TrimSpace(cfg.ClientID) == "" || strings.TrimSpace(cfg.ClientSecret) == "" || strings.TrimSpace(cfg.RedirectURL) == "" {
		return nil, ErrGoogleSSOUnavailable
	}
	if store == nil || users == nil || clock == nil || ids == nil {
		return nil, errors.New("auth: NewGoogleSSOService requires a store, a user store, a clock and an ID generator")
	}

	provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil {
		return nil, fmt.Errorf("auth: discover Google's OpenID configuration: %w", err)
	}

	return &GoogleSSOService{
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, oidc.ScopeEmail, oidc.ScopeProfile},
		},
		verifier:     provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		store:        store,
		users:        users,
		clock:        clock,
		ids:          ids,
		hostedDomain: strings.TrimSpace(cfg.HostedDomain),
	}, nil
}

// BeginLogin starts a Google sign-in.
//
// Like BeginPasswordlessLogin, no credential of any kind is required to
// call it: the state it returns names no account, and is useless to anyone
// but the browser it was issued to without also holding a Google session
// for the right account.
func (s *GoogleSSOService) BeginLogin(ctx context.Context) (GoogleLoginStart, error) {
	nonce, err := randomOpaqueString()
	if err != nil {
		return GoogleLoginStart{}, fmt.Errorf("auth: start Google sign-in: %w", err)
	}
	verifier := oauth2.GenerateVerifier()

	id := s.ids.NewID()
	now := s.clock.Now()
	if err := s.store.InsertGoogleChallenge(ctx, id, nonce, verifier, now, now.Add(GoogleChallengeLifetime)); err != nil {
		return GoogleLoginStart{}, fmt.Errorf("auth: persist Google sign-in state: %w", err)
	}

	opts := []oauth2.AuthCodeOption{
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
	}
	if s.hostedDomain != "" {
		opts = append(opts, oauth2.SetAuthURLParam("hd", s.hostedDomain))
	}

	return GoogleLoginStart{
		State:       id,
		RedirectURL: s.oauth.AuthCodeURL(id, opts...),
	}, nil
}

// googleClaims is the subset of the ID token's claims this package reads.
type googleClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	HostedDomain  string `json:"hd"`
}

// FinishLogin verifies the callback and resolves it to an account.
//
// It does not issue a session — like PasskeyAuthenticator.FinishLogin, it
// answers only "which account", and Authenticator.CompleteGoogleLogin
// decides the rest: whether the account is disabled, whether a second
// factor is still owed, and what session to mint.
func (s *GoogleSSOService) FinishLogin(ctx context.Context, state, code string) (string, error) {
	now := s.clock.Now()
	nonce, verifier, err := s.store.ClaimGoogleChallenge(ctx, state, now)
	switch {
	case errors.Is(err, ErrNotFound):
		return "", ErrGoogleCeremonyExpired
	case err != nil:
		return "", fmt.Errorf("auth: claim Google sign-in state: %w", err)
	}

	token, err := s.oauth.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return "", ErrGoogleTokenRejected
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return "", ErrGoogleTokenRejected
	}
	idToken, err := s.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return "", ErrGoogleTokenRejected
	}
	// The library verifies the token's signature, issuer, audience and
	// expiry, but explicitly leaves the nonce for the caller (its own doc
	// comment says so) — this is the check that ties the token back to THIS
	// sign-in and not one replayed from another.
	if idToken.Nonce != nonce {
		return "", ErrGoogleTokenRejected
	}

	var claims googleClaims
	if err := idToken.Claims(&claims); err != nil {
		return "", fmt.Errorf("auth: read Google claims: %w", err)
	}

	if s.hostedDomain != "" && claims.HostedDomain != s.hostedDomain {
		return "", ErrGoogleHostedDomainDenied
	}

	subject := idToken.Subject

	switch u, err := s.store.UserByGoogleSubject(ctx, subject); {
	case err == nil:
		return u.ID, nil
	case !errors.Is(err, ErrNotFound):
		return "", fmt.Errorf("auth: look up linked Google account: %w", err)
	}

	// No link yet. Google-verified email is the only signal this package
	// will link an existing account on: an unverified email is an assertion
	// from whoever holds the Google account, not from Google.
	if !claims.EmailVerified {
		return "", ErrGoogleEmailNotVerified
	}

	existing, err := s.users.UserByEmail(ctx, strings.TrimSpace(claims.Email))
	switch {
	case errors.Is(err, ErrNotFound):
		return "", ErrGoogleAccountNotFound
	case err != nil:
		return "", fmt.Errorf("auth: look up account by email: %w", err)
	}

	if err := s.store.LinkGoogleAccount(ctx, existing.ID, subject, now); err != nil {
		return "", fmt.Errorf("auth: link Google account: %w", err)
	}
	return existing.ID, nil
}

// randomOpaqueString returns 256 bits of randomness, base64url-encoded —
// the same construction NewSessionToken uses, for an OIDC nonce rather than
// a bearer credential: it is never itself a secret that grants access, only
// a value the ID token must echo back.
func randomOpaqueString() (string, error) {
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("auth: read entropy: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
