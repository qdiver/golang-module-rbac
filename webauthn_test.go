package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	auth "github.com/qdiver/golang-module-rbac"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qdiver/golang-module-rbac/webauthntest"
)

// --- fake store -------------------------------------------------------------

type fakeWebAuthnStore struct {
	creds        map[string]auth.WebAuthnCredential
	challenges   map[string]waChallenge
	listErr      error
	insertErr    error
	revokeAllErr error
}

type waChallenge struct {
	userID  string
	purpose string
	session []byte
	expires time.Time
	used    bool
}

func newFakeWebAuthnStore() *fakeWebAuthnStore {
	return &fakeWebAuthnStore{
		creds:      map[string]auth.WebAuthnCredential{},
		challenges: map[string]waChallenge{},
	}
}

func (f *fakeWebAuthnStore) InsertCredential(_ context.Context, c auth.WebAuthnCredential) error {
	if f.insertErr != nil {
		return f.insertErr
	}
	f.creds[c.ID] = c
	return nil
}

func (f *fakeWebAuthnStore) ListCredentials(_ context.Context, userID string) ([]auth.WebAuthnCredential, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := []auth.WebAuthnCredential{}
	for _, c := range f.creds {
		if c.UserID == userID {
			out = append(out, c)
		}
	}
	return out, nil
}

func (f *fakeWebAuthnStore) CredentialByID(_ context.Context, id string) (auth.WebAuthnCredential, error) {
	c, ok := f.creds[id]
	if !ok {
		return auth.WebAuthnCredential{}, auth.ErrNotFound
	}
	return c, nil
}

func (f *fakeWebAuthnStore) TouchCredential(
	_ context.Context, id string, at time.Time, cred webauthn.Credential, clone bool,
) error {
	c := f.creds[id]
	c.LastUsedAt = at
	// The credential is stored back, exactly as the real store does: it is
	// what the verifier compares the NEXT assertion's counter against.
	c.Credential = cred
	c.SignCount = cred.Authenticator.SignCount
	c.CloneWarning = c.CloneWarning || clone
	f.creds[id] = c
	return nil
}

func (f *fakeWebAuthnStore) RevokeCredential(_ context.Context, id, userID string, _ time.Time) (bool, error) {
	c, ok := f.creds[id]
	if !ok || c.UserID != userID {
		return false, nil
	}
	delete(f.creds, id)
	return true, nil
}

func (f *fakeWebAuthnStore) RevokeAllCredentials(_ context.Context, userID string, _ time.Time) error {
	if f.revokeAllErr != nil {
		return f.revokeAllErr
	}
	for id, c := range f.creds {
		if c.UserID == userID {
			delete(f.creds, id)
		}
	}
	return nil
}

func (f *fakeWebAuthnStore) InsertChallenge(_ context.Context, id, userID, purpose string, session []byte, _, expires time.Time) error {
	f.challenges[id] = waChallenge{userID: userID, purpose: purpose, session: session, expires: expires}
	return nil
}

func (f *fakeWebAuthnStore) ClaimChallenge(_ context.Context, id, userID, purpose string, now time.Time) ([]byte, error) {
	c, ok := f.challenges[id]
	if !ok || c.used || c.userID != userID || c.purpose != purpose || !now.Before(c.expires) {
		return nil, auth.ErrNotFound
	}
	c.used = true
	f.challenges[id] = c
	return c.session, nil
}

func (f *fakeWebAuthnStore) ClaimLoginChallenge(_ context.Context, id string, now time.Time) (string, []byte, error) {
	c, ok := f.challenges[id]
	if !ok || c.used || c.purpose != auth.WebAuthnPurposeLogin || !now.Before(c.expires) {
		return "", nil, auth.ErrNotFound
	}
	c.used = true
	f.challenges[id] = c
	return c.userID, c.session, nil
}

func (f *fakeWebAuthnStore) ClaimPasswordlessChallenge(_ context.Context, id string, now time.Time) ([]byte, error) {
	c, ok := f.challenges[id]
	if !ok || c.used || c.purpose != auth.WebAuthnPurposePasswordless || !now.Before(c.expires) {
		return nil, auth.ErrNotFound
	}
	c.used = true
	f.challenges[id] = c
	return c.session, nil
}

// --- harness ----------------------------------------------------------------

var waNow = time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)

func waConfig() auth.WebAuthnConfig {
	return auth.WebAuthnConfig{
		RPDisplayName: "Security Assessment",
		RPID:          "assess.example.com",
		RPOrigins:     []string{"https://assess.example.com"},
	}
}

func newWebAuthnFixture(t *testing.T) (*auth.WebAuthnService, *fakeWebAuthnStore, *fakeAdminStore) {
	t.Helper()
	store := newFakeWebAuthnStore()
	users := newFakeAdminStore()
	users.users["u-1"] = auth.User{
		ID: "u-1", OrgID: "org-1", Email: "person@example.com", Name: "A Person", Role: auth.RoleAdmin,
	}
	svc, err := auth.NewWebAuthnService(waConfig(), store, users, stubClock{waNow}, &stubIDs{})
	require.NoError(t, err)
	return svc, store, users
}

func waActor() auth.Identity {
	return auth.Identity{UserID: "u-1", OrgID: "org-1", Role: auth.RoleAdmin, Email: "person@example.com"}
}

// --- tests ------------------------------------------------------------------

// TestPasskeysAreOffWithoutARelyingParty.
//
// The RP ID cannot be inferred from a request: it is the whole of WebAuthn's
// origin binding, and taking it from the Host header would let anyone who can
// reach the server claim to be the site. So an unconfigured deployment gets
// the feature switched OFF rather than guessed at.
func TestPasskeysAreOffWithoutARelyingParty(t *testing.T) {
	t.Parallel()

	store, users := newFakeWebAuthnStore(), newFakeAdminStore()

	noID := waConfig()
	noID.RPID = ""
	_, err := auth.NewWebAuthnService(noID, store, users, stubClock{waNow}, &stubIDs{})
	assert.ErrorIs(t, err, auth.ErrWebAuthnUnavailable)

	noOrigins := waConfig()
	noOrigins.RPOrigins = nil
	_, err = auth.NewWebAuthnService(noOrigins, store, users, stubClock{waNow}, &stubIDs{})
	assert.ErrorIs(t, err, auth.ErrWebAuthnUnavailable)
}

// TestBeginRegistrationIssuesAChallengeTheBrowserCanUse.
func TestBeginRegistrationIssuesAChallengeTheBrowserCanUse(t *testing.T) {
	t.Parallel()

	svc, store, _ := newWebAuthnFixture(t)
	c, err := svc.BeginRegistration(context.Background(), waActor())
	require.NoError(t, err)

	assert.NotEmpty(t, c.ChallengeID)
	require.Len(t, store.challenges, 1, "the ceremony was not stored server-side")

	held := store.challenges[c.ChallengeID]
	assert.Equal(t, auth.WebAuthnPurposeRegistration, held.purpose)
	assert.Equal(t, waNow.Add(auth.WebAuthnChallengeLifetime), held.expires)

	// The options carry the relying party the deployment configured, not one
	// derived from a request.
	var opts struct {
		PublicKey struct {
			RP struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"rp"`
			User struct {
				ID string `json:"id"`
			} `json:"user"`
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	require.NoError(t, json.Unmarshal(c.Options, &opts))
	assert.Equal(t, "assess.example.com", opts.PublicKey.RP.ID)
	assert.Equal(t, "Security Assessment", opts.PublicKey.RP.Name)
	assert.NotEmpty(t, opts.PublicKey.Challenge, "no challenge was issued")
	assert.NotEmpty(t, opts.PublicKey.User.ID)
}

// TestTheUserHandleIsTheAccountIDNotTheEmail.
//
// The handle is what the authenticator stores and returns, and the
// specification requires authorization decisions to be made on it. An email
// is a display name that can change, and a credential bound to one would
// follow the address rather than the account.
func TestTheUserHandleIsTheAccountIDNotTheEmail(t *testing.T) {
	t.Parallel()

	svc, _, _ := newWebAuthnFixture(t)
	c, err := svc.BeginRegistration(context.Background(), waActor())
	require.NoError(t, err)

	assert.NotContains(t, string(c.Options), "person@example.com\",\"id",
		"the user handle looks like an email address")
	// The email may appear as the display name; the handle must be the id.
	var opts struct {
		PublicKey struct {
			User struct {
				ID          string `json:"id"`
				Name        string `json:"name"`
				DisplayName string `json:"displayName"`
			} `json:"user"`
		} `json:"publicKey"`
	}
	require.NoError(t, json.Unmarshal(c.Options, &opts))
	assert.Equal(t, "person@example.com", opts.PublicKey.User.Name)
	assert.Equal(t, "A Person", opts.PublicKey.User.DisplayName)
	assert.NotEqual(t, "person@example.com", opts.PublicKey.User.ID)
}

// TestARegistrationChallengeCannotCompleteALogin.
//
// Registration proves possession of a NEW key. Accepting that as a login
// would let anyone who can register sign in as somebody else.
func TestARegistrationChallengeCannotCompleteALogin(t *testing.T) {
	t.Parallel()

	svc, store, _ := newWebAuthnFixture(t)
	c, err := svc.BeginRegistration(context.Background(), waActor())
	require.NoError(t, err)

	_, _, err = store.ClaimLoginChallenge(context.Background(), c.ChallengeID, waNow)
	assert.ErrorIs(t, err, auth.ErrNotFound,
		"a registration challenge was claimable as a login")
}

// TestAChallengeIsSingleUseAndExpires.
func TestAChallengeIsSingleUseAndExpires(t *testing.T) {
	t.Parallel()

	svc, store, _ := newWebAuthnFixture(t)
	c, err := svc.BeginRegistration(context.Background(), waActor())
	require.NoError(t, err)

	_, err = store.ClaimChallenge(context.Background(), c.ChallengeID, "u-1",
		auth.WebAuthnPurposeRegistration, waNow)
	require.NoError(t, err)

	// Spent.
	_, err = store.ClaimChallenge(context.Background(), c.ChallengeID, "u-1",
		auth.WebAuthnPurposeRegistration, waNow)
	assert.ErrorIs(t, err, auth.ErrNotFound)

	// And a fresh one is no good once the window has passed.
	c2, err := svc.BeginRegistration(context.Background(), waActor())
	require.NoError(t, err)
	_, err = store.ClaimChallenge(context.Background(), c2.ChallengeID, "u-1",
		auth.WebAuthnPurposeRegistration, waNow.Add(auth.WebAuthnChallengeLifetime+time.Second))
	assert.ErrorIs(t, err, auth.ErrNotFound)
}

// TestFinishingWithAnExpiredCeremonyIsRefusedWithoutDistinction.
func TestFinishingWithAnExpiredCeremonyIsRefusedWithoutDistinction(t *testing.T) {
	t.Parallel()

	svc, _, _ := newWebAuthnFixture(t)

	_, err := svc.FinishRegistration(context.Background(), waActor(), "never-issued", "Key", []byte("{}"))
	assert.ErrorIs(t, err, auth.ErrWebAuthnCeremonyExpired)

	_, err = svc.FinishLogin(context.Background(), "never-issued", []byte("{}"))
	assert.ErrorIs(t, err, auth.ErrWebAuthnCeremonyExpired)
}

// TestLoginNeedsARegisteredKey. Offering a ceremony to an account with no
// credential would ask somebody to touch a key that could never verify.
func TestLoginNeedsARegisteredKey(t *testing.T) {
	t.Parallel()

	svc, _, _ := newWebAuthnFixture(t)
	_, err := svc.BeginLogin(context.Background(), "u-1")
	assert.ErrorIs(t, err, auth.ErrWebAuthnNotRegistered)
}

// TestRevokingTheLastKeyNeedsAStepUp.
//
// Not a refusal: refusing made the first key PERMANENT on a deployment with
// no other factor available, and contradicted /auth/mfa/disable, which
// allows the same reduction in protection after a password confirmation.
// What the guard is for is that the gesture be deliberate and recent, and a
// step-up is what proves that.
func TestRevokingTheLastKeyNeedsAStepUp(t *testing.T) {
	t.Parallel()

	svc, store, _ := newWebAuthnFixture(t)
	store.creds["c-1"] = auth.WebAuthnCredential{ID: "c-1", UserID: "u-1", Name: "Only key"}

	err := svc.RevokeCredential(context.Background(), waActor(), "c-1", false)
	assert.ErrorIs(t, err, auth.ErrStepUpRequired)
	assert.Len(t, store.creds, 1, "the last key was revoked without a step-up")

	// With an authenticator app still on the account, it is just a key.
	require.NoError(t, svc.RevokeCredential(context.Background(), waActor(), "c-1", true))
	assert.Empty(t, store.creds)
}

// TestAStepUpRemovesTheLastKey — the way out that did not exist before.
func TestAStepUpRemovesTheLastKey(t *testing.T) {
	t.Parallel()

	svc, store, _ := newWebAuthnFixture(t)
	store.creds["c-1"] = auth.WebAuthnCredential{ID: "c-1", UserID: "u-1", Name: "Only key"}

	actor := waActor()
	actor.SteppedUpAt = waNow.Add(-time.Minute)

	require.NoError(t, svc.RevokeCredential(context.Background(), actor, "c-1", false))
	assert.Empty(t, store.creds)
}

// TestAStaleStepUpDoesNotRemoveTheLastKey. The window is the control: a
// machine left unlocked an hour ago is not a standing grant to strip the
// account's last factor.
func TestAStaleStepUpDoesNotRemoveTheLastKey(t *testing.T) {
	t.Parallel()

	svc, store, _ := newWebAuthnFixture(t)
	store.creds["c-1"] = auth.WebAuthnCredential{ID: "c-1", UserID: "u-1", Name: "Only key"}

	actor := waActor()
	actor.SteppedUpAt = waNow.Add(-auth.StepUpWindow - time.Second)

	assert.ErrorIs(t, svc.RevokeCredential(context.Background(), actor, "c-1", false), auth.ErrStepUpRequired)
	assert.Len(t, store.creds, 1)
}

// TestAStepUpIsNotNeededToRemoveOneOfSeveral — the prompt belongs on the
// gesture that reduces protection, not on every removal.
func TestAStepUpIsNotNeededToRemoveOneOfSeveral(t *testing.T) {
	t.Parallel()

	svc, store, _ := newWebAuthnFixture(t)
	store.creds["c-1"] = auth.WebAuthnCredential{ID: "c-1", UserID: "u-1", Name: "Laptop"}
	store.creds["c-2"] = auth.WebAuthnCredential{ID: "c-2", UserID: "u-1", Name: "YubiKey"}

	require.NoError(t, svc.RevokeCredential(context.Background(), waActor(), "c-1", false))
	assert.Len(t, store.creds, 1)
}

// TestRevokingOneOfSeveralIsAllowed.
func TestRevokingOneOfSeveralIsAllowed(t *testing.T) {
	t.Parallel()

	svc, store, _ := newWebAuthnFixture(t)
	store.creds["c-1"] = auth.WebAuthnCredential{ID: "c-1", UserID: "u-1", Name: "Laptop"}
	store.creds["c-2"] = auth.WebAuthnCredential{ID: "c-2", UserID: "u-1", Name: "YubiKey"}

	require.NoError(t, svc.RevokeCredential(context.Background(), waActor(), "c-1", false))
	assert.Len(t, store.creds, 1)
}

// TestRevokingSomebodyElsesKeyIsNotFound. Ownership is enforced by the same
// statement that revokes, so another account's id matches nothing.
func TestRevokingSomebodyElsesKeyIsNotFound(t *testing.T) {
	t.Parallel()

	svc, store, _ := newWebAuthnFixture(t)
	store.creds["c-1"] = auth.WebAuthnCredential{ID: "c-1", UserID: "u-1", Name: "Mine"}
	store.creds["c-2"] = auth.WebAuthnCredential{ID: "c-2", UserID: "u-other", Name: "Theirs"}

	err := svc.RevokeCredential(context.Background(), waActor(), "c-2", true)
	assert.ErrorIs(t, err, auth.ErrNotFound)
	assert.Contains(t, store.creds, "c-2", "another account's key was revoked")
}

// TestHasCredentialsFailsClosed. Answering false on a database hiccup would
// sign somebody in past a factor they deliberately switched on.
func TestHasCredentialsFailsClosed(t *testing.T) {
	t.Parallel()

	svc, store, _ := newWebAuthnFixture(t)
	store.listErr = errors.New("database unavailable")

	assert.True(t, svc.HasCredentials(context.Background(), "u-1"),
		"an unreadable credential list let a login through without a second factor")
}

// TestAnonymousCallersAreRefused.
func TestAnonymousCallersAreRefused(t *testing.T) {
	t.Parallel()

	svc, _, _ := newWebAuthnFixture(t)
	var anon auth.Identity

	_, err := svc.BeginRegistration(context.Background(), anon)
	assert.ErrorIs(t, err, auth.ErrNotPermitted)
	_, err = svc.FinishRegistration(context.Background(), anon, "x", "Key", nil)
	assert.ErrorIs(t, err, auth.ErrNotPermitted)
	_, err = svc.Credentials(context.Background(), anon)
	assert.ErrorIs(t, err, auth.ErrNotPermitted)
	assert.ErrorIs(t, svc.RevokeCredential(context.Background(), anon, "x", true), auth.ErrNotPermitted)
}

// TestAPasskeyCountsAsASecondFactor: the whole point of shipping it beside
// TOTP rather than instead of it.
func TestAPasskeyCountsAsASecondFactor(t *testing.T) {
	t.Parallel()

	mfa, _, _ := newMFAFixture(t)
	waSvc, waStore, _ := newWebAuthnFixture(t)
	mfa = mfa.WithPasskeys(waSvc)

	// No factor of either kind.
	assert.False(t, mfa.RequiresSecondFactor(context.Background(), "u-1"))

	waStore.creds["c-1"] = auth.WebAuthnCredential{ID: "c-1", UserID: "u-1", Name: "YubiKey"}
	assert.True(t, mfa.RequiresSecondFactor(context.Background(), "u-1"),
		"a registered security key did not challenge a login")
	assert.True(t, mfa.HasAnyFactor(context.Background(), "u-1"))
}

// --- full ceremonies, against a software authenticator ----------------------

const (
	waRPID   = "assess.example.com"
	waOrigin = "https://assess.example.com"
)

// registerKey takes an account all the way to a usable credential.
func registerKey(t *testing.T, svc *auth.WebAuthnService, a *webauthntest.Authenticator, name string) auth.WebAuthnCredential {
	t.Helper()
	c, err := svc.BeginRegistration(context.Background(), waActor())
	require.NoError(t, err)

	cred, err := svc.FinishRegistration(context.Background(), waActor(), c.ChallengeID, name,
		a.Register(t, webauthntest.ChallengeFrom(t, c.Options), waOrigin, waRPID))
	require.NoError(t, err)
	return cred
}

// TestTheWholeRegistrationCeremony. The library verifies the client data, the
// relying party hash and the attestation; this asserts the wiring around it
// stores what was verified.
func TestTheWholeRegistrationCeremony(t *testing.T) {
	t.Parallel()

	svc, store, _ := newWebAuthnFixture(t)
	device := webauthntest.New(t)

	cred := registerKey(t, svc, device, "YubiKey on my keyring")

	assert.Equal(t, "YubiKey on my keyring", cred.Name)
	assert.Equal(t, device.CredID, cred.CredentialID)
	assert.Equal(t, "cross-platform", cred.Attachment,
		"the attachment is what distinguishes a laptop from a key on a keyring")
	require.Len(t, store.creds, 1)
	assert.NotEmpty(t, cred.Credential.PublicKey, "the verified public key was not stored")
}

// TestAnUnnamedKeyGetsAName. A list of three blank rows is not a list.
func TestAnUnnamedKeyGetsAName(t *testing.T) {
	t.Parallel()

	svc, _, _ := newWebAuthnFixture(t)
	cred := registerKey(t, svc, webauthntest.New(t), "   ")
	assert.Equal(t, "Security key", cred.Name)
}

// TestTheWholeLoginCeremony.
func TestTheWholeLoginCeremony(t *testing.T) {
	t.Parallel()

	svc, store, _ := newWebAuthnFixture(t)
	device := webauthntest.New(t)
	cred := registerKey(t, svc, device, "Key")

	c, err := svc.BeginLogin(context.Background(), "u-1")
	require.NoError(t, err)

	userID, err := svc.FinishLogin(context.Background(), c.ChallengeID,
		device.Assert(t, webauthntest.ChallengeFrom(t, c.Options), waOrigin, waRPID))
	require.NoError(t, err)
	assert.Equal(t, "u-1", userID, "the login was attributed to the wrong account")

	// The use is recorded, and the counter the authenticator reported with it.
	stored := store.creds[cred.ID]
	assert.Equal(t, waNow, stored.LastUsedAt)
	assert.Equal(t, device.SignCount, stored.SignCount)
	assert.False(t, stored.CloneWarning)
}

// TestAnAssertionFromTheWrongOriginIsRefused.
//
// This is the anti-phishing property, and the reason WebAuthn is worth having
// over TOTP: a convincing copy of this site at another origin cannot produce
// an assertion this server will take, however willingly the user cooperates.
func TestAnAssertionFromTheWrongOriginIsRefused(t *testing.T) {
	t.Parallel()

	svc, _, _ := newWebAuthnFixture(t)
	device := webauthntest.New(t)
	registerKey(t, svc, device, "Key")

	c, err := svc.BeginLogin(context.Background(), "u-1")
	require.NoError(t, err)

	_, err = svc.FinishLogin(context.Background(), c.ChallengeID,
		device.Assert(t, webauthntest.ChallengeFrom(t, c.Options), "https://assess.example.com.evil.test", waRPID))
	assert.ErrorIs(t, err, auth.ErrWebAuthnRejected)
}

// TestAnAssertionForTheWrongRelyingPartyIsRefused. The RP ID is hashed into
// the signed authenticator data, so a credential bound to one site cannot
// sign for another.
func TestAnAssertionForTheWrongRelyingPartyIsRefused(t *testing.T) {
	t.Parallel()

	svc, _, _ := newWebAuthnFixture(t)
	device := webauthntest.New(t)
	registerKey(t, svc, device, "Key")

	c, err := svc.BeginLogin(context.Background(), "u-1")
	require.NoError(t, err)

	_, err = svc.FinishLogin(context.Background(), c.ChallengeID,
		device.Assert(t, webauthntest.ChallengeFrom(t, c.Options), waOrigin, "evil.test"))
	assert.ErrorIs(t, err, auth.ErrWebAuthnRejected)
}

// TestAnAssertionForADifferentChallengeIsRefused. The challenge is what makes
// an assertion good once rather than for ever.
func TestAnAssertionForADifferentChallengeIsRefused(t *testing.T) {
	t.Parallel()

	svc, _, _ := newWebAuthnFixture(t)
	device := webauthntest.New(t)
	registerKey(t, svc, device, "Key")

	c, err := svc.BeginLogin(context.Background(), "u-1")
	require.NoError(t, err)

	_, err = svc.FinishLogin(context.Background(), c.ChallengeID,
		device.Assert(t, webauthntest.B64([]byte("a challenge nobody issued")), waOrigin, waRPID))
	assert.ErrorIs(t, err, auth.ErrWebAuthnRejected)
}

// TestAnAssertionCannotBeReplayed. The challenge is spent by the finish, so
// the same response presented twice fails the second time — and it fails at
// the ceremony, before any signature is checked.
func TestAnAssertionCannotBeReplayed(t *testing.T) {
	t.Parallel()

	svc, _, _ := newWebAuthnFixture(t)
	device := webauthntest.New(t)
	registerKey(t, svc, device, "Key")

	c, err := svc.BeginLogin(context.Background(), "u-1")
	require.NoError(t, err)
	response := device.Assert(t, webauthntest.ChallengeFrom(t, c.Options), waOrigin, waRPID)

	_, err = svc.FinishLogin(context.Background(), c.ChallengeID, response)
	require.NoError(t, err)

	_, err = svc.FinishLogin(context.Background(), c.ChallengeID, response)
	assert.ErrorIs(t, err, auth.ErrWebAuthnCeremonyExpired)
}

// TestACounterThatDoesNotAdvanceRaisesACloneWarning.
//
// An authenticator's counter only goes up, so one that does not move means
// two devices are presenting one credential. The warning is RECORDED and the
// login is allowed: authenticators that legitimately do not implement the
// counter look identical from here, and refusing would lock out working
// hardware (ADR-0031).
func TestACounterThatDoesNotAdvanceRaisesACloneWarning(t *testing.T) {
	t.Parallel()

	svc, store, _ := newWebAuthnFixture(t)
	device := webauthntest.New(t)
	cred := registerKey(t, svc, device, "Key")

	// One good login, which moves the stored counter up.
	c, err := svc.BeginLogin(context.Background(), "u-1")
	require.NoError(t, err)
	_, err = svc.FinishLogin(context.Background(), c.ChallengeID,
		device.Assert(t, webauthntest.ChallengeFrom(t, c.Options), waOrigin, waRPID))
	require.NoError(t, err)
	require.False(t, store.creds[cred.ID].CloneWarning)

	// A second login at the SAME counter: what a clone looks like.
	c, err = svc.BeginLogin(context.Background(), "u-1")
	require.NoError(t, err)
	_, err = svc.FinishLogin(context.Background(), c.ChallengeID,
		device.AssertWithoutAdvancing(t, webauthntest.ChallengeFrom(t, c.Options), waOrigin, waRPID))

	require.NoError(t, err, "a stalled counter refused a login; it is a warning, not a refusal")
	assert.True(t, store.creds[cred.ID].CloneWarning,
		"a stalled counter did not raise the clone warning, so the field is decoration")
}

// TestAKeyRegisteredToOneAccountCannotSignInAsAnother.
func TestAKeyRegisteredToOneAccountCannotSignInAsAnother(t *testing.T) {
	t.Parallel()

	svc, _, users := newWebAuthnFixture(t)
	users.users["u-2"] = auth.User{ID: "u-2", OrgID: "org-1", Email: "other@example.com", Role: auth.RoleAdmin}
	registerKey(t, svc, webauthntest.New(t), "Key")

	// The other account has no credential at all, so there is no ceremony to
	// begin — the key belongs to u-1 and nothing offers it for u-2.
	_, err := svc.BeginLogin(context.Background(), "u-2")
	assert.ErrorIs(t, err, auth.ErrWebAuthnNotRegistered)
}

// TestRegisteringTwiceExcludesTheKeyAlreadyPresent. It is what makes the
// browser say "you already have a key for this site" instead of silently
// creating a second credential on the same authenticator.
func TestRegisteringTwiceExcludesTheKeyAlreadyPresent(t *testing.T) {
	t.Parallel()

	svc, _, _ := newWebAuthnFixture(t)
	device := webauthntest.New(t)
	registerKey(t, svc, device, "Key")

	c, err := svc.BeginRegistration(context.Background(), waActor())
	require.NoError(t, err)

	var opts struct {
		PublicKey struct {
			ExcludeCredentials []struct {
				ID string `json:"id"`
			} `json:"excludeCredentials"`
		} `json:"publicKey"`
	}
	require.NoError(t, json.Unmarshal(c.Options, &opts))
	require.Len(t, opts.PublicKey.ExcludeCredentials, 1)
	assert.Equal(t, webauthntest.B64(device.CredID), opts.PublicKey.ExcludeCredentials[0].ID)
}

// --- failure paths ----------------------------------------------------------

func TestNewWebAuthnServiceRequiresItsCollaborators(t *testing.T) {
	t.Parallel()

	store, users := newFakeWebAuthnStore(), newFakeAdminStore()
	for _, tc := range []struct {
		name  string
		build func() error
	}{
		{"no store", func() error {
			_, err := auth.NewWebAuthnService(waConfig(), nil, users, stubClock{waNow}, &stubIDs{})
			return err
		}},
		{"no user store", func() error {
			_, err := auth.NewWebAuthnService(waConfig(), store, nil, stubClock{waNow}, &stubIDs{})
			return err
		}},
		{"no clock", func() error {
			_, err := auth.NewWebAuthnService(waConfig(), store, users, nil, &stubIDs{})
			return err
		}},
		{"no ids", func() error {
			_, err := auth.NewWebAuthnService(waConfig(), store, users, stubClock{waNow}, nil)
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Error(t, tc.build())
		})
	}

	// The display name is a string on somebody's phone, not a security
	// parameter, so an empty one is defaulted rather than refused.
	cfg := waConfig()
	cfg.RPDisplayName = ""
	svc, err := auth.NewWebAuthnService(cfg, store, users, stubClock{waNow}, &stubIDs{})
	require.NoError(t, err)
	assert.NotNil(t, svc)
}

// TestCredentialsListsWhatTheAccountHolds.
func TestCredentialsListsWhatTheAccountHolds(t *testing.T) {
	t.Parallel()

	svc, _, _ := newWebAuthnFixture(t)
	registerKey(t, svc, webauthntest.New(t), "Laptop")
	registerKey(t, svc, webauthntest.New(t), "YubiKey")

	list, err := svc.Credentials(context.Background(), waActor())
	require.NoError(t, err)
	assert.Len(t, list, 2)

	names := []string{list[0].Name, list[1].Name}
	assert.ElementsMatch(t, []string{"Laptop", "YubiKey"}, names)
}

// TestAnUnknownAccountCannotStartACeremony. The ceremony binds to a user
// handle, and there is none for an account that does not exist.
func TestAnUnknownAccountCannotStartACeremony(t *testing.T) {
	t.Parallel()

	svc, _, _ := newWebAuthnFixture(t)
	ghost := auth.Identity{UserID: "u-ghost", OrgID: "org-1", Role: auth.RoleAdmin}

	_, err := svc.BeginRegistration(context.Background(), ghost)
	assert.ErrorIs(t, err, auth.ErrNotFound)

	_, err = svc.BeginLogin(context.Background(), "u-ghost")
	assert.ErrorIs(t, err, auth.ErrNotFound)
}

// TestAStoreFailureStopsACeremonyRatherThanIssuingAnUnrecordedChallenge.
//
// A challenge the server did not store is one it cannot verify later, so the
// ceremony would fail at its second step with nothing to explain why.
func TestAStoreFailureStopsACeremonyRatherThanIssuingAnUnrecordedChallenge(t *testing.T) {
	t.Parallel()

	svc, store, _ := newWebAuthnFixture(t)
	store.listErr = errors.New("database unavailable")

	_, err := svc.BeginRegistration(context.Background(), waActor())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read credentials")
}

// TestRegisteringTheSameKeyTwiceIsAConflict.
//
// The browser's exclusion list is supposed to catch this first, and the
// unique constraint is what holds when it does not.
func TestRegisteringTheSameKeyTwiceIsAConflict(t *testing.T) {
	t.Parallel()

	svc, store, _ := newWebAuthnFixture(t)
	device := webauthntest.New(t)
	registerKey(t, svc, device, "Key")

	store.insertErr = auth.ErrConflict

	c, err := svc.BeginRegistration(context.Background(), waActor())
	require.NoError(t, err)
	_, err = svc.FinishRegistration(context.Background(), waActor(), c.ChallengeID, "Again",
		device.Register(t, webauthntest.ChallengeFrom(t, c.Options), waOrigin, waRPID))
	assert.ErrorIs(t, err, auth.ErrConflict)
}

// TestAMalformedResponseIsRejectedWithoutDistinction. A caller must not be
// able to tell a parse failure from a signature failure.
func TestAMalformedResponseIsRejectedWithoutDistinction(t *testing.T) {
	t.Parallel()

	svc, _, _ := newWebAuthnFixture(t)
	device := webauthntest.New(t)
	registerKey(t, svc, device, "Key")

	c, err := svc.BeginRegistration(context.Background(), waActor())
	require.NoError(t, err)
	_, err = svc.FinishRegistration(context.Background(), waActor(), c.ChallengeID, "Key",
		[]byte("not json at all"))
	assert.ErrorIs(t, err, auth.ErrWebAuthnRejected)

	lc, err := svc.BeginLogin(context.Background(), "u-1")
	require.NoError(t, err)
	_, err = svc.FinishLogin(context.Background(), lc.ChallengeID, []byte("{}"))
	assert.ErrorIs(t, err, auth.ErrWebAuthnRejected)
}

// TestRevokingAKeyThatIsNotThereIsNotFound, and not "that is your last key".
//
// The last-credential guard counts what the account holds, so with nothing
// held it fired first and told somebody with no keys that they could not
// remove their last one. Caught by the conformance suite rather than by
// reading the function.
func TestRevokingAKeyThatIsNotThereIsNotFound(t *testing.T) {
	t.Parallel()

	svc, _, _ := newWebAuthnFixture(t)

	// No credentials at all.
	err := svc.RevokeCredential(context.Background(), waActor(), "no-such-key", false)
	assert.ErrorIs(t, err, auth.ErrNotFound)

	// And with one held, an unknown id is still not found rather than being
	// refused as the last one.
	registerKey(t, svc, webauthntest.New(t), "Key")
	err = svc.RevokeCredential(context.Background(), waActor(), "still-no-such-key", false)
	assert.ErrorIs(t, err, auth.ErrNotFound)
}

// TestClearingAStrandedUsersFactorRemovesTheirSecurityKeysToo.
//
// The lockout valve has to clear EVERY factor, and the case it exists for is
// exactly the one where it did not: somebody whose security key is the thing
// they lost. Clearing only the authenticator app hands back an account that
// still demands the missing key — and the single operation that exists to
// rescue it has now been used, and reports success.
//
// The CLI half of the valve (`satool recover-account --clear-mfa`) carries
// the same fix; its summary claimed the account would sign in with a
// password alone, which a surviving passkey made untrue.
func TestClearingAStrandedUsersFactorRemovesTheirSecurityKeysToo(t *testing.T) {
	t.Parallel()

	mfa, _, _ := newMFAFixture(t)
	waSvc, waStore, _ := newWebAuthnFixture(t)
	mfa = mfa.WithPasskeys(waSvc)

	waStore.creds["c-1"] = auth.WebAuthnCredential{ID: "c-1", UserID: "u-1", Name: "Lost YubiKey"}
	require.True(t, mfa.RequiresSecondFactor(context.Background(), "u-1"))

	admin := auth.Identity{UserID: "u-admin", OrgID: "org-1", Role: auth.RoleAdmin}
	target := auth.User{ID: "u-1", OrgID: "org-1", Email: "person@example.com"}
	require.NoError(t, mfa.ClearFactorFor(context.Background(), admin, "u-1", target))

	assert.False(t, mfa.RequiresSecondFactor(context.Background(), "u-1"),
		"the account still demands a key its owner has lost, after the operation meant to fix that")
}

// TestClearingAFactorWithNoPasskeyServiceStillWorks — a deployment with no
// WEBAUTHN_RP_ID must not lose its lockout valve.
func TestClearingAFactorWithNoPasskeyServiceStillWorks(t *testing.T) {
	t.Parallel()

	mfa, _, _ := newMFAFixture(t)
	admin := auth.Identity{UserID: "u-admin", OrgID: "org-1", Role: auth.RoleAdmin}
	target := auth.User{ID: "u-1", OrgID: "org-1", Email: "person@example.com"}

	assert.NoError(t, mfa.ClearFactorFor(context.Background(), admin, "u-1", target))
}

// TestAFailureToRemoveTheKeysIsReported rather than passing as a completed
// reset: an administrator told the account was cleared would hand it back
// still locked.
func TestAFailureToRemoveTheKeysIsReported(t *testing.T) {
	t.Parallel()

	mfa, _, _ := newMFAFixture(t)
	waSvc, waStore, _ := newWebAuthnFixture(t)
	mfa = mfa.WithPasskeys(waSvc)
	waStore.revokeAllErr = errors.New("database is down")

	admin := auth.Identity{UserID: "u-admin", OrgID: "org-1", Role: auth.RoleAdmin}
	target := auth.User{ID: "u-1", OrgID: "org-1", Email: "person@example.com"}

	assert.Error(t, mfa.ClearFactorFor(context.Background(), admin, "u-1", target))
}

// --- the step-up ceremony ---------------------------------------------------

// TestAStepUpCeremonyVerifiesAndRecordsTheUse.
//
// The route that did not exist. Without it an account whose only factor is a
// key could not step up at all — StepUp demands a factor from any account
// that has one and verifies only TOTP — so the audit log, and everything
// else behind a step-up, was out of that account's reach.
func TestAStepUpCeremonyVerifiesAndRecordsTheUse(t *testing.T) {
	t.Parallel()

	svc, store, _ := newWebAuthnFixture(t)
	device := webauthntest.New(t)
	cred := registerKey(t, svc, device, "Key")

	c, err := svc.BeginStepUp(context.Background(), "u-1")
	require.NoError(t, err)
	require.NotEmpty(t, c.ChallengeID)

	require.NoError(t, svc.FinishStepUp(context.Background(), "u-1", c.ChallengeID,
		device.Assert(t, webauthntest.ChallengeFrom(t, c.Options), waOrigin, waRPID)))

	// A step-up is a real use of the key, so the counter moves. One that did
	// not would leave a gap the clone check reads as a cloned authenticator
	// on some later sign-in.
	stored := store.creds[cred.ID]
	assert.Equal(t, waNow, stored.LastUsedAt)
	assert.Equal(t, device.SignCount, stored.SignCount)
}

// TestAStepUpChallengeCannotCompleteALogin, and a login challenge cannot
// complete a step-up.
//
// The purposes are separate for the same reason registration and login are:
// a login assertion is produced by somebody with no session yet, and
// accepting one as a step-up would let a half-finished sign-in reach an
// operation meant to need a second, deliberate proof. The reverse is worse —
// a step-up challenge answering a login would let anyone already inside mint
// a session.
func TestAStepUpChallengeCannotCompleteALogin(t *testing.T) {
	t.Parallel()

	svc, _, _ := newWebAuthnFixture(t)
	device := webauthntest.New(t)
	registerKey(t, svc, device, "Key")

	stepUp, err := svc.BeginStepUp(context.Background(), "u-1")
	require.NoError(t, err)
	_, err = svc.FinishLogin(context.Background(), stepUp.ChallengeID,
		device.Assert(t, webauthntest.ChallengeFrom(t, stepUp.Options), waOrigin, waRPID))
	assert.ErrorIs(t, err, auth.ErrWebAuthnCeremonyExpired,
		"a step-up challenge minted a session")

	login, err := svc.BeginLogin(context.Background(), "u-1")
	require.NoError(t, err)
	err = svc.FinishStepUp(context.Background(), "u-1", login.ChallengeID,
		device.Assert(t, webauthntest.ChallengeFrom(t, login.Options), waOrigin, waRPID))
	assert.ErrorIs(t, err, auth.ErrWebAuthnCeremonyExpired,
		"a login challenge satisfied a step-up")
}

// TestAStepUpChallengeBelongsToTheAccountThatBeganIt.
//
// Claimed against the user as well as the purpose, so a challenge issued to
// one signed-in person cannot be answered on behalf of another.
func TestAStepUpChallengeBelongsToTheAccountThatBeganIt(t *testing.T) {
	t.Parallel()

	svc, _, users := newWebAuthnFixture(t)
	users.users["u-2"] = auth.User{ID: "u-2", OrgID: "org-1", Email: "other@example.com", Name: "Other"}
	device := webauthntest.New(t)
	registerKey(t, svc, device, "Key")

	c, err := svc.BeginStepUp(context.Background(), "u-1")
	require.NoError(t, err)

	err = svc.FinishStepUp(context.Background(), "u-2", c.ChallengeID,
		device.Assert(t, webauthntest.ChallengeFrom(t, c.Options), waOrigin, waRPID))
	assert.ErrorIs(t, err, auth.ErrWebAuthnCeremonyExpired,
		"one account answered another's step-up challenge")
}

// TestAStepUpCeremonyIsSingleUse. Replaying it would turn one touch of a key
// into a standing grant.
func TestAStepUpCeremonyIsSingleUse(t *testing.T) {
	t.Parallel()

	svc, _, _ := newWebAuthnFixture(t)
	device := webauthntest.New(t)
	registerKey(t, svc, device, "Key")

	c, err := svc.BeginStepUp(context.Background(), "u-1")
	require.NoError(t, err)
	assertion := device.AssertWithoutAdvancing(t, webauthntest.ChallengeFrom(t, c.Options), waOrigin, waRPID)

	require.NoError(t, svc.FinishStepUp(context.Background(), "u-1", c.ChallengeID, assertion))
	assert.ErrorIs(t, svc.FinishStepUp(context.Background(), "u-1", c.ChallengeID, assertion),
		auth.ErrWebAuthnCeremonyExpired, "a step-up ceremony was replayed")
}

// TestAStepUpNeedsAKeyToBeginWith.
func TestAStepUpNeedsAKeyToBeginWith(t *testing.T) {
	t.Parallel()

	svc, _, _ := newWebAuthnFixture(t)
	_, err := svc.BeginStepUp(context.Background(), "u-1")
	assert.ErrorIs(t, err, auth.ErrWebAuthnNotRegistered)
}

// --- signing in with the key alone (ADR-0031) -------------------------------

// TestTheWholePasswordlessCeremony.
//
// The front door: no account is named at any point. The browser picks the
// credential, the credential carries the user handle, and the handle is what
// says whose sign-in this is.
func TestTheWholePasswordlessCeremony(t *testing.T) {
	t.Parallel()

	svc, store, _ := newWebAuthnFixture(t)
	device := webauthntest.New(t)
	// A discoverable credential returns the handle it was registered with.
	device.UserHandle = []byte("u-1")
	cred := registerKey(t, svc, device, "Laptop")

	c, err := svc.BeginPasswordlessLogin(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, c.ChallengeID)

	userID, err := svc.FinishPasswordlessLogin(context.Background(), c.ChallengeID,
		device.Assert(t, webauthntest.ChallengeFrom(t, c.Options), waOrigin, waRPID))
	require.NoError(t, err)
	assert.Equal(t, "u-1", userID, "the sign-in was attributed to the wrong account")

	stored := store.creds[cred.ID]
	assert.Equal(t, waNow, stored.LastUsedAt)
	assert.Equal(t, device.SignCount, stored.SignCount)
}

// TestAPasswordlessCeremonyNamesNoAccountUpFront.
//
// Nothing identifies anybody until the key answers. An endpoint that took an
// email would confirm which addresses have accounts, to anybody, with no
// credential at all — so the begin call takes no argument and the stored
// challenge carries no user.
func TestAPasswordlessCeremonyNamesNoAccountUpFront(t *testing.T) {
	t.Parallel()

	svc, store, _ := newWebAuthnFixture(t)
	c, err := svc.BeginPasswordlessLogin(context.Background())
	require.NoError(t, err)

	held := store.challenges[c.ChallengeID]
	assert.Empty(t, held.userID, "the challenge was bound to an account before the key answered")
	assert.Equal(t, auth.WebAuthnPurposePasswordless, held.purpose)
}

// TestAPasswordlessChallengeCannotCompleteTheOtherCeremonies, or be completed
// by them. Four purposes, none of which may answer another's challenge.
func TestAPasswordlessChallengeCannotCompleteTheOtherCeremonies(t *testing.T) {
	t.Parallel()

	svc, _, _ := newWebAuthnFixture(t)
	device := webauthntest.New(t)
	device.UserHandle = []byte("u-1")
	registerKey(t, svc, device, "Laptop")

	pwless, err := svc.BeginPasswordlessLogin(context.Background())
	require.NoError(t, err)
	assertion := device.AssertWithoutAdvancing(t, webauthntest.ChallengeFrom(t, pwless.Options), waOrigin, waRPID)

	// It is not a second-factor login...
	_, err = svc.FinishLogin(context.Background(), pwless.ChallengeID, assertion)
	assert.ErrorIs(t, err, auth.ErrWebAuthnCeremonyExpired)
	// ...nor a step-up.
	assert.ErrorIs(t, svc.FinishStepUp(context.Background(), "u-1", pwless.ChallengeID, assertion),
		auth.ErrWebAuthnCeremonyExpired)

	// And a login challenge cannot walk in the front door.
	login, err := svc.BeginLogin(context.Background(), "u-1")
	require.NoError(t, err)
	_, err = svc.FinishPasswordlessLogin(context.Background(), login.ChallengeID,
		device.Assert(t, webauthntest.ChallengeFrom(t, login.Options), waOrigin, waRPID))
	assert.ErrorIs(t, err, auth.ErrWebAuthnCeremonyExpired,
		"a second-factor challenge signed somebody in with no password")
}

// TestAPasswordlessCeremonyIsSingleUse.
func TestAPasswordlessCeremonyIsSingleUse(t *testing.T) {
	t.Parallel()

	svc, _, _ := newWebAuthnFixture(t)
	device := webauthntest.New(t)
	device.UserHandle = []byte("u-1")
	registerKey(t, svc, device, "Laptop")

	c, err := svc.BeginPasswordlessLogin(context.Background())
	require.NoError(t, err)
	assertion := device.AssertWithoutAdvancing(t, webauthntest.ChallengeFrom(t, c.Options), waOrigin, waRPID)

	_, err = svc.FinishPasswordlessLogin(context.Background(), c.ChallengeID, assertion)
	require.NoError(t, err)
	_, err = svc.FinishPasswordlessLogin(context.Background(), c.ChallengeID, assertion)
	assert.ErrorIs(t, err, auth.ErrWebAuthnCeremonyExpired, "a passwordless ceremony was replayed")
}

// TestAPasswordlessCeremonyRefusesAnUnknownUserHandle. The handle decides
// whose sign-in this is, so one naming an account that does not exist must
// not resolve to anybody.
func TestAPasswordlessCeremonyRefusesAnUnknownUserHandle(t *testing.T) {
	t.Parallel()

	svc, _, _ := newWebAuthnFixture(t)
	device := webauthntest.New(t)
	device.UserHandle = []byte("u-1")
	registerKey(t, svc, device, "Laptop")

	device.UserHandle = []byte("u-nobody")
	c, err := svc.BeginPasswordlessLogin(context.Background())
	require.NoError(t, err)

	_, err = svc.FinishPasswordlessLogin(context.Background(), c.ChallengeID,
		device.Assert(t, webauthntest.ChallengeFrom(t, c.Options), waOrigin, waRPID))
	assert.ErrorIs(t, err, auth.ErrWebAuthnRejected)
}

// TestAKeyWithNoUserVerificationCannotSignInOnItsOwn.
//
// This is what keeps a passwordless sign-in two factors. Every other
// ceremony here accepts a U2F-era key with no PIN or biometric, because
// there the password was the first factor and the key is the second. At the
// front door there is no password, so a key that only proves possession
// would make the whole sign-in one factor — and a key found on the floor
// would be somebody's account.
func TestAKeyWithNoUserVerificationCannotSignInOnItsOwn(t *testing.T) {
	t.Parallel()

	svc, _, _ := newWebAuthnFixture(t)
	device := webauthntest.New(t)
	device.UserHandle = []byte("u-1")
	registerKey(t, svc, device, "Old YubiKey")

	// The same key, now answering without verifying the user.
	device.NoUserVerification = true

	c, err := svc.BeginPasswordlessLogin(context.Background())
	require.NoError(t, err)
	_, err = svc.FinishPasswordlessLogin(context.Background(), c.ChallengeID,
		device.Assert(t, webauthntest.ChallengeFrom(t, c.Options), waOrigin, waRPID))
	assert.ErrorIs(t, err, auth.ErrWebAuthnRejected,
		"a key that only proves possession signed in with no password")
}

// TestTheSameKeyIsStillAGoodSecondFactor — the refusal above is about the
// front door, not about the hardware.
func TestTheSameKeyIsStillAGoodSecondFactor(t *testing.T) {
	t.Parallel()

	svc, _, _ := newWebAuthnFixture(t)
	device := webauthntest.New(t)
	device.UserHandle = []byte("u-1")
	registerKey(t, svc, device, "Old YubiKey")
	device.NoUserVerification = true

	c, err := svc.BeginLogin(context.Background(), "u-1")
	require.NoError(t, err)
	userID, err := svc.FinishLogin(context.Background(), c.ChallengeID,
		device.Assert(t, webauthntest.ChallengeFrom(t, c.Options), waOrigin, waRPID))
	require.NoError(t, err, "a key with no PIN was refused as a SECOND factor, which ADR-0031 allows")
	assert.Equal(t, "u-1", userID)
}

// TestTheUserHandleDecidesWhoSignsIn.
//
// Two accounts, two keys, and the sign-in must land on whichever one the
// credential actually belongs to. Nothing in the request says who is signing
// in — that is the point of the front door — so if this were ever resolved
// from anything but the handle the authenticator returned, one person's key
// would open another person's account.
func TestTheUserHandleDecidesWhoSignsIn(t *testing.T) {
	t.Parallel()

	svc, _, users := newWebAuthnFixture(t)
	users.users["u-2"] = auth.User{
		ID: "u-2", OrgID: "org-1", Email: "other@example.com", Name: "Other Person",
	}

	// u-1's key, registered first so it is not simply the only one.
	first := webauthntest.New(t)
	first.UserHandle = []byte("u-1")
	registerKey(t, svc, first, "First laptop")

	// u-2's key.
	second := webauthntest.New(t)
	second.UserHandle = []byte("u-2")
	other := auth.Identity{UserID: "u-2", OrgID: "org-1", Role: auth.RoleViewer, Email: "other@example.com"}
	c, err := svc.BeginRegistration(context.Background(), other)
	require.NoError(t, err)
	_, err = svc.FinishRegistration(context.Background(), other, c.ChallengeID, "Second laptop",
		second.Register(t, webauthntest.ChallengeFrom(t, c.Options), waOrigin, waRPID))
	require.NoError(t, err)

	ceremony, err := svc.BeginPasswordlessLogin(context.Background())
	require.NoError(t, err)

	userID, err := svc.FinishPasswordlessLogin(context.Background(), ceremony.ChallengeID,
		second.Assert(t, webauthntest.ChallengeFrom(t, ceremony.Options), waOrigin, waRPID))
	require.NoError(t, err)
	assert.Equal(t, "u-2", userID, "one account's key signed in as another")
}
