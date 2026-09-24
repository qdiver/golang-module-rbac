package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	josejwt "github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

// --- Authenticator's side: a fake GoogleAuthenticator ----------------------
//
// Same shape as loginflow_test.go's stepPasskeys: these tests are about the
// Authenticator's own rules (disabled account, second-factor gating, which
// FactorKind gets recorded), not about OAuth or OIDC, so the collaborator is
// faked rather than driven through a real Google round trip.

type stepGoogle struct {
	started    int
	startErr   error
	startedURL GoogleLoginStart

	finishedWith []string // "state:code" pairs
	finishFor    string
	finishErr    error
}

func (g *stepGoogle) BeginLogin(context.Context) (GoogleLoginStart, error) {
	g.started++
	if g.startErr != nil {
		return GoogleLoginStart{}, g.startErr
	}
	if g.startedURL.State == "" {
		g.startedURL = GoogleLoginStart{State: "state-1", RedirectURL: "https://accounts.google.com/o/oauth2/auth?..."}
	}
	return g.startedURL, nil
}

func (g *stepGoogle) FinishLogin(_ context.Context, state, code string) (string, error) {
	g.finishedWith = append(g.finishedWith, state+":"+code)
	if g.finishErr != nil {
		return "", g.finishErr
	}
	return g.finishFor, nil
}

func googleLoginFixture(t *testing.T) (*Authenticator, *fakeStore, *stepGoogle) {
	t.Helper()
	store := newFakeStore()
	store.withUser(t, User{
		ID: "u-1", OrgID: "org-1", Email: "person@example.com", Role: testAdmin,
	}, "")

	g := &stepGoogle{finishFor: "u-1"}
	a := newTestAuthenticator(t, store)
	return a.WithGoogleSSO(g), store, g
}

func TestBeginGoogleLoginWithNoServiceConfiguredIsRefused(t *testing.T) {
	t.Parallel()

	a := newTestAuthenticator(t, newFakeStore())
	if _, err := a.BeginGoogleLogin(context.Background()); err != ErrGoogleSSOUnavailable {
		t.Fatalf("err = %v, want ErrGoogleSSOUnavailable", err)
	}
}

func TestCompleteGoogleLoginWithNoServiceConfiguredIsRefused(t *testing.T) {
	t.Parallel()

	a := newTestAuthenticator(t, newFakeStore())
	if _, err := a.CompleteGoogleLogin(context.Background(), "state", "code"); err != ErrGoogleSSOUnavailable {
		t.Fatalf("err = %v, want ErrGoogleSSOUnavailable", err)
	}
}

func TestBeginGoogleLoginDelegates(t *testing.T) {
	t.Parallel()

	a, _, g := googleLoginFixture(t)
	start, err := a.BeginGoogleLogin(context.Background())
	if err != nil {
		t.Fatalf("BeginGoogleLogin: %v", err)
	}
	if g.started != 1 {
		t.Fatalf("started = %d, want 1", g.started)
	}
	if start.State != g.startedURL.State || start.RedirectURL != g.startedURL.RedirectURL {
		t.Errorf("start = %+v, want %+v", start, g.startedURL)
	}
}

// TestCompleteGoogleLoginIssuesTheSessionAndRecordsTheFactor.
func TestCompleteGoogleLoginIssuesTheSessionAndRecordsTheFactor(t *testing.T) {
	t.Parallel()

	a, store, _ := googleLoginFixture(t)
	res, err := a.CompleteGoogleLogin(context.Background(), "state-1", "code-1")
	if err != nil {
		t.Fatalf("CompleteGoogleLogin: %v", err)
	}
	if res.SessionToken == "" {
		t.Fatal("no session was issued")
	}
	if res.FactorUsed != FactorGoogle {
		t.Errorf("FactorUsed = %q, want google", res.FactorUsed)
	}
	if len(store.inserted) != 1 {
		t.Fatalf("sessions written = %d, want 1", len(store.inserted))
	}
}

// TestCompleteGoogleLoginDoesNotAskForASecondFactor is the counterpart of
// TestLoginStopsAtTheChallengeWhenAFactorIsRequired: a Google sign-in
// completes the login on its own, as a passkey does, because the second
// step already happened at Google (see the package doc in google_sso.go).
func TestCompleteGoogleLoginDoesNotAskForASecondFactor(t *testing.T) {
	t.Parallel()

	a, store, _ := googleLoginFixture(t)
	factor := &stepFactor{token: "step-one-token", verifyKind: FactorTOTP, required: true}
	a = a.WithSecondFactor(factor)

	res, err := a.CompleteGoogleLogin(context.Background(), "state-1", "code-1")
	if err != nil {
		t.Fatalf("CompleteGoogleLogin: %v", err)
	}
	if res.MFARequired() {
		t.Fatal("a Google sign-in was sent to the account's second factor")
	}
	if res.SessionToken == "" {
		t.Error("no session was issued")
	}
	if len(store.inserted) != 1 {
		t.Errorf("persisted %d sessions, want 1", len(store.inserted))
	}
	if res.FactorUsed != FactorGoogle {
		t.Errorf("FactorUsed = %q, want %q", res.FactorUsed, FactorGoogle)
	}
}

func TestCompleteGoogleLoginRefusesAnUnknownAccount(t *testing.T) {
	t.Parallel()

	a, store, g := googleLoginFixture(t)
	g.finishFor = "no-such-user"

	if _, err := a.CompleteGoogleLogin(context.Background(), "state-1", "code-1"); err != ErrInvalidCredentials {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
	if len(store.inserted) != 0 {
		t.Error("a session was issued for an account that does not exist")
	}
}

func TestCompleteGoogleLoginRefusesADisabledAccount(t *testing.T) {
	t.Parallel()

	a, store, _ := googleLoginFixture(t)
	u := store.users["person@example.com"]
	u.Disabled = true
	store.users["person@example.com"] = u

	if _, err := a.CompleteGoogleLogin(context.Background(), "state-1", "code-1"); err != ErrInvalidCredentials {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
	if len(store.inserted) != 0 {
		t.Error("a session was issued to a disabled account")
	}
}

// TestCompleteGoogleLoginPropagatesTheServicesError, without translating it:
// the caller (the HTTP layer) needs to see ErrGoogleCeremonyExpired,
// ErrGoogleTokenRejected and friends unchanged to map them to the right
// status code.
func TestCompleteGoogleLoginPropagatesTheServicesError(t *testing.T) {
	t.Parallel()

	a, _, g := googleLoginFixture(t)
	g.finishErr = ErrGoogleTokenRejected

	if _, err := a.CompleteGoogleLogin(context.Background(), "state-1", "code-1"); err != ErrGoogleTokenRejected {
		t.Fatalf("err = %v, want ErrGoogleTokenRejected", err)
	}
}

// --- GoogleSSOService's side: the OAuth2/OIDC mechanics ---------------------
//
// NewGoogleSSOService discovers Google's configuration over the network, so
// these build a *GoogleSSOService directly (this file is package auth, so
// unexported fields are reachable) against a local token endpoint and a
// static, self-signed key set — the pattern oidc.NewVerifier's own doc
// comment recommends for tests.

// fakeGoogleStore is an in-memory GoogleSSOStore.
type fakeGoogleStore struct {
	links      map[string]string // subject -> userID
	challenges map[string]googleChallenge
	linkErr    error
}

type googleChallenge struct {
	nonce, verifier string
	expires         time.Time
	claimed         bool
}

func newFakeGoogleStore() *fakeGoogleStore {
	return &fakeGoogleStore{links: map[string]string{}, challenges: map[string]googleChallenge{}}
}

func (f *fakeGoogleStore) UserByGoogleSubject(_ context.Context, subject string) (User, error) {
	userID, ok := f.links[subject]
	if !ok {
		return User{}, ErrNotFound
	}
	return User{ID: userID}, nil
}

func (f *fakeGoogleStore) LinkGoogleAccount(_ context.Context, userID, subject string, _ time.Time) error {
	if f.linkErr != nil {
		return f.linkErr
	}
	f.links[subject] = userID
	return nil
}

func (f *fakeGoogleStore) InsertGoogleChallenge(_ context.Context, id, nonce, codeVerifier string, _, expires time.Time) error {
	f.challenges[id] = googleChallenge{nonce: nonce, verifier: codeVerifier, expires: expires}
	return nil
}

func (f *fakeGoogleStore) ClaimGoogleChallenge(_ context.Context, id string, now time.Time) (string, string, error) {
	c, ok := f.challenges[id]
	if !ok || c.claimed || now.After(c.expires) {
		return "", "", ErrNotFound
	}
	c.claimed = true
	f.challenges[id] = c
	return c.nonce, c.verifier, nil
}

var _ GoogleSSOStore = (*fakeGoogleStore)(nil)

// fakeGoogleUsers is an in-memory GoogleSSOUsers.
type fakeGoogleUsers struct {
	byEmail map[string]User
}

func (f *fakeGoogleUsers) UserByEmail(_ context.Context, email string) (User, error) {
	u, ok := f.byEmail[email]
	if !ok {
		return User{}, ErrNotFound
	}
	return u, nil
}

var _ GoogleSSOUsers = (*fakeGoogleUsers)(nil)

const googleTestIssuer = "https://accounts.google.test"
const googleTestClientID = "test-client-id"

// googleTestFixture wires a *GoogleSSOService against a local token endpoint
// and a key pair it controls, so tests can hand-craft the ID token Google
// would otherwise have signed.
type googleTestFixture struct {
	svc    *GoogleSSOService
	store  *fakeGoogleStore
	users  *fakeGoogleUsers
	clock  fixedClock
	server *httptest.Server

	// tokenResponse is served for the next call to the token endpoint. Set
	// per test after signing an ID token with a known nonce.
	tokenResponse func(nonce string) map[string]any
	lastNonce     string
	exchangeFail  bool
}

func newGoogleTestFixture(t *testing.T, hostedDomain string) *googleTestFixture {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	signer, err := josejwt.NewSigner(josejwt.SigningKey{Algorithm: josejwt.RS256, Key: key}, nil)
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}

	f := &googleTestFixture{
		store: newFakeGoogleStore(),
		users: &fakeGoogleUsers{byEmail: map[string]User{}},
		clock: fixedClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if f.exchangeFail {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		claims := map[string]any{
			"iss":            googleTestIssuer,
			"aud":            googleTestClientID,
			"sub":            "google-subject-1",
			"iat":            f.clock.Now().Unix(),
			"exp":            f.clock.Now().Add(time.Hour).Unix(),
			"nonce":          f.lastNonce,
			"email":          "person@example.com",
			"email_verified": true,
		}
		if f.tokenResponse != nil {
			for k, v := range f.tokenResponse(f.lastNonce) {
				claims[k] = v
			}
		}
		payload, err := json.Marshal(claims)
		if err != nil {
			t.Fatalf("marshal claims: %v", err)
		}
		jws, err := signer.Sign(payload)
		if err != nil {
			t.Fatalf("sign id token: %v", err)
		}
		idToken, err := jws.CompactSerialize()
		if err != nil {
			t.Fatalf("serialize id token: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"id_token":     idToken,
		})
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)

	verifier := oidc.NewVerifier(googleTestIssuer,
		&oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}},
		&oidc.Config{ClientID: googleTestClientID, Now: f.clock.Now},
	)

	f.svc = &GoogleSSOService{
		oauth: &oauth2.Config{
			ClientID:     googleTestClientID,
			ClientSecret: "test-client-secret",
			RedirectURL:  "https://app.example.com/auth/google/callback",
			Endpoint:     oauth2.Endpoint{TokenURL: f.server.URL + "/token"},
			Scopes:       []string{oidc.ScopeOpenID, oidc.ScopeEmail, oidc.ScopeProfile},
		},
		verifier:     verifier,
		store:        f.store,
		users:        f.users,
		clock:        f.clock,
		ids:          &seqIDs{},
		hostedDomain: hostedDomain,
	}
	return f
}

// begin runs BeginLogin and remembers the nonce the token endpoint must echo
// back, the way Google itself would have embedded it in the ID token.
func (f *googleTestFixture) begin(t *testing.T) GoogleLoginStart {
	t.Helper()
	start, err := f.svc.BeginLogin(context.Background())
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	parsed, err := url.Parse(start.RedirectURL)
	if err != nil {
		t.Fatalf("parse redirect url: %v", err)
	}
	f.lastNonce = parsed.Query().Get("nonce")
	return start
}

func TestGoogleBeginLoginBuildsARedirectURLAndPersistsTheChallenge(t *testing.T) {
	t.Parallel()

	f := newGoogleTestFixture(t, "")
	start := f.begin(t)

	parsed, err := url.Parse(start.RedirectURL)
	if err != nil {
		t.Fatalf("parse redirect url: %v", err)
	}
	q := parsed.Query()
	if q.Get("client_id") != googleTestClientID {
		t.Errorf("client_id = %q", q.Get("client_id"))
	}
	if q.Get("nonce") == "" {
		t.Error("no nonce on the auth URL")
	}
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		t.Errorf("no PKCE challenge on the auth URL: %+v", q)
	}
	if q.Get("state") != start.State {
		t.Errorf("state param = %q, want %q", q.Get("state"), start.State)
	}
	if q.Get("hd") != "" {
		t.Error("hd param set with no HostedDomain configured")
	}

	if _, ok := f.store.challenges[start.State]; !ok {
		t.Fatal("no challenge was persisted for the returned state")
	}
}

func TestGoogleBeginLoginSetsTheHostedDomainParam(t *testing.T) {
	t.Parallel()

	f := newGoogleTestFixture(t, "example.com")
	start := f.begin(t)

	parsed, _ := url.Parse(start.RedirectURL)
	if got := parsed.Query().Get("hd"); got != "example.com" {
		t.Errorf("hd = %q, want example.com", got)
	}
}

func TestGoogleFinishLoginResolvesAnAlreadyLinkedAccount(t *testing.T) {
	t.Parallel()

	f := newGoogleTestFixture(t, "")
	f.store.links["google-subject-1"] = "u-existing"
	start := f.begin(t)

	userID, err := f.svc.FinishLogin(context.Background(), start.State, "auth-code")
	if err != nil {
		t.Fatalf("FinishLogin: %v", err)
	}
	if userID != "u-existing" {
		t.Errorf("userID = %q, want u-existing", userID)
	}
}

// TestGoogleFinishLoginLinksAMatchingVerifiedEmailOnFirstSignIn.
func TestGoogleFinishLoginLinksAMatchingVerifiedEmailOnFirstSignIn(t *testing.T) {
	t.Parallel()

	f := newGoogleTestFixture(t, "")
	f.users.byEmail["person@example.com"] = User{ID: "u-by-email"}
	start := f.begin(t)

	userID, err := f.svc.FinishLogin(context.Background(), start.State, "auth-code")
	if err != nil {
		t.Fatalf("FinishLogin: %v", err)
	}
	if userID != "u-by-email" {
		t.Errorf("userID = %q, want u-by-email", userID)
	}
	if f.store.links["google-subject-1"] != "u-by-email" {
		t.Error("the account was not linked for next time")
	}
}

func TestGoogleFinishLoginRefusesAnUnverifiedEmail(t *testing.T) {
	t.Parallel()

	f := newGoogleTestFixture(t, "")
	f.users.byEmail["person@example.com"] = User{ID: "u-by-email"}
	f.tokenResponse = func(string) map[string]any {
		return map[string]any{"email_verified": false}
	}
	start := f.begin(t)

	if _, err := f.svc.FinishLogin(context.Background(), start.State, "auth-code"); err != ErrGoogleEmailNotVerified {
		t.Fatalf("err = %v, want ErrGoogleEmailNotVerified", err)
	}
	if len(f.store.links) != 0 {
		t.Error("an account was linked from an unverified email")
	}
}

func TestGoogleFinishLoginRefusesAnUnknownAccount(t *testing.T) {
	t.Parallel()

	f := newGoogleTestFixture(t, "")
	start := f.begin(t)

	if _, err := f.svc.FinishLogin(context.Background(), start.State, "auth-code"); err != ErrGoogleAccountNotFound {
		t.Fatalf("err = %v, want ErrGoogleAccountNotFound", err)
	}
}

func TestGoogleFinishLoginRefusesAWrongHostedDomain(t *testing.T) {
	t.Parallel()

	f := newGoogleTestFixture(t, "example.com")
	f.users.byEmail["person@example.com"] = User{ID: "u-by-email"}
	f.tokenResponse = func(string) map[string]any {
		return map[string]any{"hd": "someone-elses-workspace.com"}
	}
	start := f.begin(t)

	if _, err := f.svc.FinishLogin(context.Background(), start.State, "auth-code"); err != ErrGoogleHostedDomainDenied {
		t.Fatalf("err = %v, want ErrGoogleHostedDomainDenied", err)
	}
}

// TestGoogleFinishLoginRefusesAMismatchedNonce is the check
// oidc.IDToken's own doc comment says the package leaves to the caller.
func TestGoogleFinishLoginRefusesAMismatchedNonce(t *testing.T) {
	t.Parallel()

	f := newGoogleTestFixture(t, "")
	f.users.byEmail["person@example.com"] = User{ID: "u-by-email"}
	start := f.begin(t)
	// Corrupt the nonce the token endpoint will embed, so it no longer
	// matches what BeginLogin stored for this state.
	f.lastNonce = "a-different-nonce"

	if _, err := f.svc.FinishLogin(context.Background(), start.State, "auth-code"); err != ErrGoogleTokenRejected {
		t.Fatalf("err = %v, want ErrGoogleTokenRejected", err)
	}
}

func TestGoogleFinishLoginRefusesAFailedExchange(t *testing.T) {
	t.Parallel()

	f := newGoogleTestFixture(t, "")
	start := f.begin(t)
	f.exchangeFail = true

	if _, err := f.svc.FinishLogin(context.Background(), start.State, "auth-code"); err != ErrGoogleTokenRejected {
		t.Fatalf("err = %v, want ErrGoogleTokenRejected", err)
	}
}

func TestGoogleFinishLoginRefusesAnUnknownOrSpentState(t *testing.T) {
	t.Parallel()

	f := newGoogleTestFixture(t, "")

	if _, err := f.svc.FinishLogin(context.Background(), "never-issued", "auth-code"); err != ErrGoogleCeremonyExpired {
		t.Fatalf("err = %v, want ErrGoogleCeremonyExpired", err)
	}

	// A state used once must not work again.
	f.users.byEmail["person@example.com"] = User{ID: "u-by-email"}
	start := f.begin(t)
	if _, err := f.svc.FinishLogin(context.Background(), start.State, "auth-code"); err != nil {
		t.Fatalf("first FinishLogin: %v", err)
	}
	if _, err := f.svc.FinishLogin(context.Background(), start.State, "auth-code"); err != ErrGoogleCeremonyExpired {
		t.Fatalf("replayed state: err = %v, want ErrGoogleCeremonyExpired", err)
	}
}

func TestNewGoogleSSOServiceRequiresConfig(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cfg  GoogleSSOConfig
	}{
		{"no client id", GoogleSSOConfig{ClientSecret: "s", RedirectURL: "https://x/cb"}},
		{"no client secret", GoogleSSOConfig{ClientID: "c", RedirectURL: "https://x/cb"}},
		{"no redirect url", GoogleSSOConfig{ClientID: "c", ClientSecret: "s"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewGoogleSSOService(context.Background(), tc.cfg, newFakeGoogleStore(), &fakeGoogleUsers{}, fixedClock{}, &seqIDs{})
			if err != ErrGoogleSSOUnavailable {
				t.Fatalf("err = %v, want ErrGoogleSSOUnavailable", err)
			}
		})
	}
}

func TestNewGoogleSSOServiceRequiresItsCollaborators(t *testing.T) {
	t.Parallel()

	cfg := GoogleSSOConfig{ClientID: "c", ClientSecret: "s", RedirectURL: "https://x/cb"}
	store := newFakeGoogleStore()
	users := &fakeGoogleUsers{}

	cases := []struct {
		name  string
		store GoogleSSOStore
		users GoogleSSOUsers
		clock Clock
		ids   IDGen
	}{
		{"no store", nil, users, fixedClock{}, &seqIDs{}},
		{"no users", store, nil, fixedClock{}, &seqIDs{}},
		{"no clock", store, users, nil, &seqIDs{}},
		{"no ids", store, users, fixedClock{}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewGoogleSSOService(context.Background(), cfg, tc.store, tc.users, tc.clock, tc.ids)
			if err == nil || err == ErrGoogleSSOUnavailable {
				t.Fatalf("err = %v, want a distinct configuration error", err)
			}
		})
	}
}
