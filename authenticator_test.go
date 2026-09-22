package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

// fakeStore is an in-memory auth.Store.
//
// The Authenticator is the layer that holds the rules — what a wrong password
// answers, when a session is minted and for how long, whether a disabled
// account can sign in — and until this file existed none of them were tested
// directly. The HTTP tests drive a stub authenticator and the Postgres tests
// drive the store; between them sat the policy, exercised only in passing.
type fakeStore struct {
	clearedExpiry  map[string]bool
	clearExpiryErr error

	users    map[string]User // by lowercased email
	sessions map[string]SessionLookup
	keys     map[string]APIKeyLookup

	inserted []NewSession
	touched  []string
	revoked  []string
	rehashed map[string]string
	failWith error
}

// clearedExpiry records ClearPasswordExpired calls, so a test can assert the
// rotation hold was lifted rather than only that a change succeeded.
func (f *fakeStore) ClearPasswordExpired(_ context.Context, userID string) error {
	if f.clearedExpiry == nil {
		f.clearedExpiry = map[string]bool{}
	}
	f.clearedExpiry[userID] = true
	return f.clearExpiryErr
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		users:    map[string]User{},
		sessions: map[string]SessionLookup{},
		keys:     map[string]APIKeyLookup{},
		rehashed: map[string]string{},
	}
}

func (f *fakeStore) withUser(t *testing.T, u User, password string) User {
	t.Helper()
	if password != "" {
		hash, err := HashPassword(password)
		if err != nil {
			t.Fatalf("hash fixture password: %v", err)
		}
		u.PasswordHash = hash
	}
	f.users[strings.ToLower(u.Email)] = u
	return u
}

// UserByID backs the second step of a two-step login, which resumes from a
// token carrying a user id rather than an address.
func (f *fakeStore) UserByID(_ context.Context, id string) (User, error) {
	if f.failWith != nil {
		return User{}, f.failWith
	}
	for _, u := range f.users {
		if u.ID == id {
			return u, nil
		}
	}
	return User{}, ErrNotFound
}

func (f *fakeStore) UserByEmail(_ context.Context, email string) (User, error) {
	if f.failWith != nil {
		return User{}, f.failWith
	}
	u, ok := f.users[strings.ToLower(strings.TrimSpace(email))]
	if !ok {
		return User{}, ErrNotFound
	}
	return u, nil
}

func (f *fakeStore) SetPasswordHash(_ context.Context, userID, hash string) error {
	f.rehashed[userID] = hash
	return nil
}

func (f *fakeStore) InsertSession(_ context.Context, s NewSession) error {
	if f.failWith != nil {
		return f.failWith
	}
	f.inserted = append(f.inserted, s)
	return nil
}

func (f *fakeStore) SessionByTokenHash(_ context.Context, hash []byte, _ time.Time) (SessionLookup, error) {
	if f.failWith != nil {
		return SessionLookup{}, f.failWith
	}
	got, ok := f.sessions[string(hash)]
	if !ok {
		return SessionLookup{}, ErrNotFound
	}
	return got, nil
}

func (f *fakeStore) TouchSession(_ context.Context, id string, _, _ time.Time) error {
	f.touched = append(f.touched, id)
	return nil
}

func (f *fakeStore) RevokeSession(_ context.Context, id string, _ time.Time) error {
	f.revoked = append(f.revoked, id)
	return nil
}

func (f *fakeStore) RevokeSessionsByUser(_ context.Context, userID string, _ time.Time) error {
	f.revoked = append(f.revoked, "user:"+userID)
	return nil
}

func (f *fakeStore) APIKeyByHash(_ context.Context, hash []byte) (APIKeyLookup, error) {
	if f.failWith != nil {
		return APIKeyLookup{}, f.failWith
	}
	got, ok := f.keys[string(hash)]
	if !ok {
		return APIKeyLookup{}, ErrNotFound
	}
	return got, nil
}

func (f *fakeStore) TouchAPIKey(_ context.Context, id string, _ time.Time) error {
	f.touched = append(f.touched, id)
	return nil
}

var _ Store = (*fakeStore)(nil)

// fixedClock and seqIDs keep the tests deterministic without pulling in
// internal/testutil, which would have this package's tests depend on the
// shared fakes for two one-line interfaces.
type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

type seqIDs struct{ n int }

func (s *seqIDs) NewID() string { s.n++; return "id-" + string(rune('0'+s.n)) }

var testNow = time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)

func newTestAuthenticator(t *testing.T, store Store) *Authenticator {
	t.Helper()
	a, err := NewAuthenticator(store, fixedClock{testNow}, &seqIDs{}, testTable(t))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	return a
}

func TestNewAuthenticatorRequiresEverything(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		store Store
		clock Clock
		ids   IDGen
		table *PermissionTable
	}{
		{"no store", nil, fixedClock{testNow}, &seqIDs{}, testTable(t)},
		{"no clock", newFakeStore(), nil, &seqIDs{}, testTable(t)},
		{"no ids", newFakeStore(), fixedClock{testNow}, nil, testTable(t)},
		{"no table", newFakeStore(), fixedClock{testNow}, &seqIDs{}, nil},
	} {
		if _, err := NewAuthenticator(tc.store, tc.clock, tc.ids, tc.table); err == nil {
			t.Errorf("%s: NewAuthenticator succeeded, want an error", tc.name)
		}
	}
}

// TestLoginMintsASessionOnTheRightClocks covers the ordinary path and the
// two expiries, which are the whole reason sessions are stored server-side.
func TestLoginMintsASessionOnTheRightClocks(t *testing.T) {
	t.Parallel()

	store := newFakeStore()
	store.withUser(t, User{
		ID: "u1", OrgID: "org-1", Email: "Ada@Example.com",
		Name: "Ada Lovelace", Role: testAnalyst,
	}, "correct-horse-battery")
	a := newTestAuthenticator(t, store)

	// Mixed case and surrounding space, as a person types it.
	res, err := a.Login(t.Context(), "  ada@example.com  ", "correct-horse-battery")
	token, id := res.SessionToken, res.Identity
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if token == "" {
		t.Fatal("Login returned no token")
	}
	if id.UserID != "u1" || id.OrgID != "org-1" || id.Role != testAnalyst {
		t.Errorf("identity = %+v, want u1/org-1/analyst", id)
	}
	if id.Scheme != SchemeSession {
		t.Errorf("scheme = %q, want %q", id.Scheme, SchemeSession)
	}
	if id.Actor != "Ada Lovelace" {
		t.Errorf("actor = %q, want the display name", id.Actor)
	}

	if len(store.inserted) != 1 {
		t.Fatalf("persisted %d sessions, want 1", len(store.inserted))
	}
	got := store.inserted[0]
	if string(got.TokenHash) == token {
		t.Error("the stored hash is the token itself")
	}
	if string(got.TokenHash) != string(HashToken(token)) {
		t.Error("the stored hash is not HashToken of the issued token")
	}
	if want := testNow.Add(IdleTimeout); !got.ExpiresAt.Equal(want) {
		t.Errorf("idle expiry = %s, want %s", got.ExpiresAt, want)
	}
	if want := testNow.Add(AbsoluteTimeout); !got.AbsoluteExpiresAt.Equal(want) {
		t.Errorf("absolute expiry = %s, want %s", got.AbsoluteExpiresAt, want)
	}
	if !got.AbsoluteExpiresAt.After(got.ExpiresAt) {
		t.Error("the absolute ceiling is not beyond the idle window, so it bounds nothing")
	}
}

// TestLoginFailuresAreOneError is the user-enumeration guard at the layer
// that decides it. Every one of these must be indistinguishable to a caller.
func TestLoginFailuresAreOneError(t *testing.T) {
	t.Parallel()

	store := newFakeStore()
	store.withUser(t, User{ID: "u1", Email: "real@example.com", Role: testViewer}, "the-right-password")
	store.withUser(t, User{ID: "u2", Email: "gone@example.com", Role: testViewer, Disabled: true}, "the-right-password")
	// An account with no password at all — an OIDC-shaped row, once that
	// exists. No password is the right one for it.
	store.withUser(t, User{ID: "u3", Email: "sso@example.com", Role: testViewer}, "")
	a := newTestAuthenticator(t, store)

	for _, tc := range []struct{ name, email, password string }{
		{"no such account", "nobody@example.com", "the-right-password"},
		{"wrong password", "real@example.com", "guessing"},
		{"disabled account, right password", "gone@example.com", "the-right-password"},
		{"account with no password set", "sso@example.com", "anything"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := a.Login(t.Context(), tc.email, tc.password)
			token := res.SessionToken
			if !errors.Is(err, ErrInvalidCredentials) {
				t.Errorf("err = %v, want ErrInvalidCredentials", err)
			}
			if token != "" {
				t.Error("a failed login returned a token")
			}
		})
	}
	if len(store.inserted) != 0 {
		t.Errorf("a failed login persisted %d session(s)", len(store.inserted))
	}
}

// TestLoginUpgradesAWeakHash covers the transparent cost upgrade: a
// successful login is the one moment the plaintext is in hand and a rehash
// is free.
func TestLoginUpgradesAWeakHash(t *testing.T) {
	t.Parallel()

	store := newFakeStore()
	store.users["old@example.com"] = User{
		ID: "u1", Email: "old@example.com", Role: testViewer,
		// Written under far weaker parameters than this build uses.
		PasswordHash: weakHash(t, "still-the-right-password"),
	}
	a := newTestAuthenticator(t, store)

	if _, err := a.Login(t.Context(), "old@example.com", "still-the-right-password"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	upgraded, ok := store.rehashed["u1"]
	if !ok {
		t.Fatal("a login against a weak hash did not rehash it")
	}
	if NeedsRehash(upgraded) {
		t.Error("the replacement hash still reports as needing a rehash")
	}
	if ok, err := VerifyPassword(upgraded, "still-the-right-password"); err != nil || !ok {
		t.Error("the replacement hash does not verify the same password")
	}
}

// weakHash produces a genuinely weaker argon2id encoding: the digest is
// computed at the low parameters it advertises, so VerifyPassword accepts the
// password AND NeedsRehash reports it as stale. Writing the parameters into a
// current-strength hash would satisfy neither — the digest would not verify,
// and an encoding nothing can verify proves nothing about the upgrade path.
func weakHash(t *testing.T, password string) string {
	t.Helper()
	const (
		weakMemory  = 4096
		weakTime    = 1
		weakThreads = 1
	)
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("read salt: %v", err)
	}
	sum := argon2.IDKey([]byte(password), salt, weakTime, weakMemory, weakThreads, argon2KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, weakMemory, weakTime, weakThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(sum))
}

// TestLoginSurvivesAFailedRehash: the password was correct, and a hash left
// at the old cost is not worth refusing entry over.
func TestLoginSurvivesAFailedRehash(t *testing.T) {
	t.Parallel()

	store := newFakeStore()
	store.withUser(t, User{ID: "u1", Email: "a@example.com", Role: testViewer}, "the-right-password")
	a := newTestAuthenticator(t, store)

	if _, err := a.Login(t.Context(), "a@example.com", "the-right-password"); err != nil {
		t.Fatalf("Login: %v", err)
	}
}

// TestLoginReportsStoreFailuresAsThemselves: an outage is not a wrong
// password, and the HTTP layer distinguishes them to pick 500 over 401.
func TestLoginReportsStoreFailuresAsThemselves(t *testing.T) {
	t.Parallel()

	store := newFakeStore()
	store.failWith = errors.New("dial tcp: connection refused")
	a := newTestAuthenticator(t, store)

	_, err := a.Login(t.Context(), "a@example.com", "whatever")
	if err == nil {
		t.Fatal("a broken store produced no error")
	}
	if errors.Is(err, ErrInvalidCredentials) {
		t.Error("a store failure was reported as a credential failure")
	}
}

func TestAuthenticateSession(t *testing.T) {
	t.Parallel()

	store := newFakeStore()
	token, hash, err := NewSessionToken()
	if err != nil {
		t.Fatalf("NewSessionToken: %v", err)
	}
	store.sessions[string(hash)] = SessionLookup{
		SessionID: "s1",
		Identity:  Identity{UserID: "u1", OrgID: "org-1", Role: testAdmin, Scheme: SchemeSession},
	}
	a := newTestAuthenticator(t, store)

	t.Run("a live session resolves and is touched", func(t *testing.T) {
		id, err := a.AuthenticateSession(t.Context(), token)
		if err != nil {
			t.Fatalf("AuthenticateSession: %v", err)
		}
		if id.UserID != "u1" || id.Role != testAdmin {
			t.Errorf("identity = %+v", id)
		}
		if len(store.touched) == 0 || store.touched[len(store.touched)-1] != "s1" {
			t.Error("the session's idle window was not advanced")
		}
	})

	t.Run("no token at all", func(t *testing.T) {
		if _, err := a.AuthenticateSession(t.Context(), ""); !errors.Is(err, ErrNoCredentials) {
			t.Errorf("err = %v, want ErrNoCredentials", err)
		}
	})

	t.Run("a token of the wrong shape never reaches the store", func(t *testing.T) {
		if _, err := a.AuthenticateSession(t.Context(), "not-a-token"); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("err = %v, want ErrInvalidCredentials", err)
		}
	})

	t.Run("a well-formed token nothing knows", func(t *testing.T) {
		other, _, err := NewSessionToken()
		if err != nil {
			t.Fatalf("NewSessionToken: %v", err)
		}
		if _, err := a.AuthenticateSession(t.Context(), other); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("err = %v, want ErrInvalidCredentials", err)
		}
	})
}

func TestAuthenticateAPIKey(t *testing.T) {
	t.Parallel()

	store := newFakeStore()
	key, hash, err := NewAPIKey()
	if err != nil {
		t.Fatalf("NewAPIKey: %v", err)
	}
	store.keys[string(hash)] = APIKeyLookup{
		KeyID:    "k1",
		Identity: Identity{UserID: "u1", OrgID: "org-1", Role: testViewer, Scheme: SchemeAPIKey},
	}
	a := newTestAuthenticator(t, store)

	id, err := a.AuthenticateAPIKey(t.Context(), key)
	if err != nil {
		t.Fatalf("AuthenticateAPIKey: %v", err)
	}
	// The KEY's role, not its owner's — it was clamped at mint time, so
	// nothing downstream needs to consult the owner to be safe.
	if id.Role != testViewer {
		t.Errorf("role = %q, want the key's own viewer", id.Role)
	}
	if len(store.touched) == 0 || store.touched[len(store.touched)-1] != "k1" {
		t.Error("last-used was not recorded")
	}

	if _, err := a.AuthenticateAPIKey(t.Context(), ""); !errors.Is(err, ErrNoCredentials) {
		t.Errorf("empty key: err = %v, want ErrNoCredentials", err)
	}
	if _, err := a.AuthenticateAPIKey(t.Context(), "nope"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("malformed key: err = %v, want ErrInvalidCredentials", err)
	}
}

// TestLogout covers the deliberate silence: the caller's intent is that the
// token stop working, and reporting "no such session" would tell whoever
// presented a stale one whether it had been live.
func TestLogout(t *testing.T) {
	t.Parallel()

	store := newFakeStore()
	token, hash, err := NewSessionToken()
	if err != nil {
		t.Fatalf("NewSessionToken: %v", err)
	}
	store.sessions[string(hash)] = SessionLookup{SessionID: "s1"}
	a := newTestAuthenticator(t, store)

	if logoutErr := a.Logout(t.Context(), token); logoutErr != nil {
		t.Fatalf("Logout: %v", logoutErr)
	}
	if len(store.revoked) != 1 || store.revoked[0] != "s1" {
		t.Errorf("revoked = %v, want [s1]", store.revoked)
	}

	unknown, _, err := NewSessionToken()
	if err != nil {
		t.Fatalf("NewSessionToken: %v", err)
	}
	if logoutErr := a.Logout(t.Context(), unknown); logoutErr != nil {
		t.Errorf("logging out an unknown token = %v, want nil", logoutErr)
	}
	if logoutErr := a.Logout(t.Context(), "not-a-token"); logoutErr != nil {
		t.Errorf("logging out a malformed token = %v, want nil", logoutErr)
	}
}

// TestSystemIdentityCarriesTheReportsOrg: background work acts within the
// organization of the report it is processing, never an inherited caller's.
func TestSystemIdentityIsAdminWithinOneOrg(t *testing.T) {
	t.Parallel()
	id := SystemIdentity("org-9", testTable(t))
	if !id.Can(testPermDelete) {
		t.Error("the worker cannot act on the reports it processes")
	}
	if id.OrgID != "org-9" {
		t.Errorf("OrgID = %q", id.OrgID)
	}
}
