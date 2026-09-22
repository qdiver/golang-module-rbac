package auth_test

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	auth "github.com/qdiver/golang-module-rbac"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- fakes -----------------------------------------------------------------

type fakeAdminStore struct {
	users   map[string]auth.User
	setHash map[string]string
	revoked map[string]bool
	hashErr error
	byIDErr error
	// clearedExpiry records users whose rotation hold was lifted, so a test
	// can assert the change actually released them from the form that
	// demanded it.
	clearedExpiry  []string
	clearExpiryErr error
	nextUser       auth.NewUserRecord
	deleted        []string
	keys           map[string]auth.APIKeyInfo
	keyHashes      map[string][]byte
	keyErr         error
}

func newFakeAdminStore() *fakeAdminStore {
	return &fakeAdminStore{
		users:     map[string]auth.User{},
		setHash:   map[string]string{},
		revoked:   map[string]bool{},
		keys:      map[string]auth.APIKeyInfo{},
		keyHashes: map[string][]byte{},
	}
}

func (f *fakeAdminStore) CreateUser(_ context.Context, u auth.NewUserRecord) error {
	f.nextUser = u
	f.users[u.ID] = auth.User{
		ID: u.ID, OrgID: u.OrgID, Email: u.Email, Name: u.Name,
		PasswordHash: u.PasswordHash, Role: u.Role,
	}
	return nil
}

func (f *fakeAdminStore) UserByID(_ context.Context, id string) (auth.User, error) {
	if f.byIDErr != nil {
		return auth.User{}, f.byIDErr
	}
	u, ok := f.users[id]
	if !ok {
		return auth.User{}, auth.ErrNotFound
	}
	return u, nil
}

func (f *fakeAdminStore) UserByEmail(_ context.Context, email string) (auth.User, error) {
	for _, u := range f.users {
		if u.Email == email {
			return u, nil
		}
	}
	return auth.User{}, auth.ErrNotFound
}

func (f *fakeAdminStore) ListUsers(_ context.Context, orgID string) ([]auth.User, error) {
	out := []auth.User{}
	for _, u := range f.users {
		if u.OrgID == orgID {
			out = append(out, u)
		}
	}
	return out, nil
}

func (f *fakeAdminStore) SetDisabledAt(_ context.Context, userID string, _ time.Time) error {
	u := f.users[userID]
	u.Disabled = true
	f.users[userID] = u
	return nil
}

func (f *fakeAdminStore) ClearDisabledAt(_ context.Context, userID string) error {
	u := f.users[userID]
	u.Disabled = false
	f.users[userID] = u
	return nil
}
func (f *fakeAdminStore) SetRole(_ context.Context, userID string, r auth.Role) error {
	u := f.users[userID]
	u.Role = r
	f.users[userID] = u
	return nil
}

func (f *fakeAdminStore) DeleteUser(_ context.Context, userID string) error {
	delete(f.users, userID)
	f.deleted = append(f.deleted, userID)
	return nil
}

func (f *fakeAdminStore) SetPasswordHash(_ context.Context, userID, hash string) error {
	if f.hashErr != nil {
		return f.hashErr
	}
	f.setHash[userID] = hash
	u := f.users[userID]
	u.PasswordHash = hash
	f.users[userID] = u
	return nil
}

func (f *fakeAdminStore) RevokeSessionsByUser(_ context.Context, userID string, _ time.Time) error {
	f.revoked[userID] = true
	return nil
}

func (f *fakeAdminStore) ClearPasswordExpired(_ context.Context, userID string) error {
	f.clearedExpiry = append(f.clearedExpiry, userID)
	return f.clearExpiryErr
}

func (f *fakeAdminStore) CreateAPIKey(_ context.Context, k auth.NewAPIKeyRecord) error {
	if f.keyErr != nil {
		return f.keyErr
	}
	// The hash is kept so a test can prove the key handed back is not what
	// was stored — the point of hashing it in the first place.
	f.keyHashes[k.ID] = k.KeyHash
	f.keys[k.ID] = auth.APIKeyInfo{
		ID: k.ID, UserID: k.UserID, Name: k.Name, Role: k.Role, CreatedAt: k.CreatedAt,
	}
	return nil
}

func (f *fakeAdminStore) APIKeyByID(_ context.Context, id string) (auth.APIKeyInfo, error) {
	k, ok := f.keys[id]
	if !ok {
		return auth.APIKeyInfo{}, auth.ErrNotFound
	}
	return k, nil
}

func (f *fakeAdminStore) ListAPIKeys(_ context.Context, userID string) ([]auth.APIKeyInfo, error) {
	out := []auth.APIKeyInfo{}
	for _, k := range f.keys {
		if k.UserID == userID {
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (f *fakeAdminStore) RevokeAPIKey(_ context.Context, id string, at time.Time) error {
	k := f.keys[id]
	k.RevokedAt = at
	f.keys[id] = k
	return nil
}

type fakePolicyStore struct {
	policy     auth.Policy
	readErr    error
	history    map[string][]string
	recorded   []recordedChange
	recordErr  error
	historyErr error
	saved      []auth.Policy
	saveErr    error
}

type recordedChange struct {
	userID       string
	previousHash string
	depth        int
}

func (f *fakePolicyStore) PolicyForOrg(_ context.Context, orgID string) (auth.Policy, error) {
	if f.readErr != nil {
		return auth.Policy{}, f.readErr
	}
	p := f.policy
	p.OrgID = orgID
	return p, nil
}

func (f *fakePolicyStore) SavePolicy(_ context.Context, p auth.Policy) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	f.policy = p
	f.saved = append(f.saved, p)
	return nil
}

func (f *fakePolicyStore) RecentPasswordHashes(_ context.Context, userID string, limit int) ([]string, error) {
	if f.historyErr != nil {
		return nil, f.historyErr
	}
	h := f.history[userID]
	if len(h) > limit {
		h = h[:limit]
	}
	return h, nil
}

func (f *fakePolicyStore) RecordPasswordChange(
	_ context.Context, userID, previousHash, _ string, _ time.Time, depth int,
) error {
	if f.recordErr != nil {
		return f.recordErr
	}
	f.recorded = append(f.recorded, recordedChange{userID, previousHash, depth})
	return nil
}

// --- harness ---------------------------------------------------------------

type stubClock struct{ now time.Time }

func (c stubClock) Now() time.Time { return c.now }

type stubIDs struct{ n int }

func (g *stubIDs) NewID() string { g.n++; return "id-" + string(rune('a'+g.n)) }

const (
	goodPassword  = "Thicket-Vandal-9-Gorse"
	otherPassword = "Marrow-Kestrel-4-Plinth"
)

// Test fixtures for the role/permission mechanism, shared across this
// package's (auth_test) test files. See auth_test.go's own copy (package
// auth) for why this package defines its own role/permission vocabulary
// rather than importing one from the library.
const (
	testViewer  auth.Role = "viewer"
	testAnalyst auth.Role = "analyst"
	testAdmin   auth.Role = "admin"

	testPermRead    auth.Permission = "reports:read"
	testPermCreate  auth.Permission = "reports:create"
	testPermRerun   auth.Permission = "reports:rerun"
	testPermDelete  auth.Permission = "reports:delete"
	testPermDispute auth.Permission = "disputes:manage"
	testPermUsers   auth.Permission = "users:manage"
)

func testTable(t *testing.T) *auth.PermissionTable {
	t.Helper()
	table, err := auth.NewPermissionTable(map[auth.Role][]auth.Permission{
		testViewer: {testPermRead},
		testAnalyst: {
			testPermRead, testPermCreate, testPermRerun, testPermDispute,
		},
		testAdmin: {
			testPermRead, testPermCreate, testPermRerun,
			testPermDelete, testPermDispute, testPermUsers,
		},
	}, testPermUsers, testAdmin)
	if err != nil {
		t.Fatalf("build test permission table: %v", err)
	}
	return table
}

func newAdminFixture(t *testing.T, policy auth.Policy) (*auth.Admin, *fakeAdminStore, *fakePolicyStore) {
	t.Helper()
	store := newFakeAdminStore()
	policies := &fakePolicyStore{policy: policy, history: map[string][]string{}}
	a, err := auth.NewAdmin(store, stubClock{time.Date(2026, 9, 18, 0, 0, 0, 0, time.UTC)}, &stubIDs{}, testTable(t))
	require.NoError(t, err)
	return a.WithPolicies(policies), store, policies
}

func adminActor(t *testing.T) auth.Identity {
	t.Helper()
	return auth.Identity{
		UserID: "u-admin", OrgID: "org-1", Role: testAdmin, Actor: "admin@example.com",
	}.WithPermissions(testTable(t))
}

func seedUser(t *testing.T, store *fakeAdminStore, id, password string) auth.User {
	t.Helper()
	hash, err := auth.HashPassword(password)
	require.NoError(t, err)
	u := auth.User{ID: id, OrgID: "org-1", Email: id + "@example.com", Name: "Test", PasswordHash: hash, Role: testAdmin}
	store.users[id] = u
	return u
}

// --- tests -----------------------------------------------------------------

// TestCreateUserAppliesTheOrganizationPolicy. The floor used to be a length
// check inline in this method; it is now the org's policy, and a password
// that would have passed the old check must not pass the new one.
func TestCreateUserAppliesTheOrganizationPolicy(t *testing.T) {
	t.Parallel()

	a, _, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	_, err := a.CreateUser(context.Background(), adminActor(t),
		"new@example.com", "New Person", testViewer, "all-lower-case-and-long")

	require.Error(t, err)
	assert.True(t, errors.Is(err, auth.ErrWeakPassword))
	assert.Contains(t, rulesOf(t, err), auth.RuleUppercase)
}

// TestCreateUserRefusesAPasswordContainingTheNewAccountsOwnDetails. The
// account being created is the one whose details must not appear — not the
// administrator's.
func TestCreateUserRefusesAPasswordContainingTheNewAccountsOwnDetails(t *testing.T) {
	t.Parallel()

	a, _, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	_, err := a.CreateUser(context.Background(), adminActor(t),
		"bernard@example.com", "Bernard Quill", testViewer, "Bernard-9-Thicket!")

	assert.Contains(t, rulesOf(t, err), auth.RulePersonal)
}

func TestChangePasswordAppliesThePolicyAndRecordsTheChange(t *testing.T) {
	t.Parallel()

	a, store, policies := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	u := seedUser(t, store, "u-1", goodPassword)
	actor := auth.Identity{UserID: u.ID, OrgID: "org-1", Role: testAdmin}.WithPermissions(testTable(t))

	require.NoError(t, a.ChangePassword(context.Background(), actor, goodPassword, otherPassword))

	assert.NotEmpty(t, store.setHash[u.ID], "the new password was not written")
	assert.True(t, store.revoked[u.ID], "other sessions were not revoked")

	// The hash filed in history is the one being REPLACED, not the new one.
	// Filing the new hash would make the password the user just chose
	// immediately unusable and would leave the old one reusable for ever.
	require.Len(t, policies.recorded, 1)
	assert.Equal(t, u.PasswordHash, policies.recorded[0].previousHash,
		"history recorded the wrong hash")
	assert.Equal(t, 5, policies.recorded[0].depth)
}

// TestTheCurrentPasswordIsVerifiedBeforeTheNewOneIsJudged. Reversing the two
// would let anyone holding the session learn which passwords the policy
// accepts without knowing the current one.
func TestTheCurrentPasswordIsVerifiedBeforeTheNewOneIsJudged(t *testing.T) {
	t.Parallel()

	a, store, policies := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	u := seedUser(t, store, "u-1", goodPassword)
	actor := auth.Identity{UserID: u.ID, OrgID: "org-1", Role: testAdmin}.WithPermissions(testTable(t))

	err := a.ChangePassword(context.Background(), actor, "the-wrong-current", "weak")

	assert.True(t, errors.Is(err, auth.ErrInvalidCredentials),
		"a wrong current password produced %v, which tells the caller about the new one", err)
	assert.Empty(t, policies.recorded, "a failed change was recorded")
}

// TestReuseIsRefused is the history rule. It is the expensive one, so it
// must run only after the cheap rules pass — TestReuseIsNotCheckedUntilThe
// CheapRulesPass covers that.
func TestReuseIsRefused(t *testing.T) {
	t.Parallel()

	a, store, policies := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	u := seedUser(t, store, "u-1", goodPassword)
	actor := auth.Identity{UserID: u.ID, OrgID: "org-1", Role: testAdmin}.WithPermissions(testTable(t))

	oldHash, err := auth.HashPassword(otherPassword)
	require.NoError(t, err)
	policies.history[u.ID] = []string{oldHash}

	err = a.ChangePassword(context.Background(), actor, goodPassword, otherPassword)
	require.Error(t, err)
	assert.Contains(t, rulesOf(t, err), auth.RuleReuse)
	assert.True(t, errors.Is(err, auth.ErrWeakPassword))
}

// TestReuseIsNotCheckedUntilTheCheapRulesPass. Each stored hash costs a full
// argon2id comparison; paying that for a password about to be refused for
// being eight characters long spends the request budget on a wrong answer.
func TestReuseIsNotCheckedUntilTheCheapRulesPass(t *testing.T) {
	t.Parallel()

	a, store, policies := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	u := seedUser(t, store, "u-1", goodPassword)
	actor := auth.Identity{UserID: u.ID, OrgID: "org-1", Role: testAdmin}.WithPermissions(testTable(t))

	// Reading history at all would be the bug, so the fake fails loudly if
	// it is touched.
	policies.historyErr = errors.New("history must not be read for a password that fails the cheap rules")

	err := a.ChangePassword(context.Background(), actor, goodPassword, "short")
	require.Error(t, err)
	assert.Contains(t, rulesOf(t, err), auth.RuleMinLength)
	assert.NotContains(t, err.Error(), "must not be read")
}

// TestHistoryDepthZeroSkipsTheCheckEntirely. Depth is the knob that bounds
// the cost, and zero has to mean no comparisons rather than a default.
func TestHistoryDepthZeroSkipsTheCheckEntirely(t *testing.T) {
	t.Parallel()

	p := auth.DefaultPolicy("org-1")
	p.HistoryDepth = 0
	a, store, policies := newAdminFixture(t, p)
	u := seedUser(t, store, "u-1", goodPassword)
	actor := auth.Identity{UserID: u.ID, OrgID: "org-1", Role: testAdmin}.WithPermissions(testTable(t))

	policies.historyErr = errors.New("history must not be read when the depth is zero")
	require.NoError(t, a.ChangePassword(context.Background(), actor, goodPassword, otherPassword))
}

// TestResetPasswordAlsoRefusesReuse. The disclosure to the administrator is
// accepted deliberately: they can already set this password to anything and
// sign in as the user, whereas skipping the check would let a reset reinstate
// a password the user rotated away from because they believed it was
// compromised.
func TestResetPasswordAlsoRefusesReuse(t *testing.T) {
	t.Parallel()

	a, store, policies := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	target := seedUser(t, store, "u-2", goodPassword)

	oldHash, err := auth.HashPassword(otherPassword)
	require.NoError(t, err)
	policies.history[target.ID] = []string{oldHash}

	err = a.ResetPassword(context.Background(), adminActor(t), target.ID, otherPassword)
	require.Error(t, err)
	assert.Contains(t, rulesOf(t, err), auth.RuleReuse)
}

// TestAMissingPolicyStoreFallsBackToTheDefaults, not to no rules. A wiring
// mistake must make passwords stricter, never unchecked.
func TestAMissingPolicyStoreFallsBackToTheDefaults(t *testing.T) {
	t.Parallel()

	store := newFakeAdminStore()
	a, err := auth.NewAdmin(store, stubClock{time.Now()}, &stubIDs{}, testTable(t))
	require.NoError(t, err)

	_, err = a.CreateUser(context.Background(), adminActor(t),
		"new@example.com", "New", testViewer, "all-lower-case-and-long")
	require.Error(t, err, "a password store-less Admin accepted a password the default policy refuses")
	assert.Contains(t, rulesOf(t, err), auth.RuleUppercase)
}

// TestAPolicyReadFailureFallsBackToTheDefaults. The default is the strictest
// thing this product ships, so a database hiccup makes a change stricter than
// configured rather than laxer.
func TestAPolicyReadFailureFallsBackToTheDefaults(t *testing.T) {
	t.Parallel()

	a, _, policies := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	policies.readErr = errors.New("database unavailable")

	_, err := a.CreateUser(context.Background(), adminActor(t),
		"new@example.com", "New", testViewer, "all-lower-case-and-long")
	require.Error(t, err)
	assert.Contains(t, rulesOf(t, err), auth.RuleUppercase)
}

// TestAFailureToRecordTheChangeIsReported. Without the stamp a password
// under a rotation policy never expires, and without the history file the
// previous password can be set again immediately — both are the silent
// non-enforcement of a control somebody switched on.
func TestAFailureToRecordTheChangeIsReported(t *testing.T) {
	t.Parallel()

	a, store, policies := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	u := seedUser(t, store, "u-1", goodPassword)
	actor := auth.Identity{UserID: u.ID, OrgID: "org-1", Role: testAdmin}.WithPermissions(testTable(t))
	policies.recordErr = errors.New("history table unavailable")

	err := a.ChangePassword(context.Background(), actor, goodPassword, otherPassword)
	require.ErrorContains(t, err, "record password change")
}

// --- rotation ---------------------------------------------------------------

// TestChangePasswordLiftsTheRotationHold. ChangePassword revokes every OTHER
// session but keeps the caller's own, so that changing a password does not
// log you out of the tab you just used. That surviving session carries the
// hold, and leaving it set would lock the user out with the very password
// they had just set to satisfy the policy.
func TestChangePasswordLiftsTheRotationHold(t *testing.T) {
	t.Parallel()

	a, store, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	u := seedUser(t, store, "u-1", goodPassword)
	actor := auth.Identity{UserID: u.ID, OrgID: "org-1", Role: testAdmin, PasswordExpired: true}.WithPermissions(testTable(t))

	require.NoError(t, a.ChangePassword(context.Background(), actor, goodPassword, otherPassword))
	assert.Contains(t, store.clearedExpiry, u.ID,
		"the hold survived the change that was supposed to satisfy it")
}

// TestAFailureToLiftTheHoldIsReported. Swallowing it would leave the user
// confined to a form they have already satisfied, with no error to explain
// why — the worst version of this failure, because it looks like success.
func TestAFailureToLiftTheHoldIsReported(t *testing.T) {
	t.Parallel()

	a, store, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	u := seedUser(t, store, "u-1", goodPassword)
	store.clearExpiryErr = errors.New("sessions table unavailable")
	actor := auth.Identity{UserID: u.ID, OrgID: "org-1", Role: testAdmin}.WithPermissions(testTable(t))

	err := a.ChangePassword(context.Background(), actor, goodPassword, otherPassword)
	require.ErrorContains(t, err, "rotation hold")
}

// --- enabling a disabled account -------------------------------------------

// TestDisableThenEnableRoundTrips is the regression test for a one-way door:
// disabling existed and enabling did not, so an administrator who suspended
// the wrong colleague could only delete and recreate the account — losing its
// id, and with it the link between that id and everything they had done.
func TestDisableThenEnableRoundTrips(t *testing.T) {
	t.Parallel()

	a, store, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	// A second admin, so disabling the first is not refused as the
	// last-administrator case.
	seedUser(t, store, "u-keeper", goodPassword)
	target := seedUser(t, store, "u-2", goodPassword)

	require.NoError(t, a.DisableUser(context.Background(), adminActor(t), target.ID))
	assert.True(t, store.users[target.ID].Disabled, "the account was not disabled")

	require.NoError(t, a.EnableUser(context.Background(), adminActor(t), target.ID))
	assert.False(t, store.users[target.ID].Disabled, "the account could not be re-enabled")
}

// TestEnablingAnAlreadyEnabledUserIsANoOp. An administrator clicking twice,
// or two of them acting at once, must not be an error — there is nothing to
// report and nothing went wrong.
func TestEnablingAnAlreadyEnabledUserIsANoOp(t *testing.T) {
	t.Parallel()

	a, store, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	target := seedUser(t, store, "u-2", goodPassword)

	require.NoError(t, a.EnableUser(context.Background(), adminActor(t), target.ID))
	assert.False(t, store.users[target.ID].Disabled)
}

// TestEnableUserNeedsTheManagementPermission. Re-enabling an account is the
// undoing of a security action, so it is exactly as privileged as taking it.
func TestEnableUserNeedsTheManagementPermission(t *testing.T) {
	t.Parallel()

	a, store, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	target := seedUser(t, store, "u-2", goodPassword)
	store.users[target.ID] = auth.User{
		ID: target.ID, OrgID: "org-1", Email: target.Email, Role: testViewer, Disabled: true,
	}

	analyst := auth.Identity{UserID: "u-analyst", OrgID: "org-1", Role: testAnalyst}.WithPermissions(testTable(t))
	err := a.EnableUser(context.Background(), analyst, target.ID)
	assert.ErrorIs(t, err, auth.ErrNotPermitted)
	assert.True(t, store.users[target.ID].Disabled, "a non-manager re-enabled an account")
}

// TestEnableUserCannotReachAnotherOrganization. manageableTarget is what
// enforces the boundary; this asserts the new method actually goes through
// it rather than around it.
func TestEnableUserCannotReachAnotherOrganization(t *testing.T) {
	t.Parallel()

	a, store, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	store.users["u-other"] = auth.User{
		ID: "u-other", OrgID: "org-2", Email: "other@example.com",
		Role: testViewer, Disabled: true,
	}

	err := a.EnableUser(context.Background(), adminActor(t), "u-other")
	require.Error(t, err, "an administrator re-enabled an account in another organization")
	assert.True(t, store.users["u-other"].Disabled)
}

// --- account lookups and listing --------------------------------------------

// TestListUsersIsScopedToTheCallersOrganization. On a multi-tenant
// deployment this listing is the difference between an administrator seeing
// their own staff and seeing another customer's.
func TestListUsersIsScopedToTheCallersOrganization(t *testing.T) {
	t.Parallel()

	a, store, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	seedUser(t, store, "u-ours", goodPassword)
	store.users["u-theirs"] = auth.User{
		ID: "u-theirs", OrgID: "org-2", Email: "neighbour@example.com", Role: testAdmin,
	}

	got, err := a.ListUsers(context.Background(), adminActor(t))
	require.NoError(t, err)
	for _, u := range got {
		assert.Equal(t, "org-1", u.OrgID, "the listing reached into another organization")
	}
}

func TestListUsersNeedsTheManagementPermission(t *testing.T) {
	t.Parallel()

	a, _, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	analyst := auth.Identity{UserID: "u-analyst", OrgID: "org-1", Role: testAnalyst}.WithPermissions(testTable(t))

	_, err := a.ListUsers(context.Background(), analyst)
	assert.ErrorIs(t, err, auth.ErrNotPermitted)
}

// TestUserByIDPerformsNoAuthorizationOfItsOwn.
//
// It is a lookup, and the caller's right to act is decided by the operation
// against the row it returns. Folding a permission check in here would make
// that check invisible at the call site — the pattern ADR-0027 rejected for
// route permissions — and would mean two places deciding the same question.
func TestUserByIDPerformsNoAuthorizationOfItsOwn(t *testing.T) {
	t.Parallel()

	a, store, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	store.users["u-theirs"] = auth.User{ID: "u-theirs", OrgID: "org-2", Email: "n@example.com"}

	got, err := a.UserByID(context.Background(), "u-theirs")
	require.NoError(t, err)
	assert.Equal(t, "org-2", got.OrgID,
		"UserByID filtered by organization, which would hide the check the caller must make")

	_, err = a.UserByID(context.Background(), "nobody")
	assert.ErrorIs(t, err, auth.ErrNotFound)
}

// TestAPIKeyRevokedReadsTheTimestamp. A zero time means live; anything else
// means revoked, and reading it the other way round would make every key look
// revoked or every revoked key look live.
func TestAPIKeyRevokedReadsTheTimestamp(t *testing.T) {
	t.Parallel()

	assert.False(t, auth.APIKeyInfo{}.Revoked())
	assert.True(t, auth.APIKeyInfo{RevokedAt: time.Unix(1, 0)}.Revoked())
}
