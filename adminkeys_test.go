package auth_test

import (
	"context"
	"errors"
	"testing"

	auth "github.com/qdiver/golang-module-rbac"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The account- and key-management use cases, from the use case's own side.
//
// These run through the HTTP layer as well, but what is being checked here is
// not the wiring — it is the set of refusals that keep an organization from
// locking itself out and keep one caller's keys away from another's.

// seedAdmin adds a second enabled administrator, so the last-administrator
// guard is not the thing every test trips over.
func seedAdmin(t *testing.T, store *fakeAdminStore, id string) auth.User {
	t.Helper()
	u := auth.User{ID: id, OrgID: "org-1", Email: id + "@example.com", Role: auth.RoleAdmin}
	store.users[id] = u
	return u
}

// --- DeleteUser ------------------------------------------------------------

func TestDeleteUserRemovesTheAccount(t *testing.T) {
	t.Parallel()

	a, store, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	seedUser(t, store, "u-target", goodPassword)
	seedAdmin(t, store, "u-admin")

	require.NoError(t, a.DeleteUser(context.Background(), adminActor(), "u-target"))
	assert.Equal(t, []string{"u-target"}, store.deleted)
	assert.NotContains(t, store.users, "u-target")
}

// TestDeleteUserRefusesTheLastAdministrator. An organization that deletes its
// way out of having an administrator has no in-product way back.
func TestDeleteUserRefusesTheLastAdministrator(t *testing.T) {
	t.Parallel()

	a, store, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	seedUser(t, store, "u-target", goodPassword) // the only enabled admin

	err := a.DeleteUser(context.Background(), adminActor(), "u-target")
	assert.True(t, errors.Is(err, auth.ErrLastAdmin), "got %v", err)
	assert.Empty(t, store.deleted)
}

func TestDeleteUserRefusesYourOwnAccount(t *testing.T) {
	t.Parallel()

	a, store, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	seedAdmin(t, store, "u-admin")
	seedAdmin(t, store, "u-other")

	assert.Error(t, a.DeleteUser(context.Background(), adminActor(), "u-admin"))
	assert.Empty(t, store.deleted)
}

// TestDeleteUserRefusesAnotherOrganizationsAccount, and says "not found"
// rather than "not yours" — a distinct refusal would confirm the ID is real.
func TestDeleteUserRefusesAnotherOrganizationsAccount(t *testing.T) {
	t.Parallel()

	a, store, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	store.users["u-elsewhere"] = auth.User{ID: "u-elsewhere", OrgID: "org-2", Role: auth.RoleViewer}

	err := a.DeleteUser(context.Background(), adminActor(), "u-elsewhere")
	assert.True(t, errors.Is(err, auth.ErrNotFound), "got %v", err)
	assert.Empty(t, store.deleted)
}

func TestDeleteUserRefusesANonAdministrator(t *testing.T) {
	t.Parallel()

	a, store, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	seedUser(t, store, "u-target", goodPassword)
	viewer := auth.Identity{UserID: "u-v", OrgID: "org-1", Role: auth.RoleViewer}

	err := a.DeleteUser(context.Background(), viewer, "u-target")
	assert.True(t, errors.Is(err, auth.ErrNotPermitted), "got %v", err)
}

// --- SetRole ---------------------------------------------------------------

func TestSetRoleChangesTheRole(t *testing.T) {
	t.Parallel()

	a, store, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	seedUser(t, store, "u-target", goodPassword)
	seedAdmin(t, store, "u-admin")

	require.NoError(t, a.SetRole(context.Background(), adminActor(), "u-target", auth.RoleAnalyst))
	assert.Equal(t, auth.RoleAnalyst, store.users["u-target"].Role)
}

func TestSetRoleRejectsAnUnknownRole(t *testing.T) {
	t.Parallel()

	a, store, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	seedUser(t, store, "u-target", goodPassword)

	assert.Error(t, a.SetRole(context.Background(), adminActor(), "u-target", auth.Role("superuser")))
	assert.Equal(t, auth.RoleAdmin, store.users["u-target"].Role)
}

// TestSetRoleToTheCurrentRoleIsANoOp — an idempotent call must not trip the
// last-administrator guard, which would make "confirm this person is an
// admin" fail on the only admin.
func TestSetRoleToTheCurrentRoleIsANoOp(t *testing.T) {
	t.Parallel()

	a, store, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	seedUser(t, store, "u-target", goodPassword) // the only enabled admin

	require.NoError(t, a.SetRole(context.Background(), adminActor(), "u-target", auth.RoleAdmin))
	assert.Equal(t, auth.RoleAdmin, store.users["u-target"].Role)
}

// TestSetRoleRefusesDemotingTheLastAdministrator.
func TestSetRoleRefusesDemotingTheLastAdministrator(t *testing.T) {
	t.Parallel()

	a, store, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	seedUser(t, store, "u-target", goodPassword)

	err := a.SetRole(context.Background(), adminActor(), "u-target", auth.RoleViewer)
	assert.True(t, errors.Is(err, auth.ErrLastAdmin), "got %v", err)
	assert.Equal(t, auth.RoleAdmin, store.users["u-target"].Role)
}

func TestSetRoleRefusesYourOwnAccount(t *testing.T) {
	t.Parallel()

	a, store, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	seedAdmin(t, store, "u-admin")
	seedAdmin(t, store, "u-other")

	assert.Error(t, a.SetRole(context.Background(), adminActor(), "u-admin", auth.RoleViewer))
	assert.Equal(t, auth.RoleAdmin, store.users["u-admin"].Role)
}

// --- API keys --------------------------------------------------------------

// TestMintAPIKeyClampsTheRoleToTheCallersOwn.
//
// This is what lets any authenticated caller mint their own keys without
// PermManageUsers: a key cannot carry authority its owner does not have, so
// minting one is never an escalation.
func TestMintAPIKeyClampsTheRoleToTheCallersOwn(t *testing.T) {
	t.Parallel()

	a, store, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	analyst := auth.Identity{UserID: "u-an", OrgID: "org-1", Role: auth.RoleAnalyst}

	_, info, err := a.MintAPIKey(context.Background(), analyst, "ci", auth.RoleAdmin)
	require.NoError(t, err)
	assert.Equal(t, auth.RoleAnalyst, info.Role, "an analyst minted an admin key")
	assert.Equal(t, auth.RoleAnalyst, store.keys[info.ID].Role)
}

func TestMintAPIKeyAllowsANarrowerRole(t *testing.T) {
	t.Parallel()

	a, _, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))

	_, info, err := a.MintAPIKey(context.Background(), adminActor(), "read-only ci", auth.RoleViewer)
	require.NoError(t, err)
	assert.Equal(t, auth.RoleViewer, info.Role)
}

// TestMintAPIKeyFallsBackToTheCallersRole when the request names no valid one.
func TestMintAPIKeyFallsBackToTheCallersRole(t *testing.T) {
	t.Parallel()

	a, _, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))

	_, info, err := a.MintAPIKey(context.Background(), adminActor(), "unnamed", auth.Role(""))
	require.NoError(t, err)
	assert.Equal(t, auth.RoleAdmin, info.Role)
}

// TestMintAPIKeyReturnsTheKeyOnceAndStoresOnlyItsHash.
func TestMintAPIKeyReturnsTheKeyOnceAndStoresOnlyItsHash(t *testing.T) {
	t.Parallel()

	a, store, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))

	key, info, err := a.MintAPIKey(context.Background(), adminActor(), "  ci  ", auth.RoleAdmin)
	require.NoError(t, err)
	require.NotEmpty(t, key)
	assert.Equal(t, "ci", info.Name, "the name was not trimmed")
	assert.NotContains(t, string(store.keyHashes[info.ID]), key, "the key itself was stored")
	assert.NotEmpty(t, store.keyHashes[info.ID])
}

func TestMintAPIKeyRefusesAnUnauthenticatedCaller(t *testing.T) {
	t.Parallel()

	a, _, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))

	_, _, err := a.MintAPIKey(context.Background(), auth.Identity{}, "ci", auth.RoleAdmin)
	assert.True(t, errors.Is(err, auth.ErrNotPermitted), "got %v", err)
}

func TestMintAPIKeySurfacesAStoreFailureRatherThanTheKey(t *testing.T) {
	t.Parallel()

	a, store, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	store.keyErr = errors.New("database is down")

	key, _, err := a.MintAPIKey(context.Background(), adminActor(), "ci", auth.RoleAdmin)
	require.Error(t, err)
	assert.Empty(t, key, "a key that was never stored was handed to the caller")
}

// TestListAPIKeysReturnsOnlyTheCallersOwn, revoked ones included.
func TestListAPIKeysReturnsOnlyTheCallersOwn(t *testing.T) {
	t.Parallel()

	a, store, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	_, mine, err := a.MintAPIKey(context.Background(), adminActor(), "mine", auth.RoleAdmin)
	require.NoError(t, err)
	store.keys["k-theirs"] = auth.APIKeyInfo{ID: "k-theirs", UserID: "u-someone-else"}

	got, err := a.ListAPIKeys(context.Background(), adminActor())
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, mine.ID, got[0].ID)
}

func TestListAPIKeysRefusesAnUnauthenticatedCaller(t *testing.T) {
	t.Parallel()

	a, _, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))

	_, err := a.ListAPIKeys(context.Background(), auth.Identity{})
	assert.True(t, errors.Is(err, auth.ErrNotPermitted), "got %v", err)
}

func TestRevokeAPIKeyStampsTheKey(t *testing.T) {
	t.Parallel()

	a, store, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	_, info, err := a.MintAPIKey(context.Background(), adminActor(), "ci", auth.RoleAdmin)
	require.NoError(t, err)

	require.NoError(t, a.RevokeAPIKey(context.Background(), adminActor(), info.ID))
	assert.True(t, store.keys[info.ID].Revoked())
}

// TestRevokeAPIKeyIsIdempotent — revoking twice is the caller's intent either
// way, and an error on the second call invites a retry loop.
func TestRevokeAPIKeyIsIdempotent(t *testing.T) {
	t.Parallel()

	a, _, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	_, info, err := a.MintAPIKey(context.Background(), adminActor(), "ci", auth.RoleAdmin)
	require.NoError(t, err)

	require.NoError(t, a.RevokeAPIKey(context.Background(), adminActor(), info.ID))
	assert.NoError(t, a.RevokeAPIKey(context.Background(), adminActor(), info.ID))
}

// TestRevokeAPIKeyAnswersAsNotFoundForSomebodyElsesKey.
//
// "Not yours" would confirm the ID is real, which is the whole value of
// guessing at one.
func TestRevokeAPIKeyAnswersAsNotFoundForSomebodyElsesKey(t *testing.T) {
	t.Parallel()

	a, store, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	store.keys["k-theirs"] = auth.APIKeyInfo{ID: "k-theirs", UserID: "u-someone-else"}

	err := a.RevokeAPIKey(context.Background(), adminActor(), "k-theirs")
	assert.True(t, errors.Is(err, auth.ErrNotFound), "got %v", err)
	assert.False(t, store.keys["k-theirs"].Revoked(), "another caller's key was revoked")
}

func TestRevokeAPIKeyRefusesAnUnauthenticatedCaller(t *testing.T) {
	t.Parallel()

	a, _, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))

	err := a.RevokeAPIKey(context.Background(), auth.Identity{}, "k-1")
	assert.True(t, errors.Is(err, auth.ErrNotPermitted), "got %v", err)
}

// --- password policy -------------------------------------------------------

// TestPasswordPolicyIsReadableByAnyAuthenticatedCaller. Someone choosing a
// password has to be told the rules; the alternative is guessing until the
// form stops complaining, which is how Password1! gets chosen.
func TestPasswordPolicyIsReadableByAnyAuthenticatedCaller(t *testing.T) {
	t.Parallel()

	a, _, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	viewer := auth.Identity{UserID: "u-v", OrgID: "org-1", Role: auth.RoleViewer}

	p, err := a.PasswordPolicy(context.Background(), viewer)
	require.NoError(t, err)
	assert.Equal(t, "org-1", p.OrgID)
}

func TestPasswordPolicyRefusesAnUnauthenticatedCaller(t *testing.T) {
	t.Parallel()

	a, _, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))

	_, err := a.PasswordPolicy(context.Background(), auth.Identity{})
	assert.True(t, errors.Is(err, auth.ErrNotPermitted), "got %v", err)
}

// TestSetPasswordPolicyTakesTheOrganizationFromTheCaller.
//
// Never from the request: on a multi-tenant deployment, naming another
// organization would be a way to weaken a neighboring customer's password
// rules without touching their accounts at all.
func TestSetPasswordPolicyTakesTheOrganizationFromTheCaller(t *testing.T) {
	t.Parallel()

	a, _, policies := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	want := auth.DefaultPolicy("org-1")
	want.OrgID = "org-2-belongs-to-someone-else"

	got, err := a.SetPasswordPolicy(context.Background(), adminActor(), want)
	require.NoError(t, err)
	assert.Equal(t, "org-1", got.OrgID)
	require.Len(t, policies.saved, 1)
	assert.Equal(t, "org-1", policies.saved[0].OrgID)
}

// TestSetPasswordPolicyStampsTheAuthorItself, so a caller cannot attribute
// their own change to somebody else.
func TestSetPasswordPolicyStampsTheAuthorItself(t *testing.T) {
	t.Parallel()

	a, _, policies := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	p := auth.DefaultPolicy("org-1")
	p.UpdatedBy = "somebody.else@example.com"

	got, err := a.SetPasswordPolicy(context.Background(), adminActor(), p)
	require.NoError(t, err)
	assert.Equal(t, "admin@example.com", got.UpdatedBy)
	assert.Equal(t, "admin@example.com", policies.saved[0].UpdatedBy)
	assert.False(t, got.UpdatedAt.IsZero())
}

func TestSetPasswordPolicyRefusesANonAdministrator(t *testing.T) {
	t.Parallel()

	a, _, policies := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	viewer := auth.Identity{UserID: "u-v", OrgID: "org-1", Role: auth.RoleViewer}

	_, err := a.SetPasswordPolicy(context.Background(), viewer, auth.DefaultPolicy("org-1"))
	assert.True(t, errors.Is(err, auth.ErrNotPermitted), "got %v", err)
	assert.Empty(t, policies.saved)
}

// TestSetPasswordPolicyRejectsAnInvalidPolicy before it reaches the store.
func TestSetPasswordPolicyRejectsAnInvalidPolicy(t *testing.T) {
	t.Parallel()

	a, _, policies := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	p := auth.DefaultPolicy("org-1")
	p.MinLength = 2

	_, err := a.SetPasswordPolicy(context.Background(), adminActor(), p)
	assert.Error(t, err)
	assert.Empty(t, policies.saved, "an invalid policy reached the store")
}

// TestSetPasswordPolicyNeedsAPolicyStore rather than silently accepting a
// change nothing will persist.
func TestSetPasswordPolicyNeedsAPolicyStore(t *testing.T) {
	t.Parallel()

	store := newFakeAdminStore()
	a, err := auth.NewAdmin(store, stubClock{}, &stubIDs{})
	require.NoError(t, err)

	_, err = a.SetPasswordPolicy(context.Background(), adminActor(), auth.DefaultPolicy("org-1"))
	assert.True(t, errors.Is(err, auth.ErrNoPolicyStore), "got %v", err)
}

func TestSetPasswordPolicySurfacesAStoreFailure(t *testing.T) {
	t.Parallel()

	a, _, policies := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	policies.saveErr = errors.New("database is down")

	_, err := a.SetPasswordPolicy(context.Background(), adminActor(), auth.DefaultPolicy("org-1"))
	assert.Error(t, err)
}
