package auth_test

import (
	"context"
	"errors"
	"testing"

	auth "github.com/qdiver/golang-module-rbac"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Invitations: an account made without a password, and the one-time
// redemption that gives it its first.

func TestCreateInvitedUserStoresNoPassword(t *testing.T) {
	t.Parallel()
	a, store, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))

	u, err := a.CreateInvitedUser(context.Background(), adminActor(t), " new@example.com ", "New", testViewer)
	require.NoError(t, err)
	assert.Equal(t, "new@example.com", u.Email)
	assert.Empty(t, store.nextUser.PasswordHash, "an invitation must not carry a password")
	assert.Equal(t, testViewer, store.nextUser.Role)
}

// TestCreateInvitedUserHasCreateUsersRefusals: the same authorization, the
// same seniority rule, the same duplicate check.
func TestCreateInvitedUserHasCreateUsersRefusals(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a, store, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	seedUser(t, store, "u-existing", goodPassword)

	viewer := auth.Identity{UserID: "u-v", OrgID: "org-1", Role: testViewer}.WithPermissions(testTable(t))
	_, err := a.CreateInvitedUser(ctx, viewer, "x@example.com", "", testViewer)
	assert.ErrorIs(t, err, auth.ErrNotPermitted)

	_, err = a.CreateInvitedUser(ctx, adminActor(t), "u-existing@example.com", "", testViewer)
	assert.ErrorIs(t, err, auth.ErrEmailTaken)

	_, err = a.CreateInvitedUser(ctx, adminActor(t), "  ", "", testViewer)
	assert.Error(t, err)

	ta, _, table := newTieredFixture(t)
	_, err = ta.CreateInvitedUser(ctx, actorAs(table, "u-admin", testAdmin), "boss@example.com", "", tierOwner)
	assert.ErrorIs(t, err, auth.ErrPrivilegedTarget)
}

func TestSetInitialPasswordGivesAnInvitedAccountItsFirstPassword(t *testing.T) {
	t.Parallel()
	a, store, policies := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	store.users["u-new"] = auth.User{ID: "u-new", OrgID: "org-1", Email: "new@example.com", Role: testViewer}

	require.NoError(t, a.SetInitialPassword(context.Background(), "u-new", goodPassword))
	ok, err := auth.VerifyPassword(store.users["u-new"].PasswordHash, goodPassword)
	require.NoError(t, err)
	assert.True(t, ok)
	require.Len(t, policies.recorded, 1, "the change date must be stamped for rotation")
	assert.Equal(t, "u-new", policies.recorded[0].userID)
}

// TestSetInitialPasswordNeverReplacesOne: redeeming an invitation twice, or
// an invitation for an account that already has a password, must not be a
// way to take it over.
func TestSetInitialPasswordNeverReplacesOne(t *testing.T) {
	t.Parallel()
	a, store, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	seedUser(t, store, "u-has", goodPassword)
	before := store.users["u-has"].PasswordHash

	err := a.SetInitialPassword(context.Background(), "u-has", "Another-Long-Pass-42")
	assert.True(t, errors.Is(err, auth.ErrPasswordAlreadySet), "got %v", err)
	assert.Equal(t, before, store.users["u-has"].PasswordHash)
}

func TestSetInitialPasswordRefusesADisabledAccountAndAWeakPassword(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a, store, _ := newAdminFixture(t, auth.DefaultPolicy("org-1"))
	store.users["u-off"] = auth.User{ID: "u-off", OrgID: "org-1", Email: "off@example.com", Disabled: true}
	store.users["u-new"] = auth.User{ID: "u-new", OrgID: "org-1", Email: "new@example.com"}

	assert.ErrorIs(t, a.SetInitialPassword(ctx, "u-off", goodPassword), auth.ErrNotFound)
	assert.ErrorIs(t, a.SetInitialPassword(ctx, "u-new", "short"), auth.ErrWeakPassword)
	assert.Empty(t, store.users["u-new"].PasswordHash)
}

func TestRolesAndPermissionsReadTheTable(t *testing.T) {
	t.Parallel()
	table := testTable(t)
	assert.Equal(t, []auth.Role{testAdmin, testAnalyst, testViewer}, table.Roles())
	assert.Equal(t, []auth.Permission{testPermRead}, table.Permissions(testViewer))
	assert.Nil(t, table.Permissions("nobody"))
	for _, r := range table.Roles() {
		for _, p := range table.Permissions(r) {
			assert.True(t, table.Can(r, p))
		}
	}
}
