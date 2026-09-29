package auth_test

import (
	"context"
	"errors"
	"testing"

	auth "github.com/qdiver/golang-module-rbac"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Two tiers of administrator: the shape WithProtectedRoles and
// WithPrivilegedRoles exist for. testAdmin runs the everyday roster;
// tierOwner is the senior tier, the only one that may touch or grant
// either admin role, and the one an organization must never run out of.
const (
	tierOwner          auth.Role       = "owner"
	permManageSeniors  auth.Permission = "users:manage_privileged"
	tierNoSuchRoleName auth.Role       = "nobody"
)

func tieredBase(t *testing.T) *auth.PermissionTable {
	t.Helper()
	table, err := auth.NewPermissionTable(map[auth.Role][]auth.Permission{
		testViewer: {testPermRead},
		testAdmin:  {testPermRead, testPermUsers},
		tierOwner:  {testPermRead, testPermUsers, permManageSeniors},
	}, testPermUsers, tierOwner)
	require.NoError(t, err)
	return table
}

func tieredTable(t *testing.T) *auth.PermissionTable {
	t.Helper()
	table, err := tieredBase(t).WithPrivilegedRoles(permManageSeniors, testAdmin, tierOwner)
	require.NoError(t, err)
	table, err = table.WithProtectedRoles(tierOwner)
	require.NoError(t, err)
	return table
}

func newTieredFixture(t *testing.T) (*auth.Admin, *fakeAdminStore, *auth.PermissionTable) {
	t.Helper()
	table := tieredTable(t)
	store := newFakeAdminStore()
	a, err := auth.NewAdmin(store, stubClock{mfaNow}, &stubIDs{}, table)
	require.NoError(t, err)
	return a.WithPolicies(&fakePolicyStore{policy: auth.DefaultPolicy("org-1"), history: map[string][]string{}}), store, table
}

func seedRole(store *fakeAdminStore, id string, role auth.Role) {
	store.users[id] = auth.User{ID: id, OrgID: "org-1", Email: id + "@example.com", Role: role}
}

func actorAs(table *auth.PermissionTable, id string, role auth.Role) auth.Identity {
	return auth.Identity{UserID: id, OrgID: "org-1", Role: role, Actor: id}.WithPermissions(table)
}

// --- table construction ----------------------------------------------------

func TestWithPrivilegedRolesRejectsAHolderThatIsNotItselfPrivileged(t *testing.T) {
	t.Parallel()
	// admin carries nothing senior here, but make viewer carry the senior
	// permission without being privileged: a quieter way to the authority.
	table, err := auth.NewPermissionTable(map[auth.Role][]auth.Permission{
		testViewer: {testPermUsers, permManageSeniors},
		tierOwner:  {testPermUsers, permManageSeniors},
	}, testPermUsers, tierOwner)
	require.NoError(t, err)
	_, err = table.WithPrivilegedRoles(permManageSeniors, tierOwner)
	assert.Error(t, err)
}

func TestWithPrivilegedRolesRejectsAHolderWithoutManageUsers(t *testing.T) {
	t.Parallel()
	table, err := auth.NewPermissionTable(map[auth.Role][]auth.Permission{
		testViewer: {permManageSeniors},
		tierOwner:  {testPermUsers},
	}, testPermUsers, tierOwner)
	require.NoError(t, err)
	_, err = table.WithPrivilegedRoles(permManageSeniors, testViewer, tierOwner)
	assert.Error(t, err)
}

// TestWithPrivilegedRolesRejectsAPermissionNobodyHolds: every privileged
// account would be frozen, with no role able to manage it.
func TestWithPrivilegedRolesRejectsAPermissionNobodyHolds(t *testing.T) {
	t.Parallel()
	_, err := tieredBase(t).WithPrivilegedRoles("users:nobody", tierOwner)
	assert.Error(t, err)
}

func TestTableOptionsRejectUnknownRolesAndEmptyLists(t *testing.T) {
	t.Parallel()
	base := tieredBase(t)
	_, err := base.WithPrivilegedRoles(permManageSeniors, tierOwner, tierNoSuchRoleName)
	assert.Error(t, err)
	_, err = base.WithPrivilegedRoles(permManageSeniors)
	assert.Error(t, err)
	_, err = base.WithProtectedRoles(tierNoSuchRoleName)
	assert.Error(t, err)
	_, err = base.WithProtectedRoles()
	assert.Error(t, err)
}

// TestTableOptionsLeaveTheReceiverAlone: the table is shared by every
// service in a process, so an option must not change it underneath them.
func TestTableOptionsLeaveTheReceiverAlone(t *testing.T) {
	t.Parallel()
	base := tieredBase(t)
	_ = tieredTable(t)
	_, err := base.WithPrivilegedRoles(permManageSeniors, testAdmin, tierOwner)
	require.NoError(t, err)
	_, err = base.WithProtectedRoles(testViewer)
	require.NoError(t, err)

	assert.False(t, base.Privileged(testAdmin))
	assert.True(t, base.MayHandle(testAdmin, tierOwner))
	assert.True(t, base.Protected(tierOwner), "AdminRole is protected by default")
	assert.False(t, base.Protected(testViewer))
}

func TestMayHandle(t *testing.T) {
	t.Parallel()
	table := tieredTable(t)
	cases := []struct {
		caller, target auth.Role
		want           bool
	}{
		{testAdmin, testViewer, true},
		{testAdmin, testAdmin, false},
		{testAdmin, tierOwner, false},
		{tierOwner, testViewer, true},
		{tierOwner, testAdmin, true},
		{tierOwner, tierOwner, true},
		// The rule is seniority only; ManageUsers is still checked by the
		// operation, which is why a viewer "may handle" a viewer here.
		{testViewer, testViewer, true},
		{testViewer, testAdmin, false},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, table.MayHandle(c.caller, c.target), "%s → %s", c.caller, c.target)
	}
}

// --- privileged targets ----------------------------------------------------

// TestAnAdminCannotActOnASeniorAccount is the bug this option was written
// for: with ManageUsers alone, an admin could demote, disable, delete or
// reset the only owner.
func TestAnAdminCannotActOnASeniorAccount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for _, targetRole := range []auth.Role{testAdmin, tierOwner} {
		a, store, table := newTieredFixture(t)
		seedRole(store, "u-admin", testAdmin)
		seedRole(store, "u-other-admin", testAdmin)
		seedRole(store, "u-owner", tierOwner)
		seedRole(store, "u-owner-2", tierOwner)
		actor := actorAs(table, "u-admin", testAdmin)
		target := "u-owner"
		if targetRole == testAdmin {
			target = "u-other-admin"
		}

		ops := map[string]error{
			"disable": a.DisableUser(ctx, actor, target),
			"delete":  a.DeleteUser(ctx, actor, target),
			"setrole": a.SetRole(ctx, actor, target, testViewer),
			"reset":   a.ResetPassword(ctx, actor, target, goodPassword),
		}
		for name, err := range ops {
			assert.ErrorIs(t, err, auth.ErrPrivilegedTarget, "%s on %s", name, targetRole)
			assert.ErrorIs(t, err, auth.ErrNotPermitted, "%s on %s must still read as not permitted", name, targetRole)
		}
		assert.Equal(t, targetRole, store.users[target].Role)
		assert.False(t, store.users[target].Disabled)
		assert.Empty(t, store.deleted)
	}
}

func TestAnAdminCannotGrantASeniorRole(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a, store, table := newTieredFixture(t)
	seedRole(store, "u-viewer", testViewer)
	actor := actorAs(table, "u-admin", testAdmin)

	for _, role := range []auth.Role{testAdmin, tierOwner} {
		assert.ErrorIs(t, a.SetRole(ctx, actor, "u-viewer", role), auth.ErrPrivilegedTarget)
		_, err := a.CreateUser(ctx, actor, string(role)+"@example.com", "New", role, goodPassword)
		assert.ErrorIs(t, err, auth.ErrPrivilegedTarget)
	}
	assert.Equal(t, testViewer, store.users["u-viewer"].Role)
}

// TestAnAdminStillRunsTheEverydayRoster: the option narrows admins, it does
// not retire them.
func TestAnAdminStillRunsTheEverydayRoster(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a, store, table := newTieredFixture(t)
	seedRole(store, "u-viewer", testViewer)
	actor := actorAs(table, "u-admin", testAdmin)

	require.NoError(t, a.DisableUser(ctx, actor, "u-viewer"))
	require.NoError(t, a.EnableUser(ctx, actor, "u-viewer"))
	_, err := a.CreateUser(ctx, actor, "new@example.com", "New", testViewer, goodPassword)
	require.NoError(t, err)
}

func TestASeniorAdministratorManagesAdmins(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a, store, table := newTieredFixture(t)
	seedRole(store, "u-owner", tierOwner)
	seedRole(store, "u-viewer", testViewer)
	seedRole(store, "u-admin", testAdmin)
	actor := actorAs(table, "u-owner", tierOwner)

	require.NoError(t, a.SetRole(ctx, actor, "u-viewer", testAdmin))
	assert.Equal(t, testAdmin, store.users["u-viewer"].Role)
	require.NoError(t, a.DisableUser(ctx, actor, "u-admin"))
}

func TestClearingASeniorAccountsFactorNeedsTheSeniorPermission(t *testing.T) {
	t.Parallel()
	table := tieredTable(t)
	sealer, err := auth.NewSealerFromHex(testSealKeyHex)
	require.NoError(t, err)
	svc, err := auth.NewMFAService(newFakeMFAStore(), newFakeAdminStore(), sealer, stubClock{mfaNow}, &stubIDs{}, "Test", table)
	require.NoError(t, err)

	owner := auth.User{ID: "u-owner", OrgID: "org-1", Role: tierOwner}
	err = svc.ClearFactorFor(context.Background(), actorAs(table, "u-admin", testAdmin), "u-owner", owner)
	assert.ErrorIs(t, err, auth.ErrPrivilegedTarget)

	viewer := auth.User{ID: "u-viewer", OrgID: "org-1", Role: testViewer}
	assert.NoError(t, svc.ClearFactorFor(context.Background(), actorAs(table, "u-admin", testAdmin), "u-viewer", viewer))
	assert.NoError(t, svc.ClearFactorFor(context.Background(), actorAs(table, "u-owner", tierOwner), "u-owner-2",
		auth.User{ID: "u-owner-2", OrgID: "org-1", Role: tierOwner}))
}

// --- protected roles -------------------------------------------------------

// TestTheLastSeniorAccountIsKept. Only an owner may make an owner, so the
// last one going would leave the organization unable to mint a
// replacement — even with plain admins still enabled.
func TestTheLastSeniorAccountIsKept(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a, store, table := newTieredFixture(t)
	seedRole(store, "u-owner", tierOwner)
	seedRole(store, "u-admin", testAdmin)
	// A system job acts with AdminRole's authority (owner here) but is not
	// itself an account, so it is the one caller that can reach the last
	// owner at all.
	system := auth.SystemIdentity("org-1", table)

	for name, err := range map[string]error{
		"disable": a.DisableUser(ctx, system, "u-owner"),
		"delete":  a.DeleteUser(ctx, system, "u-owner"),
		"setrole": a.SetRole(ctx, system, "u-owner", testAdmin),
	} {
		assert.True(t, errors.Is(err, auth.ErrLastAdmin), "%s: got %v", name, err)
	}
	assert.Equal(t, tierOwner, store.users["u-owner"].Role)
	assert.False(t, store.users["u-owner"].Disabled)
}

func TestASecondSeniorAccountMayGo(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a, store, table := newTieredFixture(t)
	seedRole(store, "u-owner", tierOwner)
	seedRole(store, "u-owner-2", tierOwner)

	require.NoError(t, a.DisableUser(ctx, actorAs(table, "u-owner", tierOwner), "u-owner-2"))
}

// TestAnUnprotectedRolesLastHolderMayGo: protecting the top tier moves the
// guard rather than widening it, so the last plain admin is not stuck
// while an owner remains to replace them.
func TestAnUnprotectedRolesLastHolderMayGo(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a, store, table := newTieredFixture(t)
	seedRole(store, "u-owner", tierOwner)
	seedRole(store, "u-admin", testAdmin)
	actor := actorAs(table, "u-owner", tierOwner)

	require.NoError(t, a.SetRole(ctx, actor, "u-admin", testViewer))
	require.NoError(t, a.DisableUser(ctx, actor, "u-admin"))
}

// --- per-role guards (three tiers) -------------------------------------------

// Three tiers: an IT administrator manages admins and other IT
// administrators, but not the owner tier; only an owner manages owners.
const (
	tierIT          auth.Role       = "it_admin"
	permManageAdmin auth.Permission = "users:manage_admins"
	permManageOwner auth.Permission = "users:manage_super"
)

func threeTierTable(t *testing.T) *auth.PermissionTable {
	t.Helper()
	base, err := auth.NewPermissionTable(map[auth.Role][]auth.Permission{
		testViewer: {testPermRead},
		testAdmin:  {testPermRead, testPermUsers},
		tierIT:     {testPermUsers, permManageAdmin},
		tierOwner:  {testPermRead, testPermUsers, permManageAdmin, permManageOwner},
	}, testPermUsers, tierOwner)
	require.NoError(t, err)
	table, err := base.WithRoleGuards(map[auth.Role]auth.Permission{
		testAdmin: permManageAdmin, tierIT: permManageAdmin, tierOwner: permManageOwner,
	})
	require.NoError(t, err)
	table, err = table.WithProtectedRoles(tierOwner, tierIT)
	require.NoError(t, err)
	return table
}

func TestRoleGuardsGiveEachTierItsOwnPermission(t *testing.T) {
	t.Parallel()
	table := threeTierTable(t)
	cases := []struct {
		caller, target auth.Role
		want           bool
	}{
		{tierIT, testViewer, true},
		{tierIT, testAdmin, true},
		{tierIT, tierIT, true},
		{tierIT, tierOwner, false}, // the reason for per-role guards
		{testAdmin, testViewer, true},
		{testAdmin, testAdmin, false},
		{testAdmin, tierIT, false},
		{tierOwner, tierOwner, true},
		{tierOwner, tierIT, true},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, table.MayHandle(c.caller, c.target), "%s → %s", c.caller, c.target)
	}
}

func TestAnITAdminCannotMakeOrTouchAnOwner(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	table := threeTierTable(t)
	store := newFakeAdminStore()
	a, err := auth.NewAdmin(store, stubClock{mfaNow}, &stubIDs{}, table)
	require.NoError(t, err)
	seedRole(store, "u-it", tierIT)
	seedRole(store, "u-it-2", tierIT)
	seedRole(store, "u-owner", tierOwner)
	seedRole(store, "u-owner-2", tierOwner)
	seedRole(store, "u-viewer", testViewer)
	it := actorAs(table, "u-it", tierIT)

	assert.ErrorIs(t, a.SetRole(ctx, it, "u-viewer", tierOwner), auth.ErrPrivilegedTarget)
	assert.ErrorIs(t, a.DisableUser(ctx, it, "u-owner"), auth.ErrPrivilegedTarget)
	_, err = a.CreateInvitedUser(ctx, it, "boss@example.com", "", tierOwner)
	assert.ErrorIs(t, err, auth.ErrPrivilegedTarget)

	// Everything below the owner tier is theirs.
	require.NoError(t, a.SetRole(ctx, it, "u-viewer", testAdmin))
	require.NoError(t, a.DisableUser(ctx, it, "u-it-2"))
	_, err = a.CreateInvitedUser(ctx, it, "it2@example.com", "", tierIT)
	require.NoError(t, err)
}

func TestRoleGuardsRejectAnUnguardedHolderAndAnUnheldPermission(t *testing.T) {
	t.Parallel()
	base, err := auth.NewPermissionTable(map[auth.Role][]auth.Permission{
		testViewer: {testPermUsers, permManageAdmin}, // holds the guard, but is not guarded
		tierOwner:  {testPermUsers, permManageAdmin, permManageOwner},
	}, testPermUsers, tierOwner)
	require.NoError(t, err)
	_, err = base.WithRoleGuards(map[auth.Role]auth.Permission{tierOwner: permManageOwner, testViewer: ""})
	assert.Error(t, err, "an empty permission")
	_, err = base.WithRoleGuards(map[auth.Role]auth.Permission{tierOwner: permManageAdmin})
	assert.Error(t, err, "viewer holds manage_admins without being guarded")
	_, err = tieredBase(t).WithRoleGuards(map[auth.Role]auth.Permission{tierOwner: "users:nobody"})
	assert.Error(t, err, "a permission no role holds")
	_, err = tieredBase(t).WithRoleGuards(nil)
	assert.Error(t, err)
}
