// Package auth holds the credential primitives an HTTP service authorizes
// against: password hashing, opaque bearer tokens for sessions and API
// keys, MFA, WebAuthn passkeys, Google Sign-In, and the role/permission
// vocabulary the HTTP layer checks.
//
// It is deliberately ignorant of HTTP and of storage. Nothing here reads a
// cookie, writes a header or touches a database. What lives here is the
// part that is worth testing in isolation and getting exactly right once:
// the hash parameters, the constant-time comparisons, and the mechanism —
// not the specific roles or permissions — behind "which role may do what".
package auth

import "fmt"

// Role is the authority a credential carries.
//
// It is a string type rather than an integer so that a role read from the
// database, sent in JSON, or written in a test fixture is the same value
// everywhere, and so an unrecognized role is visible as itself in an error
// message rather than as an integer nobody can decode.
//
// This package defines no roles of its own. A deployment names its own
// (RoleViewer, RoleEditor, whatever its domain calls for) and declares what
// each one may do in a PermissionTable, built once at startup and passed to
// NewAuthenticator, NewAdmin and friends.
type Role string

// Permission is a single thing a caller may be allowed to do.
//
// Like Role, this package defines none. Permissions are conventionally
// named for operations rather than routes ("create a report", not
// "POST /reports"), so that moving or versioning a route does not silently
// change who may call it — but the naming is entirely up to the
// PermissionTable that defines them.
type Permission string

// PermissionTable is the whole authorization model for one deployment: a
// set of permissions per role, built once and handed to every service that
// needs to answer "may this role do that" — Authenticator, Admin,
// MFAService, and any Identity they produce.
//
// It is a project's OWN vocabulary, not this package's. Two of the roles it
// declares carry a meaning this package's own use cases depend on:
// ManageUsers names the permission that gates Admin's account-management
// operations (CreateUser, SetRole, MintAPIKey, ...) and
// MFAService.ClearFactorFor, and AdminRole names the role NewAdmin's
// last-enabled-administrator check protects — the one every organization
// must keep at least one enabled instance of, and the one SystemIdentity
// acts as.
type PermissionTable struct {
	perms map[Role]map[Permission]bool

	// ManageUsers is the permission this package's own account-management
	// use cases require of a caller.
	ManageUsers Permission

	// AdminRole is the role treated as "an administrator" for the
	// last-enabled-administrator safety check, and the role SystemIdentity
	// carries.
	AdminRole Role
}

// NewPermissionTable builds a PermissionTable from a project's own role and
// permission vocabulary.
//
// table lists, for each role, every permission it carries — written out in
// full per role rather than inherited from a weaker one, so it can be read
// top to bottom to answer "what can an editor do" with no second lookup and
// no inheritance chain to walk, and so a permission can be given to one
// role alone without anyone having to notice that a weaker role's set feeds
// into it.
//
// manageUsers must be one of the permissions adminRole carries: it is
// meaningless for the role this package treats as an administrator to be
// unable to manage users, and rejecting that combination at construction
// turns a wiring mistake into a startup error instead of a production 403
// nobody can explain.
func NewPermissionTable(table map[Role][]Permission, manageUsers Permission, adminRole Role) (*PermissionTable, error) {
	if len(table) == 0 {
		return nil, fmt.Errorf("auth: a permission table needs at least one role")
	}
	if manageUsers == "" {
		return nil, fmt.Errorf("auth: a permission table needs a ManageUsers permission")
	}

	perms := make(map[Role]map[Permission]bool, len(table))
	for role, list := range table {
		// The empty Role is reserved: it is what a zero-value or
		// not-yet-authenticated Identity carries, and Can's whole
		// fail-closed guarantee depends on it never matching an entry
		// here.
		if role == "" {
			return nil, fmt.Errorf("auth: the empty string is not a valid role")
		}
		set := make(map[Permission]bool, len(list))
		for _, p := range list {
			if p == "" {
				return nil, fmt.Errorf("auth: role %q lists the empty string as a permission", role)
			}
			set[p] = true
		}
		perms[role] = set
	}

	if _, ok := perms[adminRole]; !ok {
		return nil, fmt.Errorf("auth: admin role %q is not one of the table's roles", adminRole)
	}
	if !perms[adminRole][manageUsers] {
		return nil, fmt.Errorf("auth: admin role %q does not carry the manageUsers permission %q", adminRole, manageUsers)
	}

	return &PermissionTable{perms: perms, ManageUsers: manageUsers, AdminRole: adminRole}, nil
}

// Can reports whether the role carries the permission.
//
// A nil table and an unknown role both carry no permissions rather than
// causing a panic or, far worse, matching a default branch that grants
// something. A nil table is what an Identity that was never resolved
// through this package's own login path carries — the zero value of the
// field, never a caller's explicit choice — and it must fail exactly as
// closed as an unrecognized role does.
func (t *PermissionTable) Can(role Role, p Permission) bool {
	if t == nil {
		return false
	}
	return t.perms[role][p]
}

// Valid reports whether role is one this table defines.
func (t *PermissionTable) Valid(role Role) bool {
	if t == nil {
		return false
	}
	_, ok := t.perms[role]
	return ok
}

// ParseRole converts a stored or submitted string into a Role, rejecting
// anything this table does not define.
//
// Every role entering a process — from a database row, a JSON body, an
// environment variable — should go through here, so that a typo becomes an
// error at the boundary instead of a credential that silently carries no
// permissions and produces a 403 nobody can explain.
func (t *PermissionTable) ParseRole(s string) (Role, error) {
	r := Role(s)
	if !t.Valid(r) {
		return "", fmt.Errorf("auth: unknown role %q", s)
	}
	return r, nil
}

// AtMost returns role if the ceiling role carries everything role does, and
// ceiling otherwise.
//
// It backs the rule that an API key may be weaker than its owner but never
// stronger: minting clamps the requested role to the owner's. Without the
// clamp, a careless or compromised account could mint a key for a stronger
// role than its own and escalate, which would make the role boundary
// advisory.
//
// The comparison is subset containment, not a rank or a permission count.
// Counting would impose the integer hierarchy Role deliberately does not
// have, and it gets the wrong answer the moment two roles have equal-sized
// but different permission sets. When neither role contains the other, the
// result is the empty Role — guaranteed, by construction, to carry no
// permissions — rather than some specific role this table's caller might
// not have defined the way another deployment's did. AtMost's whole job is
// to never return authority the ceiling does not have, and "no authority"
// is the one answer that is always safe.
func (t *PermissionTable) AtMost(role, ceiling Role) Role {
	if t == nil {
		return ""
	}
	if containsAll(t.perms[ceiling], t.perms[role]) {
		return role
	}
	if containsAll(t.perms[role], t.perms[ceiling]) {
		return ceiling
	}
	return ""
}

// containsAll reports whether super grants every permission sub does.
func containsAll(super, sub map[Permission]bool) bool {
	for p, granted := range sub {
		if granted && !super[p] {
			return false
		}
	}
	return true
}
