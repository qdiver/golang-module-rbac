// Package auth holds the credential primitives behind ADR-0027: password
// hashing, opaque bearer tokens for sessions and API keys, and the role and
// permission vocabulary the HTTP layer authorizes against.
//
// It is deliberately ignorant of HTTP and of storage. Nothing here reads a
// cookie, writes a header or touches a database — internal/infra/httpapi
// does the first two and internal/infra/postgres the third. What lives here
// is the part that is worth testing in isolation and getting exactly right
// once: the hash parameters, the constant-time comparisons, and the table
// that says which role may do what.
package auth

import "fmt"

// Role is the authority a credential carries. ADR-0027 fixes three.
//
// It is a string type rather than an integer so that a role read from the
// database, sent in JSON, or written in a test fixture is the same value
// everywhere, and so an unrecognized role is visible as itself in an error
// message rather than as an integer nobody can decode.
//
// Roles are deliberately NOT ordered as an integer hierarchy. A hierarchy
// invites `if role >= Analyst`, which silently grants every future role
// inserted above the comparison point whatever that check was guarding.
// Authority is expressed only through the permission table below.
type Role string

const (
	// RoleViewer may read everything its organization can see and change
	// nothing.
	RoleViewer Role = "viewer"

	// RoleAnalyst may additionally create and rerun reports, and file and
	// restore disputes — the working set of someone who actually uses the
	// product on an estate.
	RoleAnalyst Role = "analyst"

	// RoleAdmin may additionally delete reports and manage users and keys.
	//
	// Deleting a report is separated from the rest because of what it
	// costs: migration 0001's foreign keys cascade, so a DELETE takes the
	// report's findings, assets, versions, disputes and change log with it.
	// That is not an operation an analyst should reach by accident.
	RoleAdmin Role = "admin"
)

// Permission is a single thing a caller may be allowed to do.
//
// Permissions name operations rather than routes ("create a report", not
// "POST /reports") so that moving or versioning a route does not silently
// change who may call it.
type Permission string

const (
	// PermReadReports covers every GET under /api/v1. Read authority is not
	// split further because the API has no read that is more sensitive than
	// another: a finding's evidence is reachable from the report that
	// carries it, so gating one and not the other would be decorative.
	PermReadReports Permission = "reports:read"

	// PermCreateReport covers POST /api/v1/reports.
	PermCreateReport Permission = "reports:create"

	// PermRerunReport covers POST /api/v1/reports/{id}/rerun.
	PermRerunReport Permission = "reports:rerun"

	// PermDeleteReport covers DELETE /api/v1/reports/{id} — and, by
	// cascade, everything hanging off it.
	PermDeleteReport Permission = "reports:delete"

	// PermManageDisputes covers filing a dispute and restoring one. The two
	// are one permission because they are one workflow: a caller who may
	// exclude an asset must be able to undo it, and splitting them produces
	// a role that can only make the score worse.
	PermManageDisputes Permission = "disputes:manage"

	// PermManageUsers covers user and API-key administration.
	PermManageUsers Permission = "users:manage"
)

// rolePermissions is the whole authorization model: a set per role, written
// out in full.
//
// Each role repeats what the weaker one has rather than inheriting from it.
// The duplication is the point — this table can be read top to bottom to
// answer "what can an analyst do", with no second lookup and no inheritance
// chain to walk, and a permission can be given to admin alone without
// anyone having to notice that viewer's set feeds into it.
var rolePermissions = map[Role]map[Permission]bool{
	RoleViewer: {
		PermReadReports: true,
	},
	RoleAnalyst: {
		PermReadReports:    true,
		PermCreateReport:   true,
		PermRerunReport:    true,
		PermManageDisputes: true,
	},
	RoleAdmin: {
		PermReadReports:    true,
		PermCreateReport:   true,
		PermRerunReport:    true,
		PermDeleteReport:   true,
		PermManageDisputes: true,
		PermManageUsers:    true,
	},
}

// Can reports whether the role carries the permission.
//
// An unknown role — a value read from a database row written by a newer
// version, or a zero Role on an uninitialised struct — carries no
// permissions rather than causing a panic or, far worse, matching a default
// branch that grants something.
func (r Role) Can(p Permission) bool {
	return rolePermissions[r][p]
}

// Valid reports whether r is one of the three roles ADR-0027 defines.
func (r Role) Valid() bool {
	_, ok := rolePermissions[r]
	return ok
}

// ParseRole converts a stored or submitted string into a Role, rejecting
// anything unrecognized.
//
// Every role entering the process — from a database row, a JSON body, an
// environment variable — goes through here, so that a typo becomes an error
// at the boundary instead of a credential that silently carries no
// permissions and produces a 403 nobody can explain.
func ParseRole(s string) (Role, error) {
	r := Role(s)
	if !r.Valid() {
		return "", fmt.Errorf("auth: unknown role %q", s)
	}
	return r, nil
}

// AtMost returns r if the ceiling role carries everything r does, and the
// ceiling otherwise.
//
// It backs the rule that an API key may be weaker than its owner but never
// stronger: minting clamps the requested role to the owner's. Without the
// clamp, a careless or compromised analyst could mint an admin key and
// escalate to deleting reports, which would make the role boundary
// advisory.
//
// The comparison is subset containment, not a rank or a permission count.
// Counting would be the integer hierarchy Role deliberately does not have,
// and it gets the wrong answer the first time two roles have equal-sized but
// different permission sets. When neither role contains the other — which no
// current pair does, but which a fourth role could easily introduce — the
// result is RoleViewer: the clamp's whole job is to never return authority
// the ceiling does not have, and the least-privileged role is the only
// answer that is always safe.
func (r Role) AtMost(ceiling Role) Role {
	if containsAll(rolePermissions[ceiling], rolePermissions[r]) {
		return r
	}
	if containsAll(rolePermissions[r], rolePermissions[ceiling]) {
		return ceiling
	}
	return RoleViewer
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
