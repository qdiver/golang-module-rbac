package auth

import (
	"strings"
	"testing"
)

// TestRolePermissions pins the whole authorization model as a table.
//
// It is written as every (role, permission) pair rather than as spot checks
// so that adding a permission to a role is impossible to do quietly: the
// test does not assert "analyst can create reports", it asserts what each of
// the three roles can and cannot do, everywhere. A grant added to the wrong
// row fails here rather than in a review nobody ran.
func TestRolePermissions(t *testing.T) {
	t.Parallel()

	all := []Permission{
		PermReadReports, PermCreateReport, PermRerunReport,
		PermDeleteReport, PermManageDisputes, PermManageUsers,
	}
	granted := map[Role]map[Permission]bool{
		RoleViewer: {
			PermReadReports: true,
		},
		RoleAnalyst: {
			PermReadReports: true, PermCreateReport: true,
			PermRerunReport: true, PermManageDisputes: true,
		},
		RoleAdmin: {
			PermReadReports: true, PermCreateReport: true,
			PermRerunReport: true, PermDeleteReport: true,
			PermManageDisputes: true, PermManageUsers: true,
		},
	}

	for role, want := range granted {
		for _, p := range all {
			if got := role.Can(p); got != want[p] {
				t.Errorf("%s.Can(%s) = %v, want %v", role, p, got, want[p])
			}
		}
	}
}

// TestUnknownRoleCarriesNoPermissions is the fail-closed property.
//
// The zero Role is what an uninitialised Identity has — the state of a
// request that reached a handler without being authenticated. It must be
// able to do nothing at all. A map lookup returning a nil inner map gives
// that for free today; this test is what stops a future rewrite from
// introducing a default branch that grants something.
func TestUnknownRoleCarriesNoPermissions(t *testing.T) {
	t.Parallel()

	for _, r := range []Role{"", "root", "superuser", "Admin", "ADMIN"} {
		for _, p := range []Permission{PermReadReports, PermDeleteReport, PermManageUsers} {
			if r.Can(p) {
				t.Errorf("unknown role %q was granted %s", r, p)
			}
		}
		if r.Valid() {
			t.Errorf("Role(%q).Valid() = true, want false", r)
		}
	}
}

// TestParseRole checks the boundary conversion, including that role
// matching is case-sensitive — "Admin" is a typo, not an admin.
func TestParseRole(t *testing.T) {
	t.Parallel()

	for _, s := range []string{"viewer", "analyst", "admin"} {
		if _, err := ParseRole(s); err != nil {
			t.Errorf("ParseRole(%q) = %v, want no error", s, err)
		}
	}
	for _, s := range []string{"", "Admin", "owner", "viewer "} {
		if _, err := ParseRole(s); err == nil {
			t.Errorf("ParseRole(%q) succeeded, want an error", s)
		}
	}
}

// TestAtMostNeverEscalates is the API-key clamp.
//
// The property that matters is one-directional: for every pair of roles, the
// clamped result must never carry a permission the ceiling lacks. Asserting
// that rather than a fixed table means a fourth role cannot be added in a
// way that escalates without this failing.
func TestAtMostNeverEscalates(t *testing.T) {
	t.Parallel()

	roles := []Role{RoleViewer, RoleAnalyst, RoleAdmin}
	all := []Permission{
		PermReadReports, PermCreateReport, PermRerunReport,
		PermDeleteReport, PermManageDisputes, PermManageUsers,
	}
	for _, requested := range roles {
		for _, ceiling := range roles {
			got := requested.AtMost(ceiling)
			for _, p := range all {
				if got.Can(p) && !ceiling.Can(p) {
					t.Errorf("%s.AtMost(%s) = %s, which escalates to %s",
						requested, ceiling, got, p)
				}
			}
		}
	}
}

// TestAtMostKeepsARequestedWeakerRole guards the other half: the clamp must
// not flatten every key to the owner's role, or an analyst could never mint
// the read-only CI key the feature exists for.
func TestAtMostKeepsARequestedWeakerRole(t *testing.T) {
	t.Parallel()

	if got := RoleViewer.AtMost(RoleAdmin); got != RoleViewer {
		t.Errorf("viewer key minted by an admin = %s, want viewer", got)
	}
	if got := RoleAnalyst.AtMost(RoleAdmin); got != RoleAnalyst {
		t.Errorf("analyst key minted by an admin = %s, want analyst", got)
	}
	if got := RoleAdmin.AtMost(RoleViewer); got != RoleViewer {
		t.Errorf("admin key requested by a viewer = %s, want viewer", got)
	}
}

// TestPasswordRoundTrip covers the ordinary path and the two ways it must
// fail: a wrong password, and a hash that no password can satisfy.
func TestPasswordRoundTrip(t *testing.T) {
	t.Parallel()

	const pw = "correct horse battery staple"
	encoded, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	ok, err := VerifyPassword(encoded, pw)
	if err != nil || !ok {
		t.Errorf("VerifyPassword(correct) = %v, %v; want true, nil", ok, err)
	}
	ok, err = VerifyPassword(encoded, pw+"!")
	if err != nil || ok {
		t.Errorf("VerifyPassword(wrong) = %v, %v; want false, nil", ok, err)
	}
}

// TestPasswordHashesAreSalted asserts that the same password hashed twice
// produces different output.
//
// Without a per-password salt, a stolen dump reveals which users share a
// password and falls to one rainbow table for all of them. This is cheap to
// get wrong by refactoring the salt out into a package-level constant, and
// it is invisible in every other test, because both hashes would still
// verify correctly.
func TestPasswordHashesAreSalted(t *testing.T) {
	t.Parallel()

	const pw = "same password"
	a, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	b, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if a == b {
		t.Fatal("two hashes of the same password are identical — the salt is not random")
	}
}

// TestVerifyRejectsMalformedHashes covers the hostile and the merely broken.
//
// The zero-cost case is the pointed one: a row reading m=0,t=0,p=0 would
// verify near-instantly against anything, so a hash claiming no work must be
// rejected rather than honored. An attacker who can write one column of one
// row should not thereby be able to log in as that user with any password.
func TestVerifyRejectsMalformedHashes(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"empty":             "",
		"not PHC":           "plaintext-password",
		"wrong algorithm":   "$argon2i$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
		"wrong version":     "$argon2id$v=16$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
		"truncated":         "$argon2id$v=19$m=19456,t=2,p=1",
		"zero cost":         "$argon2id$v=19$m=0,t=0,p=0$c2FsdHNhbHQ$aGFzaGhhc2g",
		"bad base64 salt":   "$argon2id$v=19$m=19456,t=2,p=1$!!!!$aGFzaGhhc2g",
		"bad base64 digest": "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$!!!!",
	}
	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ok, err := VerifyPassword(encoded, "anything at all")
			if ok {
				t.Fatal("a malformed hash verified — any password would be accepted")
			}
			if err == nil {
				t.Fatal("want ErrInvalidHash, got nil")
			}
		})
	}
}

// TestNeedsRehash checks the cost-upgrade path: a hash written under weaker
// parameters is flagged, one at current parameters is not.
func TestNeedsRehash(t *testing.T) {
	t.Parallel()

	current, err := HashPassword("pw")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if NeedsRehash(current) {
		t.Error("a freshly written hash wants rehashing")
	}
	if !NeedsRehash("$argon2id$v=19$m=4096,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2g") {
		t.Error("a hash at 4 MiB / 1 pass was not flagged for rehash")
	}
	if NeedsRehash("garbage") {
		t.Error("an unparseable hash should not be reported as rehashable")
	}
}

// TestTokensAreDistinctAndHashed covers the one-shot contract: the
// plaintext is returned once, what is stored is its hash, and two mints
// never collide.
func TestTokensAreDistinctAndHashed(t *testing.T) {
	t.Parallel()

	seen := map[string]bool{}
	for range 100 {
		tok, hash, err := NewSessionToken()
		if err != nil {
			t.Fatalf("NewSessionToken: %v", err)
		}
		if seen[tok] {
			t.Fatal("NewSessionToken returned a duplicate")
		}
		seen[tok] = true
		if strings.Contains(string(hash), tok) {
			t.Fatal("the stored hash contains the plaintext token")
		}
		if string(hash) != string(HashToken(tok)) {
			t.Fatal("the returned hash is not HashToken of the token")
		}
	}
}

// TestAPIKeysCarryTheScannablePrefix pins the prefix, which exists so secret
// scanners can spot a leaked key. Changing it is a breaking change for
// whatever is watching for it, so it should not be changeable by accident.
func TestAPIKeysCarryTheScannablePrefix(t *testing.T) {
	t.Parallel()

	key, hash, err := NewAPIKey()
	if err != nil {
		t.Fatalf("NewAPIKey: %v", err)
	}
	if !strings.HasPrefix(key, "sa_key_") {
		t.Errorf("minted key %q lacks the sa_key_ prefix", key)
	}
	parsed, err := ParseAPIKey(key)
	if err != nil {
		t.Fatalf("ParseAPIKey on a freshly minted key: %v", err)
	}
	if string(parsed) != string(hash) {
		t.Error("ParseAPIKey produced a different hash than NewAPIKey stored")
	}
}

// TestParseRejectsMalformedCredentials checks that shape validation rejects
// the near-misses, so a garbage header never reaches the database.
func TestParseRejectsMalformedCredentials(t *testing.T) {
	t.Parallel()

	badKeys := []string{"", "sa_key_", "sa_key_!!!", "sa_key_c2hvcnQ", "no-prefix-abc"}
	for _, k := range badKeys {
		if _, err := ParseAPIKey(k); err == nil {
			t.Errorf("ParseAPIKey(%q) succeeded, want an error", k)
		}
	}
	badTokens := []string{"", "!!!", "c2hvcnQ"}
	for _, tok := range badTokens {
		if _, err := ParseSessionToken(tok); err == nil {
			t.Errorf("ParseSessionToken(%q) succeeded, want an error", tok)
		}
	}
}

// TestZeroIdentityCanDoNothing is the fail-closed property at the level
// handlers actually see it: a request that was never authenticated carries
// the zero Identity, and it must be powerless.
func TestZeroIdentityCanDoNothing(t *testing.T) {
	t.Parallel()

	var anonymous Identity
	for _, p := range []Permission{
		PermReadReports, PermCreateReport, PermRerunReport,
		PermDeleteReport, PermManageDisputes, PermManageUsers,
	} {
		if anonymous.Can(p) {
			t.Errorf("the zero Identity was granted %s", p)
		}
	}
}

// TestIdentityContextRoundTrip covers the plumbing, including that a context
// with no identity reports one absent rather than yielding a usable zero
// value that looks authenticated.
func TestIdentityContextRoundTrip(t *testing.T) {
	t.Parallel()

	want := Identity{UserID: "u1", OrgID: "o1", Role: RoleAnalyst, Actor: "alice", Scheme: SchemeSession}
	got, ok := FromContext(WithIdentity(t.Context(), want))
	if !ok || got != want {
		t.Errorf("FromContext = %+v, %v; want %+v, true", got, ok, want)
	}
	if _, ok := FromContext(t.Context()); ok {
		t.Error("FromContext on a bare context reported an identity")
	}
}

// TestSystemIdentityIsDistinguishable guards ADR-0027's requirement that
// work with no human origin is identifiable in the audit trail rather than
// borrowing a person's name — the thing betaActor could not express.
func TestSystemIdentityIsDistinguishable(t *testing.T) {
	t.Parallel()

	id := SystemIdentity("org-7")
	if id.Scheme != SchemeSystem {
		t.Errorf("Scheme = %q, want %q", id.Scheme, SchemeSystem)
	}
	if id.OrgID != "org-7" {
		t.Errorf("OrgID = %q, want the report's org", id.OrgID)
	}
	if id.UserID != "" {
		t.Errorf("UserID = %q, want empty — no person ran this", id.UserID)
	}
}
