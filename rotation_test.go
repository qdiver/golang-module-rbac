package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

// rotationPolicies is a PolicyStore that answers with one fixed policy, and
// can be made to fail.
type rotationPolicies struct {
	policy Policy
	err    error
}

func (r *rotationPolicies) PolicyForOrg(_ context.Context, orgID string) (Policy, error) {
	if r.err != nil {
		return Policy{}, r.err
	}
	p := r.policy
	p.OrgID = orgID
	return p, nil
}
func (r *rotationPolicies) SavePolicy(context.Context, Policy) error { return nil }
func (r *rotationPolicies) RecentPasswordHashes(context.Context, string, int) ([]string, error) {
	return nil, nil
}
func (r *rotationPolicies) RecordPasswordChange(
	context.Context, string, string, string, time.Time, int,
) error {
	return nil
}

func rotatingPolicy(days int) Policy {
	p := DefaultPolicy("org-1")
	p.MaxAgeDays = days
	return p
}

const rotationPassword = "Thicket-Vandal-9-Gorse"

func loginWithPolicy(t *testing.T, p *rotationPolicies, changedAt time.Time) (*fakeStore, Identity) {
	t.Helper()
	store := newFakeStore()
	store.withUser(t, User{
		ID: "u-1", OrgID: "org-1", Email: "person@example.com",
		Name: "Person", Role: testAdmin, PasswordChangedAt: changedAt,
	}, rotationPassword)

	a := newTestAuthenticator(t, store)
	if p != nil {
		a = a.WithPolicies(p)
	}
	res, err := a.Login(context.Background(), "person@example.com", rotationPassword)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	return store, res.Identity
}

// TestLoginMarksAnExpiredPasswordAndStillIssuesASession is the grace path in
// one assertion. Refusing the login outright would sign the user out into a
// change form they cannot reach, because changing a password requires being
// authenticated.
func TestLoginMarksAnExpiredPasswordAndStillIssuesASession(t *testing.T) {
	t.Parallel()

	p := &rotationPolicies{policy: rotatingPolicy(90)}
	store, id := loginWithPolicy(t, p, testNow.AddDate(0, 0, -100))

	if !id.PasswordExpired {
		t.Error("a password 100 days old under a 90-day policy was not marked expired")
	}
	if len(store.inserted) != 1 {
		t.Fatalf("sessions inserted = %d, want 1 — the login must still succeed", len(store.inserted))
	}
	if !store.inserted[0].PasswordExpired {
		t.Error("the hold was not persisted on the session row, so it would vanish on the next request")
	}
}

func TestLoginDoesNotMarkAPasswordInsideTheWindow(t *testing.T) {
	t.Parallel()

	p := &rotationPolicies{policy: rotatingPolicy(90)}
	store, id := loginWithPolicy(t, p, testNow.AddDate(0, 0, -30))

	if id.PasswordExpired || store.inserted[0].PasswordExpired {
		t.Error("a 30-day-old password was marked expired under a 90-day policy")
	}
}

// TestRotationOffNeverExpires. Zero is the shipped default (decision 5), and
// reading it as anything other than "off" would expire every password on
// every deployment at once.
func TestRotationOffNeverExpires(t *testing.T) {
	t.Parallel()

	p := &rotationPolicies{policy: rotatingPolicy(0)}
	_, id := loginWithPolicy(t, p, testNow.AddDate(-10, 0, 0))

	if id.PasswordExpired {
		t.Error("a ten-year-old password expired under a policy with rotation off")
	}
}

// TestAnAccountWithNoRecordedChangeDateIsNotExpired. Every account predating
// migration 0013 has a NULL password_changed_at, and treating that as the
// zero time meaning "very old" would lock out every user of an upgraded
// deployment the moment rotation was switched on.
func TestAnAccountWithNoRecordedChangeDateIsNotExpired(t *testing.T) {
	t.Parallel()

	p := &rotationPolicies{policy: rotatingPolicy(90)}
	_, id := loginWithPolicy(t, p, time.Time{})

	if id.PasswordExpired {
		t.Error("an account with no recorded change date was expired")
	}
}

// TestAPolicyReadFailureDoesNotExpireAnyone. This fallback is the OPPOSITE of
// Admin's, deliberately: there the failure mode is accepting a weak password,
// so it falls back to the strictest policy. Here the failure mode is locking
// a user out of their own account over a policy the process could not read.
func TestAPolicyReadFailureDoesNotExpireAnyone(t *testing.T) {
	t.Parallel()

	p := &rotationPolicies{policy: rotatingPolicy(90), err: errors.New("database unavailable")}
	_, id := loginWithPolicy(t, p, testNow.AddDate(0, 0, -100))

	if id.PasswordExpired {
		t.Error("an unreadable policy locked a user out")
	}
}

// TestNoPolicyStoreMeansNoRotation: the behavior every deployment had
// before ADR-0029 existed.
func TestNoPolicyStoreMeansNoRotation(t *testing.T) {
	t.Parallel()

	_, id := loginWithPolicy(t, nil, testNow.AddDate(-10, 0, 0))
	if id.PasswordExpired {
		t.Error("an Authenticator with no policy store expired a password")
	}
}
