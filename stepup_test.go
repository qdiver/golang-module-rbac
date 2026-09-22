package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pquerna/otp/hotp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stepUpPassword is this file's fixture credential.
const stepUpPassword = "Thicket-Vandal-9-Gorse"

// stepUpKeyHex is a fixed AES key for sealing the fixture's TOTP secret.
const stepUpKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

// stepUpAdminStore satisfies AdminStore for NewMFAService, which needs one
// only for Disable — a path this file does not take.
type stepUpAdminStore struct{ AdminStore }

// TestSteppedUpIsAWindowNotAFlag. It is a window precisely so that walking
// away from an unlocked machine ends it.
func TestSteppedUpIsAWindowNotAFlag(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)

	// Never stepped up — the state of every session that has not, including
	// every session that existed before this feature did. Fail closed, or
	// shipping it would have granted the audit log to every live session on
	// the deployment at once.
	assert.False(t, Identity{}.SteppedUp(now))

	fresh := Identity{SteppedUpAt: now.Add(-time.Minute)}
	assert.True(t, fresh.SteppedUp(now))

	edge := Identity{SteppedUpAt: now.Add(-StepUpWindow)}
	assert.False(t, edge.SteppedUp(now), "the window is inclusive at its far edge")

	stale := Identity{SteppedUpAt: now.Add(-StepUpWindow - time.Second)}
	assert.False(t, stale.SteppedUp(now))
}

// stepUpMFAStore is the smallest MFAStore that lets a real MFAService be
// built here. The external test package has a fuller one; this file is
// internal because it needs fakeStore, which is.
type stepUpMFAStore struct {
	enrollment *TOTPEnrollment
	recovery   map[string]bool
}

func (f *stepUpMFAStore) TOTPByUser(context.Context, string) (TOTPEnrollment, error) {
	if f.enrollment == nil {
		return TOTPEnrollment{}, ErrNotFound
	}
	return *f.enrollment, nil
}

func (f *stepUpMFAStore) UpsertTOTP(_ context.Context, userID, sealed string, now time.Time) error {
	f.enrollment = &TOTPEnrollment{UserID: userID, SecretSealed: sealed, CreatedAt: now}
	return nil
}

func (f *stepUpMFAStore) ConfirmTOTP(_ context.Context, _ string, at time.Time, step int64) error {
	f.enrollment.ConfirmedAt = at
	f.enrollment.LastUsedStep = step
	return nil
}

func (f *stepUpMFAStore) SetTOTPLastUsedStep(_ context.Context, _ string, step int64) error {
	if step > f.enrollment.LastUsedStep {
		f.enrollment.LastUsedStep = step
	}
	return nil
}

func (f *stepUpMFAStore) DeleteTOTP(context.Context, string) error { f.enrollment = nil; return nil }

func (f *stepUpMFAStore) ReplaceRecoveryCodes(
	_ context.Context, _ string, hashes [][]byte, _ []string, _ time.Time,
) error {
	f.recovery = map[string]bool{}
	for _, h := range hashes {
		f.recovery[string(h)] = false
	}
	return nil
}

func (f *stepUpMFAStore) SpendRecoveryCode(_ context.Context, _ string, hash []byte, _ time.Time) (bool, error) {
	spent, ok := f.recovery[string(hash)]
	if !ok || spent {
		return false, nil
	}
	f.recovery[string(hash)] = true
	return true, nil
}

func (f *stepUpMFAStore) UnusedRecoveryCodeCount(context.Context, string) (int64, error) {
	return 0, nil
}

func (f *stepUpMFAStore) InsertMFAToken(context.Context, string, string, []byte, time.Time, time.Time) error {
	return nil
}

func (f *stepUpMFAStore) ClaimMFAToken(context.Context, []byte, time.Time) (MFAToken, error) {
	return MFAToken{}, ErrNotFound
}

// stepUpStore records what StepUp stamped.
type stepUpStore struct {
	stamped map[string]time.Time
	err     error
}

func (s *stepUpStore) StampStepUp(_ context.Context, sessionID string, at time.Time) error {
	if s.err != nil {
		return s.err
	}
	if s.stamped == nil {
		s.stamped = map[string]time.Time{}
	}
	s.stamped[sessionID] = at
	return nil
}

func stepUpFixture(t *testing.T, withFactor bool) (*Authenticator, *stepUpStore, *fakeStore) {
	t.Helper()
	store := newFakeStore()
	store.withUser(t, User{
		ID: "u-1", OrgID: "org-1", Email: "person@example.com", Role: RoleAdmin,
	}, stepUpPassword)

	steps := &stepUpStore{}
	a, err := NewAuthenticator(store, fixedClock{testNow}, &seqIDs{})
	require.NoError(t, err)
	a = a.WithStepUp(steps)

	if withFactor {
		sealer, sErr := NewSealerFromHex(stepUpKeyHex)
		require.NoError(t, sErr)
		svc, mErr := NewMFAService(&stepUpMFAStore{}, &stepUpAdminStore{}, sealer,
			fixedClock{testNow}, &seqIDs{}, "Test")
		require.NoError(t, mErr)

		// An active factor for u-1, confirmed with a real code.
		e, bErr := svc.BeginEnrollment(context.Background(), Identity{UserID: "u-1", Email: "person@example.com"})
		require.NoError(t, bErr)
		code, cErr := hotp.GenerateCodeCustom(e.Secret, uint64(TOTPStep(testNow)), hotp.ValidateOpts{
			Digits: TOTPDigits, Algorithm: TOTPAlgorithm,
		})
		require.NoError(t, cErr)
		_, confirmErr := svc.ConfirmEnrollment(context.Background(), Identity{UserID: "u-1"}, code)
		require.NoError(t, confirmErr)
		a = a.WithSecondFactor(svc)
	}
	return a, steps, store
}

func stepUpActor() Identity {
	return Identity{
		UserID: "u-1", OrgID: "org-1", Role: RoleAdmin,
		Actor: "person@example.com", SessionID: "sess-1", Scheme: SchemeSession,
	}
}

// TestStepUpWithAPasswordWhenThereIsNoFactor.
//
// Demanding a factor from an account with none would make the audit log
// unreachable on a deployment that has not enabled MFA, and a control nobody
// can use is not a control.
func TestStepUpWithAPasswordWhenThereIsNoFactor(t *testing.T) {
	t.Parallel()

	a, steps, _ := stepUpFixture(t, false)
	ctx := context.Background()

	assert.Equal(t, StepUpPassword, a.StepUpMethodFor(ctx, stepUpActor()))
	require.NoError(t, a.StepUp(ctx, stepUpActor(), stepUpPassword))
	assert.Contains(t, steps.stamped, "sess-1", "the session was not marked")
}

func TestStepUpRefusesAWrongPassword(t *testing.T) {
	t.Parallel()

	a, steps, _ := stepUpFixture(t, false)
	err := a.StepUp(context.Background(), stepUpActor(), "not-the-password")

	assert.ErrorIs(t, err, ErrInvalidCredentials)
	assert.Empty(t, steps.stamped, "a failed step-up marked the session anyway")
}

// TestStepUpDemandsTheFactorWhenTheAccountHasOne.
//
// An account carrying a second factor is saying the password alone is not
// enough for it, and step-up must not be the one place that disagrees.
func TestStepUpDemandsTheFactorWhenTheAccountHasOne(t *testing.T) {
	t.Parallel()

	a, steps, _ := stepUpFixture(t, true)
	ctx := context.Background()

	assert.Equal(t, StepUpFactor, a.StepUpMethodFor(ctx, stepUpActor()))

	// The password is no longer enough.
	err := a.StepUp(ctx, stepUpActor(), stepUpPassword)
	require.Error(t, err, "a password stepped up an account that carries a second factor")
	assert.Empty(t, steps.stamped)
}

// TestStepUpNeedsASessionToMark.
//
// An API key has none. That is not an oversight: a key is a standing
// credential with no human at the other end, and "confirm it is still you"
// has no meaning for one.
func TestStepUpNeedsASessionToMark(t *testing.T) {
	t.Parallel()

	a, steps, _ := stepUpFixture(t, false)
	keyActor := Identity{UserID: "u-1", OrgID: "org-1", Role: RoleAdmin, Scheme: SchemeAPIKey}

	assert.ErrorIs(t, a.StepUp(context.Background(), keyActor, stepUpPassword), ErrStepUpRequired)
	assert.Empty(t, steps.stamped)
}

// TestStepUpReportsAFailureToRecord. A step-up that verified but was not
// stamped would send the user round the prompt again with no explanation.
func TestStepUpReportsAFailureToRecord(t *testing.T) {
	t.Parallel()

	a, steps, _ := stepUpFixture(t, false)
	steps.err = assert.AnError

	err := a.StepUp(context.Background(), stepUpActor(), stepUpPassword)
	require.ErrorContains(t, err, "record step-up")
}

// TestStepUpRefusesADisabledAccount. A suspension that only took effect at
// the next sign-in would be no suspension at all.
func TestStepUpRefusesADisabledAccount(t *testing.T) {
	t.Parallel()

	a, _, store := stepUpFixture(t, false)
	u := store.users["person@example.com"]
	u.Disabled = true
	store.users["person@example.com"] = u

	assert.ErrorIs(t, a.StepUp(context.Background(), stepUpActor(), stepUpPassword), ErrInvalidCredentials)
}

// TestStepUpWithNoStoreIsAnError, not a silent success — a deployment that
// cannot record a step-up must keep the view behind it closed.
func TestStepUpWithNoStoreIsAnError(t *testing.T) {
	t.Parallel()

	store := newFakeStore()
	store.withUser(t, User{ID: "u-1", OrgID: "org-1", Email: "person@example.com"}, stepUpPassword)
	a, err := NewAuthenticator(store, fixedClock{testNow}, &seqIDs{})
	require.NoError(t, err)

	require.Error(t, a.StepUp(context.Background(), stepUpActor(), stepUpPassword))
}

// --- stepping up with a security key (ADR-0031) -----------------------------

// A passkey-only account: RequiresSecondFactor is true, but there is no code
// VerifyFactor could ever check.
type passkeyOnlyFactor struct{}

func (passkeyOnlyFactor) RequiresSecondFactor(context.Context, string) bool          { return true }
func (passkeyOnlyFactor) HasAnyFactorOtherThanPasskeys(context.Context, string) bool { return false }
func (passkeyOnlyFactor) IssueMFAToken(context.Context, string) (string, error)      { return "t", nil }

func (passkeyOnlyFactor) ClaimMFAToken(context.Context, string) (MFAToken, error) {
	return MFAToken{ID: "m-1", UserID: "u-1"}, nil
}

// What the real MFAService answers for an account with no TOTP row.
func (passkeyOnlyFactor) VerifyFactor(context.Context, string, string) (FactorKind, error) {
	return "", ErrMFANotEnrolled
}

type stepUpPasskeys struct {
	begunFor        []string
	finishedAs      []string
	beginErr        error
	finishErr       error
	passwordlessFor string
}

func (p *stepUpPasskeys) BeginLogin(context.Context, string) (Ceremony, error) {
	return Ceremony{}, nil
}

func (p *stepUpPasskeys) FinishLogin(context.Context, string, []byte) (string, error) {
	return "", nil
}

func (p *stepUpPasskeys) BeginPasswordlessLogin(context.Context) (Ceremony, error) {
	if p.beginErr != nil {
		return Ceremony{}, p.beginErr
	}
	return Ceremony{ChallengeID: "pwless-1", Options: []byte(`{"publicKey":{}}`)}, nil
}

func (p *stepUpPasskeys) FinishPasswordlessLogin(_ context.Context, _ string, _ []byte) (string, error) {
	if p.finishErr != nil {
		return "", p.finishErr
	}
	return p.passwordlessFor, nil
}

func (p *stepUpPasskeys) BeginStepUp(_ context.Context, userID string) (Ceremony, error) {
	p.begunFor = append(p.begunFor, userID)
	if p.beginErr != nil {
		return Ceremony{}, p.beginErr
	}
	return Ceremony{ChallengeID: "chal-1", Options: []byte(`{"publicKey":{}}`)}, nil
}

func (p *stepUpPasskeys) FinishStepUp(_ context.Context, userID, challengeID string, _ []byte) error {
	p.finishedAs = append(p.finishedAs, userID+":"+challengeID)
	return p.finishErr
}

// TestAPasskeyOnlyAccountIsToldToUseItsKey.
//
// It used to be told to enter a six-digit code. RequiresSecondFactor answers
// for factors of either kind, VerifyFactor understands only one of them, so
// the account was asked for something it cannot produce — and the audit log,
// which sits behind a step-up, was unreachable for it entirely.
func TestAPasskeyOnlyAccountIsToldToUseItsKey(t *testing.T) {
	t.Parallel()

	a, _, _ := stepUpFixture(t, false)
	a = a.WithSecondFactor(passkeyOnlyFactor{})

	got := a.StepUpMethodFor(context.Background(), stepUpActor())
	if got != StepUpPasskey {
		t.Fatalf("StepUpMethodFor = %q, want passkey — the client will render a code box", got)
	}
}

// TestAPasswordIsNotAcceptedForAPasskeyOnlyAccount, and the refusal is a
// refusal rather than a 500.
//
// An account carrying a second factor has said the password alone is not
// enough for it, and step-up must not be the one place that disagrees. What
// used to happen is worse than either: VerifyFactor answered ErrMFANotEnrolled,
// nothing mapped it, and a CORRECT password came back as an internal error.
func TestAPasswordIsNotAcceptedForAPasskeyOnlyAccount(t *testing.T) {
	t.Parallel()

	a, steps, _ := stepUpFixture(t, false)
	a = a.WithSecondFactor(passkeyOnlyFactor{})

	err := a.StepUp(context.Background(), stepUpActor(), stepUpPassword)
	if !errors.Is(err, ErrStepUpNeedsPasskey) {
		t.Fatalf("StepUp = %v, want ErrStepUpNeedsPasskey", err)
	}
	if errors.Is(err, ErrMFANotEnrolled) {
		t.Error("the unmapped error that produced a 500 is still leaking out")
	}
	if len(steps.stamped) != 0 {
		t.Error("the session was stamped anyway")
	}
}

// TestSteppingUpWithASecurityKeyStampsTheSession.
func TestSteppingUpWithASecurityKeyStampsTheSession(t *testing.T) {
	t.Parallel()

	a, steps, _ := stepUpFixture(t, false)
	keys := &stepUpPasskeys{}
	a = a.WithSecondFactor(passkeyOnlyFactor{}).WithPasskeys(keys)

	c, err := a.BeginStepUpWithPasskey(context.Background(), stepUpActor())
	if err != nil {
		t.Fatalf("BeginStepUpWithPasskey: %v", err)
	}
	if c.ChallengeID != "chal-1" {
		t.Fatalf("no ceremony came back: %+v", c)
	}
	if len(keys.begunFor) != 1 || keys.begunFor[0] != "u-1" {
		t.Errorf("the ceremony was begun for %v, want u-1", keys.begunFor)
	}

	if err := a.CompleteStepUpWithPasskey(context.Background(), stepUpActor(), "chal-1", []byte("{}")); err != nil {
		t.Fatalf("CompleteStepUpWithPasskey: %v", err)
	}
	if _, ok := steps.stamped["sess-1"]; !ok {
		t.Fatal("the session was not stamped, so the step-up counts for nothing")
	}
}

// TestAFailedKeyCeremonyDoesNotStampTheSession.
func TestAFailedKeyCeremonyDoesNotStampTheSession(t *testing.T) {
	t.Parallel()

	a, steps, _ := stepUpFixture(t, false)
	a = a.WithSecondFactor(passkeyOnlyFactor{}).
		WithPasskeys(&stepUpPasskeys{finishErr: ErrWebAuthnRejected})

	if err := a.CompleteStepUpWithPasskey(context.Background(), stepUpActor(), "chal-1", []byte("{}")); err == nil {
		t.Fatal("a rejected assertion completed a step-up")
	}
	if len(steps.stamped) != 0 {
		t.Error("the session was stamped despite the ceremony failing")
	}
}

// TestAKeyCeremonyStampsTheSessionAndNotTheUser. A key touched in one
// browser must not unlock a privileged view in another — the whole
// difference between a step-up and simply checking enrolment.
func TestAKeyCeremonyStampsTheSessionAndNotTheUser(t *testing.T) {
	t.Parallel()

	a, steps, _ := stepUpFixture(t, false)
	a = a.WithSecondFactor(passkeyOnlyFactor{}).WithPasskeys(&stepUpPasskeys{})

	require.NoError(t, a.CompleteStepUpWithPasskey(context.Background(), stepUpActor(), "chal-1", []byte("{}")))

	other := stepUpActor()
	other.SessionID = "sess-2"
	if _, ok := steps.stamped[other.SessionID]; ok {
		t.Error("a second session inherited the step-up")
	}
}

// TestAnAPIKeyCannotStepUpWithAPasskey either: there is no session to stamp,
// and "confirm it is still you" has no meaning for a standing credential.
func TestAnAPIKeyCannotStepUpWithAPasskey(t *testing.T) {
	t.Parallel()

	a, _, _ := stepUpFixture(t, false)
	a = a.WithPasskeys(&stepUpPasskeys{})

	keyActor := Identity{UserID: "u-1", OrgID: "org-1", Role: RoleAdmin, Scheme: SchemeAPIKey}
	if _, err := a.BeginStepUpWithPasskey(context.Background(), keyActor); !errors.Is(err, ErrStepUpRequired) {
		t.Fatalf("BeginStepUpWithPasskey = %v, want ErrStepUpRequired", err)
	}
	if err := a.CompleteStepUpWithPasskey(context.Background(), keyActor, "c", nil); !errors.Is(err, ErrStepUpRequired) {
		t.Fatalf("CompleteStepUpWithPasskey = %v, want ErrStepUpRequired", err)
	}
}

// TestAnAccountWithBothIsOfferedTheCode. A code is quicker to produce than
// finding a key, and the key stays available to anyone who prefers it.
func TestAnAccountWithBothIsOfferedTheCode(t *testing.T) {
	t.Parallel()

	a, _, _ := stepUpFixture(t, true) // a real, confirmed TOTP enrollment
	if got := a.StepUpMethodFor(context.Background(), stepUpActor()); got != StepUpFactor {
		t.Fatalf("StepUpMethodFor = %q, want second_factor", got)
	}
}
