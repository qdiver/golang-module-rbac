package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// The two-step login, from the authenticator's own side.
//
// These paths are exercised through the HTTP layer too, but coverage is
// credited per package and — more to the point — the ORDER of operations here
// is the security property (ADR-0028): the token is spent before the code is
// checked, and the account is re-read before a session is issued.

// stepFactor is a SecondFactor that records what it was asked.
type stepFactor struct {
	required   bool
	token      string
	claimed    []string
	claimErr   error
	verifyKind FactorKind
	verifyErr  error
	verified   []string
	// trace records the order the authenticator called us in. The order is
	// the security property, so counting calls is not enough to test it.
	trace []string

	// passkeyOnly models an account whose only second factor is a key:
	// RequiresSecondFactor is true, but there is no code to check.
	passkeyOnly bool
}

func (f *stepFactor) RequiresSecondFactor(context.Context, string) bool { return f.required }

// otherFactor says whether VerifyFactor has anything it can check. It
// defaults to the same answer as RequiresSecondFactor, because most of these
// tests are about TOTP; the passkey-only case sets it false explicitly.
func (f *stepFactor) HasAnyFactorOtherThanPasskeys(context.Context, string) bool {
	if f.passkeyOnly {
		return false
	}
	return f.required
}

func (f *stepFactor) IssueMFAToken(context.Context, string) (string, error) {
	return f.token, nil
}

func (f *stepFactor) ClaimMFAToken(_ context.Context, token string) (MFAToken, error) {
	f.claimed = append(f.claimed, token)
	f.trace = append(f.trace, "claim")
	if f.claimErr != nil {
		return MFAToken{}, f.claimErr
	}
	if token != f.token {
		return MFAToken{}, ErrInvalidMFAToken
	}
	return MFAToken{ID: "mfa-1", UserID: "u-1"}, nil
}

func (f *stepFactor) VerifyFactor(_ context.Context, userID, code string) (FactorKind, error) {
	f.verified = append(f.verified, userID+":"+code)
	f.trace = append(f.trace, "verify")
	return f.verifyKind, f.verifyErr
}

// stepPasskeys is a PasskeyAuthenticator that records what it was asked.
type stepPasskeys struct {
	begun           []string
	beginErr        error
	finishFor       string
	finishErr       error
	steppedUpFor    []string
	finishedStepUp  []string
	passwordlessFor string
}

func (p *stepPasskeys) BeginLogin(_ context.Context, userID string) (Ceremony, error) {
	p.begun = append(p.begun, userID)
	if p.beginErr != nil {
		return Ceremony{}, p.beginErr
	}
	return Ceremony{ChallengeID: "chal-1", Options: []byte(`{"publicKey":{}}`)}, nil
}

func (p *stepPasskeys) FinishLogin(context.Context, string, []byte) (string, error) {
	if p.finishErr != nil {
		return "", p.finishErr
	}
	return p.finishFor, nil
}

func (p *stepPasskeys) BeginPasswordlessLogin(context.Context) (Ceremony, error) {
	if p.beginErr != nil {
		return Ceremony{}, p.beginErr
	}
	return Ceremony{ChallengeID: "pwless-1", Options: []byte(`{"publicKey":{}}`)}, nil
}

func (p *stepPasskeys) FinishPasswordlessLogin(_ context.Context, _ string, _ []byte) (string, error) {
	if p.finishErr != nil {
		return "", p.finishErr
	}
	return p.passwordlessFor, nil
}

func (p *stepPasskeys) BeginStepUp(_ context.Context, userID string) (Ceremony, error) {
	p.steppedUpFor = append(p.steppedUpFor, userID)
	if p.beginErr != nil {
		return Ceremony{}, p.beginErr
	}
	return Ceremony{ChallengeID: "step-chal-1", Options: []byte(`{"publicKey":{}}`)}, nil
}

func (p *stepPasskeys) FinishStepUp(_ context.Context, userID, challengeID string, _ []byte) error {
	p.finishedStepUp = append(p.finishedStepUp, userID+":"+challengeID)
	return p.finishErr
}

func loginFixture(t *testing.T) (*Authenticator, *fakeStore, *stepFactor) {
	t.Helper()
	store := newFakeStore()
	store.withUser(t, User{
		ID: "u-1", OrgID: "org-1", Email: "person@example.com", Role: testAdmin,
	}, stepUpPassword)

	factor := &stepFactor{token: "step-one-token", verifyKind: FactorTOTP}
	a := newTestAuthenticator(t, store)
	return a.WithSecondFactor(factor), store, factor
}

// TestLoginStopsAtTheChallengeWhenAFactorIsRequired.
func TestLoginStopsAtTheChallengeWhenAFactorIsRequired(t *testing.T) {
	t.Parallel()

	a, store, factor := loginFixture(t)
	factor.required = true

	res, err := a.Login(context.Background(), "person@example.com", stepUpPassword)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if !res.MFARequired() {
		t.Fatal("an account with a factor was signed straight in")
	}
	if res.SessionToken != "" {
		t.Error("a session was issued before the second factor")
	}
	if len(store.inserted) != 0 {
		t.Error("a session row was written before the second factor")
	}
	// The identity travels so the audit log can name the account even for a
	// login that has not finished.
	if res.Identity.UserID != "u-1" {
		t.Errorf("the challenge names no account: %+v", res.Identity)
	}
}

// TestCompleteMFASpendsTheTokenBeforeCheckingTheCode.
//
// A token that survived a wrong code would let whoever held it try the six
// digits as many times as they liked. The order is the control.
func TestCompleteMFASpendsTheTokenBeforeCheckingTheCode(t *testing.T) {
	t.Parallel()

	a, _, factor := loginFixture(t)
	factor.required = true
	factor.verifyErr = ErrInvalidTOTPCode

	_, err := a.CompleteMFA(context.Background(), "step-one-token", "000000")
	if err == nil {
		t.Fatal("a wrong code completed the login")
	}
	if got := strings.Join(factor.trace, ","); got != "claim,verify" {
		t.Fatalf("the authenticator did %q, want claim,verify", got)
	}
}

// TestCompleteMFAIssuesTheSession.
func TestCompleteMFAIssuesTheSession(t *testing.T) {
	t.Parallel()

	a, store, factor := loginFixture(t)
	factor.required = true

	res, err := a.CompleteMFA(context.Background(), "step-one-token", "123456")
	if err != nil {
		t.Fatalf("CompleteMFA: %v", err)
	}
	if res.SessionToken == "" {
		t.Fatal("no session was issued")
	}
	if res.FactorUsed != FactorTOTP {
		t.Errorf("FactorUsed = %q, want totp", res.FactorUsed)
	}
	if len(store.inserted) != 1 {
		t.Fatalf("sessions written = %d, want 1", len(store.inserted))
	}
}

// TestCompleteMFARefusesAnAccountDisabledBetweenTheSteps.
//
// A suspension that only took effect at the next login would be no suspension
// at all.
func TestCompleteMFARefusesAnAccountDisabledBetweenTheSteps(t *testing.T) {
	t.Parallel()

	a, store, factor := loginFixture(t)
	factor.required = true

	u := store.users["person@example.com"]
	u.Disabled = true
	store.users["person@example.com"] = u

	if _, err := a.CompleteMFA(context.Background(), "step-one-token", "123456"); err == nil {
		t.Fatal("an account disabled between the two steps completed its login")
	}
	if len(store.inserted) != 0 {
		t.Error("a session was issued to a disabled account")
	}
}

// TestCompleteMFAWithNoFactorServiceIsRefused, rather than falling through to
// a session.
func TestCompleteMFAWithNoFactorServiceIsRefused(t *testing.T) {
	t.Parallel()

	store := newFakeStore()
	a := newTestAuthenticator(t, store)

	if _, err := a.CompleteMFA(context.Background(), "anything", "123456"); err == nil {
		t.Fatal("a process with no second-factor service completed a two-step login")
	}
}

// TestAPasskeyLoginSpendsTheTokenAtBegin.
//
// ADR-0028's rule applied to a two-call ceremony: the attempt begins at
// begin, so a failed ceremony costs a fresh password authentication.
func TestAPasskeyLoginSpendsTheTokenAtBegin(t *testing.T) {
	t.Parallel()

	a, _, factor := loginFixture(t)
	factor.required = true
	keys := &stepPasskeys{finishFor: "u-1"}
	a = a.WithPasskeys(keys)

	c, err := a.BeginPasskeyLogin(context.Background(), "step-one-token")
	if err != nil {
		t.Fatalf("BeginPasskeyLogin: %v", err)
	}
	if c.ChallengeID == "" {
		t.Fatal("no ceremony was returned")
	}
	if got := strings.Join(factor.trace, ","); got != "claim" {
		t.Fatalf("the authenticator did %q at begin, want claim", got)
	}
	if len(keys.begun) != 1 || keys.begun[0] != "u-1" {
		t.Errorf("the ceremony was begun for %v, want u-1", keys.begun)
	}
}

// TestAPasskeyLoginNeedsAValidToken.
func TestAPasskeyLoginNeedsAValidToken(t *testing.T) {
	t.Parallel()

	a, _, factor := loginFixture(t)
	factor.required = true
	a = a.WithPasskeys(&stepPasskeys{finishFor: "u-1"})

	if _, err := a.BeginPasskeyLogin(context.Background(), "never-issued"); err == nil {
		t.Fatal("a ceremony began without a valid token")
	}
}

// TestCompletingAPasskeyLoginIssuesTheSession, and takes the account from the
// ceremony rather than the caller.
func TestCompletingAPasskeyLoginIssuesTheSession(t *testing.T) {
	t.Parallel()

	a, store, factor := loginFixture(t)
	factor.required = true
	a = a.WithPasskeys(&stepPasskeys{finishFor: "u-1"})

	res, err := a.CompletePasskeyLogin(context.Background(), "chal-1", []byte("{}"))
	if err != nil {
		t.Fatalf("CompletePasskeyLogin: %v", err)
	}
	if res.SessionToken == "" {
		t.Fatal("no session was issued")
	}
	if res.FactorUsed != FactorPasskey {
		t.Errorf("FactorUsed = %q, want passkey", res.FactorUsed)
	}
	if res.Identity.UserID != "u-1" {
		t.Errorf("the session was issued to %q", res.Identity.UserID)
	}
	if len(store.inserted) != 1 {
		t.Fatalf("sessions written = %d, want 1", len(store.inserted))
	}
}

// TestAPasskeyLoginRefusesAnAccountDisabledBetweenTheCalls.
func TestAPasskeyLoginRefusesAnAccountDisabledBetweenTheCalls(t *testing.T) {
	t.Parallel()

	a, store, factor := loginFixture(t)
	factor.required = true
	a = a.WithPasskeys(&stepPasskeys{finishFor: "u-1"})

	u := store.users["person@example.com"]
	u.Disabled = true
	store.users["person@example.com"] = u

	if _, err := a.CompletePasskeyLogin(context.Background(), "chal-1", []byte("{}")); err == nil {
		t.Fatal("an account disabled mid-ceremony completed its login")
	}
	if len(store.inserted) != 0 {
		t.Error("a session was issued to a disabled account")
	}
}

// TestAPasskeyLoginWithNoServiceIsRefused.
func TestAPasskeyLoginWithNoServiceIsRefused(t *testing.T) {
	t.Parallel()

	a, _, factor := loginFixture(t)
	factor.required = true

	if _, err := a.BeginPasskeyLogin(context.Background(), "step-one-token"); err == nil {
		t.Fatal("a ceremony began on a process with no passkey service")
	}
	if _, err := a.CompletePasskeyLogin(context.Background(), "chal-1", nil); err == nil {
		t.Fatal("a ceremony completed on a process with no passkey service")
	}
}

// TestMFARequiredReadsTheResult.
func TestMFARequiredReadsTheResult(t *testing.T) {
	t.Parallel()

	if (LoginResult{}).MFARequired() {
		t.Error("an empty result claims a factor is required")
	}
	if !(LoginResult{MFAToken: "t"}).MFARequired() {
		t.Error("a challenge does not report itself as one")
	}
	if (LoginResult{SessionToken: "s"}).MFARequired() {
		t.Error("a completed login claims a factor is required")
	}
}

// TestAnAccountWithNoFactorIsSignedInAtOnce — the two-step flow must not
// become a step everybody pays.
func TestAnAccountWithNoFactorIsSignedInAtOnce(t *testing.T) {
	t.Parallel()

	a, store, factor := loginFixture(t)
	factor.required = false

	res, err := a.Login(context.Background(), "person@example.com", stepUpPassword)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if res.MFARequired() {
		t.Fatal("an account with no factor was challenged")
	}
	if res.SessionToken == "" || len(store.inserted) != 1 {
		t.Fatal("no session was issued")
	}
}

// --- the front door ---------------------------------------------------------

// TestAPasswordlessLoginIssuesTheSession, with no password and no second
// step: a key that verified its user carries both factors already.
func TestAPasswordlessLoginIssuesTheSession(t *testing.T) {
	t.Parallel()

	a, store, factor := loginFixture(t)
	// The account HAS a second factor configured. That must not add a step:
	// the key already was one.
	factor.required = true
	a = a.WithPasskeys(&stepPasskeys{passwordlessFor: "u-1"})

	res, err := a.CompletePasswordlessLogin(context.Background(), "chal-1", []byte("{}"))
	if err != nil {
		t.Fatalf("CompletePasswordlessLogin: %v", err)
	}
	if res.MFARequired() {
		t.Fatal("somebody who signed in with their key was asked for a second factor as well")
	}
	if res.SessionToken == "" || len(store.inserted) != 1 {
		t.Fatal("no session was issued")
	}
	if res.FactorUsed != FactorPasskey {
		t.Errorf("FactorUsed = %q, want passkey", res.FactorUsed)
	}
	if res.Identity.UserID != "u-1" {
		t.Errorf("the session was issued to %q", res.Identity.UserID)
	}
}

// TestAPasswordlessLoginRefusesADisabledAccount.
//
// The key is valid and the account is not. A suspension that a passkey could
// walk past would be no suspension at all — and this is the one sign-in path
// with no password step to catch it first.
func TestAPasswordlessLoginRefusesADisabledAccount(t *testing.T) {
	t.Parallel()

	a, store, _ := loginFixture(t)
	a = a.WithPasskeys(&stepPasskeys{passwordlessFor: "u-1"})

	u := store.users["person@example.com"]
	u.Disabled = true
	store.users["person@example.com"] = u

	if _, err := a.CompletePasswordlessLogin(context.Background(), "chal-1", []byte("{}")); err == nil {
		t.Fatal("a disabled account signed in with its key")
	}
	if len(store.inserted) != 0 {
		t.Error("a session was issued to a disabled account")
	}
}

// TestAPasswordlessLoginWithNoServiceIsRefused, rather than falling through.
func TestAPasswordlessLoginWithNoServiceIsRefused(t *testing.T) {
	t.Parallel()

	a, _, _ := loginFixture(t)

	if _, err := a.BeginPasswordlessLogin(context.Background()); !errors.Is(err, ErrWebAuthnUnavailable) {
		t.Fatalf("BeginPasswordlessLogin = %v, want ErrWebAuthnUnavailable", err)
	}
	if _, err := a.CompletePasswordlessLogin(context.Background(), "c", nil); !errors.Is(err, ErrWebAuthnUnavailable) {
		t.Fatalf("CompletePasswordlessLogin = %v, want ErrWebAuthnUnavailable", err)
	}
}

// TestAFailedPasswordlessCeremonyIssuesNothing.
func TestAFailedPasswordlessCeremonyIssuesNothing(t *testing.T) {
	t.Parallel()

	a, store, _ := loginFixture(t)
	a = a.WithPasskeys(&stepPasskeys{finishErr: ErrWebAuthnRejected})

	if _, err := a.CompletePasswordlessLogin(context.Background(), "chal-1", []byte("{}")); err == nil {
		t.Fatal("a rejected assertion signed somebody in")
	}
	if len(store.inserted) != 0 {
		t.Error("a session was issued despite the ceremony failing")
	}
}
