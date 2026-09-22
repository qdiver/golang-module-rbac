package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/qdiver/golang-module-rbac"

	"github.com/pquerna/otp/hotp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- fake store -------------------------------------------------------------

type fakeMFAStore struct {
	enrollment  *auth.TOTPEnrollment
	recovery    map[string]bool // hash hex -> spent
	tokens      map[string]auth.MFAToken
	claimed     map[string]bool
	readErr     error
	stepErr     error
	replaceErr  error
	replaceCall int
}

func newFakeMFAStore() *fakeMFAStore {
	return &fakeMFAStore{
		recovery: map[string]bool{},
		tokens:   map[string]auth.MFAToken{},
		claimed:  map[string]bool{},
	}
}

func (f *fakeMFAStore) TOTPByUser(context.Context, string) (auth.TOTPEnrollment, error) {
	if f.readErr != nil {
		return auth.TOTPEnrollment{}, f.readErr
	}
	if f.enrollment == nil {
		return auth.TOTPEnrollment{}, auth.ErrNotFound
	}
	return *f.enrollment, nil
}

func (f *fakeMFAStore) UpsertTOTP(_ context.Context, userID, sealed string, now time.Time) error {
	f.enrollment = &auth.TOTPEnrollment{UserID: userID, SecretSealed: sealed, CreatedAt: now}
	return nil
}

func (f *fakeMFAStore) ConfirmTOTP(_ context.Context, _ string, at time.Time, step int64) error {
	f.enrollment.ConfirmedAt = at
	f.enrollment.LastUsedStep = step
	return nil
}

func (f *fakeMFAStore) SetTOTPLastUsedStep(_ context.Context, _ string, step int64) error {
	if f.stepErr != nil {
		return f.stepErr
	}
	if step > f.enrollment.LastUsedStep {
		f.enrollment.LastUsedStep = step
	}
	return nil
}

func (f *fakeMFAStore) DeleteTOTP(context.Context, string) error {
	f.enrollment = nil
	return nil
}

func (f *fakeMFAStore) ReplaceRecoveryCodes(
	_ context.Context, _ string, hashes [][]byte, _ []string, _ time.Time,
) error {
	f.replaceCall++
	if f.replaceErr != nil {
		return f.replaceErr
	}
	f.recovery = map[string]bool{}
	for _, h := range hashes {
		f.recovery[string(h)] = false
	}
	return nil
}

func (f *fakeMFAStore) SpendRecoveryCode(_ context.Context, _ string, hash []byte, _ time.Time) (bool, error) {
	spent, ok := f.recovery[string(hash)]
	if !ok || spent {
		return false, nil
	}
	f.recovery[string(hash)] = true
	return true, nil
}

func (f *fakeMFAStore) UnusedRecoveryCodeCount(context.Context, string) (int64, error) {
	var n int64
	for _, spent := range f.recovery {
		if !spent {
			n++
		}
	}
	return n, nil
}

func (f *fakeMFAStore) InsertMFAToken(
	_ context.Context, id, userID string, hash []byte, now, expires time.Time,
) error {
	f.tokens[string(hash)] = auth.MFAToken{ID: id, UserID: userID, CreatedAt: now, ExpiresAt: expires}
	return nil
}

func (f *fakeMFAStore) ClaimMFAToken(_ context.Context, hash []byte, now time.Time) (auth.MFAToken, error) {
	t, ok := f.tokens[string(hash)]
	if !ok || f.claimed[string(hash)] || !now.Before(t.ExpiresAt) {
		return auth.MFAToken{}, auth.ErrNotFound
	}
	f.claimed[string(hash)] = true
	return t, nil
}

// --- harness ----------------------------------------------------------------

var mfaNow = time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)

func newMFAFixture(t *testing.T) (*auth.MFAService, *fakeMFAStore, *fakeAdminStore) {
	t.Helper()
	store := newFakeMFAStore()
	users := newFakeAdminStore()
	sealer, err := auth.NewSealerFromHex(testSealKeyHex)
	require.NoError(t, err)
	svc, err := auth.NewMFAService(store, users, sealer, stubClock{mfaNow}, &stubIDs{}, "Security Assessment", testTable(t))
	require.NoError(t, err)
	return svc, store, users
}

func mfaActor() auth.Identity {
	return auth.Identity{
		UserID: "u-1", OrgID: "org-1", Role: testAdmin,
		Actor: "person@example.com", Email: "person@example.com",
	}
}

// currentCode is what the user's authenticator would be showing.
func currentCode(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	code, err := hotp.GenerateCodeCustom(secret, uint64(auth.TOTPStep(at)), hotp.ValidateOpts{
		Digits: auth.TOTPDigits, Algorithm: auth.TOTPAlgorithm,
	})
	require.NoError(t, err)
	return code
}

// enrollAndConfirm takes an account all the way to an active factor.
func enrollAndConfirm(t *testing.T, svc *auth.MFAService) (secret string, codes []string) {
	t.Helper()
	e, err := svc.BeginEnrollment(context.Background(), mfaActor())
	require.NoError(t, err)
	codes, err = svc.ConfirmEnrollment(context.Background(), mfaActor(), currentCode(t, e.Secret, mfaNow))
	require.NoError(t, err)
	return e.Secret, codes
}

// --- tests ------------------------------------------------------------------

// TestEnrollmentIsTwoSteps. A secret stored and treated as active the moment
// it is generated locks out anyone whose scan failed or whose phone clock is
// wrong — and they would discover it at their next sign-in, with no way back.
func TestEnrollmentIsTwoSteps(t *testing.T) {
	t.Parallel()

	svc, store, _ := newMFAFixture(t)
	e, err := svc.BeginEnrollment(context.Background(), mfaActor())
	require.NoError(t, err)
	assert.NotEmpty(t, e.Secret)
	assert.Contains(t, e.URI, "otpauth://totp/")

	// Pending, so login must NOT ask for a code yet.
	assert.False(t, svc.RequiresSecondFactor(context.Background(), "u-1"),
		"an unconfirmed enrollment already demands a second factor")

	status, err := svc.Status(context.Background(), mfaActor())
	require.NoError(t, err)
	assert.False(t, status.Enabled)
	assert.True(t, status.PendingEnrollment)

	// The stored secret is ciphertext, not the secret.
	require.NotNil(t, store.enrollment)
	assert.True(t, auth.IsSealed(store.enrollment.SecretSealed))
	assert.NotContains(t, store.enrollment.SecretSealed, e.Secret)
}

func TestConfirmingEnrollmentActivatesItAndIssuesRecoveryCodes(t *testing.T) {
	t.Parallel()

	svc, _, _ := newMFAFixture(t)
	_, codes := enrollAndConfirm(t, svc)

	assert.Len(t, codes, auth.RecoveryCodeCount)
	assert.True(t, svc.RequiresSecondFactor(context.Background(), "u-1"))

	status, err := svc.Status(context.Background(), mfaActor())
	require.NoError(t, err)
	assert.True(t, status.Enabled)
	assert.Equal(t, auth.RecoveryCodeCount, status.RecoveryCodesLeft)
}

// TestTheConfirmingCodeCannotAlsoCompleteALogin. Recording the confirming
// step as used is what stops the very code that proved enrollment being
// replayed a moment later to finish a sign-in.
func TestTheConfirmingCodeCannotAlsoCompleteALogin(t *testing.T) {
	t.Parallel()

	svc, _, _ := newMFAFixture(t)
	secret, _ := enrollAndConfirm(t, svc)

	_, err := svc.VerifyFactor(context.Background(), "u-1", currentCode(t, secret, mfaNow))
	assert.ErrorIs(t, err, auth.ErrInvalidTOTPCode,
		"the code that confirmed enrollment also completed a login")
}

// TestAWrongCodeDoesNotConfirm. Otherwise enrollment would activate a factor
// the user cannot actually produce codes for.
func TestAWrongCodeDoesNotConfirm(t *testing.T) {
	t.Parallel()

	svc, _, _ := newMFAFixture(t)
	_, err := svc.BeginEnrollment(context.Background(), mfaActor())
	require.NoError(t, err)

	_, err = svc.ConfirmEnrollment(context.Background(), mfaActor(), "000000")
	assert.ErrorIs(t, err, auth.ErrInvalidTOTPCode)
	assert.False(t, svc.RequiresSecondFactor(context.Background(), "u-1"))
}

// TestEnrollmentWillNotSilentlyReplaceAnActiveFactor. Letting anyone holding
// a live session swap the second factor for their own is the control
// defeating itself through its own settings page.
func TestEnrollmentWillNotSilentlyReplaceAnActiveFactor(t *testing.T) {
	t.Parallel()

	svc, _, _ := newMFAFixture(t)
	enrollAndConfirm(t, svc)

	_, err := svc.BeginEnrollment(context.Background(), mfaActor())
	assert.ErrorIs(t, err, auth.ErrMFAAlreadyConfirmed)
}

// TestRe-enrollingReplacesAPendingSecret: the common reason to enroll twice
// is that the first scan failed.
func TestReEnrollingReplacesAPendingSecret(t *testing.T) {
	t.Parallel()

	svc, _, _ := newMFAFixture(t)
	first, err := svc.BeginEnrollment(context.Background(), mfaActor())
	require.NoError(t, err)
	second, err := svc.BeginEnrollment(context.Background(), mfaActor())
	require.NoError(t, err)

	assert.NotEqual(t, first.Secret, second.Secret)
	// The old secret no longer confirms.
	_, err = svc.ConfirmEnrollment(context.Background(), mfaActor(), currentCode(t, first.Secret, mfaNow))
	assert.ErrorIs(t, err, auth.ErrInvalidTOTPCode)
}

// TestARecoveryCodeCompletesTheFactorAndIsSpent.
func TestARecoveryCodeCompletesTheFactorAndIsSpent(t *testing.T) {
	t.Parallel()

	svc, _, _ := newMFAFixture(t)
	_, codes := enrollAndConfirm(t, svc)

	kind, err := svc.VerifyFactor(context.Background(), "u-1", codes[0])
	require.NoError(t, err)
	assert.Equal(t, auth.FactorRecovery, kind)

	// Single use.
	_, err = svc.VerifyFactor(context.Background(), "u-1", codes[0])
	assert.ErrorIs(t, err, auth.ErrInvalidRecoveryCode)

	status, err := svc.Status(context.Background(), mfaActor())
	require.NoError(t, err)
	assert.Equal(t, auth.RecoveryCodeCount-1, status.RecoveryCodesLeft)
}

// TestTheShapeDecidesWhichCredentialIsChecked. Trying both for every input
// would mean a mistyped TOTP code took a swing at the recovery hashes — and,
// far worse, a recovery code entered while the authenticator still worked
// could be spent by a caller who did not mean to spend one.
func TestTheShapeDecidesWhichCredentialIsChecked(t *testing.T) {
	t.Parallel()

	svc, _, _ := newMFAFixture(t)
	_, codes := enrollAndConfirm(t, svc)

	// Six digits go to the authenticator, and a wrong one does not touch the
	// recovery table.
	kind, err := svc.VerifyFactor(context.Background(), "u-1", "000000")
	assert.Equal(t, auth.FactorTOTP, kind)
	assert.ErrorIs(t, err, auth.ErrInvalidTOTPCode)

	status, err := svc.Status(context.Background(), mfaActor())
	require.NoError(t, err)
	assert.Equal(t, auth.RecoveryCodeCount, status.RecoveryCodesLeft,
		"a wrong six-digit code spent a recovery code")

	// And a recovery code is accepted in any transcription.
	_, err = svc.VerifyFactor(context.Background(), "u-1", "  "+codes[0]+"  ")
	assert.NoError(t, err)
}

// TestReissuingRecoveryCodesInvalidatesTheOldSet. Reissuing exists because
// the old set may be compromised or lost; leaving the previous codes working
// would mean a printout from last year still opens the account.
func TestReissuingRecoveryCodesInvalidatesTheOldSet(t *testing.T) {
	t.Parallel()

	svc, _, _ := newMFAFixture(t)
	_, old := enrollAndConfirm(t, svc)

	fresh, err := svc.RegenerateRecoveryCodes(context.Background(), mfaActor())
	require.NoError(t, err)
	assert.Len(t, fresh, auth.RecoveryCodeCount)

	_, err = svc.VerifyFactor(context.Background(), "u-1", old[0])
	assert.ErrorIs(t, err, auth.ErrInvalidRecoveryCode, "an old recovery code still works")

	_, err = svc.VerifyFactor(context.Background(), "u-1", fresh[0])
	assert.NoError(t, err)
}

// TestDisablingRequiresThePassword. A session cookie is a bearer credential,
// and someone at an unlocked machine must not be able to strip the second
// factor off the account and keep it.
func TestDisablingRequiresThePassword(t *testing.T) {
	t.Parallel()

	svc, _, users := newMFAFixture(t)
	seedUser(t, users, "u-1", goodPassword)
	enrollAndConfirm(t, svc)

	err := svc.Disable(context.Background(), mfaActor(), "not-the-password")
	assert.ErrorIs(t, err, auth.ErrInvalidCredentials)
	assert.True(t, svc.RequiresSecondFactor(context.Background(), "u-1"),
		"the factor was removed without the password")

	require.NoError(t, svc.Disable(context.Background(), mfaActor(), goodPassword))
	assert.False(t, svc.RequiresSecondFactor(context.Background(), "u-1"))
}

// TestDisablingTakesTheRecoveryCodesWithIt. They exist only to get past this
// factor, so leaving them live after it is gone would leave a set of
// standalone credentials nobody remembers issuing.
func TestDisablingTakesTheRecoveryCodesWithIt(t *testing.T) {
	t.Parallel()

	svc, store, users := newMFAFixture(t)
	seedUser(t, users, "u-1", goodPassword)
	enrollAndConfirm(t, svc)

	require.NoError(t, svc.Disable(context.Background(), mfaActor(), goodPassword))
	assert.Empty(t, store.recovery, "recovery codes outlived the factor they existed for")
}

// TestRequiresSecondFactorFailsClosed. Answering false on a database hiccup
// would sign somebody straight in past a factor they had deliberately
// switched on — the one error here that cannot be walked back.
func TestRequiresSecondFactorFailsClosed(t *testing.T) {
	t.Parallel()

	svc, store, _ := newMFAFixture(t)
	store.readErr = errors.New("database unavailable")
	assert.True(t, svc.RequiresSecondFactor(context.Background(), "u-1"),
		"an unreadable enrollment let a login through without a second factor")
}

// TestATOTPCodeThatCannotBeRecordedIsRefused. A code that verified but whose
// step could not be stored is a code that can be used again; refusing the
// login means the user retries in thirty seconds and no replay window opens.
func TestATOTPCodeThatCannotBeRecordedIsRefused(t *testing.T) {
	t.Parallel()

	svc, store, _ := newMFAFixture(t)
	secret, _ := enrollAndConfirm(t, svc)

	// A second service over the SAME store, one step later, so the code
	// below is genuinely fresh rather than a replay of the confirming one.
	later := mfaNow.Add(time.Duration(auth.TOTPPeriod) * time.Second)
	sealer, err := auth.NewSealerFromHex(testSealKeyHex)
	require.NoError(t, err)
	svcLater, err := auth.NewMFAService(store, newFakeAdminStore(), sealer,
		stubClock{later}, &stubIDs{}, "Security Assessment", testTable(t))
	require.NoError(t, err)

	// It verifies when the step can be recorded...
	code := currentCode(t, secret, later)
	store.stepErr = errors.New("database unavailable")
	_, err = svcLater.VerifyFactor(context.Background(), "u-1", code)
	require.Error(t, err, "a code whose step could not be recorded was accepted")
	assert.Contains(t, err.Error(), "record the used TOTP step")

	// ...and the guard is still where it was, so the code has not been
	// silently consumed either.
	store.stepErr = nil
	_, err = svcLater.VerifyFactor(context.Background(), "u-1", code)
	assert.NoError(t, err, "the code was consumed by the failed attempt")
}

// TestMFATokensAreSingleUseAndExpire.
func TestMFATokensAreSingleUseAndExpire(t *testing.T) {
	t.Parallel()

	svc, _, _ := newMFAFixture(t)

	token, err := svc.IssueMFAToken(context.Background(), "u-1")
	require.NoError(t, err)

	claimed, err := svc.ClaimMFAToken(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "u-1", claimed.UserID)

	// Spent.
	_, err = svc.ClaimMFAToken(context.Background(), token)
	assert.ErrorIs(t, err, auth.ErrInvalidMFAToken)

	// And an unknown token is the same answer.
	_, err = svc.ClaimMFAToken(context.Background(), "never-issued")
	assert.ErrorIs(t, err, auth.ErrInvalidMFAToken)
}

func TestNewMFAServiceRequiresASealer(t *testing.T) {
	t.Parallel()

	_, err := auth.NewMFAService(newFakeMFAStore(), newFakeAdminStore(), nil, stubClock{mfaNow}, &stubIDs{}, "X", testTable(t))
	assert.ErrorIs(t, err, auth.ErrNoSealKey,
		"a second factor with no sealer would store its secret in plaintext")
}

// --- failure paths ----------------------------------------------------------

// TestMFAOperationsRefuseAnAnonymousCaller. Every one of these acts on "the
// caller's own account", so a zero identity has no account to act on — and
// must not fall through to acting on whatever a zero user id matches.
func TestMFAOperationsRefuseAnAnonymousCaller(t *testing.T) {
	t.Parallel()

	svc, _, _ := newMFAFixture(t)
	var anon auth.Identity

	_, err := svc.Status(context.Background(), anon)
	assert.ErrorIs(t, err, auth.ErrNotPermitted)

	_, err = svc.BeginEnrollment(context.Background(), anon)
	assert.ErrorIs(t, err, auth.ErrNotPermitted)

	_, err = svc.ConfirmEnrollment(context.Background(), anon, "123456")
	assert.ErrorIs(t, err, auth.ErrNotPermitted)

	_, err = svc.RegenerateRecoveryCodes(context.Background(), anon)
	assert.ErrorIs(t, err, auth.ErrNotPermitted)

	assert.ErrorIs(t, svc.Disable(context.Background(), anon, goodPassword), auth.ErrNotPermitted)
}

// TestAStoreFailureIsReportedRatherThanTreatedAsAbsent. auth.ErrNotFound
// means "no factor"; anything else means "we do not know", and treating the
// second as the first would quietly enroll over an existing factor or report
// an account unprotected when it is not.
func TestAStoreFailureIsReportedRatherThanTreatedAsAbsent(t *testing.T) {
	t.Parallel()

	svc, store, _ := newMFAFixture(t)
	store.readErr = errors.New("database unavailable")

	_, err := svc.Status(context.Background(), mfaActor())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read enrollment")

	_, err = svc.BeginEnrollment(context.Background(), mfaActor())
	require.Error(t, err, "enrolment proceeded over an enrollment it could not read")
	assert.Contains(t, err.Error(), "read enrollment")

	_, err = svc.ConfirmEnrollment(context.Background(), mfaActor(), "123456")
	require.Error(t, err)

	_, err = svc.VerifyFactor(context.Background(), "u-1", "123456")
	require.Error(t, err)
}

// TestConfirmationSaysSoWhenTheFactorIsOnButTheCodesAreNot.
//
// This is the worst state this feature can reach: a second factor is active
// and the user has no way past it if they lose their phone. The error has to
// say exactly that, because the person reading it is one page-close away from
// an account they cannot recover.
func TestConfirmationSaysSoWhenTheFactorIsOnButTheCodesAreNot(t *testing.T) {
	t.Parallel()

	svc, store, _ := newMFAFixture(t)
	e, err := svc.BeginEnrollment(context.Background(), mfaActor())
	require.NoError(t, err)
	store.replaceErr = errors.New("database unavailable")

	_, err = svc.ConfirmEnrollment(context.Background(), mfaActor(), currentCode(t, e.Secret, mfaNow))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "generate a set before signing out",
		"the error does not tell the user their account is now unrecoverable")

	// And the factor really is on, which is why the message matters.
	assert.True(t, svc.RequiresSecondFactor(context.Background(), "u-1"))
}

// TestRecoveryCodesCannotBeIssuedForAPendingEnrollment. They are the way past
// an ACTIVE factor; issuing them for one that may never be switched on would
// hand out a second set of working credentials for nothing.
func TestRecoveryCodesCannotBeIssuedForAPendingEnrollment(t *testing.T) {
	t.Parallel()

	svc, _, _ := newMFAFixture(t)
	_, err := svc.BeginEnrollment(context.Background(), mfaActor())
	require.NoError(t, err)

	_, err = svc.RegenerateRecoveryCodes(context.Background(), mfaActor())
	assert.ErrorIs(t, err, auth.ErrMFANotEnrolled)
}

func TestRecoveryCodesCannotBeIssuedWithNoFactorAtAll(t *testing.T) {
	t.Parallel()

	svc, _, _ := newMFAFixture(t)
	_, err := svc.RegenerateRecoveryCodes(context.Background(), mfaActor())
	assert.ErrorIs(t, err, auth.ErrMFANotEnrolled)
}

// TestDisablingWithNoFactorSaysSoRatherThanAskingForAPassword.
func TestDisablingWithNoFactorSaysSoRatherThanAskingForAPassword(t *testing.T) {
	t.Parallel()

	svc, _, users := newMFAFixture(t)
	seedUser(t, users, "u-1", goodPassword)

	assert.ErrorIs(t, svc.Disable(context.Background(), mfaActor(), goodPassword), auth.ErrMFANotEnrolled)
}

// TestVerifyingAgainstAPendingEnrollmentIsRefused. An unconfirmed row must
// not be usable to complete a login: nobody has proved they can produce its
// codes.
func TestVerifyingAgainstAPendingEnrollmentIsRefused(t *testing.T) {
	t.Parallel()

	svc, _, _ := newMFAFixture(t)
	e, err := svc.BeginEnrollment(context.Background(), mfaActor())
	require.NoError(t, err)

	_, err = svc.VerifyFactor(context.Background(), "u-1", currentCode(t, e.Secret, mfaNow))
	assert.ErrorIs(t, err, auth.ErrMFANotEnrolled)
}

func TestVerifyingWithNoFactorIsRefused(t *testing.T) {
	t.Parallel()

	svc, _, _ := newMFAFixture(t)
	_, err := svc.VerifyFactor(context.Background(), "u-1", "123456")
	assert.ErrorIs(t, err, auth.ErrMFANotEnrolled)
}

// TestAnEmptyRecoveryCodeIsRefusedWithoutTouchingTheStore.
func TestAnEmptyRecoveryCodeIsRefusedWithoutTouchingTheStore(t *testing.T) {
	t.Parallel()

	svc, _, _ := newMFAFixture(t)
	enrollAndConfirm(t, svc)

	for _, code := range []string{"", "   ", "---"} {
		kind, err := svc.VerifyFactor(context.Background(), "u-1", code)
		assert.Equal(t, auth.FactorRecovery, kind)
		assert.ErrorIs(t, err, auth.ErrInvalidRecoveryCode, "code %q", code)
	}
}

// TestLooksLikeTOTPIsStrictAboutShape, since the shape is what routes an
// input to one credential store or the other.
func TestLooksLikeTOTPIsStrictAboutShape(t *testing.T) {
	t.Parallel()

	svc, _, _ := newMFAFixture(t)
	enrollAndConfirm(t, svc)

	// Six digits, however spaced, go to the authenticator.
	for _, code := range []string{"000000", "00 00 00", "000-000"} {
		kind, _ := svc.VerifyFactor(context.Background(), "u-1", code)
		assert.Equal(t, auth.FactorTOTP, kind, "code %q", code)
	}

	// Anything else goes to the recovery codes — including five digits,
	// seven digits, and six characters that are not all digits.
	for _, code := range []string{"00000", "0000000", "00000A", "ABCD-1234-EFGH-5678"} {
		kind, _ := svc.VerifyFactor(context.Background(), "u-1", code)
		assert.Equal(t, auth.FactorRecovery, kind, "code %q", code)
	}
}

func TestNewMFAServiceRequiresItsCollaborators(t *testing.T) {
	t.Parallel()

	sealer, err := auth.NewSealerFromHex(testSealKeyHex)
	require.NoError(t, err)

	_, err = auth.NewMFAService(nil, newFakeAdminStore(), sealer, stubClock{mfaNow}, &stubIDs{}, "X", testTable(t))
	assert.Error(t, err)
	_, err = auth.NewMFAService(newFakeMFAStore(), nil, sealer, stubClock{mfaNow}, &stubIDs{}, "X", testTable(t))
	assert.Error(t, err)
	_, err = auth.NewMFAService(newFakeMFAStore(), newFakeAdminStore(), sealer, nil, &stubIDs{}, "X", testTable(t))
	assert.Error(t, err)
	_, err = auth.NewMFAService(newFakeMFAStore(), newFakeAdminStore(), sealer, stubClock{mfaNow}, nil, "X", testTable(t))
	assert.Error(t, err)
	_, err = auth.NewMFAService(newFakeMFAStore(), newFakeAdminStore(), sealer, stubClock{mfaNow}, &stubIDs{}, "X", nil)
	assert.Error(t, err, "no permission table was refused")

	// An empty issuer is refused rather than defaulted: it is what every
	// enrolled authenticator app shows next to the account, and this
	// package has no generic name that would be right for someone else's
	// deployment.
	_, err = auth.NewMFAService(newFakeMFAStore(), newFakeAdminStore(), sealer, stubClock{mfaNow}, &stubIDs{}, "", testTable(t))
	assert.Error(t, err, "an empty issuer was accepted")
}

// --- the lockout valve ------------------------------------------------------

// TestAnAdministratorCanClearAStrandedUsersFactor.
//
// This is the reason a second factor is safe to switch on. Recovery codes
// cover the ordinary loss of a phone; this covers the case where the codes
// are gone too, which is common enough that without it the honest advice
// would be "do not enable this".
func TestAnAdministratorCanClearAStrandedUsersFactor(t *testing.T) {
	t.Parallel()

	svc, store, _ := newMFAFixture(t)
	enrollAndConfirm(t, svc)
	require.True(t, svc.RequiresSecondFactor(context.Background(), "u-1"))

	admin := auth.Identity{UserID: "u-admin", OrgID: "org-1", Role: testAdmin}.WithPermissions(testTable(t))
	target := auth.User{ID: "u-1", OrgID: "org-1", Email: "person@example.com"}

	require.NoError(t, svc.ClearFactorFor(context.Background(), admin, "u-1", target))
	assert.False(t, svc.RequiresSecondFactor(context.Background(), "u-1"))
	// The codes go with it: they exist only to get past the factor.
	assert.Empty(t, store.recovery)
}

// TestClearingAFactorNeedsTheManagementPermission. Stripping a control off
// an account the actor does not own is exactly as privileged as resetting
// its password.
func TestClearingAFactorNeedsTheManagementPermission(t *testing.T) {
	t.Parallel()

	svc, _, _ := newMFAFixture(t)
	enrollAndConfirm(t, svc)

	analyst := auth.Identity{UserID: "u-analyst", OrgID: "org-1", Role: testAnalyst}.WithPermissions(testTable(t))
	target := auth.User{ID: "u-1", OrgID: "org-1"}

	assert.ErrorIs(t, svc.ClearFactorFor(context.Background(), analyst, "u-1", target), auth.ErrNotPermitted)
	assert.True(t, svc.RequiresSecondFactor(context.Background(), "u-1"),
		"an analyst stripped a second factor off another account")
}

// TestClearingAFactorCannotReachAnotherOrganization. On a multi-tenant
// deployment this would be a way to weaken a neighbour's accounts directly.
func TestClearingAFactorCannotReachAnotherOrganization(t *testing.T) {
	t.Parallel()

	svc, _, _ := newMFAFixture(t)
	enrollAndConfirm(t, svc)

	admin := auth.Identity{UserID: "u-admin", OrgID: "org-1", Role: testAdmin}.WithPermissions(testTable(t))
	elsewhere := auth.User{ID: "u-1", OrgID: "org-2"}

	assert.ErrorIs(t, svc.ClearFactorFor(context.Background(), admin, "u-1", elsewhere), auth.ErrNotPermitted)
	assert.True(t, svc.RequiresSecondFactor(context.Background(), "u-1"))
}
