package auth_test

import (
	"encoding/base32"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/qdiver/golang-module-rbac"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rfc6238Secret is the shared secret from RFC 6238's Appendix B test table:
// the ASCII string "12345678901234567890", which the otpauth scheme carries
// base32-encoded.
var rfc6238Secret = base32.StdEncoding.WithPadding(base32.NoPadding).
	EncodeToString([]byte("12345678901234567890"))

// codeAt is what a correct authenticator app would show at an instant.
func codeAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	code, err := hotp.GenerateCodeCustom(secret, uint64(auth.TOTPStep(at)), hotp.ValidateOpts{
		Digits: auth.TOTPDigits, Algorithm: auth.TOTPAlgorithm,
	})
	require.NoError(t, err)
	return code
}

// TestTOTPMatchesRFC6238 pins the implementation to the standard's own
// published values.
//
// This is the test that matters most in this file. Every authenticator app
// in the world implements RFC 6238; if this server disagrees with it by one
// step, one digit or one algorithm, nobody can sign in and the failure looks
// like "MFA is broken" rather than like a specification mismatch. The vectors
// below are Appendix B's SHA-1 rows, truncated to the six digits this product
// uses.
func TestTOTPMatchesRFC6238(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		unix int64
		want string // last 6 digits of the RFC's 8-digit SHA-1 value
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	} {
		at := time.Unix(tc.unix, 0).UTC()
		t.Run(at.Format(time.RFC3339), func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, codeAt(t, rfc6238Secret, at),
				"this build disagrees with RFC 6238, so no authenticator app will work with it")

			// And the validator accepts the value the standard specifies.
			step, err := auth.ValidateTOTPCode(rfc6238Secret, tc.want, at, 0)
			require.NoError(t, err)
			assert.Equal(t, auth.TOTPStep(at), step)
		})
	}
}

// TestTOTPStepIsTheRFCCounter. Getting this wrong by a factor or an offset
// would put every code in the wrong window.
func TestTOTPStepIsTheRFCCounter(t *testing.T) {
	t.Parallel()

	assert.Equal(t, int64(1), auth.TOTPStep(time.Unix(59, 0)))
	assert.Equal(t, int64(2), auth.TOTPStep(time.Unix(60, 0)))
	assert.Equal(t, int64(37037036), auth.TOTPStep(time.Unix(1111111109, 0)))
}

// TestAReplayedCodeIsRefused is the guard the plan called non-optional. A
// six-digit code stays valid for the whole acceptance window, so without
// recording the step it was used at, anyone who observes one — over a
// shoulder, through a phishing proxy, from a logged body — can use it again
// inside that window.
func TestAReplayedCodeIsRefused(t *testing.T) {
	t.Parallel()

	now := time.Unix(1700000000, 0).UTC()
	code := codeAt(t, rfc6238Secret, now)

	step, err := auth.ValidateTOTPCode(rfc6238Secret, code, now, 0)
	require.NoError(t, err, "a fresh code was refused")

	// Same code, same window, now that the step has been recorded.
	_, err = auth.ValidateTOTPCode(rfc6238Secret, code, now, step)
	assert.ErrorIs(t, err, auth.ErrTOTPReplay)
}

// TestAnEarlierStepIsRefusedOnceALaterOneIsUsed. The skew window reaches
// backwards, so without this an attacker holding a code from the previous
// step could use it after the user had already authenticated with the
// current one.
func TestAnEarlierStepIsRefusedOnceALaterOneIsUsed(t *testing.T) {
	t.Parallel()

	now := time.Unix(1700000000, 0).UTC()
	previous := codeAt(t, rfc6238Secret, now.Add(-auth.TOTPPeriod*time.Second))

	// Accepted on its own: it is inside the skew window.
	_, err := auth.ValidateTOTPCode(rfc6238Secret, previous, now, 0)
	require.NoError(t, err)

	// Refused once the current step has been recorded.
	_, err = auth.ValidateTOTPCode(rfc6238Secret, previous, now, auth.TOTPStep(now))
	assert.ErrorIs(t, err, auth.ErrTOTPReplay)
}

// TestTheSkewWindowIsOneStepEitherWay. Wider would leave an intercepted code
// usable for longer; narrower would refuse people whose phone clock drifts by
// a few seconds.
func TestTheSkewWindowIsOneStepEitherWay(t *testing.T) {
	t.Parallel()

	now := time.Unix(1700000000, 0).UTC()
	period := time.Duration(auth.TOTPPeriod) * time.Second

	for _, offset := range []time.Duration{-period, 0, period} {
		code := codeAt(t, rfc6238Secret, now.Add(offset))
		_, err := auth.ValidateTOTPCode(rfc6238Secret, code, now, 0)
		assert.NoError(t, err, "a code %v from now was refused", offset)
	}

	for _, offset := range []time.Duration{-2 * period, 2 * period} {
		code := codeAt(t, rfc6238Secret, now.Add(offset))
		_, err := auth.ValidateTOTPCode(rfc6238Secret, code, now, 0)
		assert.ErrorIs(t, err, auth.ErrInvalidTOTPCode,
			"a code %v from now was accepted", offset)
	}
}

func TestInvalidCodesAreRefusedWithoutDistinction(t *testing.T) {
	t.Parallel()

	now := time.Unix(1700000000, 0).UTC()
	for _, code := range []string{"", "000000", "12345", "abcdef", "1234567", "   "} {
		_, err := auth.ValidateTOTPCode(rfc6238Secret, code, now, 0)
		assert.ErrorIs(t, err, auth.ErrInvalidTOTPCode, "code %q", code)
	}

	// An empty secret is an unenrolled account, not a reason to panic.
	_, err := auth.ValidateTOTPCode("", "123456", now, 0)
	assert.ErrorIs(t, err, auth.ErrInvalidTOTPCode)
}

// TestNewTOTPSecretIsUnpaddedBase32OfTheRightLength. Padding characters in
// the secret field make some authenticator apps refuse the QR outright, and
// a short secret weakens every code derived from it.
func TestNewTOTPSecretIsUnpaddedBase32OfTheRightLength(t *testing.T) {
	t.Parallel()

	seen := map[string]bool{}
	for range 25 {
		s, err := auth.NewTOTPSecret()
		require.NoError(t, err)

		assert.NotContains(t, s, "=", "the secret carries base32 padding")
		raw, decErr := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
		require.NoError(t, decErr, "the secret is not valid base32: %q", s)
		assert.Len(t, raw, 20, "the secret is not 160 bits")

		assert.False(t, seen[s], "two generated secrets were identical")
		seen[s] = true
	}
}

// TestTOTPKeyURIIsWhatAnAuthenticatorAppExpects. A malformed URI is a QR
// that scans to nothing, which reads to a user as "this product is broken".
func TestTOTPKeyURIIsWhatAnAuthenticatorAppExpects(t *testing.T) {
	t.Parallel()

	uri := auth.TOTPKeyURI("JBSWY3DPEHPK3PXP", "Security Assessment", "person@example.com")

	u, err := url.Parse(uri)
	require.NoError(t, err)
	assert.Equal(t, "otpauth", u.Scheme)
	assert.Equal(t, "totp", u.Host)

	// The issuer appears in the label AND as a parameter: older apps read
	// the prefix, newer ones the parameter, and one that reads neither files
	// the account under a bare address with no hint of what it belongs to.
	// u.Path is decoded; EscapedPath is what actually goes on the wire, and
	// the space must be percent-encoded there or the URI is malformed.
	assert.Equal(t, "/Security Assessment:person@example.com", u.Path)
	assert.True(t, strings.HasPrefix(u.EscapedPath(), "/Security%20Assessment:"),
		"the issuer is not escaped on the wire: %q", u.EscapedPath())

	q := u.Query()
	assert.Equal(t, "JBSWY3DPEHPK3PXP", q.Get("secret"))
	assert.Equal(t, "Security Assessment", q.Get("issuer"))
	assert.Equal(t, "SHA1", q.Get("algorithm"))
	assert.Equal(t, "6", q.Get("digits"))
	assert.Equal(t, "30", q.Get("period"))
}

// TestTheParametersAreTheOnesEveryAppAssumes. Changing any of them means the
// code on the phone and the code this server expects stop agreeing, for
// everyone, at once — so they are pinned rather than left to a constant
// somebody might tune.
func TestTheParametersAreTheOnesEveryAppAssumes(t *testing.T) {
	t.Parallel()

	assert.Equal(t, 30, auth.TOTPPeriod)
	assert.Equal(t, otp.DigitsSix, auth.TOTPDigits)
	assert.Equal(t, otp.AlgorithmSHA1, auth.TOTPAlgorithm)
	assert.Equal(t, int64(1), int64(auth.TOTPSkew))
}
