package auth

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
)

// TOTP parameters. These are the values every authenticator app assumes by
// default — Google Authenticator, 1Password, Aegis and the rest — and
// changing any of them means the code on the phone and the code this server
// expects stop agreeing, for everyone, at once.
const (
	// TOTPPeriod is the step length in seconds (RFC 6238 §5.2).
	TOTPPeriod = 30

	// TOTPDigits is the code length. Six is what the apps show.
	TOTPDigits = otp.DigitsSix

	// TOTPSkew is how many steps either side of now are accepted.
	//
	// One, not zero, because phone clocks drift and a person typing six
	// digits takes a few seconds. One step each way accepts a 90-second
	// window, which is the usual trade; two would nearly triple the window
	// an intercepted code stays usable in, for very little extra tolerance.
	TOTPSkew = 1

	// totpSecretBytes is the shared secret's size. RFC 4226 §4 requires at
	// least 128 bits and recommends 160, which is also the HMAC-SHA1 output
	// length, so a longer secret would add no strength.
	totpSecretBytes = 20
)

// TOTPAlgorithm is the HMAC hash. SHA1 is not a strength choice — it is the
// only algorithm the installed base of authenticator apps reliably supports,
// and its weaknesses (collision resistance) are not the property HMAC relies
// on. RFC 6238 specifies it as the default for exactly this reason.
const TOTPAlgorithm = otp.AlgorithmSHA1

// Errors from the TOTP path.
var (
	// ErrInvalidTOTPCode is returned for a code that does not match any
	// accepted step. It is deliberately the same error whether the code was
	// wrong, malformed or replayed: a caller must not be able to tell a
	// stale-but-real code from a guess.
	ErrInvalidTOTPCode = errors.New("auth: that code is not valid")

	// ErrTOTPReplay is for internal reporting only — it never reaches a
	// caller, because ValidateTOTPCode collapses it into
	// ErrInvalidTOTPCode. It exists so the audit log can distinguish a
	// replayed code, which means someone is reusing an observed one, from
	// an ordinary wrong code.
	ErrTOTPReplay = errors.New("auth: that code has already been used")
)

// NewTOTPSecret returns a fresh base32 shared secret.
//
// Base32 without padding, because that is what the otpauth:// URI scheme and
// every authenticator app expect; padding characters in the secret field
// make some apps refuse the QR outright.
func NewTOTPSecret() (string, error) {
	buf := make([]byte, totpSecretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("auth: generate TOTP secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

// TOTPKeyURI builds the otpauth:// URI an authenticator app consumes.
//
// The issuer appears twice — as a path prefix and as a parameter — which
// looks redundant and is not: older apps read the prefix, newer ones read
// the parameter, and an app that reads neither files the account under a
// bare email address with no hint of which system it belongs to.
//
// The account is the email address, so somebody with three work accounts can
// tell which entry is which.
func TOTPKeyURI(secret, issuer, account string) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", fmt.Sprint(TOTPPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// TOTPStep is the counter for an instant: the number of whole periods since
// the Unix epoch (RFC 6238 §4.2).
func TOTPStep(t time.Time) int64 { return t.Unix() / TOTPPeriod }

// ValidateTOTPCode checks a code and returns the step it matched.
//
// # Why this is not totp.Validate
//
// The library's TOTP validator answers yes or no and does not say WHICH step
// matched. That is exactly the value the replay guard needs: a six-digit code
// stays valid for the whole acceptance window, so without recording the step
// it was used at, anyone who observes a code — over the user's shoulder, in a
// phishing proxy, from a logged request body — can use it again inside that
// window. So the counters are walked here and the matching one is returned.
//
// lastUsedStep is the step this account last authenticated with, or 0 for an
// account that never has. Any step at or below it is refused.
//
// # Why the steps are tried newest-first
//
// Only for cost: the current step is overwhelmingly the likely match, and the
// comparison is constant-time per candidate regardless of order.
func ValidateTOTPCode(secret, code string, now time.Time, lastUsedStep int64) (int64, error) {
	code = strings.TrimSpace(code)
	if code == "" || secret == "" {
		return 0, ErrInvalidTOTPCode
	}

	current := TOTPStep(now)
	// Ordered current, then alternating forward and back, so the common case
	// costs one HMAC.
	candidates := make([]int64, 0, 1+2*TOTPSkew)
	candidates = append(candidates, current)
	for i := int64(1); i <= TOTPSkew; i++ {
		candidates = append(candidates, current+i, current-i)
	}

	for _, step := range candidates {
		if step < 0 {
			continue
		}
		ok, err := hotp.ValidateCustom(code, uint64(step), secret, hotp.ValidateOpts{
			Digits:    TOTPDigits,
			Algorithm: TOTPAlgorithm,
		})
		if err != nil {
			// A malformed code or an unparseable secret. Reported as an
			// invalid code, because the alternative is telling a caller
			// which of the two it was.
			return 0, ErrInvalidTOTPCode
		}
		if !ok {
			continue
		}
		// Matched. The replay guard is applied AFTER the match, so a
		// replayed code and a wrong code cost the same work and are
		// indistinguishable from outside.
		if step <= lastUsedStep {
			return step, ErrTOTPReplay
		}
		return step, nil
	}
	return 0, ErrInvalidTOTPCode
}
