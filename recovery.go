package auth

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
)

// Recovery codes are the way back in when the second factor is gone: a lost
// phone, a wiped authenticator, a device that went into the sea. Without
// them, enabling MFA on a single-administrator deployment is a way to lock
// an organization out of its own installation permanently — which is why
// docs/proposals/auth-hardening.md sequences recovery before any factor.
const (
	// RecoveryCodeCount is how many are issued at enrollment.
	//
	// Ten is enough to survive a few years of occasional use and few enough
	// that a person will actually store them somewhere. They are issued as
	// a set and replaced as a set.
	RecoveryCodeCount = 10

	// recoveryCodeChars is the length of one code in alphabet characters.
	//
	// The alphabet has 32 symbols, so each character carries 5 bits and
	// sixteen of them carry 80. That is far beyond what an online guessing
	// attack can reach, and the throttle on the MFA endpoint bounds it
	// further. Longer would only make them harder to transcribe from paper,
	// which is the situation they exist for.
	//
	// They are machine-generated and high-entropy, so they are hashed with
	// SHA-256 rather than argon2 — the reasoning in token.go applies exactly.
	recoveryCodeChars = 16

	// recoveryGroupSize is how many characters between the dashes.
	recoveryGroupSize = 4
)

// recoveryAlphabet is Crockford base32 minus the letters that are read
// wrong: no I, L, O or U.
//
// People transcribe these by hand from paper, in a hurry, having lost their
// phone. An alphabet where 0/O and 1/I are distinct is the difference
// between a code that works and a support call.
const recoveryAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// ErrInvalidRecoveryCode is returned when no unused code matches. It does
// not distinguish "wrong" from "already used", because a caller must not be
// able to discover which of their codes have been spent.
var ErrInvalidRecoveryCode = errors.New("auth: that recovery code is not valid")

// NewRecoveryCodes returns a fresh set in plaintext, with their hashes.
//
// The plaintext is returned once, to be shown once. Only the hashes are
// stored, so a database dump does not hand over a way past the second
// factor — which would make the whole factor decorative.
func NewRecoveryCodes() (codes []string, hashes [][]byte, err error) {
	codes = make([]string, 0, RecoveryCodeCount)
	hashes = make([][]byte, 0, RecoveryCodeCount)
	for range RecoveryCodeCount {
		code, genErr := newRecoveryCode()
		if genErr != nil {
			return nil, nil, genErr
		}
		codes = append(codes, code)
		hashes = append(hashes, HashToken(NormalizeRecoveryCode(code)))
	}
	return codes, hashes, nil
}

// newRecoveryCode returns one code, formatted in dashed groups.
//
// Characters are drawn by rejection sampling rather than by taking a byte
// modulo the alphabet size. With 32 symbols and 256 byte values the modulo
// happens to be unbiased today, but the bias would reappear silently the
// moment somebody added or removed a character from the alphabet — and a
// biased recovery code is weaker than its length claims in a way no test
// would notice.
func newRecoveryCode() (string, error) {
	// The usable range: the largest multiple of the alphabet size that fits
	// in a byte. Values at or above it are discarded.
	limit := (256 / len(recoveryAlphabet)) * len(recoveryAlphabet)

	var b strings.Builder
	buf := make([]byte, recoveryCodeChars)
	for written := 0; written < recoveryCodeChars; {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("auth: generate recovery code: %w", err)
		}
		for _, x := range buf {
			if written == recoveryCodeChars {
				break
			}
			if int(x) >= limit {
				continue
			}
			if written > 0 && written%recoveryGroupSize == 0 {
				b.WriteByte('-')
			}
			b.WriteByte(recoveryAlphabet[int(x)%len(recoveryAlphabet)])
			written++
		}
	}
	return b.String(), nil
}

// NormalizeRecoveryCode puts a typed code into the form that was hashed.
//
// Someone entering one of these has lost their phone and is reading from
// paper. Case, dashes and stray spaces must not be the reason they cannot
// get back in, so all three are removed before comparison — and, because the
// hash is over the normalised form, the same normalisation must happen when
// the codes are created. Both paths call this.
func NormalizeRecoveryCode(code string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(strings.TrimSpace(code)) {
		if r == '-' || r == ' ' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
