package auth_test

import (
	"strings"
	"testing"

	auth "github.com/qdiver/golang-module-rbac"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRecoveryCodesShape(t *testing.T) {
	t.Parallel()

	codes, hashes, err := auth.NewRecoveryCodes()
	require.NoError(t, err)
	require.Len(t, codes, auth.RecoveryCodeCount)
	require.Len(t, hashes, auth.RecoveryCodeCount)

	seen := map[string]bool{}
	for _, c := range codes {
		assert.Equal(t, "XXXX-XXXX-XXXX-XXXX", pattern(c), "unexpected format: %q", c)

		// The alphabet deliberately excludes I, L, O and U: these are
		// transcribed by hand, from paper, by someone who has just lost
		// their phone, and 0/O confusion is the difference between getting
		// back in and a support call.
		for _, r := range strings.ReplaceAll(c, "-", "") {
			assert.NotContains(t, "ILOU", string(r), "code %q contains an ambiguous character", c)
		}

		assert.False(t, seen[c], "two recovery codes in one set were identical")
		seen[c] = true
	}
}

// pattern renders a code's shape, so the format assertion does not depend on
// the random characters in it.
func pattern(code string) string {
	var b strings.Builder
	for _, r := range code {
		if r == '-' {
			b.WriteByte('-')
			continue
		}
		b.WriteByte('X')
	}
	return b.String()
}

// TestTheHashesMatchTheCodesAsTyped is the one that would strand a user.
// The hash is over the NORMALISED code, so if generation hashed the dashed
// form and verification normalised, every recovery code would be rejected —
// and the person finding out would be the one who had already lost their
// phone.
func TestTheHashesMatchTheCodesAsTyped(t *testing.T) {
	t.Parallel()

	codes, hashes, err := auth.NewRecoveryCodes()
	require.NoError(t, err)

	for i, c := range codes {
		assert.Equal(t, hashes[i], auth.HashToken(auth.NormalizeRecoveryCode(c)),
			"code %q does not hash to its stored value", c)
	}
}

// TestNormalizeAcceptsWhatAPersonActuallyTypes.
func TestNormalizeAcceptsWhatAPersonActuallyTypes(t *testing.T) {
	t.Parallel()

	const canonical = "ABCD1234EFGH5678"
	for _, typed := range []string{
		"ABCD-1234-EFGH-5678",
		"abcd-1234-efgh-5678",
		"  ABCD-1234-EFGH-5678  ",
		"ABCD 1234 EFGH 5678",
		"abcd1234efgh5678",
	} {
		assert.Equal(t, canonical, auth.NormalizeRecoveryCode(typed), "input %q", typed)
	}
}

// TestCodesDifferAcrossSets. Two enrollments must not produce the same set,
// which would mean the generator was not actually random.
func TestCodesDifferAcrossSets(t *testing.T) {
	t.Parallel()

	first, _, err := auth.NewRecoveryCodes()
	require.NoError(t, err)
	second, _, err := auth.NewRecoveryCodes()
	require.NoError(t, err)

	overlap := 0
	inFirst := map[string]bool{}
	for _, c := range first {
		inFirst[c] = true
	}
	for _, c := range second {
		if inFirst[c] {
			overlap++
		}
	}
	assert.Zero(t, overlap, "two independently generated sets shared codes")
}
