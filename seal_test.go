package auth_test

import (
	"encoding/base64"
	"strings"
	"testing"

	auth "github.com/qdiver/golang-module-rbac"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSealKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

func testSealer(t *testing.T) *auth.Sealer {
	t.Helper()
	s, err := auth.NewSealerFromHex(testSealKeyHex)
	require.NoError(t, err)
	return s
}

func TestSealRoundTrips(t *testing.T) {
	t.Parallel()

	s := testSealer(t)
	secret, err := auth.NewTOTPSecret()
	require.NoError(t, err)

	sealed, err := s.Seal(secret)
	require.NoError(t, err)
	assert.True(t, auth.IsSealed(sealed), "the stored value carries no ciphertext marker")
	assert.NotContains(t, sealed, secret, "the secret appears verbatim in its own ciphertext")

	opened, err := s.Open(sealed)
	require.NoError(t, err)
	assert.Equal(t, secret, opened)
}

// TestEachSealUsesAFreshNonce. Reusing a nonce under GCM is catastrophic —
// it leaks the XOR of the plaintexts and, worse, the authentication key. The
// mistake that makes reuse look reasonable is deriving the nonce from
// something stable about the user, so this pins that two seals of the SAME
// secret differ.
func TestEachSealUsesAFreshNonce(t *testing.T) {
	t.Parallel()

	s := testSealer(t)
	const secret = "JBSWY3DPEHPK3PXP"

	seen := map[string]bool{}
	for range 20 {
		sealed, err := s.Seal(secret)
		require.NoError(t, err)
		assert.False(t, seen[sealed], "two seals of the same secret were identical: nonce reuse")
		seen[sealed] = true
	}
}

// TestAWrongKeyCannotOpen. The point of sealing is that a database dump
// without the key is not enough to mint codes for every enrolled account.
func TestAWrongKeyCannotOpen(t *testing.T) {
	t.Parallel()

	sealed, err := testSealer(t).Seal("JBSWY3DPEHPK3PXP")
	require.NoError(t, err)

	other, err := auth.NewSealerFromHex(strings.Repeat("ab", 32))
	require.NoError(t, err)

	_, err = other.Open(sealed)
	assert.ErrorIs(t, err, auth.ErrUnseal)
}

// TestTamperedCiphertextIsRefused. GCM authenticates, so a flipped bit must
// fail rather than decrypt to a different secret — otherwise an attacker with
// write access to the column could steer a secret to a value they know.
func TestTamperedCiphertextIsRefused(t *testing.T) {
	t.Parallel()

	s := testSealer(t)
	sealed, err := s.Seal("JBSWY3DPEHPK3PXP")
	require.NoError(t, err)

	body := strings.TrimPrefix(sealed, "mfav1:")
	raw, err := base64.StdEncoding.DecodeString(body)
	require.NoError(t, err)
	raw[len(raw)-1] ^= 0x01

	_, err = s.Open("mfav1:" + base64.StdEncoding.EncodeToString(raw))
	assert.ErrorIs(t, err, auth.ErrUnseal)
}

// TestAnUnmarkedValueIsRefusedRatherThanTrusted. A value with no marker is
// not a legacy plaintext to be accepted — it is a row this build cannot
// account for, and accepting it would mean a secret written as plaintext by a
// bug kept working and was never noticed.
func TestAnUnmarkedValueIsRefusedRatherThanTrusted(t *testing.T) {
	t.Parallel()

	s := testSealer(t)
	for _, v := range []string{"", "JBSWY3DPEHPK3PXP", "encv1:abc", "mfav1:not-base64!!"} {
		_, err := s.Open(v)
		assert.ErrorIs(t, err, auth.ErrUnseal, "value %q", v)
	}
}

func TestSealerRejectsBadKeys(t *testing.T) {
	t.Parallel()

	_, err := auth.NewSealerFromHex("")
	assert.ErrorIs(t, err, auth.ErrNoSealKey)

	_, err = auth.NewSealerFromHex("nothex")
	assert.ErrorContains(t, err, "must be hex")

	// 17 bytes: hex-valid, and not an AES key length.
	_, err = auth.NewSealerFromHex(strings.Repeat("ab", 17))
	assert.ErrorIs(t, err, auth.ErrSealKeySize)

	for _, n := range []int{16, 24, 32} {
		_, err := auth.NewSealerFromHex(strings.Repeat("cd", n))
		assert.NoError(t, err, "a %d-byte key was refused", n)
	}
}

// TestANilSealerFailsClosed. A process wired without a key must refuse to
// store a second factor rather than store it in plaintext.
func TestANilSealerFailsClosed(t *testing.T) {
	t.Parallel()

	var s *auth.Sealer
	_, err := s.Seal("JBSWY3DPEHPK3PXP")
	assert.ErrorIs(t, err, auth.ErrNoSealKey)
	_, err = s.Open("mfav1:whatever")
	assert.ErrorIs(t, err, auth.ErrNoSealKey)
}
