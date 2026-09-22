// Package webauthntest provides a software authenticator for tests.
//
// Two suites need one — the service's own, and the HTTP layer's — and a
// second copy would be a second thing to keep correct. It lives under
// internal/testutil for the same reason internal/testutil/fakes does: it is a
// test double, not application code, and nothing outside a test imports it.
package webauthntest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// A software authenticator, for testing the ceremonies end to end.
//
// # Why this exists rather than a mock
//
// The interesting half of WebAuthn is the part the library verifies: that the
// client data names the right origin and challenge, that the authenticator
// data hashes the right relying party, that the signature is over both, and
// that the counter went up. Stubbing the library out would test none of it and
// would pass just as happily against code that skipped verification entirely.
//
// So this produces the real thing — a P-256 key pair, a COSE-encoded public
// key, a CBOR attestation object, and an ECDSA signature over
// authenticatorData||SHA256(clientDataJSON) — and the production path verifies
// it for real. What the tests then assert is behaviour under a working
// authenticator AND under a subtly wrong one: a bad origin, a replayed
// challenge, a counter that goes backwards.
//
// It implements the "none" attestation format, which is what a real
// authenticator sends when attestation is not requested — and this deployment
// does not request it (ADR-0031).
type Authenticator struct {
	key *ecdsa.PrivateKey
	// CredID is the credential identifier this authenticator presents.
	CredID []byte
	aaguid []byte
	// SignCount is the signature counter, which a real authenticator
	// increments on every assertion.
	SignCount uint32

	// UserHandle is the account the credential was registered to, returned
	// with an assertion. Optional: a non-discoverable credential may omit
	// it, and a WRONG one is refused — which is what a hardcoded value in
	// this file caused until a test signed in as a second account.
	UserHandle []byte

	// NoUserVerification models a U2F-era key with no PIN or biometric: it
	// proves possession and nothing else. Such a key is a perfectly good
	// SECOND factor beside a password, and must not be able to sign in on
	// its own.
	NoUserVerification bool
}

// New builds an authenticator with a fresh P-256 key pair.
func New(t *testing.T) *Authenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	credID := make([]byte, 32)
	_, err = rand.Read(credID)
	require.NoError(t, err)

	return &Authenticator{
		key:    key,
		CredID: credID,
		// A fixed, obviously-fake model id. A real one identifies the
		// hardware; nothing here verifies it, which ADR-0031 says plainly.
		aaguid:    make([]byte, 16),
		SignCount: 1,
	}
}

// B64 is WebAuthn's encoding: base64url, no padding.
func B64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// clientData builds the JSON the browser would send.
func clientData(t *testing.T, ceremonyType, challenge, origin string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"type":        ceremonyType,
		"challenge":   challenge,
		"origin":      origin,
		"crossOrigin": false,
	})
	require.NoError(t, err)
	return raw
}

// coseKey encodes the public key the way WebAuthn expects: a CBOR map keyed
// by the COSE labels for key type, algorithm, curve and the two coordinates.
func (a *Authenticator) coseKey(t *testing.T) []byte {
	t.Helper()
	x := make([]byte, 32)
	y := make([]byte, 32)
	a.key.PublicKey.X.FillBytes(x)
	a.key.PublicKey.Y.FillBytes(y)

	raw, err := cbor.Marshal(map[int]any{
		1:  2,  // kty: EC2
		3:  -7, // alg: ES256
		-1: 1,  // crv: P-256
		-2: x,
		-3: y,
	})
	require.NoError(t, err)
	return raw
}

// authData builds authenticator data. `attested` includes the credential and
// its public key, which registration carries and an assertion does not.
func (a *Authenticator) authData(t *testing.T, rpID string, attested bool) []byte {
	t.Helper()
	rpHash := sha256.Sum256([]byte(rpID))

	// UP (user present), and UV (user verified) unless this device is
	// modelling a key with no PIN or biometric. AT (attested credential
	// data) is set only for registration.
	//
	// The distinction is the whole of what makes a passwordless sign-in two
	// factors: with no password, a key that only proves possession is one,
	// and a found key would be a sign-in.
	flags := byte(0x01)
	if !a.NoUserVerification {
		flags |= 0x04
	}
	if attested {
		flags |= 0x40
	}

	out := make([]byte, 0, 128)
	out = append(out, rpHash[:]...)
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, a.SignCount)

	if attested {
		out = append(out, a.aaguid...)
		out = binary.BigEndian.AppendUint16(out, uint16(len(a.CredID))) // #nosec G115 -- 32 bytes by construction
		out = append(out, a.CredID...)
		out = append(out, a.coseKey(t)...)
	}
	return out
}

// register produces what navigator.credentials.create() would return.
func (a *Authenticator) Register(t *testing.T, challenge, origin, rpID string) []byte {
	t.Helper()
	cd := clientData(t, "webauthn.create", challenge, origin)
	ad := a.authData(t, rpID, true)

	attestation, err := cbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": ad,
	})
	require.NoError(t, err)

	raw, err := json.Marshal(map[string]any{
		"id":    B64(a.CredID),
		"rawId": B64(a.CredID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    B64(cd),
			"attestationObject": B64(attestation),
		},
		"clientExtensionResults":  map[string]any{},
		"authenticatorAttachment": "cross-platform",
	})
	require.NoError(t, err)
	return raw
}

// assert produces what navigator.credentials.get() would return.
//
// The counter is advanced first, because that is what a real authenticator
// does on every assertion and is the property the clone check relies on.
func (a *Authenticator) Assert(t *testing.T, challenge, origin, rpID string) []byte {
	t.Helper()
	a.SignCount++
	return a.AssertWithoutAdvancing(t, challenge, origin, rpID)
}

// assertWithoutAdvancing signs at the CURRENT counter, for the test that
// checks what happens when a counter does not move — which is what a cloned
// authenticator looks like from the server's side.
func (a *Authenticator) AssertWithoutAdvancing(t *testing.T, challenge, origin, rpID string) []byte {
	t.Helper()
	cd := clientData(t, "webauthn.get", challenge, origin)
	ad := a.authData(t, rpID, false)

	cdHash := sha256.Sum256(cd)
	signed := append(append([]byte{}, ad...), cdHash[:]...)
	digest := sha256.Sum256(signed)

	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	require.NoError(t, err)

	resp := map[string]any{
		"clientDataJSON":    B64(cd),
		"authenticatorData": B64(ad),
		"signature":         B64(sig),
	}
	// Only when the caller set one. A non-discoverable credential may omit
	// the handle entirely, and sending the wrong one is refused — so a
	// hardcoded value here would quietly work for one account and fail for
	// every other.
	if len(a.UserHandle) > 0 {
		resp["userHandle"] = B64(a.UserHandle)
	}

	raw, err := json.Marshal(map[string]any{
		"id":                     B64(a.CredID),
		"rawId":                  B64(a.CredID),
		"type":                   "public-key",
		"response":               resp,
		"clientExtensionResults": map[string]any{},
	})
	require.NoError(t, err)
	return raw
}

// challengeFrom reads the challenge out of the options a begin call returned,
// the way a browser would.
// ChallengeFrom reads the challenge out of the options a begin call
// returned, the way a browser would.
func ChallengeFrom(t *testing.T, options []byte) string {
	t.Helper()
	var opts struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	require.NoError(t, json.Unmarshal(options, &opts))
	require.NotEmpty(t, opts.PublicKey.Challenge)
	return opts.PublicKey.Challenge
}
