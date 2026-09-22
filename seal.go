package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// A TOTP shared secret has to be ENCRYPTED at rest, not hashed, because
// verifying a code needs the secret back. That makes it unlike every other
// credential this package stores: a password hash and a session token hash
// are one-way, and this is not.
//
// So the database row is not the last line of defense it is elsewhere.
// Someone with a dump of `user_totp` and the key can generate valid codes
// for every enrolled account — which is why the key lives outside the
// database and why ADR-0013's reasoning about sealed evidence applies here
// too.
//
// # Why a separate key from EVIDENCE_KEY
//
// ADR-0013's key seals breach evidence and is held by the WORKER, which runs
// collectors against the internet. This one seals second factors and is held
// by the API. Sharing one key would mean a compromise of either process
// yielded both, and would tie the rotation of a customer-data key to the
// rotation of an authentication key. Same pattern, same documented KMS gap,
// different key.
const (
	// sealedPrefix marks a value as AES-GCM ciphertext. Greppable on
	// purpose: a reader without the key can tell "sealed" from "plaintext"
	// without attempting to decrypt, and a test can assert a column really
	// is ciphertext rather than hoping.
	sealedPrefix = "mfav1:"
)

// Sealing errors. Every decrypt failure collapses into ErrUnseal: telling a
// caller "wrong key" apart from "corrupt ciphertext" apart from "bad tag"
// hands out an oracle, and nothing here needs the distinction.
var (
	// ErrNoSealKey is returned when a sealer is built without a key.
	// Encryption of a second factor is not optional, so this is a wiring
	// error rather than a fallback to plaintext.
	ErrNoSealKey = errors.New("auth: no MFA secret key configured")

	// ErrSealKeySize is returned for a key that is not a valid AES length.
	ErrSealKeySize = errors.New("auth: the MFA secret key must be 16, 24 or 32 bytes (AES-128/192/256)")

	// ErrUnseal is returned whenever a sealed secret cannot be opened.
	ErrUnseal = errors.New("auth: cannot decrypt the stored MFA secret")
)

// Sealer encrypts and decrypts TOTP secrets for storage.
type Sealer struct {
	aead cipher.AEAD
}

// NewSealer builds a Sealer over a raw AES key.
func NewSealer(key []byte) (*Sealer, error) {
	switch len(key) {
	case 16, 24, 32:
	case 0:
		return nil, ErrNoSealKey
	default:
		return nil, ErrSealKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("auth: build cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("auth: build GCM: %w", err)
	}
	return &Sealer{aead: aead}, nil
}

// NewSealerFromHex builds a Sealer from a hex-encoded key, which is how the
// key arrives from configuration.
//
// Decoding here rather than passing the text through means an operator who
// pasted hex gets the key they generated: treating "00112233..." as 16 ASCII
// bytes would silently produce a different, weaker key than intended.
func NewSealerFromHex(hexKey string) (*Sealer, error) {
	trimmed := strings.TrimSpace(hexKey)
	if trimmed == "" {
		return nil, ErrNoSealKey
	}
	raw, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("auth: the MFA secret key must be hex: %w", err)
	}
	return NewSealer(raw)
}

// Seal encrypts a TOTP secret for storage.
//
// A fresh nonce per call, prepended to the ciphertext. Reusing a nonce under
// GCM is catastrophic — it leaks the XOR of the plaintexts and the
// authentication key — so it is generated here rather than derived from
// anything about the user, which is the mistake that makes nonce reuse look
// reasonable.
func (s *Sealer) Seal(secret string) (string, error) {
	if s == nil || s.aead == nil {
		return "", ErrNoSealKey
	}
	// One buffer holding the nonce followed by the ciphertext GCM writes
	// after it, so the concatenation below does not reallocate.
	n := s.aead.NonceSize()
	buf := make([]byte, n, n+len(secret)+s.aead.Overhead())
	if _, err := rand.Read(buf[:n]); err != nil {
		return "", fmt.Errorf("auth: generate nonce: %w", err)
	}
	sealed := s.aead.Seal(buf, buf[:n], []byte(secret), nil)
	return sealedPrefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// Open decrypts a stored TOTP secret.
func (s *Sealer) Open(sealed string) (string, error) {
	if s == nil || s.aead == nil {
		return "", ErrNoSealKey
	}
	if !strings.HasPrefix(sealed, sealedPrefix) {
		// A value with no marker is not a legacy plaintext to be trusted —
		// it is a row this build cannot account for. Refusing is the only
		// safe reading: accepting it would mean a secret written as
		// plaintext by a bug would keep working and never be noticed.
		return "", ErrUnseal
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(sealed, sealedPrefix))
	if err != nil {
		return "", ErrUnseal
	}
	if len(raw) < s.aead.NonceSize() {
		return "", ErrUnseal
	}
	nonce, ct := raw[:s.aead.NonceSize()], raw[s.aead.NonceSize():]
	pt, err := s.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", ErrUnseal
	}
	return string(pt), nil
}

// IsSealed reports whether a stored value carries the ciphertext marker. It
// is for tests and for an operator checking a column, not for control flow.
func IsSealed(v string) bool { return strings.HasPrefix(v, sealedPrefix) }
