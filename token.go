package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Token sizes and the prefix an API key wears.
const (
	// tokenBytes is the entropy in a session token or API key. 256 bits is
	// past any brute-force argument and costs nothing — these are generated
	// and stored by machines, never typed.
	tokenBytes = 32

	// APIKeyPrefix marks a string as this product's API key.
	//
	// It is not a security control; it is a recognisability control. Secret
	// scanners key on fixed prefixes, so a key pasted into a commit, an
	// issue or a CI log can be spotted and revoked — which matters
	// especially for a product that itself reports leaked credentials.
	APIKeyPrefix = "sa_key_"
)

// ErrMalformedToken is returned when a presented credential is not shaped
// like one this package issues.
//
// Callers must answer it exactly as they answer a token that is simply
// unknown. Distinguishing "not a valid key format" from "valid format,
// no such key" in a response tells an attacker when they have the shape
// right, which is the one useful signal available to them.
var ErrMalformedToken = errors.New("auth: malformed token")

// NewSessionToken returns a fresh session token and the hash to store.
//
// The plaintext is returned once, to be written into a cookie, and never
// persisted: migration 0010 stores only the hash so that a database backup
// or a stray SELECT is not enough to impersonate anyone.
func NewSessionToken() (token string, hash []byte, err error) {
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("auth: read token entropy: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	return token, HashToken(token), nil
}

// NewAPIKey returns a fresh API key and the hash to store.
//
// Same one-shot contract as NewSessionToken: this is the only moment the
// plaintext exists, so a caller that fails to show it to the user has lost
// it, and the user mints another.
func NewAPIKey() (key string, hash []byte, err error) {
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("auth: read key entropy: %w", err)
	}
	key = APIKeyPrefix + base64.RawURLEncoding.EncodeToString(raw)
	return key, HashToken(key), nil
}

// HashToken returns the SHA-256 of a bearer credential, for storage and
// lookup.
//
// Plain SHA-256, not argon2 — which would be wrong here in both directions.
// These tokens are 256 bits of machine-generated randomness, so there is no
// guessable input for a slow hash to defend; and paying argon2's ~19 MiB
// and two passes on every single API request would be a self-inflicted rate
// limit on the whole API. A slow hash protects low-entropy secrets. It is
// the right choice in password.go and the wrong one here.
//
// Lookup is by hash equality on a UNIQUE index, so the database finds the
// row directly rather than scanning candidates — which is also why a
// per-token salt would be actively harmful: it would make lookup a table
// scan and buy nothing against a preimage of 256 random bits.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// ParseAPIKey validates an API key's shape and returns its storage hash.
//
// Shape is checked before the database is touched so that a malformed header
// — the common case when something is misconfigured — costs a string
// comparison rather than a query, and so a flood of them cannot be used to
// load the sessions table.
func ParseAPIKey(key string) ([]byte, error) {
	if !strings.HasPrefix(key, APIKeyPrefix) {
		return nil, ErrMalformedToken
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(key, APIKeyPrefix))
	if err != nil || len(raw) != tokenBytes {
		return nil, ErrMalformedToken
	}
	return HashToken(key), nil
}

// ParseSessionToken validates a session token's shape and returns its
// storage hash. See ParseAPIKey for why shape is checked first.
func ParseSessionToken(token string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != tokenBytes {
		return nil, ErrMalformedToken
	}
	return HashToken(token), nil
}
