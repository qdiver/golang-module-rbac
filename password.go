package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// ADR-0027 records password storage as this design's largest single
// liability — a product whose own rubric deducts for credential exposure is
// now holding credentials. These parameters are the mitigation, so they are
// stated rather than defaulted.
//
// argon2id, not bcrypt or PBKDF2: it is the only one of the three that
// resists GPU and ASIC attack by costing memory as well as time, which is
// the attack that matters for a stolen database dump.
//
// The cost is OWASP's second recommended profile (19 MiB, 2 passes,
// 1 degree of parallelism). Memory-hard is chosen over iteration-hard
// deliberately: doubling argon2Time doubles an attacker's work and ours
// equally, whereas doubling argon2Memory doubles their hardware cost
// superlinearly.
const (
	argon2Time    = 2
	argon2Memory  = 19 * 1024 // KiB
	argon2Threads = 1
	argon2KeyLen  = 32
	argon2SaltLen = 16

	// argon2MaxKeyLen bounds the digest length VerifyPassword will accept
	// from a stored hash. Nothing this package writes exceeds
	// argon2KeyLen; the ceiling exists for rows it did not write.
	argon2MaxKeyLen = 1024
)

// ErrInvalidHash is returned when a stored hash cannot be parsed — a
// truncated column, a value written by a different scheme, or a row that
// predates this format.
//
// It is deliberately distinct from a password simply not matching. A caller
// must never present the two the same way to a user (both are "login
// failed") while never conflating them in the logs (one is a wrong password,
// the other is a corrupt row that no password will ever satisfy).
var ErrInvalidHash = errors.New("auth: malformed password hash")

// HashPassword returns an encoded argon2id hash of the password, with a
// fresh random salt.
//
// The encoding is the standard PHC string — $argon2id$v=19$m=…,t=…,p=…$salt$hash
// — which carries the parameters alongside the digest. That is what makes
// the cost raisable later: VerifyPassword reads each hash's own parameters,
// so raising the constants above affects new and rehashed passwords without
// invalidating every existing one.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: read salt: %w", err)
	}
	sum := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argon2Memory, argon2Time, argon2Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(sum),
	), nil
}

// VerifyPassword reports whether password matches the encoded hash.
//
// Comparison is constant-time. The reasoning is the same one
// httpapi.RequireAPIKey already records for the shared key: a byte-by-byte
// comparison leaks the digest prefix through response timing, and it is a
// cheap mistake to avoid.
func VerifyPassword(encoded, password string) (bool, error) {
	params, salt, want, err := decodeHash(encoded)
	if err != nil {
		return false, err
	}
	// The key length is taken from the stored digest so that a hash written
	// at a different length still verifies. decodeHash has already rejected
	// an empty digest; this bound rejects an absurd one, which keeps the
	// conversion below provably in range and stops a corrupt row from
	// asking argon2 for a multi-gigabyte key.
	if len(want) > argon2MaxKeyLen {
		return false, ErrInvalidHash
	}
	// #nosec G115 -- len(want) is bounded above by argon2MaxKeyLen on the
	// line above and below by decodeHash's rejection of an empty digest, so
	// the conversion cannot overflow.
	got := argon2.IDKey([]byte(password), salt, params.time, params.memory, params.threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// hashParams are the cost parameters read back out of an encoded hash.
type hashParams struct {
	memory  uint32
	time    uint32
	threads uint8
}

// decodeHash parses the PHC string produced by HashPassword.
//
// Every failure returns ErrInvalidHash rather than a parse-specific error:
// the caller's only sane response to any of them is identical, and the
// detail would otherwise be tempting to put in an HTTP response.
func decodeHash(encoded string) (hashParams, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	// "", "argon2id", "v=19", "m=…,t=…,p=…", salt, hash
	if len(parts) != 6 || parts[1] != "argon2id" {
		return hashParams{}, nil, nil, ErrInvalidHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return hashParams{}, nil, nil, ErrInvalidHash
	}
	var p hashParams
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.time, &p.threads); err != nil {
		return hashParams{}, nil, nil, ErrInvalidHash
	}
	// A hash recording zero cost would verify instantly against anything the
	// attacker likes; reject it rather than honoring parameters that no
	// HashPassword ever wrote.
	if p.memory == 0 || p.time == 0 || p.threads == 0 {
		return hashParams{}, nil, nil, ErrInvalidHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) == 0 {
		return hashParams{}, nil, nil, ErrInvalidHash
	}
	sum, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(sum) == 0 {
		return hashParams{}, nil, nil, ErrInvalidHash
	}
	return p, salt, sum, nil
}

// NeedsRehash reports whether a stored hash was produced with weaker
// parameters than this build now uses.
//
// Raising the cost constants is only half a migration: existing rows keep
// their old parameters forever unless something notices. A successful login
// is the one moment the plaintext is in hand and a rehash is free, so the
// login path checks this and upgrades in place.
//
// A hash that cannot be parsed reports false. It needs replacing rather than
// rehashing, and no password will ever verify against it to trigger one.
func NeedsRehash(encoded string) bool {
	p, _, _, err := decodeHash(encoded)
	if err != nil {
		return false
	}
	return p.memory < argon2Memory || p.time < argon2Time
}
