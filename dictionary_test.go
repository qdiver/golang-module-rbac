package auth_test

import (
	"strings"
	"testing"
	"time"

	auth "github.com/qdiver/golang-module-rbac"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTheDictionaryIsActuallyLoaded. The list is embedded, so a mistyped
// //go:embed path or an empty file would make every dictionary check pass
// silently — a rule that is on, reports nothing, and protects nothing.
func TestTheDictionaryIsActuallyLoaded(t *testing.T) {
	t.Parallel()

	require.True(t, auth.InCommonPasswordList("password"),
		"the embedded word list is empty or did not load")
	require.True(t, auth.InCommonPasswordList("qwerty"))
	require.True(t, auth.InCommonPasswordList("123456"))
}

// TestNormalisationCatchesTheVariantsPeopleActuallyType. Each of these is
// the same word wearing whatever a composition rule demanded.
func TestNormalisationCatchesTheVariantsPeopleActuallyType(t *testing.T) {
	t.Parallel()

	for _, pw := range []string{
		"PASSWORD", "Password", "  password  ",
		"password1", "password123", "password!", "password123!!!",
		"P@ssword", "P@ssw0rd", "p455w0rd", "Pa55word!",
		// "1" read as "l": letmein, not ietmein.
		"1etmein", "1etmein!", "1etme1n",
		// "1" read as "i": admin, not admln.
		"adm1n", "Adm1n!", "@dm1n123",
		"qw3rty", "qwerty123!", "m0nkey", "Dr@g0n!",
	} {
		t.Run(pw, func(t *testing.T) {
			t.Parallel()
			assert.True(t, auth.InCommonPasswordList(pw), "%q was not recognized", pw)
		})
	}
}

// TestNormalisationDoesNotOverreach. Substitution can destroy a match as
// easily as reveal one, and a dictionary that refuses good passwords trains
// people to work around it.
func TestNormalisationDoesNotOverreach(t *testing.T) {
	t.Parallel()

	for _, pw := range []string{
		"Thicket-Vandal-Gorse", "pass401k-Ledger", "Quilt7Marrow", "zqx-plinth-9",
		"", "   ",
	} {
		t.Run(pw, func(t *testing.T) {
			t.Parallel()
			assert.False(t, auth.InCommonPasswordList(pw), "%q was refused", pw)
		})
	}
}

// TestKeyboardWalksAndRepeatsAreCovered. A raw frequency list
// under-represents these because they are spread across thousands of
// distinct strings; they are generated into the file instead.
func TestKeyboardWalksAndRepeatsAreCovered(t *testing.T) {
	t.Parallel()

	for _, pw := range []string{
		"qwertyuiop", "asdfgh", "zxcvbnm", "poiuytrewq",
		"aaaaaaaa", "9999999", "1234567890", "0987654321",
		"1987", "2026",
	} {
		t.Run(pw, func(t *testing.T) {
			t.Parallel()
			assert.True(t, auth.InCommonPasswordList(pw), "%q was not recognized", pw)
		})
	}
}

// TestMixedAmbiguousReadings. "1etme1n" uses "1" as an l and as an i in the
// same string; a uniform substitution table cannot see it, which is why the
// glyphs are expanded per occurrence.
func TestMixedAmbiguousReadings(t *testing.T) {
	t.Parallel()

	assert.True(t, auth.InCommonPasswordList("1etme1n"))
	assert.True(t, auth.InCommonPasswordList("1etme!n2026"))
}

// TestManyAmbiguousGlyphsStillCheckAndReturnPromptly.
//
// The expansion is exponential in the number of ambiguous glyphs, so it is
// capped. The failure mode is subtler than a hang: with the cap removed,
// `1 << 200` overflows to zero on a 64-bit int and the loop generates NO
// forms at all — the check returns false for everything, quietly, which is a
// rule that is switched on and protects nothing. So this asserts that a
// pathological input still produces a real answer, and quickly.
func TestManyAmbiguousGlyphsStillCheckAndReturnPromptly(t *testing.T) {
	t.Parallel()

	type result struct {
		common bool
	}
	done := make(chan result, 1)
	go func() {
		// Well past the cap, and still a common password under the uniform
		// fallback reading: the trailing run is filler, so the stem is
		// "1etmein" -> "letmein".
		done <- result{auth.InCommonPasswordList("1etmein" + strings.Repeat("!", 40))}
	}()

	select {
	case r := <-done:
		assert.True(t, r.common,
			"a password past the glyph cap was not checked at all; the expansion "+
				"produced no forms rather than falling back")
	case <-time.After(5 * time.Second):
		t.Fatal("the dictionary check did not return: the glyph expansion is unbounded")
	}
}

// TestTheDictionaryIsTheRealList guards against the file being truncated or
// replaced by a stub.
//
// The rule is only as good as the list behind it, and a list that quietly
// shrank would leave the check switched on and reporting nothing — the same
// silent-non-enforcement failure the embed test guards against, one level up.
func TestTheDictionaryIsTheRealList(t *testing.T) {
	t.Parallel()

	// Ten thousand is the floor the plan named (docs/proposals/auth-hardening.md
	// §C: "top ~10k-100k breached passwords").
	assert.Greater(t, auth.CommonPasswordCount(), 10_000,
		"the word list has shrunk below the size ADR-0029 claims")
}

// TestTheListCoversWhatAFrequencyListAloneWouldMiss.
//
// Two different sources, and each covers the other's blind spot. A leak-derived
// frequency list has what consumers chose; it does not have the vocabulary of
// default and operator accounts, because nobody leaks those from a shopping
// site. The generated families cover keyboard walks and repeats, which are
// spread too thinly across distinct strings to rank highly anywhere.
func TestTheListCoversWhatAFrequencyListAloneWouldMiss(t *testing.T) {
	t.Parallel()

	for _, pw := range []string{
		// From the breach compilation.
		"trustno1", "michael", "jennifer", "superman", "iloveyou",
		// From the curated operator vocabulary.
		"administrator", "changeme", "toor", "admin123",
		// From the generated families.
		"qwertyuiop", "poiuytrewq", "aaaaaaaa", "1987",
	} {
		t.Run(pw, func(t *testing.T) {
			t.Parallel()
			assert.True(t, auth.InCommonPasswordList(pw), "%q is not refused", pw)
		})
	}
}
