package auth_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	auth "github.com/qdiver/golang-module-rbac"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rulesOf extracts the rules a check failed on, so a test names the
// requirement rather than matching on a sentence that may be reworded.
func rulesOf(t *testing.T, err error) []auth.PolicyRule {
	t.Helper()
	var pe *auth.PolicyError
	require.ErrorAs(t, err, &pe, "not a policy error: %v", err)
	out := make([]auth.PolicyRule, 0, len(pe.Violations))
	for _, v := range pe.Violations {
		out = append(out, v.Rule)
	}
	return out
}

func TestDefaultPolicyIsValidAndFollowsTheDecisions(t *testing.T) {
	t.Parallel()

	p := auth.DefaultPolicy("org-1")
	require.NoError(t, p.Validate())

	// Decision 5: rotation off by default, following NIST, so a sole
	// administrator is not locked out on day 366.
	assert.Zero(t, p.MaxAgeDays, "rotation is on by default, against decision 5")
	// Composition on, because it was asked for.
	assert.True(t, p.RequireUpper)
	assert.True(t, p.RequireLower)
	assert.True(t, p.RequireDigit)
	assert.True(t, p.RequireSymbol)
	assert.True(t, p.CheckDictionary)
	assert.Equal(t, auth.MinPasswordLen, p.MinLength)
}

// TestPolicyErrorSatisfiesErrWeakPassword keeps every existing caller
// working. auth.Admin's handlers already map ErrWeakPassword to a 422, and a
// new error type that did not match would turn a weak password into a 500.
func TestPolicyErrorSatisfiesErrWeakPassword(t *testing.T) {
	t.Parallel()

	err := auth.DefaultPolicy("org-1").Check("short")
	require.Error(t, err)
	assert.True(t, errors.Is(err, auth.ErrWeakPassword),
		"a policy failure is not recognized as a weak password")
}

// TestCheckReportsEveryFailureAtOnce. A form that refuses a password for its
// missing digit, then its missing symbol, then its length, teaches people to
// guess one rule at a time.
func TestCheckReportsEveryFailureAtOnce(t *testing.T) {
	t.Parallel()

	err := auth.DefaultPolicy("org-1").Check("abc")
	assert.ElementsMatch(t,
		[]auth.PolicyRule{auth.RuleMinLength, auth.RuleUppercase, auth.RuleDigit, auth.RuleSymbol},
		rulesOf(t, err))
}

func TestCheckAcceptsAPasswordThatMeetsEveryRule(t *testing.T) {
	t.Parallel()
	require.NoError(t, auth.DefaultPolicy("org-1").Check("Tr0ubadour&Vex!"))
}

// TestAPassphraseIsAcceptedWithoutPunctuation. A space counts as a symbol,
// deliberately: passphrases are the strongest thing people actually choose,
// and refusing one for lacking punctuation pushes them back to Password1!.
func TestAPassphraseIsAcceptedWithoutPunctuation(t *testing.T) {
	t.Parallel()
	require.NoError(t, auth.DefaultPolicy("org-1").Check("Vexing Zebra Quilt 7"))
}

// TestCompositionRulesDoNotCancelTheDictionaryOut is the point of the whole
// design. "Password1!" satisfies upper, lower, digit and symbol, and is one
// of the most common passwords in existence. A policy that accepted it would
// be worse than no policy, because it would look like one.
func TestCompositionRulesDoNotCancelTheDictionaryOut(t *testing.T) {
	t.Parallel()

	p := auth.DefaultPolicy("org-1")
	for _, pw := range []string{
		"Password1!", "P@ssw0rd123", "Passw0rd!2024", "Letmein123!", "Qwerty123456!",
		"Monkey123!!", "Welcome@2026", "Adm1n1strator!", "Sunshine123!",
		// The whole "!" and "1" family, which is where the normaliser's two
		// substitution orders earn their keep.
		"1etmein!2026", "Qw3rtyu1op!", "Dr@gon1234!",
	} {
		t.Run(pw, func(t *testing.T) {
			t.Parallel()
			assert.Contains(t, rulesOf(t, p.Check(pw)), auth.RuleDictionary,
				"%q passed the dictionary rule", pw)
		})
	}
}

// TestDictionaryDoesNotRefuseAStrongPassword. A dictionary that refuses good
// passwords trains people to work around it, which is worse than not having
// one.
func TestDictionaryDoesNotRefuseAStrongPassword(t *testing.T) {
	t.Parallel()

	p := auth.DefaultPolicy("org-1")
	for _, pw := range []string{
		"Thicket-Vandal-9-Gorse", "qT7!vbnMxwzZ", "Plinth Marrow Kestrel 4",
		"Zw9$kdmRpxTv", "unsalted-BRIDGE-42!",
	} {
		t.Run(pw, func(t *testing.T) {
			t.Parallel()
			assert.NoError(t, p.Check(pw), "%q was refused", pw)
		})
	}
}

// TestPersonalDetailsAreRefused: an attacker targeting one person starts
// from their name and address, and no character-class rule notices.
func TestPersonalDetailsAreRefused(t *testing.T) {
	t.Parallel()

	p := auth.DefaultPolicy("org-1")
	personal := []string{"eugene.yeo@convergeict.com", "Eugene Yeo", "Converge ICT"}

	for _, pw := range []string{"Eugene2026!", "Vex-eugene-9!", "Convergeict#1"} {
		t.Run(pw, func(t *testing.T) {
			t.Parallel()
			assert.Contains(t, rulesOf(t, p.Check(pw, personal...)), auth.RulePersonal,
				"%q was accepted despite containing a personal detail", pw)
		})
	}
}

// TestGenericDomainWordsAreNotPersonal. Refusing every password containing
// "mail" because the address is at gmail.com would be indefensible, and
// short fragments appear inside ordinary words.
func TestGenericDomainWordsAreNotPersonal(t *testing.T) {
	t.Parallel()

	p := auth.DefaultPolicy("org-1")
	personal := []string{"jo.li@gmail.com", "Jo Li", "Acme Co"}

	// "mail" and "com" come from the address; "jo" and "li" are under the
	// four-character floor, which is why a short name cannot refuse every
	// password in an organization.
	require.NoError(t, p.Check("Blackmail-Hedge-7!", personal...))
	require.NoError(t, p.Check("Jolt Combine 9 Rye", personal...))
}

func TestMinLengthIsCountedInRunesNotBytes(t *testing.T) {
	t.Parallel()

	// Twelve characters, each three bytes. Measuring bytes would let this
	// pass a much longer minimum, and measuring bytes on a Latin password
	// would refuse one that is long enough.
	p := auth.Policy{OrgID: "o", MinLength: 12}
	require.NoError(t, p.Check("日本語日本語日本語日本語"))
	assert.Contains(t, rulesOf(t, p.Check("日本語日本語")), auth.RuleMinLength)
}

// TestOverlongPasswordsAreRefusedBeforeAnyWork. argon2id costs 19 MiB a
// call; an unbounded password on an unauthenticated endpoint is a way to
// make the server do arbitrary work.
func TestOverlongPasswordsAreRefusedBeforeAnyWork(t *testing.T) {
	t.Parallel()

	err := auth.DefaultPolicy("org-1").Check(strings.Repeat("a", auth.MaxPasswordLen+1))
	assert.Equal(t, []auth.PolicyRule{auth.RuleMaxRuneCount}, rulesOf(t, err),
		"an overlong password was walked by the other rules instead of refused outright")
}

func TestValidateRejectsAPolicyThatRemovesTheFloor(t *testing.T) {
	t.Parallel()

	base := auth.DefaultPolicy("org-1")

	weak := base
	weak.MinLength = 4
	require.ErrorContains(t, weak.Validate(), "may not be below")

	long := base
	long.MinLength = auth.PolicyMinLengthCeiling + 1
	require.Error(t, long.Validate())

	deep := base
	deep.HistoryDepth = auth.PolicyMaxHistoryDepth + 1
	require.ErrorContains(t, deep.Validate(), "history depth")

	negative := base
	negative.HistoryDepth = -1
	require.Error(t, negative.Validate())

	old := base
	old.MaxAgeDays = auth.PolicyMaxAgeDaysCeiling + 1
	require.ErrorContains(t, old.Validate(), "maximum age")
}

func TestRotation(t *testing.T) {
	t.Parallel()

	changed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	off := auth.DefaultPolicy("org-1")
	_, expires := off.ExpiresAt(changed)
	assert.False(t, expires, "rotation is on when MaxAgeDays is zero")
	assert.False(t, off.IsExpired(changed, changed.AddDate(10, 0, 0)),
		"a password expired under a policy with rotation off")

	on := off
	on.MaxAgeDays = 365
	at, expires := on.ExpiresAt(changed)
	require.True(t, expires)
	assert.Equal(t, changed.AddDate(0, 0, 365), at)

	assert.False(t, on.IsExpired(changed, at.Add(-time.Second)), "expired a second early")
	assert.True(t, on.IsExpired(changed, at), "not expired at the boundary")
	assert.True(t, on.IsExpired(changed, at.Add(time.Hour)))

	// A user row with no recorded change date must not be treated as
	// expired: every account predating this migration has one, and
	// expiring them all at once would lock out every user of an upgraded
	// deployment simultaneously.
	assert.False(t, on.IsExpired(time.Time{}, changed.AddDate(5, 0, 0)),
		"an account with no recorded change date was expired")
}
