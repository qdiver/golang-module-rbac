package auth

import (
	"bufio"
	_ "embed"
	"strings"
	"sync"
	"unicode"
)

// commonPasswords is the refused-word list, embedded the way the rubric YAML
// is: compiled into the binary, versioned with it, and needing no network at
// verification time.
//
// It deliberately does NOT reuse the mirrored breach corpora behind
// internal/infra/ipreputation and the infoleak collector. Those are
// customer-scoped findings data under ADR-0026's licensing questions, and
// borrowing them as an internal wordlist would extend that question into a
// place nobody agreed to.
//
//go:embed data/common-passwords.txt
var commonPasswords string

// dictionary is parsed once. The file is a few hundred lines today and a
// caller may check a password on any request, so the parse is not repeated.
var dictionary = sync.OnceValue(func() map[string]struct{} {
	set := make(map[string]struct{}, 1024)
	sc := bufio.NewScanner(strings.NewReader(commonPasswords))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		set[strings.ToLower(line)] = struct{}{}
	}
	return set
})

// unambiguousLeet undoes the substitutions with exactly one reading.
var unambiguousLeet = strings.NewReplacer(
	"4", "a", "@", "a",
	"3", "e",
	"0", "o",
	"5", "s", "$", "s",
	"7", "t", "+", "t",
	"8", "b",
	"9", "g",
)

// ambiguousLeet are the glyphs with two readings each, and the readings.
//
// "1" is "i" in "adm1n" and "l" in "1etmein". A single table has to pick
// one, which silently lets the other family through — and a password can use
// both readings at once, as "1etme1n" does. They are therefore expanded per
// occurrence rather than replaced wholesale.
var ambiguousLeet = map[byte][2]byte{
	'1': {'i', 'l'},
	'!': {'i', 'l'},
	'|': {'i', 'l'},
}

// maxAmbiguousGlyphs bounds the expansion at 2^6 forms.
//
// Beyond six the combinations grow faster than the value: a password with
// seven "1"s is not a dictionary word wearing a disguise. The uniform
// readings are still generated in that case, so nothing is lost outright.
const maxAmbiguousGlyphs = 6

// expandAmbiguous returns every reading of a string's ambiguous glyphs.
func expandAmbiguous(s string) []string {
	positions := make([]int, 0, maxAmbiguousGlyphs+1)
	for i := 0; i < len(s); i++ {
		if _, ok := ambiguousLeet[s[i]]; ok {
			positions = append(positions, i)
			if len(positions) > maxAmbiguousGlyphs {
				break
			}
		}
	}
	if len(positions) == 0 {
		return []string{s}
	}
	if len(positions) > maxAmbiguousGlyphs {
		// Too many to enumerate: fall back to the two uniform readings.
		out := make([]string, 0, 2)
		for _, r := range []byte{'i', 'l'} {
			b := []byte(s)
			for i := range b {
				if _, ok := ambiguousLeet[b[i]]; ok {
					b[i] = r
				}
			}
			out = append(out, string(b))
		}
		return out
	}

	out := make([]string, 0, 1<<len(positions))
	for mask := range 1 << len(positions) {
		b := []byte(s)
		for bit, pos := range positions {
			b[pos] = ambiguousLeet[s[pos]][(mask>>bit)&1]
		}
		out = append(out, string(b))
	}
	return out
}

// normalizations returns the forms of a candidate to look up.
//
// Each transformation destroys matches as readily as it reveals them, and
// they interact, so the forms are generated as a small product rather than a
// pipeline. Two failures the tests here found:
//
//   - Substitution and stripping must be applied in BOTH orders.
//     "Adm1n1strator!" needs the 1s turned into i's, but the trailing "!" is
//     filler rather than a letter, so substituting first yields
//     "administratori" and finds nothing; stripping first leaves
//     "adm1n1strator", which still needs the substitution.
//   - The ambiguous glyphs need per-occurrence readings, not one uniform
//     choice, because "1etme1n" uses both.
//
// Substitution alone is not safe either — it turns "pass401k" into
// "passaoik" — and stripping alone turns "2026" into nothing. So every form
// is checked and a match in any of them counts.
func normalizations(password string) []string {
	lower := strings.ToLower(strings.TrimSpace(password))
	if lower == "" {
		return nil
	}

	seen := make(map[string]struct{}, 32)
	forms := make([]string, 0, 32)
	add := func(s string) {
		if s == "" {
			return
		}
		if _, dup := seen[s]; dup {
			return
		}
		seen[s] = struct{}{}
		forms = append(forms, s)
	}

	for _, base := range []string{lower, stripTrailingFiller(lower)} {
		add(base)
		for _, replaced := range expandAmbiguous(unambiguousLeet.Replace(base)) {
			add(replaced)
			add(stripTrailingFiller(replaced))
		}
	}
	return forms
}

// stripTrailingFiller removes the digits and punctuation people append to
// get past a composition rule, so "password123!" is looked up as "password".
//
// Only the trailing run is removed, and only when something is left. A
// password that is entirely digits stays itself, which is what lets the year
// and repeated-digit entries in the list match at all.
func stripTrailingFiller(s string) string {
	end := len(s)
	for end > 0 {
		r := rune(s[end-1])
		if unicode.IsDigit(r) || unicode.IsPunct(r) || unicode.IsSymbol(r) {
			end--
			continue
		}
		break
	}
	if end == 0 {
		return s
	}
	return s[:end]
}

// CommonPasswordCount is how many entries the embedded list holds.
//
// Exported for the test that guards against the file being truncated or
// stubbed: a list that quietly shrank would leave the rule switched on and
// catching nothing, which is the failure this package is most concerned with
// elsewhere too.
func CommonPasswordCount() int { return len(dictionary()) }

// InCommonPasswordList reports whether a candidate is a known common
// password, in any of its normalised forms.
func InCommonPasswordList(password string) bool {
	set := dictionary()
	for _, form := range normalizations(password) {
		if _, found := set[form]; found {
			return true
		}
	}
	return false
}

// containsPersonalDetail reports whether the password contains a
// recognizable piece of the account's own identity.
//
// NIST recommends this where a composition rule is not recommended at all:
// an attacker targeting one person starts from their name and their email
// address, so "eugene2026" is weak in a way no character-class rule notices.
//
// Matching is on normalised forms and on fragments of at least four
// characters, so a two-letter name or a common word inside a domain does not
// refuse every password an organisation's staff can think of.
func containsPersonalDetail(password string, details []string) bool {
	forms := normalizations(password)
	for _, d := range details {
		for _, frag := range personalFragments(d) {
			for _, form := range forms {
				if strings.Contains(form, frag) {
					return true
				}
			}
		}
	}
	return false
}

// personalFragments splits an identity detail into the pieces worth matching:
// the words of a name, and the local part and labels of an email address,
// each at least four characters.
func personalFragments(detail string) []string {
	detail = strings.ToLower(strings.TrimSpace(detail))
	if detail == "" {
		return nil
	}
	// Everything that separates words in a name, an email or a domain.
	parts := strings.FieldsFunc(detail, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})

	out := make([]string, 0, len(parts))
	for _, p := range parts {
		// Four is the floor: shorter fragments ("com", "ltd", "de") appear
		// inside ordinary words and would refuse passwords for no reason.
		if len(p) < 4 {
			continue
		}
		// Public suffixes and the words every corporate domain contains are
		// not personal: refusing any password containing "mail" because the
		// address is at gmail.com would be indefensible.
		if _, generic := genericDomainWords[p]; generic {
			continue
		}
		out = append(out, p)
	}
	return out
}

// genericDomainWords are the fragments that appear in a large share of email
// addresses and say nothing about the person holding one.
var genericDomainWords = map[string]struct{}{
	"mail": {}, "email": {}, "gmail": {}, "yahoo": {}, "hotmail": {},
	"outlook": {}, "live": {}, "icloud": {}, "proton": {}, "protonmail": {},
	"com": {}, "net": {}, "org": {}, "co": {}, "io": {}, "inc": {}, "ltd": {},
	"corp": {}, "group": {}, "holdings": {},
}
