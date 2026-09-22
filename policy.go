package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
)

// PolicyRule names one requirement, so a caller can react to a specific
// failure rather than parsing a sentence.
type PolicyRule string

// The rules a password can fail. Values are stable strings: they cross the
// API boundary so a client can react to a specific rule rather than parsing
// a sentence.
const (
	RuleMinLength    PolicyRule = "min_length"
	RuleUppercase    PolicyRule = "require_upper"
	RuleLowercase    PolicyRule = "require_lower"
	RuleDigit        PolicyRule = "require_digit"
	RuleSymbol       PolicyRule = "require_symbol"
	RuleDictionary   PolicyRule = "dictionary"
	RulePersonal     PolicyRule = "personal_detail"
	RuleReuse        PolicyRule = "history"
	RuleMaxRuneCount PolicyRule = "max_length"
)

// Violation is one unmet requirement, with a sentence for the person typing.
type Violation struct {
	Rule    PolicyRule
	Message string
}

// PolicyError carries every violation at once.
//
// All of them, not the first: a form that rejects a password for its missing
// digit, then for its missing symbol, then for its length, teaches people to
// guess. It also costs nothing — every cheap rule has already been evaluated
// by the time one fails.
type PolicyError struct {
	Violations []Violation
}

func (e *PolicyError) Error() string {
	parts := make([]string, 0, len(e.Violations))
	for _, v := range e.Violations {
		parts = append(parts, v.Message)
	}
	return "auth: the password does not meet this organization's policy: " + strings.Join(parts, "; ")
}

// Is makes errors.Is(err, ErrWeakPassword) true for any policy failure, so
// every existing caller that already handles a weak password keeps working
// without knowing this type exists.
func (e *PolicyError) Is(target error) bool { return target == ErrWeakPassword }

// MaxPasswordLen is the ceiling on what will be hashed.
//
// Not a strength rule — a longer password is a better one. It is a denial-of-
// service bound: argon2id at these parameters costs 19 MiB per call, and an
// unbounded input on an unauthenticated endpoint is a way to make the server
// do arbitrary work. OWASP's guidance is to cap well above any real password.
const MaxPasswordLen = 256

// Policy is one organization's password requirements.
//
// It lives in a table rather than the environment, which is a deliberate
// departure from ADR-0009 recorded in ADR-0029: an administrator edits it at
// runtime, it differs per organization, and it is not an operator's
// deployment concern.
type Policy struct {
	OrgID string

	MinLength     int
	RequireUpper  bool
	RequireLower  bool
	RequireDigit  bool
	RequireSymbol bool

	// MaxAgeDays forces a change after this many days. Zero is off, and is
	// the shipped default.
	//
	// NIST SP 800-63B recommends against periodic rotation without evidence
	// of compromise, on the finding that it produces Password1 -> Password2.
	// The capability exists because an auditor or a customer contract may
	// require it; the default follows the guidance. Decision 5.
	MaxAgeDays int

	// HistoryDepth is how many previous passwords may not be reused. Zero
	// is off. Each one costs an argon2id comparison, so it is bounded.
	HistoryDepth int

	CheckDictionary bool

	UpdatedAt time.Time
	UpdatedBy string
}

// Policy bounds. These are limits on what an administrator may configure,
// not on what a password may be.
const (
	// A policy may not be set below the floor the product has always
	// enforced. An administrator lowering the minimum to 4 is not
	// configuring a policy, they are removing one, and the last account to
	// benefit would be whoever compromised the admin account.
	PolicyMinLengthFloor = MinPasswordLen

	// A minimum longer than this cannot be satisfied by any password this
	// product will hash, so accepting it would lock the organization out
	// with a valid-looking configuration.
	PolicyMinLengthCeiling = 64

	// Each unit of depth is an argon2id comparison on the request path:
	// 10 x 19 MiB x 2 passes is already a tenth of a second of pure CPU.
	PolicyMaxHistoryDepth = 10

	// Ten years. Beyond this the setting is indistinguishable from off, and
	// a typo of 36500 for 365 should not silently mean "never".
	PolicyMaxAgeDaysCeiling = 3650
)

// DefaultPolicy is what an organization gets before anybody edits one.
//
// The composition rules are ON because they were asked for, and rotation is
// OFF because it was not — decisions 5 and 6. That split is not an accident
// of taste: composition rules are a weak control that a customer's auditor
// routinely demands, whereas rotation actively degrades password quality and
// would, on a single-administrator deployment, be the thing that locks the
// only admin out on day 366.
func DefaultPolicy(orgID string) Policy {
	return Policy{
		OrgID:           orgID,
		MinLength:       MinPasswordLen,
		RequireUpper:    true,
		RequireLower:    true,
		RequireDigit:    true,
		RequireSymbol:   true,
		MaxAgeDays:      0,
		HistoryDepth:    5,
		CheckDictionary: true,
	}
}

// Validate rejects a policy an administrator should not be able to save.
func (p Policy) Validate() error {
	switch {
	case p.MinLength < PolicyMinLengthFloor:
		return fmt.Errorf("auth: the minimum length may not be below %d, the floor this product enforces",
			PolicyMinLengthFloor)
	case p.MinLength > PolicyMinLengthCeiling:
		return fmt.Errorf("auth: a minimum length above %d could not be satisfied", PolicyMinLengthCeiling)
	case p.HistoryDepth < 0 || p.HistoryDepth > PolicyMaxHistoryDepth:
		return fmt.Errorf("auth: the history depth must be between 0 and %d", PolicyMaxHistoryDepth)
	case p.MaxAgeDays < 0 || p.MaxAgeDays > PolicyMaxAgeDaysCeiling:
		return fmt.Errorf("auth: the maximum age must be between 0 (off) and %d days", PolicyMaxAgeDaysCeiling)
	}
	return nil
}

// Check applies every rule that does not need the database.
//
// History is deliberately absent: it costs an argon2id comparison per stored
// hash, and doing it here would pay that price for a password that is about
// to be refused for being eight characters long. auth.Admin runs it after
// this returns nil.
//
// personal is the account's own identity — email, name, organization — which
// an attacker targeting one person starts from.
func (p Policy) Check(password string, personal ...string) error {
	var vs []Violation

	// Counted in runes, not bytes. A password of twelve non-ASCII
	// characters is twelve characters; measuring bytes would silently
	// reward one alphabet over another.
	n := len([]rune(password))
	if n < p.MinLength {
		vs = append(vs, Violation{RuleMinLength,
			fmt.Sprintf("it must be at least %d characters long", p.MinLength)})
	}
	if n > MaxPasswordLen {
		vs = append(vs, Violation{RuleMaxRuneCount,
			fmt.Sprintf("it must be no more than %d characters long", MaxPasswordLen)})
		// Returned early: the rules below walk the string, and this is the
		// bound that exists to stop unbounded work.
		return &PolicyError{Violations: vs}
	}

	var hasUpper, hasLower, hasDigit, hasSymbol bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r), unicode.IsSymbol(r), unicode.IsSpace(r):
			// A space counts as a symbol. Passphrases are the strongest
			// thing a person actually chooses, and refusing "correct horse
			// battery staple" for lacking punctuation would push them back
			// to Password1!.
			hasSymbol = true
		}
	}

	if p.RequireUpper && !hasUpper {
		vs = append(vs, Violation{RuleUppercase, "it must contain an uppercase letter"})
	}
	if p.RequireLower && !hasLower {
		vs = append(vs, Violation{RuleLowercase, "it must contain a lowercase letter"})
	}
	if p.RequireDigit && !hasDigit {
		vs = append(vs, Violation{RuleDigit, "it must contain a digit"})
	}
	if p.RequireSymbol && !hasSymbol {
		vs = append(vs, Violation{RuleSymbol, "it must contain a symbol or a space"})
	}

	if p.CheckDictionary && InCommonPasswordList(password) {
		vs = append(vs, Violation{RuleDictionary,
			"it is one of the most commonly used passwords, or a small variation of one"})
	}
	if containsPersonalDetail(password, personal) {
		vs = append(vs, Violation{RulePersonal,
			"it must not contain your name, email address or organization"})
	}

	if len(vs) == 0 {
		return nil
	}
	return &PolicyError{Violations: vs}
}

// PolicyStore is the persistence the policy rules need.
//
// It is separate from AdminStore rather than folded into it because the two
// have different lifetimes in this design: AdminStore is the account CRUD
// that has existed since ADR-0027, and this arrived with ADR-0029. Keeping
// them apart means an Admin built without a policy store still works — it
// falls back to the product defaults — so a process wired before this
// existed does not start refusing every password change.
type PolicyStore interface {
	// PolicyForOrg returns an organization's policy. A missing row is not an
	// error: it means the product defaults, which is the state every
	// organization is in until somebody edits one.
	PolicyForOrg(ctx context.Context, orgID string) (Policy, error)

	// SavePolicy writes an organization's policy.
	SavePolicy(ctx context.Context, p Policy) error

	// RecentPasswordHashes returns a user's previous hashes, newest first.
	RecentPasswordHashes(ctx context.Context, userID string, limit int) ([]string, error)

	// RecordPasswordChange files the outgoing hash, trims history to depth,
	// and stamps when the new password was set.
	RecordPasswordChange(ctx context.Context, userID, previousHash, historyID string, at time.Time, depth int) error
}

// ErrNoPolicyStore is returned when a policy write is attempted on a process
// wired without a policy store.
//
// It is a distinct error because it is a deployment fault, not a bad request:
// answering 422 would tell an administrator their perfectly valid policy was
// rejected, and send them editing values until they gave up.
var ErrNoPolicyStore = errors.New("auth: this deployment has no password policy store wired")

// ErrPasswordExpired is returned when a password is past the policy's
// maximum age. It is deliberately distinct from a wrong password: the
// credential is correct, and the caller must be sent to a change form rather
// than told their password is wrong.
var ErrPasswordExpired = errors.New("auth: the password has expired and must be changed")

// ExpiresAt returns when a password set at changedAt must be changed, and
// whether it expires at all.
func (p Policy) ExpiresAt(changedAt time.Time) (time.Time, bool) {
	if p.MaxAgeDays <= 0 || changedAt.IsZero() {
		return time.Time{}, false
	}
	return changedAt.AddDate(0, 0, p.MaxAgeDays), true
}

// IsExpired reports whether a password set at changedAt is past its maximum
// age as of now.
func (p Policy) IsExpired(changedAt, now time.Time) bool {
	at, ok := p.ExpiresAt(changedAt)
	return ok && !now.Before(at)
}
