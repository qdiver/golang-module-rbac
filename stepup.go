package auth

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// StepUpWindow is how long a re-verification counts for.
//
// Ten minutes: long enough to read the audit log, filter it and export it
// without being asked again mid-task, and short enough that a machine left
// unlocked after someone walks away is not a standing grant. It is a window
// rather than a flag precisely so that walking away ends it.
const StepUpWindow = 10 * time.Minute

// ErrStepUpRequired is returned when an operation needs a re-verification the
// session does not have. It is distinct from ErrNotPermitted: the caller's
// role IS sufficient, and they can fix this by proving themselves again —
// telling them "forbidden" would send them asking for a permission they
// already hold.
var ErrStepUpRequired = errors.New("auth: this action needs you to confirm it is still you")

// ErrStepUpNeedsPasskey is returned when a secret was sent for an account
// whose only second factor is a security key.
//
// It is NOT "wrong password". The password may be perfectly correct and is
// still not the right proof: an account carrying a second factor has said
// the password alone is not enough for it, and step-up is not the place to
// disagree. Before this existed the path fell through to VerifyFactor, which
// answered ErrMFANotEnrolled, which nothing mapped — so a correct password
// came back as a 500.
var ErrStepUpNeedsPasskey = errors.New("auth: this account confirms with its security key")

// SteppedUp reports whether an identity was re-verified recently enough.
//
// A zero timestamp means never, which is the state of every session that has
// not stepped up — including every session that existed before this feature
// did. Fail closed is the only safe reading here: the alternative would grant
// the audit log to every live session on the deployment at the moment this
// shipped.
func (i Identity) SteppedUp(now time.Time) bool {
	if i.SteppedUpAt.IsZero() {
		return false
	}
	return now.Sub(i.SteppedUpAt) < StepUpWindow
}

// StepUpStore is the persistence step-up needs.
type StepUpStore interface {
	// StampStepUp records a re-verification against ONE session.
	StampStepUp(ctx context.Context, sessionID string, at time.Time) error
}

// StepUp re-verifies the caller and marks their session.
//
// # What counts as proof
//
// A second factor when the account has one, and the password when it does
// not. Both are "prove it is still you"; which one is available depends on
// what the account carries, and demanding a factor from an account with none
// would make the audit log unreachable on a deployment that has not enabled
// MFA — a control nobody can use is not a control.
//
// The password is deliberately accepted for an account WITHOUT a factor and
// deliberately not for one WITH: an account that has a second factor is
// saying the password alone is not enough for it, and step-up must not be the
// one place that disagrees.
//
// # Why it stamps the session and not the user
//
// A second factor satisfied in one browser must not unlock the audit log in
// another. That is the whole difference between step-up and simply checking
// enrolment, and it is why a stolen cookie does not inherit somebody else's
// re-verification.
func (a *Authenticator) StepUp(ctx context.Context, actor Identity, secret string) error {
	if actor.UserID == "" || actor.SessionID == "" {
		// An API key has no session to stamp. That is not an oversight: a
		// key is a standing credential with no human at the other end, and
		// "confirm it is still you" has no meaning for one.
		return ErrStepUpRequired
	}
	if a.steps == nil {
		return errors.New("auth: this deployment cannot record a step-up")
	}

	switch {
	case a.factor != nil && a.factor.HasAnyFactorOtherThanPasskeys(ctx, actor.UserID):
		// A code this method can actually check.
		if _, err := a.factor.VerifyFactor(ctx, actor.UserID, secret); err != nil {
			return err
		}
	case a.factor != nil && a.factor.RequiresSecondFactor(ctx, actor.UserID):
		// A factor exists but it is a security key, which no secret can
		// stand in for. Say so plainly; the caller's next move is the
		// ceremony, not another guess at the box in front of them.
		return ErrStepUpNeedsPasskey
	default:
		if err := a.verifyPasswordFor(ctx, actor.UserID, secret); err != nil {
			return err
		}
	}

	if err := a.steps.StampStepUp(ctx, actor.SessionID, a.clock.Now()); err != nil {
		return fmt.Errorf("auth: record step-up: %w", err)
	}
	return nil
}

// BeginStepUpWithPasskey starts a step-up ceremony for the caller's own
// account.
//
// The account comes from the session, never from the request: a caller able
// to name the account would be a caller able to start a ceremony on
// somebody else's behalf.
func (a *Authenticator) BeginStepUpWithPasskey(ctx context.Context, actor Identity) (Ceremony, error) {
	if actor.UserID == "" || actor.SessionID == "" {
		return Ceremony{}, ErrStepUpRequired
	}
	if a.passkeys == nil {
		return Ceremony{}, ErrWebAuthnUnavailable
	}
	return a.passkeys.BeginStepUp(ctx, actor.UserID)
}

// CompleteStepUpWithPasskey verifies the assertion and stamps the session.
//
// It stamps the SESSION, like the secret path does and for the same reason:
// a key touched in one browser must not unlock a privileged view in another.
func (a *Authenticator) CompleteStepUpWithPasskey(
	ctx context.Context, actor Identity, challengeID string, response []byte,
) error {
	if actor.UserID == "" || actor.SessionID == "" {
		return ErrStepUpRequired
	}
	if a.passkeys == nil {
		return ErrWebAuthnUnavailable
	}
	if a.steps == nil {
		return errors.New("auth: this deployment cannot record a step-up")
	}

	if err := a.passkeys.FinishStepUp(ctx, actor.UserID, challengeID, response); err != nil {
		return err
	}
	if err := a.steps.StampStepUp(ctx, actor.SessionID, a.clock.Now()); err != nil {
		return fmt.Errorf("auth: record step-up: %w", err)
	}
	return nil
}

// verifyPasswordFor checks a password for an account, for the step-up path of
// an account with no second factor.
func (a *Authenticator) verifyPasswordFor(ctx context.Context, userID, password string) error {
	u, err := a.store.UserByID(ctx, userID)
	if err != nil {
		return err
	}
	if u.PasswordHash == "" || u.Disabled {
		return ErrInvalidCredentials
	}
	ok, err := VerifyPassword(u.PasswordHash, password)
	if err != nil {
		return fmt.Errorf("auth: verify password: %w", err)
	}
	if !ok {
		return ErrInvalidCredentials
	}
	return nil
}

// StepUpMethod says what a caller must present to step up, so a client can
// render the right prompt instead of guessing.
type StepUpMethod string

const (
	// StepUpFactor means a TOTP or recovery code.
	StepUpFactor StepUpMethod = "second_factor"

	// StepUpPassword means the account password, for an account with no
	// second factor.
	StepUpPassword StepUpMethod = "password"

	// StepUpPasskey means a security-key ceremony, for an account whose only
	// second factor is a key. A client that rendered a code box for one of
	// these would be asking for something the account cannot produce.
	StepUpPasskey StepUpMethod = "passkey"
)

// StepUpMethodFor reports what this account must present.
//
// It discloses whether the caller has a second factor — to the caller, about
// their own account, which they already know.
func (a *Authenticator) StepUpMethodFor(ctx context.Context, actor Identity) StepUpMethod {
	if a.factor == nil || actor.UserID == "" {
		return StepUpPassword
	}
	switch {
	// An authenticator app first when the account has both: a code is
	// quicker to produce than finding a key, and the key remains available
	// to anyone who prefers it.
	case a.factor.HasAnyFactorOtherThanPasskeys(ctx, actor.UserID):
		return StepUpFactor
	case a.factor.RequiresSecondFactor(ctx, actor.UserID):
		return StepUpPasskey
	default:
		return StepUpPassword
	}
}
