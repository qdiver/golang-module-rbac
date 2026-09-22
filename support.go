package auth

import "time"

// Clock abstracts wall-clock time so this package's use cases are
// deterministic under test.
type Clock interface {
	Now() time.Time
}

// IDGen abstracts ID generation so this package's use cases are
// deterministic under test.
type IDGen interface {
	NewID() string
}

// ErrNotFound is returned by any Store method when the requested row does
// not exist. Callers type-check against this rather than a store-specific
// sentinel so this package's own code stays independent of the concrete
// adapter.
var ErrNotFound = errNotFound{}

type errNotFound struct{}

func (errNotFound) Error() string { return "not found" }

// ErrConflict is returned when a write would violate a uniqueness
// constraint (e.g. creating a user with an email already in use).
var ErrConflict = errConflict{}

type errConflict struct{}

func (errConflict) Error() string { return "conflict" }
