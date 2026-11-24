// Package apperr defines the errors domain services return to describe
// *why* a request cannot be fulfilled, independently of HTTP. The API layer
// maps each Kind to a status code; anything else is an internal error.
package apperr

import (
	"errors"
	"fmt"
)

// Kind classifies an error for the caller.
type Kind int

// The error kinds.
const (
	// KindInvalid means the input failed validation (400).
	KindInvalid Kind = iota + 1
	// KindUnauthenticated means no valid credentials were presented (401).
	KindUnauthenticated
	// KindForbidden means the caller may see the resource but not do this (403).
	KindForbidden
	// KindNotFound means the resource does not exist *for this caller* (404).
	KindNotFound
	// KindConflict means the request clashes with current state (409).
	KindConflict
	// KindRateLimited means the caller must slow down (429).
	KindRateLimited
)

// Error is a classified error with a stable machine-readable code and a
// human-readable message safe to show to the caller.
type Error struct {
	Kind    Kind
	Code    string
	Message string
}

// Error implements the error interface.
func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func newError(kind Kind, code, format string, args ...any) *Error {
	return &Error{Kind: kind, Code: code, Message: fmt.Sprintf(format, args...)}
}

// Invalid reports bad input.
func Invalid(code, format string, args ...any) *Error {
	return newError(KindInvalid, code, format, args...)
}

// Unauthenticated reports missing or invalid credentials.
func Unauthenticated(format string, args ...any) *Error {
	return newError(KindUnauthenticated, "unauthenticated", format, args...)
}

// Forbidden reports a permission failure on a resource the caller can see.
func Forbidden(format string, args ...any) *Error {
	return newError(KindForbidden, "forbidden", format, args...)
}

// NotFound reports a missing resource. Use it also for resources that
// exist but belong to another tenant, so existence is not leaked.
func NotFound(format string, args ...any) *Error {
	return newError(KindNotFound, "not_found", format, args...)
}

// Conflict reports a clash with current state.
func Conflict(code, format string, args ...any) *Error {
	return newError(KindConflict, code, format, args...)
}

// RateLimited reports that a rate limit was exceeded.
func RateLimited(format string, args ...any) *Error {
	return newError(KindRateLimited, "rate_limited", format, args...)
}

// As returns the classified error inside err, if any.
func As(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}
