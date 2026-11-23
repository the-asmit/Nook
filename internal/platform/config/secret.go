package config

import (
	"fmt"
	"log/slog"
)

const redacted = "[REDACTED]"

// Secret holds a sensitive configuration value such as a connection URL
// with an embedded password.
//
// Every way of printing a Secret (fmt verbs, slog, JSON) yields
// "[REDACTED]", so a secret cannot leak into logs or error messages by
// accident. Code that genuinely needs the plaintext calls Reveal.
type Secret struct {
	value string
}

// NewSecret wraps a plaintext value.
func NewSecret(value string) Secret {
	return Secret{value: value}
}

// UnmarshalText lets the environment parser populate a Secret.
func (s *Secret) UnmarshalText(text []byte) error {
	s.value = string(text)
	return nil
}

// Reveal returns the plaintext. Call it only where the value is handed to
// the library that needs it, never to build log or error messages.
func (s Secret) Reveal() string {
	return s.value
}

// IsZero reports whether the secret is empty.
func (s Secret) IsZero() bool {
	return s.value == ""
}

// String implements fmt.Stringer with a redacted value.
func (s Secret) String() string {
	return redacted
}

// Format redacts the value for every fmt verb, including %#v and %x,
// which would otherwise bypass String.
func (s Secret) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte(redacted))
}

// LogValue implements slog.LogValuer with a redacted value.
func (s Secret) LogValue() slog.Value {
	return slog.StringValue(redacted)
}

// MarshalJSON encodes the secret as the redacted placeholder.
func (s Secret) MarshalJSON() ([]byte, error) {
	return []byte(`"` + redacted + `"`), nil
}
