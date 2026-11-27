//go:build integration

package testinfra

import (
	"fmt"
	"strings"
	"unicode"

	tclog "github.com/testcontainers/testcontainers-go/log"
)

// Every integration test imports testinfra, so this runs before any
// container starts: testcontainers' messages begin with emojis, which make
// test and CI logs harder to grep and render badly in some terminals.
func init() {
	tclog.SetDefault(plainLogger{next: tclog.Default()})
}

// plainLogger passes testcontainers' messages to the logger it replaces
// (stderr, or nothing under -test.v=false) without pictographs.
type plainLogger struct {
	next tclog.Logger
}

// Printf implements tclog.Logger.
func (l plainLogger) Printf(format string, v ...any) {
	l.next.Printf("%s", plainText(fmt.Sprintf(format, v...)))
}

// plainText removes emojis and the invisible characters that build them
// (skin-tone modifiers, variation selectors, zero-width joiners), then the
// space they leave at the start.
func plainText(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r < 0x80:
			return r
		case unicode.Is(unicode.So, r), unicode.Is(unicode.Sk, r),
			unicode.Is(unicode.Variation_Selector, r), r == '‍':
			return -1
		}
		return r
	}, s)
	return strings.TrimLeft(s, " ")
}
