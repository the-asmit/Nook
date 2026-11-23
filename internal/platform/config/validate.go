package config

import (
	"cmp"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"
)

// CheckDuration returns an error naming the variable when d is outside
// [lowest, highest].
func CheckDuration(name string, d, lowest, highest time.Duration) error {
	if d < lowest || d > highest {
		return fmt.Errorf("%s: must be between %s and %s, got %s", name, lowest, highest, d)
	}
	return nil
}

// CheckRange returns an error naming the variable when v is outside
// [lowest, highest].
func CheckRange[T cmp.Ordered](name string, v, lowest, highest T) error {
	if v < lowest || v > highest {
		return fmt.Errorf("%s: must be between %v and %v, got %v", name, lowest, highest, v)
	}
	return nil
}

// CheckListenAddr validates a host:port listen address. The host may be
// empty (all interfaces); the port must be numeric and in range. Port 0
// asks the kernel for a free port, which tests rely on.
func CheckListenAddr(name, addr string) error {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%s: must be host:port, got %q", name, addr)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return fmt.Errorf("%s: port must be a number between 0 and 65535, got %q", name, port)
	}
	return nil
}

// RedactURLError strips the URL from a *url.Error. The standard library
// includes the full input in its message, which would leak any password
// embedded in a connection URL.
func RedactURLError(err error) error {
	var uerr *url.Error
	if !errors.As(err, &uerr) {
		return err
	}
	// An escape error quotes the offending bytes, which may be part of a
	// password, so only its kind is reported.
	var escErr url.EscapeError
	if errors.As(uerr.Err, &escErr) {
		return errors.New("invalid URL: malformed percent-encoding")
	}
	return fmt.Errorf("invalid URL: %w", uerr.Err)
}
