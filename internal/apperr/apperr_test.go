package apperr

import (
	"errors"
	"fmt"
	"testing"
)

func TestConstructorsAndAs(t *testing.T) {
	cases := []struct {
		err  *Error
		kind Kind
		code string
	}{
		{Invalid("bad_x", "x is %d", 3), KindInvalid, "bad_x"},
		{Unauthenticated("no"), KindUnauthenticated, "unauthenticated"},
		{Forbidden("no"), KindForbidden, "forbidden"},
		{NotFound("no"), KindNotFound, "not_found"},
		{Conflict("taken", "no"), KindConflict, "taken"},
		{RateLimited("slow"), KindRateLimited, "rate_limited"},
	}
	for _, tc := range cases {
		wrapped := fmt.Errorf("context: %w", tc.err)
		got, ok := As(wrapped)
		if !ok || got.Kind != tc.kind || got.Code != tc.code {
			t.Errorf("As(%v) = %+v, %v", wrapped, got, ok)
		}
	}
	if Invalid("c", "x is %d", 3).Message != "x is 3" {
		t.Error("message not formatted")
	}
	if _, ok := As(errors.New("plain")); ok {
		t.Error("plain error classified")
	}
}
