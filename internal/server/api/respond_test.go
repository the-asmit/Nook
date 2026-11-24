package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/platform/httpserver"
)

type sample struct {
	Name string `json:"name"`
}

func runDecode(t *testing.T, contentType, body string, limit int64) (*httptest.ResponseRecorder, sample, bool) {
	t.Helper()
	var got sample
	var ok bool
	e := gin.New()
	e.Use(httpserver.BodyLimit(limit))
	e.POST("/", func(c *gin.Context) {
		ok = decodeJSON(c, &got)
		if ok {
			c.Status(http.StatusNoContent)
		}
	})
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", strings.NewReader(body))
	r.ContentLength = -1
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, r)
	return rec, got, ok
}

func TestDecodeJSON(t *testing.T) {
	if rec, got, ok := runDecode(t, "application/json; charset=utf-8", `{"name":"x"}`, 1024); !ok || got.Name != "x" || rec.Code != http.StatusNoContent {
		t.Fatalf("valid body rejected: %d", rec.Code)
	}
	cases := []struct {
		name, ct, body string
		limit          int64
		status         int
		code           string
	}{
		{"form content type", "application/x-www-form-urlencoded", `{"name":"x"}`, 1024, 415, "unsupported_media_type"},
		{"no content type", "", `{"name":"x"}`, 1024, 415, "unsupported_media_type"},
		{"unknown field", "application/json", `{"name":"x","admin":true}`, 1024, 400, "invalid_body"},
		{"trailing data", "application/json", `{"name":"x"}{"name":"y"}`, 1024, 400, "invalid_body"},
		{"not json", "application/json", `name=x`, 1024, 400, "invalid_body"},
		{"too large", "application/json", `{"name":"` + strings.Repeat("x", 100) + `"}`, 32, 413, "payload_too_large"},
	}
	for _, tc := range cases {
		rec, _, ok := runDecode(t, tc.ct, tc.body, tc.limit)
		if ok || rec.Code != tc.status || !strings.Contains(rec.Body.String(), `"code":"`+tc.code+`"`) {
			t.Errorf("%s: ok=%v status=%d body=%s", tc.name, ok, rec.Code, rec.Body.String())
		}
	}
}

func TestPageParams(t *testing.T) {
	get := func(query string) (int32, idCursor, error) {
		var cur idCursor
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/?"+query, http.NoBody)
		n, err := pageParams(c, &cur)
		return n, cur, err
	}
	if n, _, err := get(""); err != nil || n != defaultPageSize {
		t.Fatalf("default: %d %v", n, err)
	}
	for _, q := range []string{"limit=0", "limit=101", "limit=x", "cursor=!!!", "cursor=" + strings.Repeat("a", 600), "cursor=bm90LWpzb24"} {
		if _, _, err := get(q); err == nil {
			t.Errorf("%q accepted", q)
		}
	}
	cursor := encodeCursor(idCursor{ID: maxUUID})
	if _, cur, err := get("limit=5&cursor=" + cursor); err != nil || cur.ID != maxUUID {
		t.Fatalf("cursor round trip failed: %v %v", cur, err)
	}
}

func TestPage(t *testing.T) {
	ident := func(s *string) string { return *s }
	cur := func(s *string) any { return map[string]string{"after": *s} }

	full := page([]string{"a", "b", "c"}, 2, ident, cur)
	if len(full.Items) != 2 || full.NextCursor == nil {
		t.Fatalf("expected 2 items and a cursor: %+v", full)
	}
	last := page([]string{"a"}, 2, ident, cur)
	if len(last.Items) != 1 || last.NextCursor != nil {
		t.Fatalf("last page must have no cursor: %+v", last)
	}
	empty := page([]string{}, 2, ident, cur)
	b, _ := json.Marshal(empty)
	if string(b) != `{"items":[],"next_cursor":null}` {
		t.Fatalf("empty page encodes as %s", b)
	}
}

func TestWriteErrorMapsKindsAndHidesInternals(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for err, status := range map[error]int{
		apperr.Invalid("x", "bad"): 400, apperr.Unauthenticated("no"): 401, apperr.Forbidden("no"): 403,
		apperr.NotFound("no"): 404, apperr.Conflict("c", "no"): 409, apperr.RateLimited("slow"): 429,
		io.ErrUnexpectedEOF: 500,
	} {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
		writeError(c, logger, err)
		if rec.Code != status {
			t.Errorf("%v: status %d, want %d", err, rec.Code, status)
		}
		if status == 500 && strings.Contains(rec.Body.String(), "EOF") {
			t.Error("internal error details leaked")
		}
	}
}
