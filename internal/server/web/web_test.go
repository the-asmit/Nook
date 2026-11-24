package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/the-asmit/nook/internal/store"
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	os.Exit(m.Run())
}

func newHandlers(t *testing.T) *Handlers {
	t.Helper()
	h, err := New(&Deps{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), ProviderName: "Google"})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func render(t *testing.T, h *Handlers, page string, data any) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	h.render(c, http.StatusOK, page, data)
	return rec
}

func TestEveryPageRendersWithCSP(t *testing.T) {
	h := newHandlers(t)
	user := &store.User{Email: "a@nook.test", Name: "A"}
	pages := map[string]any{
		"signin":         signinPage{pageData: pageData{Title: "Sign in"}, ProviderName: "Google", ReturnTo: "/"},
		"home":           homePage{pageData: pageData{Title: "Home", User: user, CSRFToken: "tok"}, PublicURL: "https://nook.example.com"},
		"message":        messagePage{pageData: pageData{Title: "Hi"}, Heading: "Hi", Message: "there"},
		"device":         devicePage{pageData: pageData{Title: "Device", User: user, CSRFToken: "tok"}},
		"device_confirm": deviceConfirmPage{pageData: pageData{Title: "Approve", User: user, CSRFToken: "tok"}, UserCode: "BCDF-GHJK", ClientName: "cli"},
	}
	if len(pages) != len(h.pages) {
		t.Fatalf("test covers %d pages, templates define %d", len(pages), len(h.pages))
	}
	for name, data := range pages {
		rec := render(t, h, name, data)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "</html>") {
			t.Errorf("%s: status %d", name, rec.Code)
		}
		if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "script-src") {
			t.Errorf("%s: CSP = %q", name, csp)
		}
	}
}

func TestUntrustedValuesAreEscaped(t *testing.T) {
	h := newHandlers(t)
	evil := `<script>alert(1)</script>"><img src=x onerror=alert(1)>`
	rec := render(t, h, "device_confirm", deviceConfirmPage{
		pageData:   pageData{Title: "Approve", User: &store.User{Email: evil}, CSRFToken: "tok"},
		UserCode:   "BCDF-GHJK",
		ClientName: evil,
	})
	body := rec.Body.String()
	if strings.Contains(body, "<script>") || strings.Contains(body, "<img") {
		t.Fatalf("unescaped markup in page:\n%s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Fatal("expected the escaped client name")
	}

	rec = render(t, h, "signin", signinPage{pageData: pageData{Title: "x"}, ProviderName: "G", ReturnTo: `/a"b&c=<d>`})
	if strings.Contains(rec.Body.String(), `"b&c=<d>`) {
		t.Fatal("return_to not URL-escaped in the link")
	}
}

func TestUnknownPageIsInternalError(t *testing.T) {
	if rec := render(t, newHandlers(t), "nope", nil); rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestStylesheetIsServedWithType(t *testing.T) {
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	newHandlers(t).css(c)
	if rec.Header().Get("Content-Type") != "text/css; charset=utf-8" || rec.Body.Len() == 0 {
		t.Fatalf("css: %q %d", rec.Header().Get("Content-Type"), rec.Body.Len())
	}
}
