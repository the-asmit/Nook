package gateway

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"html/template"
	"net/http"
	"strconv"
)

//go:embed templates/page.html
var pageTemplate string

// pageStyle is the pages' only styling, allowed by its hash in the CSP.
const pageStyle = "body{font-family:system-ui,sans-serif;background:#f6f7f9;color:#1f2328;margin:0}" +
	"main{max-width:34rem;margin:12vh auto;padding:2rem;background:#fff;border:1px solid #d0d7de;border-radius:8px}" +
	"h1{font-size:1.4rem;margin-top:0}.id{color:#656d76;font-size:.85rem}a{color:#0969da}"

var (
	pageTmpl = template.Must(template.New("page").Parse(pageTemplate))
	pageCSP  = func() string {
		sum := sha256.Sum256([]byte(pageStyle))
		return "default-src 'none'; style-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
	}()
)

type pageLink struct {
	URL, Text string
}

type pageData struct {
	Title, Message, RequestID string
	Style                     template.CSS
	Link                      *pageLink
}

// page writes one of the gateway's own pages (errors, denial).
func page(w http.ResponseWriter, r *http.Request, status int, title, message string, link *pageLink) {
	var buf bytes.Buffer
	err := pageTmpl.Execute(&buf, pageData{
		Title: title, Message: message, RequestID: requestID(r.Context()), Style: template.CSS(pageStyle), Link: link, //nolint:gosec // G203: a constant style sheet, no input.
	})
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	if err != nil {
		h.Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(title + "\n"))
		return
	}
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", pageCSP)
	h.Set("Content-Length", strconv.Itoa(buf.Len()))
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(buf.Bytes())
	}
}
