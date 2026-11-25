package objstore

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// AWS Signature Version 4, as used by S3 and every S3-compatible service
// (MinIO, Cloudflare R2). Only what Nook needs is implemented: header
// signing for its own requests and query-string signing for presigned
// URLs.

const (
	algorithm       = "AWS4-HMAC-SHA256"
	service         = "s3"
	unsignedPayload = "UNSIGNED-PAYLOAD"
	amzDateFormat   = "20060102T150405Z"
	dateFormat      = "20060102"
)

// credentials sign requests for one region.
type credentials struct {
	accessKeyID string
	secret      string
	region      string
}

func hashHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func (c *credentials) scope(t time.Time) string {
	return t.Format(dateFormat) + "/" + c.region + "/" + service + "/aws4_request"
}

func (c *credentials) signingKey(t time.Time) []byte {
	k := hmacSHA256([]byte("AWS4"+c.secret), t.Format(dateFormat))
	k = hmacSHA256(k, c.region)
	k = hmacSHA256(k, service)
	return hmacSHA256(k, "aws4_request")
}

// uriEncode percent-encodes s as SigV4 requires: everything except the
// unreserved characters A-Z a-z 0-9 - _ . ~ (and "/" when keepSlash).
func uriEncode(s string, keepSlash bool) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := range len(s) {
		c := s[i]
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && keepSlash:
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&15])
		}
	}
	return b.String()
}

func canonicalQuery(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vals := append([]string(nil), q[k]...)
		sort.Strings(vals)
		for _, v := range vals {
			parts = append(parts, uriEncode(k, false)+"="+uriEncode(v, false))
		}
	}
	return strings.Join(parts, "&")
}

// canonicalHeaders returns the canonical header block and the signed
// header list for the given lower-case header names.
func canonicalHeaders(h map[string]string) (block, signed string) {
	names := make([]string, 0, len(h))
	for k := range h {
		names = append(names, k)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		b.WriteString(n)
		b.WriteByte(':')
		b.WriteString(strings.Join(strings.Fields(h[n]), " "))
		b.WriteByte('\n')
	}
	return b.String(), strings.Join(names, ";")
}

// signature computes the SigV4 signature of a canonical request.
func (c *credentials) signature(t time.Time, method, escapedPath, query, headerBlock, signedHeaders, payloadHash string) string {
	canonical := strings.Join([]string{method, escapedPath, query, headerBlock, signedHeaders, payloadHash}, "\n")
	toSign := strings.Join([]string{algorithm, t.Format(amzDateFormat), c.scope(t), hashHex([]byte(canonical))}, "\n")
	return hex.EncodeToString(hmacSHA256(c.signingKey(t), toSign))
}

// signRequest adds header authentication to req. headers are extra
// headers (lower-case names) to set and sign besides host and the
// x-amz-* headers this function adds.
func (c *credentials) signRequest(req *http.Request, t time.Time, payloadHash string, headers map[string]string) {
	t = t.UTC()
	signedSet := map[string]string{
		"host":                 req.URL.Host,
		"x-amz-date":           t.Format(amzDateFormat),
		"x-amz-content-sha256": payloadHash,
	}
	for k, v := range headers {
		signedSet[k] = v
	}
	for k, v := range signedSet {
		if k != "host" {
			req.Header.Set(k, v)
		}
	}
	block, signed := canonicalHeaders(signedSet)
	sig := c.signature(t, req.Method, uriEncode(req.URL.Path, true), canonicalQuery(req.URL.Query()), block, signed, payloadHash)
	req.Header.Set("Authorization", algorithm+" Credential="+c.accessKeyID+"/"+c.scope(t)+
		", SignedHeaders="+signed+", Signature="+sig)
}

// presign returns u with query-string authentication valid for expires.
// headers (lower-case names, besides host) are signed: whoever uses the
// URL must send exactly these values.
func (c *credentials) presign(method string, u *url.URL, t time.Time, expires time.Duration, headers map[string]string) string {
	t = t.UTC()
	signedSet := map[string]string{"host": u.Host}
	for k, v := range headers {
		signedSet[k] = v
	}
	block, signed := canonicalHeaders(signedSet)
	q := u.Query()
	q.Set("X-Amz-Algorithm", algorithm)
	q.Set("X-Amz-Credential", c.accessKeyID+"/"+c.scope(t))
	q.Set("X-Amz-Date", t.Format(amzDateFormat))
	q.Set("X-Amz-Expires", formatSeconds(expires))
	q.Set("X-Amz-SignedHeaders", signed)
	query := canonicalQuery(q)
	sig := c.signature(t, method, uriEncode(u.Path, true), query, block, signed, unsignedPayload)
	out := *u
	out.RawPath = uriEncode(u.Path, true)
	out.RawQuery = query + "&X-Amz-Signature=" + sig
	return out.String()
}
