package registry

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/the-asmit/nook/internal/pki"
)

// TestTokenIsVerifiableWithTheCA checks a token the way the registry
// does: the x5c certificate chains to the CA and signs the token.
func TestTokenIsVerifiableWithTheCA(t *testing.T) {
	ca, _, err := pki.LoadOrCreateCA(filepath.Join(t.TempDir(), "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	iss := NewIssuer(ca, "nook", "nook-registry")
	now := time.Now()
	iss.now = func() time.Time { return now }
	tok, err := iss.Token("node:a", time.Minute, RepositoryAccess("ws/app", ActionPush, ActionPull))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token %q", tok)
	}
	var header struct {
		Alg string   `json:"alg"`
		X5c []string `json:"x5c"`
	}
	var claims struct {
		Iss    string   `json:"iss"`
		Sub    string   `json:"sub"`
		Aud    string   `json:"aud"`
		Exp    int64    `json:"exp"`
		Access []Access `json:"access"`
	}
	decode := func(s string, v any) {
		raw, decErr := base64.RawURLEncoding.DecodeString(s)
		if decErr != nil || json.Unmarshal(raw, v) != nil {
			t.Fatalf("decode %q: %v", s, decErr)
		}
	}
	decode(parts[0], &header)
	decode(parts[1], &claims)
	if header.Alg != "ES256" || len(header.X5c) != 1 {
		t.Fatalf("header %+v", header)
	}
	if claims.Iss != "nook" || claims.Aud != "nook-registry" || claims.Sub != "node:a" || claims.Exp != now.Add(time.Minute).Unix() ||
		len(claims.Access) != 1 || claims.Access[0].Name != "ws/app" {
		t.Fatalf("claims %+v", claims)
	}
	der, _ := base64.StdEncoding.DecodeString(header.X5c[0])
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("signer does not chain to the CA: %v", err)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	pub, _ := cert.PublicKey.(*ecdsa.PublicKey)
	if len(sig) != 64 || !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("signature does not verify")
	}
	// The signer is reused while it is fresh.
	again, _ := iss.Token("node:a", time.Minute)
	var h2 struct {
		X5c []string `json:"x5c"`
	}
	decode(strings.Split(again, ".")[0], &h2)
	if h2.X5c[0] != header.X5c[0] {
		t.Fatal("signer rotated too early")
	}
}

func TestConfigValidate(t *testing.T) {
	good := Config{Addr: "registry:5000", Service: "s", Issuer: "i", RequestTimeout: time.Second}
	good.GCSecret.UnmarshalText([]byte("0123456789abcdef")) //nolint:errcheck // never fails
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	if good.BaseURL() != "https://registry:5000" {
		t.Fatal(good.BaseURL())
	}
	for name, mutate := range map[string]func(*Config){
		"addr":   func(c *Config) { c.Addr = "registry" },
		"url":    func(c *Config) { c.URL = "http://registry:5000" },
		"secret": func(c *Config) { c.GCSecret.UnmarshalText([]byte("short")) }, //nolint:errcheck // never fails
	} {
		c := good
		mutate(&c)
		if c.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if !ValidDigest("sha256:"+strings.Repeat("a", 64)) || ValidDigest("sha256:abc") {
		t.Fatal("ValidDigest")
	}
}
