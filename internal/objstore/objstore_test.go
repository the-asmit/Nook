package objstore

import (
	"crypto/sha256"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/the-asmit/nook/internal/platform/config"
)

// The two worked examples from the AWS documentation for Signature
// Version 4 ("Authenticating Requests: Using the Authorization Header" and
// "Authenticating Requests: Using Query Parameters").
var awsExample = credentials{
	accessKeyID: "AKIAIOSFODNN7EXAMPLE",
	secret:      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	region:      "us-east-1",
}

var awsExampleTime = time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)

func TestSignRequestMatchesAWSExample(t *testing.T) {
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://examplebucket.s3.amazonaws.com/test.txt", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	empty := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	awsExample.signRequest(req, awsExampleTime, empty, map[string]string{"range": "bytes=0-9"})
	want := "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, " +
		"SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, " +
		"Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("Authorization =\n%s\nwant\n%s", got, want)
	}
}

func TestPresignMatchesAWSExample(t *testing.T) {
	u, _ := url.Parse("https://examplebucket.s3.amazonaws.com/test.txt")
	got := awsExample.presign(http.MethodGet, u, awsExampleTime, 24*time.Hour, nil)
	if !strings.HasSuffix(got, "&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404") {
		t.Fatalf("presigned URL %s", got)
	}
	if !strings.Contains(got, "X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request") {
		t.Fatalf("credential not encoded: %s", got)
	}
}

func testClient(t *testing.T) *Client {
	t.Helper()
	c, err := New(&Config{
		Endpoint: "http://127.0.0.1:9000", PresignEndpoint: "https://storage.example.com", Region: "us-east-1", Bucket: "nook",
		AccessKeyID: "key", SecretAccessKey: config.NewSecret("secret"), RequestTimeout: time.Second,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.now = func() time.Time { return awsExampleTime }
	return c
}

func TestPresignPutPinsSizeAndChecksum(t *testing.T) {
	c := testClient(t)
	sum := sha256.Sum256([]byte("hello"))
	up := c.PresignPut("sources/a/b.tar.gz", 5, sum[:], 15*time.Minute)
	u, err := url.Parse(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "storage.example.com" || u.Path != "/nook/sources/a/b.tar.gz" {
		t.Fatalf("URL %s does not use the presign endpoint", up.URL)
	}
	if got := u.Query().Get("X-Amz-SignedHeaders"); got != "content-length;host;x-amz-checksum-sha256" {
		t.Fatalf("signed headers %q", got)
	}
	if up.Headers["x-amz-checksum-sha256"] != "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=" || up.Method != http.MethodPut {
		t.Fatalf("upload %+v", up)
	}
	if !up.ExpiresAt.Equal(awsExampleTime.Add(15 * time.Minute)) {
		t.Fatalf("expires %v", up.ExpiresAt)
	}
	// A different size or checksum produces a different signature, so the
	// URL cannot be reused for other content.
	other := c.PresignPut("sources/a/b.tar.gz", 6, sum[:], 15*time.Minute)
	if other.URL == up.URL {
		t.Fatal("size is not part of the signature")
	}
}

func TestConfigValidate(t *testing.T) {
	good := Config{Endpoint: "https://s3.example.com", Region: "auto", Bucket: "nook-data", AccessKeyID: "k",
		SecretAccessKey: config.NewSecret("s"), RequestTimeout: time.Second}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	if !good.TLS() {
		t.Fatal("https endpoint not reported as TLS")
	}
	for name, mutate := range map[string]func(*Config){
		"endpoint path":   func(c *Config) { c.Endpoint = "https://s3.example.com/bucket" },
		"endpoint scheme": func(c *Config) { c.Endpoint = "ftp://x" },
		"bucket":          func(c *Config) { c.Bucket = "Bad_Bucket" },
		"credentials":     func(c *Config) { c.AccessKeyID = "" },
		"presign":         func(c *Config) { c.PresignEndpoint = "not a url" },
	} {
		c := good
		mutate(&c)
		if c.Validate() == nil {
			t.Errorf("%s: invalid config accepted", name)
		}
	}
	plain := good
	plain.PresignEndpoint = "http://localhost:9000"
	if plain.TLS() {
		t.Fatal("plain presign endpoint reported as TLS")
	}
}

func TestErrorsNeverContainTheURL(t *testing.T) {
	c := testClient(t)
	c.endpoint, _ = url.Parse("http://127.0.0.1:1")
	_, err := c.Head(t.Context(), "sources/x")
	if err == nil {
		t.Fatal("expected a connection error")
	}
	if strings.Contains(err.Error(), "http://") || strings.Contains(err.Error(), "X-Amz") {
		t.Fatalf("error leaks the request URL: %v", err)
	}
}
