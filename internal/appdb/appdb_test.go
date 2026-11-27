package appdb

import (
	"net/url"
	"strings"
	"testing"
	"uuid"

	"github.com/the-asmit/nook/internal/objstore"
	"github.com/the-asmit/nook/internal/platform/config"
)

func TestSCRAMVerifierMatchesAnIndependentImplementation(t *testing.T) {
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i)
	}
	// Computed with Python's hashlib (PBKDF2-HMAC-SHA256, RFC 5802 keys).
	const want = "SCRAM-SHA-256$4096:AAECAwQFBgcICQoLDA0ODw==$zHCdol2044/ZyWzPLi7oxApCkamKw9Z+E4U/QApd/5Y=:dd5peBOitVnLNFu7VmwP+HiDaaw4OUCv396eVCWhYiE="
	got, err := scramVerifierWithSalt("pencil", salt, 4096)
	if err != nil || got != want {
		t.Fatalf("verifier = %q, %v; want %q", got, err, want)
	}
	a, _ := scramVerifier("pencil")
	b, _ := scramVerifier("pencil")
	if a == b || !strings.HasPrefix(a, "SCRAM-SHA-256$4096:") {
		t.Fatalf("verifiers must use fresh salts: %q %q", a, b)
	}
	if _, err := sqlLiteral(a); err != nil {
		t.Fatalf("a verifier must be quotable: %v", err)
	}
}

func TestNamesAndQuoting(t *testing.T) {
	id := uuid.MustParse("01a21823-cfd5-76b9-bb67-9504f56a4a35")
	name := DatabaseName(id)
	if name != "app_01a21823cfd576b9bb679504f56a4a35" || !namePattern.MatchString(name) {
		t.Fatalf("DatabaseName = %q", name)
	}
	if q, err := sqlIdent(name); err != nil || q != `"`+name+`"` {
		t.Fatalf("sqlIdent(%q) = %q, %v", name, q, err)
	}
	for _, bad := range []string{`app_x"; DROP DATABASE postgres; --`, "APP_01a21823cfd576b9bb679504f56a4a35", "nook_admin", ""} {
		if _, err := sqlIdent(bad); err == nil {
			t.Errorf("sqlIdent(%q) accepted", bad)
		}
	}
	for _, bad := range []string{"it's", `a\b`, "x\x00", "semi;colon", "space here"} {
		if _, err := sqlLiteral(bad); err == nil {
			t.Errorf("sqlLiteral(%q) accepted", bad)
		} else if strings.Contains(err.Error(), bad) {
			t.Errorf("the error repeats the value: %v", err)
		}
	}
	if s, err := sqlLiteral("abc$1:2+/="); err != nil || s != "'abc$1:2+/='" {
		t.Fatalf("sqlLiteral = %q, %v", s, err)
	}
}

func TestDatabaseURL(t *testing.T) {
	pw, err := newPassword()
	if err != nil || len(pw) != 43 {
		t.Fatalf("password %q (%d characters), %v", pw, len(pw), err)
	}
	u, err := url.Parse(DatabaseURL("app_0123", pw, "10.0.0.5", 5433))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := u.User.Password()
	if u.Scheme != "postgres" || u.User.Username() != "app_0123" || got != pw || u.Host != "10.0.0.5:5433" ||
		u.Path != "/app_0123" || u.Query().Get("sslmode") != "require" {
		t.Fatalf("DATABASE_URL %s", u.Redacted())
	}
	if v6 := DatabaseURL("app_0123", "pw", "fd00::5", 5433); !strings.Contains(v6, "@[fd00::5]:5433/") {
		t.Fatalf("IPv6 URL %q", v6)
	}
}

func TestDiskOK(t *testing.T) {
	free := func(n int64) *int64 { return &n }
	for _, tc := range []struct {
		free    *int64
		total   int64
		percent int
		ok      bool
	}{
		{free(10), 100, 10, true},
		{free(9), 100, 10, false},
		{nil, 100, 10, true},
		{free(0), 0, 10, true},
		{free(0), 100, 0, true},
	} {
		if got := diskOK(tc.free, tc.total, tc.percent); got != tc.ok {
			t.Errorf("diskOK(%v, %d, %d) = %v", tc.free, tc.total, tc.percent, got)
		}
	}
}

func validConfig() Config {
	return Config{
		Image: "nook-postgres:dev", BackupPrefix: "appdb", ArchiveTimeout: 60e9, BackupInterval: 24 * 3600e9, Retention: 168 * 3600e9,
		MemoryMB: 512, CPUMillicores: 1000, MaxConnections: 200, ConnectionLimit: 20, MinFreeDiskPercent: 10,
		NodeLabel: "nook.database", Interval: 5e9, MonitorInterval: 30e9, DumpMaxBytes: 5 << 30, DumpTTL: 3600e9,
	}
}

func TestConfig(t *testing.T) {
	s3 := objstore.Config{Endpoint: "http://127.0.0.1:9000", Region: "us-east-1", Bucket: "nook", AccessKeyID: "k", SecretAccessKey: config.NewSecret("s")}
	c := validConfig()
	c.Resolve(&s3)
	if c.BackupBucket != "nook" || c.S3Endpoint != s3.Endpoint || c.S3AccessKeyID != "k" || c.walgPrefix() != "s3://nook/appdb" {
		t.Fatalf("resolved %+v", c)
	}
	if err := c.Validate(false); err != nil {
		t.Fatalf("development: %v", err)
	}
	err := c.Validate(true)
	if err == nil || !strings.Contains(err.Error(), "pinned by digest") || !strings.Contains(err.Error(), "https") {
		t.Fatalf("production must require a pinned image and https storage: %v", err)
	}
	c.Image = "ghcr.io/x/nook-postgres:1.0@sha256:" + strings.Repeat("a", 64)
	c.S3Endpoint = "https://storage.example.com"
	if err := c.Validate(true); err != nil {
		t.Fatalf("production: %v", err)
	}
	c.ConnectionLimit = 500
	if err := c.Validate(true); err == nil {
		t.Fatal("a per-app connection limit above max_connections was accepted")
	}
	if off := (Config{}); off.Enabled() || off.Validate(true) != nil {
		t.Fatal("an empty image disables app databases without errors")
	}
}
