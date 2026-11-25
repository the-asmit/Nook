package apps

import (
	"strings"
	"testing"

	"github.com/the-asmit/nook/internal/store"
)

func TestEnvKeyValidation(t *testing.T) {
	for _, ok := range []string{"A", "_X", "DATABASE_URL", "a1", strings.Repeat("K", 128)} {
		if err := validateEnvKey(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "1A", "A-B", "A B", "A=B", strings.Repeat("K", 129), "PORT", "NOOK_APP", "NOOK_DEPLOYMENT", "NOOK_ANYTHING"} {
		if err := validateEnvKey(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestEnvValueValidationNeverEchoesTheValue(t *testing.T) {
	secret := "hunter2-" + strings.Repeat("x", 33<<10)
	for name, v := range map[string]string{"too large": secret, "nul": "hunter2\x00", "not utf-8": "hunter2\xff"} {
		err := validateEnvValue("PASSWORD", v)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%s: the error shows the value: %v", name, err)
		}
	}
	if err := validateEnvValue("A", "multi\nline value ünïcode"); err != nil {
		t.Fatal(err)
	}
}

func TestEnvSize(t *testing.T) {
	current := map[string]store.AppEnv{
		"A": {Key: "A", Value: make([]byte, 28+10)},
		"B": {Key: "B", Value: make([]byte, 28+5)},
	}
	total, count := envSize(current, map[string]string{"B": "123", "C": "1234"})
	if total != 10+3+4 || count != 3 {
		t.Fatalf("total %d count %d", total, count)
	}
}
