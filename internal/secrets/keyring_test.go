package secrets

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"uuid"
)

func ring(t *testing.T, lines ...string) *Keyring {
	t.Helper()
	k, err := ParseKeyring(strings.Join(lines, "\n"))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSealAndOpen(t *testing.T) {
	l1, _ := NewKeyLine(1)
	k := ring(t, "# comment", "", l1)
	app := uuid.NewV7()
	ct, v, err := k.Seal(EnvAAD(app, "API_KEY"), []byte("secret value"))
	if err != nil || v != 1 {
		t.Fatal(err, v)
	}
	if bytes.Contains(ct, []byte("secret value")) {
		t.Fatal("plaintext in the ciphertext")
	}
	pt, err := k.Open(1, EnvAAD(app, "API_KEY"), ct)
	if err != nil || string(pt) != "secret value" {
		t.Fatalf("open: %q %v", pt, err)
	}
	// Bound to the app and the key: moved values do not decrypt.
	for name, aad := range map[string][]byte{"other key": EnvAAD(app, "OTHER"), "other app": EnvAAD(uuid.NewV7(), "API_KEY")} {
		if _, err := k.Open(1, aad, ct); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s: %v", name, err)
		}
	}
	ct[len(ct)-1] ^= 1
	if _, err := k.Open(1, EnvAAD(app, "API_KEY"), ct); !errors.Is(err, ErrDecrypt) {
		t.Errorf("tampered: %v", err)
	}
	// Two seals of the same value differ (random nonces).
	a, _, _ := k.Seal(nil, []byte("x"))
	b, _, _ := k.Seal(nil, []byte("x"))
	if bytes.Equal(a, b) {
		t.Fatal("nonce reuse")
	}
}

func TestNewestVersionEncrypts(t *testing.T) {
	l1, _ := NewKeyLine(1)
	l3, _ := NewKeyLine(3)
	k := ring(t, l3, l1)
	if k.Active() != 3 || !k.Has(1) || k.Has(2) {
		t.Fatalf("active %d", k.Active())
	}
	old := ring(t, l1)
	ct, _, _ := old.Seal(nil, []byte("v"))
	if pt, err := k.Open(1, nil, ct); err != nil || string(pt) != "v" {
		t.Fatal("old versions must still decrypt")
	}
	if _, err := k.Open(2, nil, ct); !errors.Is(err, ErrDecrypt) {
		t.Fatal("missing version opened")
	}
	if !k.matches(1, mustCheck(t, old)) || k.matches(3, mustCheck(t, old)) {
		t.Fatal("key checks")
	}
}

func mustCheck(t *testing.T, k *Keyring) []byte {
	t.Helper()
	c, err := k.checkValue(k.Active())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestParseKeyringErrorsNeverShowKeys(t *testing.T) {
	l1, _ := NewKeyLine(1)
	key := strings.SplitN(l1, ":", 2)[1]
	for name, text := range map[string]string{
		"empty":        "",
		"no version":   key,
		"bad version":  "x:" + key,
		"zero version": "0:" + key,
		"short key":    "1:" + key[:20],
		"duplicate":    l1 + "\n" + l1,
		"not base64":   "1:!!!" + key[3:],
	} {
		_, err := ParseKeyring(text)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), key[:10]) {
			t.Errorf("%s: the error shows key material: %v", name, err)
		}
	}
}

func TestAddKey(t *testing.T) {
	l1, _ := NewKeyLine(1)
	text, v, err := AddKey("# keys\n" + l1)
	if err != nil || v != 2 {
		t.Fatal(err, v)
	}
	k := ring(t, text)
	if k.Active() != 2 || !k.Has(1) || !strings.HasPrefix(text, "# keys\n"+l1+"\n") {
		t.Fatalf("%q", text)
	}
	c := Config{}
	if c.Validate() == nil {
		t.Fatal("empty key accepted")
	}
}
