// Package secrets encrypts app environment values at rest with
// AES-256-GCM under a versioned master key, and rotates them to a new key.
//
// The master key comes from NOOK_SECRETS_KEY, normally supplied as a file
// through NOOK_SECRETS_KEY_FILE. It holds one key per line,
// "<version>:<base64 of 32 random bytes>"; the highest version encrypts
// new values and every listed version can decrypt. Each ciphertext is
// bound (as GCM additional data) to the app and variable it belongs to,
// so a value copied to another app or key fails to decrypt instead of
// leaking into the wrong place.
package secrets

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"uuid"

	"github.com/the-asmit/nook/internal/platform/config"
)

// Config locates the master key.
type Config struct {
	// Key is the keyring text; supply it as a file with NOOK_SECRETS_KEY_FILE.
	Key config.Secret `env:"NOOK_SECRETS_KEY"`
}

// Validate checks that the keyring parses.
func (c *Config) Validate() error {
	if c.Key.IsZero() {
		return errors.New("NOOK_SECRETS_KEY: required (normally as NOOK_SECRETS_KEY_FILE; create one with `nook-server secrets init`)")
	}
	if _, err := ParseKeyring(c.Key.Reveal()); err != nil {
		return fmt.Errorf("NOOK_SECRETS_KEY: %w", err)
	}
	return nil
}

// Keyring returns the parsed keyring; call after Validate.
func (c *Config) Keyring() (*Keyring, error) {
	return ParseKeyring(c.Key.Reveal())
}

// keySize is the AES-256 key length.
const keySize = 32

// maxVersion bounds key versions to something an operator types.
const maxVersion = 1_000_000

// ErrDecrypt means a value could not be decrypted: wrong key, missing key
// version or tampered data. It never carries the value.
var ErrDecrypt = errors.New("the value cannot be decrypted with the configured master key")

// Keyring holds the master keys by version.
type Keyring struct {
	aeads map[int]cipher.AEAD
	// raw keys, only for deriving purpose-specific keys (Derive).
	raw    map[int][]byte
	active int
}

// ParseKeyring reads "<version>:<base64 key>" lines; blank lines and
// lines starting with # are ignored. Errors never include key material.
func ParseKeyring(text string) (*Keyring, error) {
	k := &Keyring{aeads: map[int]cipher.AEAD{}, raw: map[int][]byte{}}
	sc := bufio.NewScanner(strings.NewReader(text))
	line := 0
	for sc.Scan() {
		line++
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		vs, b64, ok := strings.Cut(l, ":")
		if !ok {
			return nil, fmt.Errorf("line %d: expected <version>:<base64 key>", line)
		}
		v, err := strconv.Atoi(strings.TrimSpace(vs))
		if err != nil || v < 1 || v > maxVersion {
			return nil, fmt.Errorf("line %d: the version must be a number from 1 to %d", line, maxVersion)
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
		if err != nil || len(raw) != keySize {
			return nil, fmt.Errorf("line %d: the key must be %d bytes, base64-encoded", line, keySize)
		}
		if _, dup := k.aeads[v]; dup {
			return nil, fmt.Errorf("line %d: version %d appears twice", line, v)
		}
		aead, err := newAEAD(raw)
		if err != nil {
			return nil, err
		}
		k.aeads[v] = aead
		k.raw[v] = raw
		k.active = max(k.active, v)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read keyring: %w", err)
	}
	if len(k.aeads) == 0 {
		return nil, errors.New("no key found")
	}
	return k, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	return aead, nil
}

// Active is the version that encrypts new values.
func (k *Keyring) Active() int { return k.active }

// Versions lists the versions in the keyring, ascending.
func (k *Keyring) Versions() []int { return slices.Sorted(maps.Keys(k.aeads)) }

// Has reports whether the keyring holds version v.
func (k *Keyring) Has(v int) bool {
	_, ok := k.aeads[v]
	return ok
}

// Seal encrypts plaintext under the active key, bound to aad. The result
// is the random 96-bit nonce followed by the sealed value and its tag.
func (k *Keyring) Seal(aad, plaintext []byte) (ciphertext []byte, version int, err error) {
	aead := k.aeads[k.active]
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, 0, fmt.Errorf("nonce: %w", err)
	}
	return aead.Seal(nonce, nonce, plaintext, aad), k.active, nil
}

// Open decrypts a value sealed with version v and aad.
func (k *Keyring) Open(v int, aad, ciphertext []byte) ([]byte, error) {
	aead, ok := k.aeads[v]
	if !ok || len(ciphertext) < aead.NonceSize()+aead.Overhead() {
		return nil, ErrDecrypt
	}
	n := aead.NonceSize()
	out, err := aead.Open(nil, ciphertext[:n], ciphertext[n:], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return out, nil
}

// EnvAAD binds an environment value to its app and variable name.
func EnvAAD(appID uuid.UUID, key string) []byte {
	return []byte("nook/env/v1\x00" + appID.String() + "\x00" + key)
}

// CertAAD binds a stored gateway certificate (or ACME account key) to its
// name.
func CertAAD(name string) []byte {
	return []byte("nook/gateway-cert/v1\x00" + name)
}

// checkAAD and checkPlaintext make the key-check value of a version.
var (
	checkAAD       = []byte("nook/key-check/v1")
	checkPlaintext = []byte("nook master key check")
)

// checkValue seals the fixed check plaintext under version v.
func (k *Keyring) checkValue(v int) ([]byte, error) {
	aead := k.aeads[v]
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	return aead.Seal(nonce, nonce, checkPlaintext, checkAAD), nil
}

// matches reports whether version v decrypts a stored check value.
func (k *Keyring) matches(v int, check []byte) bool {
	_, err := k.Open(v, checkAAD, check)
	return err == nil
}

// NewKeyLine returns a keyring line with a fresh random key.
func NewKeyLine(version int) (string, error) {
	if version < 1 || version > maxVersion {
		return "", fmt.Errorf("the version must be from 1 to %d", maxVersion)
	}
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("generate key: %w", err)
	}
	return strconv.Itoa(version) + ":" + base64.StdEncoding.EncodeToString(key), nil
}

// Derive returns a size-byte key for purpose, derived with HKDF-SHA256
// from master key version v. Different purposes get unrelated keys, so a
// key handed to one component (the app database server's backup
// encryption) never decrypts anything else.
func (k *Keyring) Derive(v int, purpose string, size int) ([]byte, error) {
	raw, ok := k.raw[v]
	if !ok {
		return nil, fmt.Errorf("master key version %d is not configured", v)
	}
	key, err := hkdf.Key(sha256.New, raw, nil, "nook/"+purpose, size)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	return key, nil
}

// DatabasePasswordAAD binds a sealed app database password to its app.
func DatabasePasswordAAD(appID uuid.UUID) []byte {
	return []byte("nook/appdb-password/v1\x00" + appID.String())
}

// DatabaseSuperuserAAD binds a sealed database server superuser password
// to its server.
func DatabaseSuperuserAAD(serverID uuid.UUID) []byte {
	return []byte("nook/appdb-superuser/v1\x00" + serverID.String())
}
