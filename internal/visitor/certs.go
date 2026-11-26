package visitor

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/the-asmit/nook/internal/secrets"
	"github.com/the-asmit/nook/internal/store"
)

// ErrNoCertificate means nothing is stored under a name.
var ErrNoCertificate = errors.New("no such certificate")

// certNamePattern matches the names autocert stores (host names, "+rsa"
// variants, "acme_account+key").
var certNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,252}$`)

// ValidCertName reports whether name may be stored.
func ValidCertName(name string) bool { return certNamePattern.MatchString(name) }

// GetCertificate returns a stored certificate (or ACME account key) in
// plain form, for a gateway.
func (s *Service) GetCertificate(ctx context.Context, name string) ([]byte, error) {
	if !ValidCertName(name) {
		return nil, ErrNoCertificate
	}
	row, err := s.store.GetGatewayCertificate(ctx, name)
	if store.IsNotFound(err) {
		return nil, ErrNoCertificate
	}
	if err != nil {
		return nil, fmt.Errorf("read certificate: %w", err)
	}
	return s.keyring.Open(int(row.KeyVersion), secrets.CertAAD(name), row.Data)
}

// PutCertificate stores a certificate sealed with the keyring.
func (s *Service) PutCertificate(ctx context.Context, name string, data []byte) error {
	if !ValidCertName(name) {
		return errors.New("invalid certificate name")
	}
	sealed, v, err := s.keyring.Seal(secrets.CertAAD(name), data)
	if err != nil {
		return err
	}
	if err := s.store.PutGatewayCertificate(ctx, store.PutGatewayCertificateParams{Name: name, Data: sealed, KeyVersion: int32(v)}); err != nil { //nolint:gosec // G115: versions are at most 1e6.
		return fmt.Errorf("store certificate: %w", err)
	}
	return nil
}

// DeleteCertificate removes a stored certificate.
func (s *Service) DeleteCertificate(ctx context.Context, name string) error {
	if !ValidCertName(name) {
		return nil
	}
	if err := s.store.DeleteGatewayCertificate(ctx, name); err != nil {
		return fmt.Errorf("delete certificate: %w", err)
	}
	return nil
}
