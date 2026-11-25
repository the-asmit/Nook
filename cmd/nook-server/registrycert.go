package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/the-asmit/nook/internal/agentlink"
	"github.com/the-asmit/nook/internal/pki"
	"github.com/the-asmit/nook/internal/platform/config"
)

// runRegistryCert implements `nook-server registry-cert`: it issues the
// image registry's TLS certificate from Nook's internal CA (creating the CA
// if it does not exist yet) and writes tls.crt, tls.key and ca.crt, the
// files the registry container mounts. An existing certificate that stays
// valid for longer than --renew-before is kept.
func runRegistryCert(args []string, environ map[string]string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("registry-cert", flag.ContinueOnError)
	flags.SetOutput(stderr)
	out := flags.String("out", "", "directory to write tls.crt, tls.key and ca.crt to (required)")
	names := flags.String("names", "", "comma-separated DNS names and IP addresses the certificate covers (required)")
	validFor := flags.Duration("valid-for", 365*24*time.Hour, "certificate lifetime")
	renewBefore := flags.Duration("renew-before", 30*24*time.Hour, "reissue when the existing certificate expires sooner than this")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	var list []string
	for _, n := range strings.Split(*names, ",") {
		if n = strings.TrimSpace(n); n != "" {
			list = append(list, n)
		}
	}
	if *out == "" || len(list) == 0 || *validFor < time.Hour {
		_, _ = fmt.Fprintln(stderr, "registry-cert: --out and --names are required, and --valid-for must be at least 1h")
		return 2
	}
	cfg, err := config.Load[agentlink.Config](environ)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "registry-cert: invalid configuration: %v\n", err)
		return 2
	}
	if expiry, expErr := existingExpiry(filepath.Join(*out, "tls.crt")); expErr == nil && time.Until(expiry) > *renewBefore {
		_, _ = fmt.Fprintf(stdout, "registry certificate in %s is valid until %s; keeping it\n", *out, expiry.Format(time.RFC3339))
		return 0
	}
	ca, created, err := pki.LoadOrCreateCA(cfg.CAPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "registry-cert: %v\n", err)
		return 1
	}
	cert, err := ca.IssueServerCertificate(list, *validFor)
	if err == nil {
		err = ca.WriteServerFiles(*out, cert)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "registry-cert: %v\n", err)
		return 1
	}
	if created {
		_, _ = fmt.Fprintf(stdout, "created the Nook CA at %s\n", cfg.CAPath)
	}
	_, _ = fmt.Fprintf(stdout, "issued the registry certificate for %s into %s (valid until %s)\n",
		strings.Join(list, ", "), *out, cert.Leaf.NotAfter.Format(time.RFC3339))
	return 0
}

func existingExpiry(path string) (time.Time, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: the operator chose the output directory.
	if err != nil {
		return time.Time{}, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return time.Time{}, errors.New("no certificate")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return c.NotAfter, nil
}
