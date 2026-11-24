// Package agent is nook-agent, the program that runs on every worker
// node: it joins the node to a Nook installation, keeps a mutually
// authenticated gRPC session with the control plane, sends heartbeats,
// executes commands against the local Docker engine and renews its
// certificate before it expires.
package agent

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/the-asmit/nook/internal/pki"
)

// State file names inside the state directory.
const (
	stateFile = "state.json"
	// identityFile holds the node certificate and its private key in one
	// PEM file, so renewal replaces both in a single atomic rename.
	identityFile = "node.pem"
	caFile       = "ca.crt"
)

// ErrNotJoined means the state directory holds no node identity yet.
var ErrNotJoined = errors.New("this machine has not joined a Nook installation; run `nook-agent join` first")

// identity is the persistent state of a joined node.
type identity struct {
	NodeID string `json:"node_id"`
	Name   string `json:"name"`
	// Server is the control plane's host:port.
	Server string `json:"server"`

	cert *x509.Certificate
	key  crypto.Signer
	ca   *x509.Certificate
}

func (id *identity) tlsCertificate() *tls.Certificate {
	return &tls.Certificate{Certificate: [][]byte{id.cert.Raw}, PrivateKey: id.key, Leaf: id.cert}
}

// stateDir is the agent's state directory. It must be private to the
// agent's user (mode 0700, files 0600): it holds the node's private key.
type stateDir string

func (d stateDir) path(name string) string { return filepath.Join(string(d), name) }

// ensure creates the directory with mode 0700 if needed and refuses an
// existing one that others can access.
func (d stateDir) ensure() error {
	if err := os.MkdirAll(string(d), 0o700); err != nil {
		return fmt.Errorf("create state directory %s: %w", d, err)
	}
	return d.check()
}

func (d stateDir) check() error {
	info, err := os.Stat(string(d))
	if err != nil {
		return fmt.Errorf("state directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("state directory %s is not a directory", d)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("state directory %s has mode %04o; it holds the node's private key and must be 0700 (chmod 700 %s)",
			d, info.Mode().Perm(), d)
	}
	return nil
}

// joined reports whether the directory already holds a node identity.
func (d stateDir) joined() bool {
	_, err := os.Stat(d.path(stateFile))
	return err == nil
}

func (d stateDir) load() (*identity, error) {
	if err := d.check(); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNotJoined
		}
		return nil, err
	}
	raw, err := pki.ReadPrivateFile(d.path(stateFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotJoined
	}
	if err != nil {
		return nil, err
	}
	var id identity
	if err = json.Unmarshal(raw, &id); err != nil {
		return nil, fmt.Errorf("parse %s: %w", stateFile, err)
	}
	pair, err := pki.ReadPrivateFile(d.path(identityFile))
	if err != nil {
		return nil, err
	}
	if id.cert, id.key, err = pki.ParseKeyPair(pair); err != nil {
		return nil, fmt.Errorf("%s: %w", identityFile, err)
	}
	caPEM, err := pki.ReadPrivateFile(d.path(caFile))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(caPEM)
	if block == nil {
		return nil, fmt.Errorf("%s holds no certificate", caFile)
	}
	if id.ca, err = x509.ParseCertificate(block.Bytes); err != nil {
		return nil, fmt.Errorf("parse %s: %w", caFile, err)
	}
	return &id, nil
}

// save writes the full identity (after joining).
func (d stateDir) save(id *identity) error {
	if err := d.ensure(); err != nil {
		return err
	}
	if err := d.saveCA(id.ca.Raw); err != nil {
		return err
	}
	if err := d.saveCertificate(id.cert.Raw, id.key); err != nil {
		return err
	}
	data, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	// Written last: its presence means the join completed.
	return writePrivate(d.path(stateFile), append(data, '\n'))
}

func (d stateDir) saveCA(der []byte) error {
	return writePrivate(d.path(caFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func (d stateDir) saveCertificate(certDER []byte, key crypto.Signer) error {
	pair, err := pki.EncodeKeyPair(certDER, key)
	if err != nil {
		return err
	}
	return writePrivate(d.path(identityFile), pair)
}

// writePrivate replaces path atomically with a 0600 file.
func writePrivate(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
