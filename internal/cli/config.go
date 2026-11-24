package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

// Config is the CLI's saved state: which server to talk to, the API token
// for it, and the default workspace.
type Config struct {
	Server    string `json:"server,omitempty"`
	Token     string `json:"token,omitempty"`
	Workspace string `json:"workspace,omitempty"`
}

// configFileName is the file inside the config directory.
const configFileName = "config.json"

// maxConfigSize bounds how much is read from the config file.
const maxConfigSize = 64 << 10

// ErrInsecureConfig means the config file is readable by other users.
var ErrInsecureConfig = errors.New("config file permissions are too open")

// configDir returns $XDG_CONFIG_HOME/nook, or ~/.config/nook.
func configDir(getenv func(string) string) (string, error) {
	if x := getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "nook"), nil
	}
	home := getenv("HOME")
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("find home directory: %w", err)
		}
		home = h
	}
	return filepath.Join(home, ".config", "nook"), nil
}

// loadConfig reads the config file. A missing file is an empty config.
// On Unix the file holds a bearer token, so it is refused unless only its
// owner can read it (mode 0600 or stricter), the same rule ssh applies to
// private keys. Windows has no Unix modes; there the user profile ACLs
// protect the file.
func loadConfig(dir string) (Config, error) {
	path := filepath.Join(dir, configFileName)
	f, err := os.Open(path) //nolint:gosec // G304: the path is the user's own config directory.
	if errors.Is(err, fs.ErrNotExist) {
		return Config{}, nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return Config{}, fmt.Errorf("stat %s: %w", path, err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return Config{}, fmt.Errorf("%w: %s has mode %04o; run: chmod 600 %s", ErrInsecureConfig, path, info.Mode().Perm(), path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxConfigSize+1))
	if err != nil {
		return Config{}, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > maxConfigSize {
		return Config{}, fmt.Errorf("%s is larger than %d bytes", path, maxConfigSize)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return cfg, nil
}

// saveConfig writes the config with mode 0600 in a 0700 directory,
// replacing the file atomically.
func saveConfig(dir string, cfg Config) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: a directory needs the execute bit; 0700 is owner-only.
		return fmt.Errorf("secure %s: %w", dir, err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".config-*.json")
	if err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write config: %w", err)
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, configFileName)); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}
