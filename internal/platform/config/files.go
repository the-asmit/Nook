package config

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
)

const (
	// fileSuffix marks a variable whose value is a path to read the real value from.
	fileSuffix = "_FILE"
	// varPrefix limits file resolution to Nook's own variables, so unrelated
	// variables that happen to end in _FILE are never read.
	varPrefix = "NOOK_"
	// maxFileSize bounds file reads so a wrong path (say /dev/zero) cannot
	// exhaust memory. Secrets such as URLs and keys are far smaller.
	maxFileSize = 64 << 10
)

// resolveFileVariables returns a copy of environ in which every NOOK_X_FILE
// variable has been replaced by NOOK_X holding the file's contents.
func resolveFileVariables(environ map[string]string) (map[string]string, error) {
	out := maps.Clone(environ)
	if out == nil {
		out = map[string]string{}
	}
	var errs []error
	// Sorted so that error messages come out in a stable order.
	for _, key := range slices.Sorted(maps.Keys(environ)) {
		path := environ[key]
		if len(key) <= len(varPrefix)+len(fileSuffix) ||
			!strings.HasPrefix(key, varPrefix) || !strings.HasSuffix(key, fileSuffix) {
			continue
		}
		target := strings.TrimSuffix(key, fileSuffix)
		delete(out, key)
		if _, set := environ[target]; set {
			errs = append(errs, fmt.Errorf("%s and %s are both set; use only one", target, key))
			continue
		}
		value, err := readBoundedFile(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", key, err))
			continue
		}
		out[target] = value
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return out, nil
}

func readBoundedFile(path string) (string, error) {
	if path == "" {
		return "", errors.New("path is empty")
	}
	f, err := os.Open(path) //nolint:gosec // The path comes from operator-controlled configuration by design.
	if err != nil {
		return "", fmt.Errorf("open file: %w", err)
	}
	// A close error on a read-only file cannot lose data, so it is ignored.
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return "", fmt.Errorf("read file: %w", err)
	}
	if len(data) > maxFileSize {
		return "", fmt.Errorf("file is larger than %d bytes", maxFileSize)
	}
	return strings.TrimRight(string(data), "\r\n"), nil
}
