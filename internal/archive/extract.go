package archive

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
)

// Limits bound what an archive may expand to.
type Limits struct {
	// MaxBytes is the total size of all extracted files.
	MaxBytes int64
	// MaxEntries is the number of archive entries.
	MaxEntries int
}

// ErrUnsafe means the archive tried to write outside the destination or
// contained an entry type that is never allowed.
var ErrUnsafe = errors.New("unsafe archive")

// maxNameLength bounds entry names and link targets.
const maxNameLength = 4096

// Extract unpacks a gzip-compressed tar archive into dest, which must be
// an existing, empty directory. Every archive is treated as hostile:
//
//   - names must be relative, without ".." components or NUL bytes;
//   - only directories, regular files, symbolic links and hard links are
//     allowed (no devices, FIFOs or other special files);
//   - link targets must stay inside dest;
//   - an entry may not replace one already extracted;
//   - all file system access goes through an os.Root opened at dest, which
//     refuses any operation that would leave it (for example through a
//     symbolic link), so even a missed case cannot escape;
//   - total size and entry count are limited.
//
// Modes are reduced to 0755 or 0644: no setuid, setgid or sticky bits.
func Extract(r io.Reader, dest string, limits Limits) error {
	root, err := os.OpenRoot(dest)
	if err != nil {
		return fmt.Errorf("open %s: %w", dest, err)
	}
	defer func() { _ = root.Close() }()

	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("%w: not a gzip stream: %w", ErrUnsafe, err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	var total int64
	entries := 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read archive: %w", err)
		}
		entries++
		if limits.MaxEntries > 0 && entries > limits.MaxEntries {
			return fmt.Errorf("%w: more than %d entries", ErrUnsafe, limits.MaxEntries)
		}
		name, err := cleanName(hdr.Name)
		if err != nil {
			return err
		}
		if name == "." {
			continue
		}
		// Link targets are checked against the entry's path as written,
		// which is only accurate if no directory on that path is itself a
		// link; and nothing may be created through a link anyway.
		if err := noLinkOnPath(root, name); err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(name, 0o755); err != nil {
				return fmt.Errorf("%w: directory %s: %w", ErrUnsafe, name, err)
			}
		case tar.TypeReg:
			if hdr.Size < 0 || (limits.MaxBytes > 0 && total+hdr.Size > limits.MaxBytes) {
				return fmt.Errorf("%w: extracted size exceeds %d bytes", ErrUnsafe, limits.MaxBytes)
			}
			total += hdr.Size
			if err := writeFile(root, name, hdr, tr); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if err := makeSymlink(root, name, hdr.Linkname); err != nil {
				return err
			}
		case tar.TypeLink:
			target, err := cleanName(hdr.Linkname)
			if err != nil || target == "." {
				return fmt.Errorf("%w: hard link %s has an invalid target", ErrUnsafe, name)
			}
			if err := noLinkOnPath(root, target); err != nil {
				return err
			}
			if info, err := root.Lstat(target); err != nil || !info.Mode().IsRegular() {
				return fmt.Errorf("%w: hard link %s must point to a regular file extracted earlier", ErrUnsafe, name)
			}
			if err := mkParent(root, name); err != nil {
				return err
			}
			if err := root.Link(target, name); err != nil {
				return fmt.Errorf("%w: hard link %s: %w", ErrUnsafe, name, err)
			}
		case tar.TypeXHeader, tar.TypeXGlobalHeader:
			// PAX metadata records are consumed by the tar reader itself.
		default:
			return fmt.Errorf("%w: %s has a forbidden type (%q)", ErrUnsafe, name, string(hdr.Typeflag))
		}
	}
}

// cleanName validates an entry name and returns it slash-cleaned.
func cleanName(raw string) (string, error) {
	if raw == "" || len(raw) > maxNameLength || strings.ContainsRune(raw, 0) || strings.Contains(raw, "\\") {
		return "", fmt.Errorf("%w: invalid entry name %q", ErrUnsafe, truncate(raw))
	}
	if path.IsAbs(raw) {
		return "", fmt.Errorf("%w: absolute path %q", ErrUnsafe, truncate(raw))
	}
	for _, part := range strings.Split(raw, "/") {
		if part == ".." {
			return "", fmt.Errorf("%w: path %q leaves the build directory", ErrUnsafe, truncate(raw))
		}
	}
	return path.Clean(raw), nil
}

// noLinkOnPath rejects name if any of its parent directories exists as a
// symbolic link.
func noLinkOnPath(root *os.Root, name string) error {
	parts := strings.Split(name, "/")
	for i := 1; i < len(parts); i++ {
		prefix := strings.Join(parts[:i], "/")
		info, err := root.Lstat(prefix)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: %s: %w", ErrUnsafe, prefix, err)
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%w: %s goes through the symbolic link %s", ErrUnsafe, name, prefix)
		}
	}
	return nil
}

func mkParent(root *os.Root, name string) error {
	if dir := path.Dir(name); dir != "." {
		if err := root.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("%w: directory for %s: %w", ErrUnsafe, name, err)
		}
	}
	return nil
}

func writeFile(root *os.Root, name string, hdr *tar.Header, src io.Reader) error {
	if err := mkParent(root, name); err != nil {
		return err
	}
	mode := fs.FileMode(0o644)
	if hdr.Mode&0o111 != 0 {
		mode = 0o755
	}
	// O_EXCL: an entry never replaces an earlier one (or a link).
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("%w: create %s: %w", ErrUnsafe, name, err)
	}
	n, copyErr := io.Copy(f, io.LimitReader(src, hdr.Size))
	closeErr := f.Close()
	if copyErr != nil {
		return fmt.Errorf("extract %s: %w", name, copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("extract %s: %w", name, closeErr)
	}
	if n != hdr.Size {
		return fmt.Errorf("extract %s: archive truncated", name)
	}
	return nil
}

func makeSymlink(root *os.Root, name, target string) error {
	if len(target) > maxNameLength || !linkInside(name, target) {
		return fmt.Errorf("%w: symbolic link %s points outside the build directory", ErrUnsafe, name)
	}
	if err := mkParent(root, name); err != nil {
		return err
	}
	if err := root.Symlink(target, name); err != nil {
		return fmt.Errorf("%w: symbolic link %s: %w", ErrUnsafe, name, err)
	}
	return nil
}

func truncate(s string) string {
	if len(s) > 80 {
		return s[:80] + "…"
	}
	return s
}
