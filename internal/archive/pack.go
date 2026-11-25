// Package archive packs a project folder into the source archive `nook
// deploy` uploads, and extracts such archives on worker nodes without
// letting a malicious archive touch anything outside the build directory.
package archive

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/moby/patternmatcher"
	"github.com/moby/patternmatcher/ignorefile"
)

// Ignore files read from the project root. Both use .dockerignore syntax
// and both apply: .dockerignore keeps the archive in line with what Docker
// would send, .nookignore excludes what only Nook should skip.
const (
	DockerIgnoreFile = ".dockerignore"
	NookIgnoreFile   = ".nookignore"
)

// alwaysExcluded never leave the developer's machine, whatever the ignore
// files say: version-control history and Nook's own local state.
var alwaysExcluded = []string{".git", ".nook"}

// epoch is the timestamp of every archive entry, so archives depend only
// on file names, contents and modes.
var epoch = time.Unix(0, 0).UTC()

// ErrTooLarge means the archive would exceed the size limit.
var ErrTooLarge = errors.New("source archive exceeds the size limit")

// PackOptions configure Pack.
type PackOptions struct {
	// MaxBytes limits the compressed archive size.
	MaxBytes int64
	// ExcludeFiles are absolute paths that must never be packed, such as
	// the CLI's credentials file if it lives inside the project.
	ExcludeFiles []string
	// Progress, if set, is called after each file with running totals.
	Progress func(files int, bytes int64)
}

// PackResult describes a packed archive.
type PackResult struct {
	SHA256 []byte
	// Size is the archive's (compressed) size in bytes.
	Size  int64
	Files int
}

// Pack writes dir as a gzip-compressed tar archive to w. The archive is
// reproducible: entries are sorted, timestamps fixed and ownership
// cleared, so the same files always produce the same bytes and checksum.
// Symbolic links are kept but must point inside dir.
func Pack(dir string, w io.Writer, opts PackOptions) (PackResult, error) {
	root, err := filepath.Abs(dir)
	if err != nil {
		return PackResult{}, fmt.Errorf("resolve %s: %w", dir, err)
	}
	pm, err := loadIgnore(root)
	if err != nil {
		return PackResult{}, err
	}
	excluded := map[string]bool{}
	for _, f := range opts.ExcludeFiles {
		if abs, absErr := filepath.Abs(f); absErr == nil {
			excluded[abs] = true
		}
	}

	out := &limitedWriter{w: w, limit: opts.MaxBytes, hash: sha256.New()}
	gz, err := gzip.NewWriterLevel(out, gzip.BestCompression)
	if err != nil {
		return PackResult{}, fmt.Errorf("gzip: %w", err)
	}
	tw := tar.NewWriter(gz)
	p := &packer{root: root, pm: pm, excluded: excluded, tw: tw, opts: opts}
	if err := filepath.WalkDir(root, p.visit); err != nil {
		if out.exceeded {
			return PackResult{}, ErrTooLarge
		}
		return PackResult{}, err
	}
	if err := tw.Close(); err != nil {
		return PackResult{}, p.writeErr(err, out)
	}
	if err := gz.Close(); err != nil {
		return PackResult{}, p.writeErr(err, out)
	}
	if p.files == 0 {
		return PackResult{}, fmt.Errorf("%s contains no files to deploy", dir)
	}
	return PackResult{SHA256: out.hash.Sum(nil), Size: out.n, Files: p.files}, nil
}

func loadIgnore(root string) (*patternmatcher.PatternMatcher, error) {
	var patterns []string
	for _, name := range []string{DockerIgnoreFile, NookIgnoreFile} {
		f, err := os.Open(filepath.Join(root, name)) //nolint:gosec // G304: an ignore file inside the project being packed.
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		p, err := ignorefile.ReadAll(f)
		_ = f.Close()
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
		patterns = append(patterns, p...)
	}
	pm, err := patternmatcher.New(patterns)
	if err != nil {
		return nil, fmt.Errorf("ignore patterns: %w", err)
	}
	return pm, nil
}

type packer struct {
	root     string
	pm       *patternmatcher.PatternMatcher
	excluded map[string]bool
	tw       *tar.Writer
	opts     PackOptions
	files    int
	bytes    int64
}

func (p *packer) visit(abs string, d fs.DirEntry, err error) error {
	if err != nil {
		return fmt.Errorf("read %s: %w", abs, err)
	}
	if abs == p.root {
		return nil
	}
	rel, err := filepath.Rel(p.root, abs)
	if err != nil {
		return fmt.Errorf("relative path of %s: %w", abs, err)
	}
	name := filepath.ToSlash(rel)
	skip, err := p.skip(name, abs)
	if err != nil {
		return err
	}
	if skip {
		if d.IsDir() && !p.pm.Exclusions() {
			return filepath.SkipDir
		}
		return nil
	}
	info, err := d.Info()
	if err != nil {
		return fmt.Errorf("stat %s: %w", name, err)
	}
	hdr := &tar.Header{Name: name, ModTime: epoch, Format: tar.FormatPAX}
	switch {
	case d.IsDir():
		hdr.Typeflag, hdr.Name, hdr.Mode = tar.TypeDir, name+"/", 0o755
		return p.tw.WriteHeader(hdr)
	case info.Mode()&fs.ModeSymlink != 0:
		target, err := os.Readlink(abs)
		if err != nil {
			return fmt.Errorf("read link %s: %w", name, err)
		}
		if !linkInside(name, filepath.ToSlash(target)) {
			return fmt.Errorf("symbolic link %s points outside the project (%s); remove it or add it to %s", name, target, NookIgnoreFile)
		}
		hdr.Typeflag, hdr.Linkname, hdr.Mode = tar.TypeSymlink, filepath.ToSlash(target), 0o777
		return p.tw.WriteHeader(hdr)
	case info.Mode().IsRegular():
		return p.addFile(hdr, abs, info)
	default:
		return fmt.Errorf("%s is not a regular file, directory or symbolic link; add it to %s", name, NookIgnoreFile)
	}
}

// skip decides whether an entry is left out of the archive.
func (p *packer) skip(name, abs string) (bool, error) {
	for _, ex := range alwaysExcluded {
		if name == ex || strings.HasPrefix(name, ex+"/") {
			return true, nil
		}
	}
	if p.excluded[abs] {
		return true, nil
	}
	// Docker always sends the Dockerfile, even if an ignore file matches it.
	if name == "Dockerfile" {
		return false, nil
	}
	matched, err := p.pm.MatchesOrParentMatches(name)
	if err != nil {
		return false, fmt.Errorf("match %s: %w", name, err)
	}
	return matched, nil
}

func (p *packer) addFile(hdr *tar.Header, abs string, info fs.FileInfo) error {
	hdr.Typeflag, hdr.Size, hdr.Mode = tar.TypeReg, info.Size(), 0o644
	if info.Mode()&0o111 != 0 {
		hdr.Mode = 0o755
	}
	f, err := os.Open(abs) //nolint:gosec // G304: a file inside the project being packed.
	if err != nil {
		return fmt.Errorf("open %s: %w", hdr.Name, err)
	}
	defer func() { _ = f.Close() }()
	if hdrErr := p.tw.WriteHeader(hdr); hdrErr != nil {
		return hdrErr
	}
	n, err := io.Copy(p.tw, io.LimitReader(f, hdr.Size))
	if err != nil {
		return err
	}
	if n != hdr.Size {
		return fmt.Errorf("%s changed while it was being packed", hdr.Name)
	}
	p.files++
	p.bytes += n
	if p.opts.Progress != nil {
		p.opts.Progress(p.files, p.bytes)
	}
	return nil
}

func (p *packer) writeErr(err error, out *limitedWriter) error {
	if out.exceeded {
		return ErrTooLarge
	}
	return fmt.Errorf("write archive: %w", err)
}

// linkInside reports whether a symbolic link at name (slash-separated,
// relative to the root) with target stays inside the root.
func linkInside(name, target string) bool {
	if target == "" || path.IsAbs(target) || strings.Contains(target, "\x00") {
		return false
	}
	resolved := path.Clean(path.Join(path.Dir(name), target))
	return resolved != ".." && !strings.HasPrefix(resolved, "../")
}

// limitedWriter counts, hashes and limits what is written.
type limitedWriter struct {
	w        io.Writer
	limit    int64
	n        int64
	hash     hash.Hash
	exceeded bool
}

func (l *limitedWriter) Write(b []byte) (int, error) {
	if l.limit > 0 && l.n+int64(len(b)) > l.limit {
		l.exceeded = true
		return 0, ErrTooLarge
	}
	n, err := l.w.Write(b)
	l.n += int64(n)
	l.hash.Write(b[:n])
	return n, err
}
