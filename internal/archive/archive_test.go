package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

// project creates files (name → content; a value starting with "->" makes
// a symbolic link) under a new directory.
func project(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if target, ok := strings.CutPrefix(content, "->"); ok {
			if err := os.Symlink(target, p); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func pack(t *testing.T, dir string, opts PackOptions) ([]byte, PackResult) {
	t.Helper()
	var buf bytes.Buffer
	res, err := Pack(dir, &buf, opts)
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), res
}

func entries(t *testing.T, archive []byte) []string {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var names []string
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if hdr.Typeflag == tar.TypeReg || hdr.Typeflag == tar.TypeSymlink {
			names = append(names, hdr.Name)
		}
	}
	return names
}

func TestPackHonorsIgnoreFiles(t *testing.T) {
	dir := project(t, map[string]string{
		"Dockerfile":               "FROM scratch\n",
		".dockerignore":            "node_modules\n*.log\n!keep.log\nDockerfile\n",
		".nookignore":              "secrets/\n",
		"main.go":                  "package main\n",
		"debug.log":                "x",
		"keep.log":                 "y",
		"node_modules/a/index.js":  "z",
		"secrets/token":            "s",
		".git/config":              "g",
		".nook/state":              "n",
		"credentials/config.json":  "c",
		"src/lib/util.go":          "package lib\n",
		"src/link-to-util":         "->lib/util.go",
		"src/lib/link-to-main.go":  "->../../main.go",
		"assets/images/logo.png":   "png",
		"assets/images/.gitignore": "",
	})
	data, res := pack(t, dir, PackOptions{ExcludeFiles: []string{filepath.Join(dir, "credentials", "config.json")}})
	got := entries(t, data)
	want := []string{
		".dockerignore", ".nookignore", "Dockerfile", "assets/images/.gitignore", "assets/images/logo.png",
		"keep.log", "main.go", "src/lib/link-to-main.go", "src/lib/util.go", "src/link-to-util",
	}
	sort.Strings(got)
	if !slices.Equal(got, want) {
		t.Fatalf("entries\n got %v\nwant %v", got, want)
	}
	if res.Files != 8 || res.Size != int64(len(data)) || len(res.SHA256) != 32 {
		t.Fatalf("result %+v", res)
	}
}

func TestPackRejectsLinksLeavingTheProject(t *testing.T) {
	for name, target := range map[string]string{
		"relative": "->../outside",
		"absolute": "->/etc/passwd",
		"deep":     "->a/../../outside",
	} {
		t.Run(name, func(t *testing.T) {
			dir := project(t, map[string]string{"Dockerfile": "FROM scratch\n", "evil": target})
			_, err := Pack(dir, &bytes.Buffer{}, PackOptions{})
			if err == nil || !strings.Contains(err.Error(), "points outside the project") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestPackIsReproducible(t *testing.T) {
	files := map[string]string{"Dockerfile": "FROM scratch\n", "b.txt": "b", "a/c.txt": "c", "run.sh": "#!/bin/sh\n"}
	d1, d2 := project(t, files), project(t, files)
	if err := os.Chmod(filepath.Join(d1, "run.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(d2, "run.sh"), 0o750); err != nil {
		t.Fatal(err)
	}
	// Different timestamps must not matter.
	old := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(filepath.Join(d2, "b.txt"), old, old); err != nil {
		t.Fatal(err)
	}
	a, ra := pack(t, d1, PackOptions{})
	b, rb := pack(t, d2, PackOptions{})
	if !bytes.Equal(a, b) || !bytes.Equal(ra.SHA256, rb.SHA256) {
		t.Fatal("identical projects produced different archives")
	}
	if err := os.WriteFile(filepath.Join(d2, "b.txt"), []byte("B"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, rc := pack(t, d2, PackOptions{}); bytes.Equal(rc.SHA256, ra.SHA256) {
		t.Fatal("changed content kept the same checksum")
	}
}

func TestPackSizeLimit(t *testing.T) {
	dir := project(t, map[string]string{"Dockerfile": "FROM scratch\n"})
	// Random bytes do not compress, so the archive is about as large.
	noise := make([]byte, 256<<10)
	_, _ = rand.Read(noise)
	if err := os.WriteFile(filepath.Join(dir, "blob.bin"), noise, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Pack(dir, &bytes.Buffer{}, PackOptions{MaxBytes: 64 << 10}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v", err)
	}
	if _, err := Pack(dir, &bytes.Buffer{}, PackOptions{MaxBytes: 1 << 20}); err != nil {
		t.Fatalf("within the limit: %v", err)
	}
}

func TestRoundTrip(t *testing.T) {
	dir := project(t, map[string]string{"Dockerfile": "FROM scratch\n", "a/b.txt": "hello", "link": "->a/b.txt"})
	data, _ := pack(t, dir, PackOptions{})
	dest := t.TempDir()
	if err := Extract(bytes.NewReader(data), dest, Limits{MaxBytes: 1 << 20, MaxEntries: 100}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "link"))
	if err != nil || string(got) != "hello" {
		t.Fatalf("link content %q %v", got, err)
	}
}

// hostile builds an archive from raw tar headers.
func hostile(t *testing.T, hdrs ...*tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, h := range hdrs {
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len("payload"))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			_, _ = tw.Write([]byte("payload"))
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func reg(name string) *tar.Header { return &tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o644} }

func TestExtractRejectsHostileArchives(t *testing.T) {
	cases := map[string][]*tar.Header{
		"path traversal":        {reg("../evil")},
		"nested traversal":      {reg("a/../../evil")},
		"absolute path":         {reg("/tmp/evil")},
		"backslash name":        {reg(`..\evil`)},
		"symlink out":           {{Typeflag: tar.TypeSymlink, Name: "l", Linkname: "../outside"}},
		"absolute symlink":      {{Typeflag: tar.TypeSymlink, Name: "l", Linkname: "/etc"}},
		"write through symlink": {{Typeflag: tar.TypeSymlink, Name: "l", Linkname: "."}, {Typeflag: tar.TypeSymlink, Name: "l/m", Linkname: ".."}},
		"symlink then file":     {{Typeflag: tar.TypeSymlink, Name: "a", Linkname: "b"}, {Typeflag: tar.TypeSymlink, Name: "b", Linkname: ".."}},
		"file through symlink":  {{Typeflag: tar.TypeSymlink, Name: "d", Linkname: "sub"}, reg("d/x")},
		"hard link to symlink":  {{Typeflag: tar.TypeSymlink, Name: "l", Linkname: "x"}, {Typeflag: tar.TypeLink, Name: "h", Linkname: "l"}},
		"hard link out":         {{Typeflag: tar.TypeLink, Name: "h", Linkname: "../../etc/passwd"}},
		"absolute hard link":    {{Typeflag: tar.TypeLink, Name: "h", Linkname: "/etc/passwd"}},
		"character device":      {{Typeflag: tar.TypeChar, Name: "null", Devmajor: 1, Devminor: 3}},
		"block device":          {{Typeflag: tar.TypeBlock, Name: "sda", Devmajor: 8}},
		"fifo":                  {{Typeflag: tar.TypeFifo, Name: "pipe"}},
		"overwrite earlier":     {reg("a"), reg("a")},
		"replace symlink":       {{Typeflag: tar.TypeSymlink, Name: "l", Linkname: "x"}, reg("l")},
	}
	for name, hdrs := range cases {
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			dest := filepath.Join(parent, "build")
			if err := os.Mkdir(dest, 0o700); err != nil {
				t.Fatal(err)
			}
			err := Extract(bytes.NewReader(hostile(t, hdrs...)), dest, Limits{MaxBytes: 1 << 20, MaxEntries: 100})
			if !errors.Is(err, ErrUnsafe) {
				t.Fatalf("err = %v, want ErrUnsafe", err)
			}
			// Nothing appeared next to the build directory.
			list, _ := os.ReadDir(parent)
			if len(list) != 1 || list[0].Name() != "build" {
				t.Fatalf("extraction touched the parent directory: %v", list)
			}
		})
	}
}

func TestExtractLimits(t *testing.T) {
	many := make([]*tar.Header, 0, 20)
	for i := range 20 {
		many = append(many, reg("f"+string(rune('a'+i))))
	}
	if err := Extract(bytes.NewReader(hostile(t, many...)), t.TempDir(), Limits{MaxBytes: 1 << 20, MaxEntries: 10}); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("entry limit: %v", err)
	}
	if err := Extract(bytes.NewReader(hostile(t, many...)), t.TempDir(), Limits{MaxBytes: 50, MaxEntries: 100}); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("size limit: %v", err)
	}
	if err := Extract(bytes.NewReader([]byte("not gzip")), t.TempDir(), Limits{}); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("garbage input: %v", err)
	}
}

func TestExtractStripsSpecialModeBits(t *testing.T) {
	dest := t.TempDir()
	h := reg("tool")
	h.Mode = 0o4755
	if err := Extract(bytes.NewReader(hostile(t, h)), dest, Limits{}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dest, "tool"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != 0 || info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("mode %v", info.Mode())
	}
}
