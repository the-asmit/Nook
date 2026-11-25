package agent

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// buildUID owns everything copied into the build container (the
// BuildKit image's unprivileged user).
const buildUID = 1000

// containerFiles streams, as a tar archive for CopyToContainer, the files
// the build container needs under /home/user: the extracted build
// context, the registry credentials (a short-lived token for one
// repository) and the CA that signs the registry's certificate.
func containerFiles(ctxDir string, cmd *agentv1.BuildCommand, caPEM []byte) io.ReadCloser {
	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(writeContainerFiles(pw, ctxDir, cmd, caPEM))
	}()
	return pr
}

func writeContainerFiles(w io.Writer, ctxDir string, cmd *agentv1.BuildCommand, caPEM []byte) error {
	tw := tar.NewWriter(w)
	now := time.Now()
	header := func(name string, typ byte, mode int64, size int64) *tar.Header {
		return &tar.Header{Name: name, Typeflag: typ, Mode: mode, Size: size, Uid: buildUID, Gid: buildUID, ModTime: now, Format: tar.FormatPAX}
	}
	for _, d := range []string{".docker/", ".config/", ".config/buildkit/", "out/", contextDir + "/"} {
		if err := tw.WriteHeader(header(d, tar.TypeDir, 0o700, 0)); err != nil {
			return err
		}
	}
	auth, err := json.Marshal(map[string]any{"auths": map[string]any{
		cmd.GetRegistry(): map[string]string{"registrytoken": cmd.GetRegistryToken()},
	}})
	if err != nil {
		return fmt.Errorf("encode registry credentials: %w", err)
	}
	// The registry address was validated (validateBuild), so it cannot
	// break out of the quoted TOML key.
	toml := fmt.Sprintf("[registry.%q]\n  ca = [%q]\n", cmd.GetRegistry(), containerHome+"/.config/buildkit/registry-ca.crt")
	for _, f := range []struct {
		name string
		data []byte
	}{
		{".docker/config.json", auth},
		{".config/buildkit/buildkitd.toml", []byte(toml)},
		{".config/buildkit/registry-ca.crt", caPEM},
	} {
		if hdrErr := tw.WriteHeader(header(f.name, tar.TypeReg, 0o600, int64(len(f.data)))); hdrErr != nil {
			return hdrErr
		}
		if _, err = tw.Write(f.data); err != nil {
			return err
		}
	}
	err = filepath.WalkDir(ctxDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == ctxDir {
			return err
		}
		rel, err := filepath.Rel(ctxDir, p)
		if err != nil {
			return err
		}
		name := contextDir + "/" + filepath.ToSlash(rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			return tw.WriteHeader(header(name+"/", tar.TypeDir, 0o755, 0))
		case info.Mode()&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			h := header(name, tar.TypeSymlink, 0o777, 0)
			h.Linkname = target
			return tw.WriteHeader(h)
		case info.Mode().IsRegular():
			return copyFile(tw, header(name, tar.TypeReg, int64(info.Mode().Perm()), info.Size()), p)
		default:
			return fmt.Errorf("unexpected file type at %s", name)
		}
	})
	if err != nil {
		return fmt.Errorf("pack build context: %w", err)
	}
	return tw.Close()
}

func copyFile(tw *tar.Writer, h *tar.Header, path string) error {
	f, err := os.Open(path) //nolint:gosec // G304: a file the agent extracted into its own build directory.
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if hdrErr := tw.WriteHeader(h); hdrErr != nil {
		return hdrErr
	}
	_, err = io.Copy(tw, io.LimitReader(f, h.Size))
	return err
}
