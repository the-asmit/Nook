package agent

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// The archive loads into both image stores: the OCI layout (containerd)
// and the docker-archive manifest (Docker's classic store, which ignores
// index.json and otherwise reads every directory as a v1 layer).
func TestWriteLayoutHasBothManifests(t *testing.T) {
	dir := t.TempDir()
	cfg, layer := descriptor{Digest: "sha256:" + hex64('c'), Size: 2}, descriptor{Digest: "sha256:" + hex64('l'), Size: 3}
	for d, data := range map[string]string{hex64('c'): "{}", hex64('l'): "abc"} {
		if err := os.WriteFile(filepath.Join(dir, d), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	ref := "registry:5000/ws/app:sha256-" + hex64('m')
	if err := writeLayout(&buf, dir, ref, "sha256:"+hex64('m'), mediaOCIManifest, []byte(`{"schemaVersion":2}`), []descriptor{cfg, layer, layer}); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	tr := tar.NewReader(&buf)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		files[h.Name], _ = io.ReadAll(tr)
	}
	for _, name := range []string{"oci-layout", "index.json", "manifest.json", "blobs/sha256/" + hex64('m'), "blobs/sha256/" + hex64('c'), "blobs/sha256/" + hex64('l')} {
		if _, ok := files[name]; !ok {
			t.Errorf("the archive lacks %s", name)
		}
	}
	var m []struct {
		Config   string
		RepoTags []string
		Layers   []string
	}
	if err := json.Unmarshal(files["manifest.json"], &m); err != nil || len(m) != 1 {
		t.Fatalf("manifest.json %s: %v", files["manifest.json"], err)
	}
	if m[0].Config != "blobs/sha256/"+hex64('c') || len(m[0].RepoTags) != 1 || m[0].RepoTags[0] != ref ||
		len(m[0].Layers) != 2 || m[0].Layers[0] != "blobs/sha256/"+hex64('l') {
		t.Fatalf("manifest.json %+v", m[0])
	}
}

func hex64(c byte) string { return string(bytes.Repeat([]byte{"0123456789abcdef"[c%16]}, 64)) }
