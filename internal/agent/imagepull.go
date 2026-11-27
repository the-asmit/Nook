package agent

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/moby/moby/client"
)

// Media types of manifests the registry may hold.
const (
	mediaOCIIndex       = "application/vnd.oci.image.index.v1+json"
	mediaDockerList     = "application/vnd.docker.distribution.manifest.list.v2+json"
	mediaOCIManifest    = "application/vnd.oci.image.manifest.v1+json"
	mediaDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
)

// Pull limits.
const (
	maxManifestBytes = 4 << 20
	maxLayers        = 256
	// maxImageBytes bounds the total size of an app image.
	maxImageBytes = 20 << 30
)

type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	Platform  *struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
	} `json:"platform,omitempty"`
}

type manifest struct {
	MediaType string       `json:"mediaType"`
	Config    descriptor   `json:"config"`
	Layers    []descriptor `json:"layers"`
	Manifests []descriptor `json:"manifests"`
}

// puller fetches app images from Nook's registry itself and loads them
// into the Docker engine. The engine needs no registry configuration or
// credentials: the agent trusts Nook's CA, uses the short-lived pull token
// from the start command and verifies every blob's digest.
type puller struct {
	docker   *docker
	caPEM    func() []byte
	override string
	tmpDir   string
}

// imageRef is the local name of an app image: the registry repository and
// a tag derived from the digest (so a name always means one image).
func imageRef(registry, repo, digest string) string {
	return registry + "/" + repo + ":" + strings.Replace(digest, ":", "-", 1)
}

// ensure makes the image registry/repo@digest available locally under
// imageRef and returns that name.
func (p *puller) ensure(ctx context.Context, registry, repo, digest, token string) (string, error) {
	ref := imageRef(registry, repo, digest)
	inspectCtx, cancel := context.WithTimeout(ctx, dockerTimeout)
	_, err := p.docker.client.ImageInspect(inspectCtx, ref)
	cancel()
	if err == nil {
		return ref, nil
	}
	host := registry
	if p.override != "" {
		host = p.override
	}
	dir, err := os.MkdirTemp(p.tmpDir, "pull-")
	if err != nil {
		return "", fmt.Errorf("create pull directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	f := &fetcher{base: "https://" + host + "/v2/" + repo, token: token, dir: dir}
	if f.client, err = p.httpClient(); err != nil {
		return "", err
	}
	man, raw, mediaType, manDigest, err := f.platformManifest(ctx, digest)
	if err != nil {
		return "", err
	}
	blobs := append([]descriptor{man.Config}, man.Layers...)
	var total int64
	for _, b := range blobs {
		total += b.Size
		if b.Size < 0 || total > maxImageBytes {
			return "", errors.New("the image is too large")
		}
		if err := f.blob(ctx, b); err != nil {
			return "", err
		}
	}
	if err := p.load(ctx, dir, ref, manDigest, mediaType, raw, blobs); err != nil {
		return "", err
	}
	return ref, nil
}

func (p *puller) httpClient() (*http.Client, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(p.caPEM()) {
		return nil, errors.New("no CA certificate to verify the registry with")
	}
	return &http.Client{
		Timeout: 30 * time.Minute,
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
			ResponseHeaderTimeout: 30 * time.Second,
		},
		// The registry runs with redirects disabled; never follow one with
		// the token.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// fetcher downloads one repository's manifests and blobs.
type fetcher struct {
	client *http.Client
	base   string
	token  string
	dir    string
}

func (f *fetcher) get(ctx context.Context, path, accept string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.base+path, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("registry request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+f.token)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, fmt.Errorf("reach the registry: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("the registry answered HTTP %d for %s", resp.StatusCode, path)
	}
	return resp, nil
}

// manifestAt fetches and verifies the manifest (or index) with digest.
func (f *fetcher) manifestAt(ctx context.Context, digest string) (manifest, []byte, string, error) {
	resp, err := f.get(ctx, "/manifests/"+digest, strings.Join([]string{mediaOCIIndex, mediaDockerList, mediaOCIManifest, mediaDockerManifest}, ", "))
	if err != nil {
		return manifest{}, nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestBytes+1))
	if err != nil || len(raw) > maxManifestBytes {
		return manifest{}, nil, "", errors.New("could not read the image manifest")
	}
	if sum := sha256.Sum256(raw); "sha256:"+hex.EncodeToString(sum[:]) != digest {
		return manifest{}, nil, "", errors.New("the image manifest does not match its digest")
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return manifest{}, nil, "", errors.New("the image manifest is not valid JSON")
	}
	mediaType := m.MediaType
	if mediaType == "" {
		mediaType = strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0])
	}
	return m, raw, mediaType, nil
}

// platformManifest resolves digest to the image manifest for this node's
// platform (following an index if the digest names one).
func (f *fetcher) platformManifest(ctx context.Context, digest string) (manifest, []byte, string, string, error) {
	m, raw, mediaType, err := f.manifestAt(ctx, digest)
	if err != nil {
		return manifest{}, nil, "", "", err
	}
	if mediaType == mediaOCIIndex || mediaType == mediaDockerList || (len(m.Manifests) > 0 && len(m.Layers) == 0) {
		child := ""
		for _, d := range m.Manifests {
			if d.Platform != nil && d.Platform.OS == runtime.GOOS && d.Platform.Architecture == runtime.GOARCH && validDigest(d.Digest) {
				child = d.Digest
				break
			}
		}
		if child == "" {
			return manifest{}, nil, "", "", fmt.Errorf("the image has no variant for %s/%s", runtime.GOOS, runtime.GOARCH)
		}
		digest = child
		if m, raw, mediaType, err = f.manifestAt(ctx, digest); err != nil {
			return manifest{}, nil, "", "", err
		}
	}
	if mediaType != mediaOCIManifest && mediaType != mediaDockerManifest {
		return manifest{}, nil, "", "", fmt.Errorf("unsupported manifest type %q", mediaType)
	}
	if !validDigest(m.Config.Digest) || len(m.Layers) > maxLayers {
		return manifest{}, nil, "", "", errors.New("the image manifest is invalid")
	}
	for _, l := range m.Layers {
		if !validDigest(l.Digest) {
			return manifest{}, nil, "", "", errors.New("the image manifest is invalid")
		}
	}
	return m, raw, mediaType, digest, nil
}

func validDigest(d string) bool {
	return strings.HasPrefix(d, "sha256:") && sha256Pattern.MatchString(strings.TrimPrefix(d, "sha256:"))
}

// blob downloads a blob into the pull directory, verifying size and digest.
func (f *fetcher) blob(ctx context.Context, d descriptor) error {
	path := filepath.Join(f.dir, strings.TrimPrefix(d.Digest, "sha256:"))
	if _, err := os.Stat(path); err == nil {
		return nil // the same blob listed twice
	}
	resp, err := f.get(ctx, "/blobs/"+d.Digest, "")
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: a digest-named file in the agent's own pull directory.
	if err != nil {
		return fmt.Errorf("create blob file: %w", err)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(resp.Body, d.Size+1))
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("download image layer: %w", err)
	}
	if n != d.Size || "sha256:"+hex.EncodeToString(h.Sum(nil)) != d.Digest {
		return errors.New("an image layer does not match its digest")
	}
	return nil
}

// load streams an OCI image layout of the verified blobs into the engine,
// naming the image ref.
func (p *puller) load(ctx context.Context, dir, ref, manDigest, mediaType string, rawManifest []byte, blobs []descriptor) error {
	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(writeLayout(pw, dir, ref, manDigest, mediaType, rawManifest, blobs))
	}()
	ctx, cancel := context.WithTimeout(ctx, imagePullTimeout)
	defer cancel()
	res, err := p.docker.client.ImageLoad(ctx, pr, client.ImageLoadWithQuiet(true))
	if err != nil {
		_ = pr.CloseWithError(err)
		return fmt.Errorf("load the image into Docker: %w", err)
	}
	defer func() { _ = res.Close() }()
	body, _ := io.ReadAll(io.LimitReader(res, 1<<20))
	if strings.Contains(string(body), `"errorDetail"`) {
		return fmt.Errorf("load the image into Docker: %s", strings.TrimSpace(string(body)))
	}
	inspectCtx, cancelInspect := context.WithTimeout(ctx, dockerTimeout)
	defer cancelInspect()
	if _, err := p.docker.client.ImageInspect(inspectCtx, ref); err != nil {
		return fmt.Errorf("the loaded image is missing: %w", err)
	}
	return nil
}

func writeLayout(w io.Writer, dir, ref, manDigest, mediaType string, rawManifest []byte, blobs []descriptor) error {
	tw := tar.NewWriter(w)
	index, err := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     mediaOCIIndex,
		"manifests": []map[string]any{{
			"mediaType": mediaType, "digest": manDigest, "size": len(rawManifest),
			"annotations": map[string]string{
				"io.containerd.image.name":          ref,
				"org.opencontainers.image.ref.name": ref[strings.LastIndex(ref, ":")+1:],
			},
		}},
	})
	if err != nil {
		return fmt.Errorf("encode index: %w", err)
	}
	// Docker's classic image store (no containerd snapshotter) loads only
	// the docker-archive manifest; the containerd store reads index.json.
	// `docker save` writes both for the same reason.
	layers := make([]string, 0, len(blobs)-1)
	for _, b := range blobs[1:] {
		layers = append(layers, "blobs/sha256/"+strings.TrimPrefix(b.Digest, "sha256:"))
	}
	legacy, err := json.Marshal([]map[string]any{{
		"Config":   "blobs/sha256/" + strings.TrimPrefix(blobs[0].Digest, "sha256:"),
		"RepoTags": []string{ref},
		"Layers":   layers,
	}})
	if err != nil {
		return fmt.Errorf("encode manifest: %w", err)
	}
	files := []struct {
		name string
		data []byte
	}{
		{"oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`)},
		{"index.json", index},
		{"manifest.json", legacy},
		{"blobs/sha256/" + strings.TrimPrefix(manDigest, "sha256:"), rawManifest},
	}
	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.data)), Typeflag: tar.TypeReg}); err != nil {
			return fmt.Errorf("write layout: %w", err)
		}
		if _, err := tw.Write(f.data); err != nil {
			return fmt.Errorf("write layout: %w", err)
		}
	}
	written := map[string]bool{}
	for _, b := range blobs {
		hexd := strings.TrimPrefix(b.Digest, "sha256:")
		if written[hexd] {
			continue
		}
		written[hexd] = true
		if err := copyBlob(tw, filepath.Join(dir, hexd), "blobs/sha256/"+hexd, b.Size); err != nil {
			return err
		}
	}
	return tw.Close()
}

func copyBlob(tw *tar.Writer, path, name string, size int64) error {
	f, err := os.Open(path) //nolint:gosec // G304: a digest-named file in the agent's own pull directory.
	if err != nil {
		return fmt.Errorf("open blob: %w", err)
	}
	defer func() { _ = f.Close() }()
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: size, Typeflag: tar.TypeReg}); err != nil {
		return fmt.Errorf("write layout: %w", err)
	}
	if _, err := io.Copy(tw, f); err != nil {
		return fmt.Errorf("write layout: %w", err)
	}
	return nil
}
