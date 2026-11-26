//go:build integration

package testinfra

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"sync"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// BusyboxImage is the base image tests build from (pinned; pulled through
// the local Docker engine, then pushed into the test registry so builds
// need no internet access).
const BusyboxImage = "busybox:1.37@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"

// busybox caches the exported layer. Only success is cached: a failed
// pull (the network is flaky) is tried again by the next caller.
var busybox struct {
	mu    sync.Mutex
	layer []byte
}

// BusyboxLayer returns the busybox root file system as one uncompressed
// layer (exported from a container of BusyboxImage), built once.
func BusyboxLayer(ctx context.Context) ([]byte, error) {
	busybox.mu.Lock()
	defer busybox.mu.Unlock()
	if busybox.layer != nil {
		return busybox.layer, nil
	}
	layer, err := exportBusybox(ctx)
	if err != nil {
		return nil, err
	}
	busybox.layer = layer
	return layer, nil
}

func exportBusybox(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	d, err := client.New(client.FromEnv)
	if err != nil {
		return nil, fmt.Errorf("docker client: %w", err)
	}
	defer func() { _ = d.Close() }()
	// The reference is pinned by digest, so a local copy is the same
	// image; pull only when there is none.
	if _, inspectErr := d.ImageInspect(ctx, BusyboxImage); inspectErr != nil {
		pull, pullErr := d.ImagePull(ctx, BusyboxImage, client.ImagePullOptions{})
		if pullErr != nil {
			return nil, fmt.Errorf("pull %s: %w", BusyboxImage, pullErr)
		}
		if pullErr = pull.Wait(ctx); pullErr != nil {
			return nil, fmt.Errorf("pull %s: %w", BusyboxImage, pullErr)
		}
	}
	created, err := d.ContainerCreate(ctx, client.ContainerCreateOptions{Config: &container.Config{Image: BusyboxImage, Cmd: []string{"true"}}})
	if err != nil {
		return nil, fmt.Errorf("create busybox container: %w", err)
	}
	defer func() {
		_, _ = d.ContainerRemove(context.WithoutCancel(ctx), created.ID, client.ContainerRemoveOptions{Force: true})
	}()
	rc, err := d.ContainerExport(ctx, created.ID, client.ContainerExportOptions{})
	if err != nil {
		return nil, fmt.Errorf("export busybox: %w", err)
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("read busybox export: %w", err)
	}
	return data, nil
}

// PushImage pushes a one-layer image (layer is an uncompressed tar) whose
// config holds runConfig to repo:tag on the registry at addr (host:port,
// TLS verified with roots, token with push access) and returns the
// manifest digest.
func PushImage(ctx context.Context, addr string, roots *x509.CertPool, token, repo, tag string, layer []byte, runConfig map[string]any) (string, error) {
	hc := &http.Client{Timeout: 2 * time.Minute, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}}
	base := "https://" + addr
	type result struct {
		StatusCode int
		Header     http.Header
	}
	call := func(method, target, ctype string, body []byte) (result, error) {
		req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
		if err != nil {
			return result{}, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
		resp, err := hc.Do(req)
		if err != nil {
			return result{}, err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return result{StatusCode: resp.StatusCode, Header: resp.Header}, nil
	}
	digest := func(b []byte) string { s := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(s[:]) }
	cfg, err := json.Marshal(map[string]any{
		"architecture": runtime.GOARCH, "os": "linux", "config": runConfig,
		"rootfs": map[string]any{"type": "layers", "diff_ids": []string{digest(layer)}},
	})
	if err != nil {
		return "", err
	}
	for _, blob := range [][]byte{cfg, layer} {
		start, callErr := call(http.MethodPost, base+"/v2/"+repo+"/blobs/uploads/", "", nil)
		if callErr != nil {
			return "", callErr
		}
		loc, parseErr := url.Parse(start.Header.Get("Location"))
		if parseErr != nil || start.StatusCode != http.StatusAccepted {
			return "", fmt.Errorf("start upload: HTTP %d", start.StatusCode)
		}
		q := loc.Query()
		q.Set("digest", digest(blob))
		loc.RawQuery = q.Encode()
		done, putErr := call(http.MethodPut, base+loc.RequestURI(), "application/octet-stream", blob)
		if putErr != nil {
			return "", putErr
		}
		if done.StatusCode != http.StatusCreated {
			return "", fmt.Errorf("finish upload: HTTP %d", done.StatusCode)
		}
	}
	manifest, err := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": digest(cfg), "size": len(cfg)},
		"layers": []any{map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": digest(layer), "size": len(layer)}},
	})
	if err != nil {
		return "", err
	}
	resp, err := call(http.MethodPut, base+"/v2/"+repo+"/manifests/"+tag, "application/vnd.oci.image.manifest.v1+json", manifest)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("push manifest: HTTP %d", resp.StatusCode)
	}
	return digest(manifest), nil
}
