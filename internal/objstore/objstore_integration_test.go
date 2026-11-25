//go:build integration

package objstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"

	"github.com/the-asmit/nook/internal/platform/config"
	"github.com/the-asmit/nook/internal/testinfra"
)

func startMinIO(t *testing.T) *Client {
	t.Helper()
	ctx := context.Background()
	nw, err := testinfra.NewNetwork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nw.Remove(context.Background()) })
	m, err := testinfra.StartMinIO(ctx, nw)
	testcontainers.CleanupContainer(t, m)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.CreateBucket(ctx, "nook-test"); err != nil {
		t.Fatal(err)
	}
	c, err := New(&Config{Endpoint: m.URL, Region: "us-east-1", Bucket: "nook-test", AccessKeyID: m.AccessKey,
		SecretAccessKey: config.NewSecret(m.SecretKey), RequestTimeout: 10 * time.Second}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// upload performs a presigned upload the way the CLI does.
func upload(ctx context.Context, t *testing.T, up Upload, body []byte) int {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, up.Method, up.URL, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range up.Headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func TestPresignedUploadIsVerified(t *testing.T) {
	c := startMinIO(t)
	ctx := context.Background()
	body := []byte(strings.Repeat("nook source archive ", 100))
	sum := sha256.Sum256(body)

	t.Run("exact size and checksum", func(t *testing.T) {
		up := c.PresignPut("sources/ok.tar.gz", int64(len(body)), sum[:], time.Minute)
		if code := upload(ctx, t, up, body); code != http.StatusOK {
			t.Fatalf("upload: HTTP %d", code)
		}
		info, err := c.Head(ctx, "sources/ok.tar.gz")
		if err != nil {
			t.Fatal(err)
		}
		if info.Size != int64(len(body)) || !bytes.Equal(info.SHA256, sum[:]) {
			t.Fatalf("head %+v", info)
		}
	})
	t.Run("other content with the same length", func(t *testing.T) {
		up := c.PresignPut("sources/tampered.tar.gz", int64(len(body)), sum[:], time.Minute)
		tampered := bytes.Clone(body)
		tampered[0] ^= 1
		if code := upload(ctx, t, up, tampered); code < 400 {
			t.Fatalf("tampered upload accepted: HTTP %d", code)
		}
		if _, err := c.Head(ctx, "sources/tampered.tar.gz"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("tampered object stored: %v", err)
		}
	})
	t.Run("wrong size", func(t *testing.T) {
		up := c.PresignPut("sources/short.tar.gz", int64(len(body)), sum[:], time.Minute)
		if code := upload(ctx, t, up, body[:len(body)-1]); code < 400 {
			t.Fatalf("short upload accepted: HTTP %d", code)
		}
	})
	t.Run("expired URL", func(t *testing.T) {
		c.now = func() time.Time { return time.Now().Add(-2 * time.Minute) }
		up := c.PresignPut("sources/late.tar.gz", int64(len(body)), sum[:], time.Minute)
		c.now = time.Now
		if code := upload(ctx, t, up, body); code != http.StatusForbidden {
			t.Fatalf("expired URL: HTTP %d", code)
		}
	})
	t.Run("presigned download", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.PresignGet("sources/ok.tar.gz", time.Minute), http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		got, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK || !bytes.Equal(got, body) {
			t.Fatalf("download: HTTP %d, %d bytes", resp.StatusCode, len(got))
		}
	})
}

func TestPutGetDelete(t *testing.T) {
	c := startMinIO(t)
	ctx := context.Background()
	if err := c.Put(ctx, "logs/a.log", "text/plain; charset=utf-8", []byte("line 1\nline 2\n")); err != nil {
		t.Fatal(err)
	}
	got, err := c.Get(ctx, "logs/a.log", 1<<20)
	if err != nil || string(got) != "line 1\nline 2\n" {
		t.Fatalf("get: %q %v", got, err)
	}
	if _, err := c.Get(ctx, "logs/a.log", 3); err == nil {
		t.Fatal("size limit not enforced")
	}
	if err := c.Delete(ctx, "logs/a.log"); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(ctx, "logs/a.log"); err != nil {
		t.Fatalf("deleting a missing object: %v", err)
	}
	if _, err := c.Get(ctx, "logs/a.log", 1<<20); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
}
