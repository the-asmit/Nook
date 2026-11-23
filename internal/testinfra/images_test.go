//go:build integration

package testinfra

import (
	"os"
	"strings"
	"testing"
)

// TestImagesMatchComposeFile keeps the integration-test images and the
// developer stack on identical versions.
func TestImagesMatchComposeFile(t *testing.T) {
	data, err := os.ReadFile("../../deploy/compose/docker-compose.dev.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, img := range []string{PostgresImage, RedisImage} {
		if !strings.Contains(string(data), "image: "+img+"\n") {
			t.Errorf("compose file does not use %s", img)
		}
	}
}
