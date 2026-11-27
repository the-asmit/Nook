//go:build integration

package agent

import (
	"testing"

	"github.com/the-asmit/nook/internal/platform/config"
	"github.com/the-asmit/nook/internal/testinfra"
)

// The tests' routing helper runs the agent's firewall image.
func TestRoutingHelperUsesTheFirewallImage(t *testing.T) {
	cfg, err := config.Load[Config](map[string]string{"NOOK_AGENT_ADVERTISE_ADDR": "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FirewallImage != testinfra.IPTablesImage {
		t.Fatalf("testinfra.IPTablesImage %q differs from the agent's default %q", testinfra.IPTablesImage, cfg.FirewallImage)
	}
}
