package discover

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

// Kimi CLI is launch-scoped: it has no project config file, only a user-scope
// ~/.kimi/mcp.json in the canonical mcpServers shape.
func TestKimiDiscoversMCPFromUserConfig(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".kimi", "mcp.json"), `{
		"mcpServers": {
			"vex": { "command": "/abs/vex-mcp", "args": ["--project", "abc"] }
		}
	}`)

	k := &Kimi{home: home}
	if k.Tool() != "kimi" {
		t.Fatalf("Tool() = %q", k.Tool())
	}
	arts, err := k.Discover(context.Background(), []ports.Scope{{Kind: "global"}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	m := byName(arts)
	if m["vex"].Type != artifact.TypeMCPServer || m["vex"].Tool != "kimi" {
		t.Errorf("vex server not discovered: %+v", arts)
	}
}

// A project scope carries no kimi config, and nothing installed is not an error.
func TestKimiAbsentIsQuiet(t *testing.T) {
	k := &Kimi{home: t.TempDir()}
	arts, err := k.Discover(context.Background(), []ports.Scope{
		{Kind: "global"}, {Kind: "project", Path: t.TempDir()},
	})
	if err != nil || len(arts) != 0 {
		t.Errorf("absent config should yield nothing, no error: %v %+v", err, arts)
	}
}
