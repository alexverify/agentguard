package discover

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

func TestClaudeDesktopDiscoversGlobalMCP(t *testing.T) {
	cfg := t.TempDir()
	writeFile(t, filepath.Join(cfg, "Claude", "claude_desktop_config.json"), `{
  "mcpServers": {
    "filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]},
    "remote": {"url": "https://api.example.com/sse"}
  }
}`)

	d := &ClaudeDesktop{configDir: cfg}
	arts, err := d.Discover(context.Background(), []ports.Scope{
		{Kind: "global"}, {Kind: "project", Path: t.TempDir()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.Tool() != "claude-desktop" {
		t.Errorf("Tool() = %q", d.Tool())
	}
	m := byName(arts)
	if a, ok := m["filesystem"]; !ok || a.Type != artifact.TypeMCPServer || a.Source.Kind != artifact.SourceNPM || a.Tool != "claude-desktop" {
		t.Errorf("filesystem server wrong: %+v", m["filesystem"])
	}
	if a, ok := m["remote"]; !ok || a.Source.Kind != artifact.SourceURL {
		t.Errorf("remote server wrong: %+v", m["remote"])
	}
}

// Claude Desktop is a global app: a project scope alone contributes nothing.
func TestClaudeDesktopIgnoresProjectScope(t *testing.T) {
	cfg := t.TempDir()
	writeFile(t, filepath.Join(cfg, "Claude", "claude_desktop_config.json"), `{
  "mcpServers": {"x": {"command": "node"}}
}`)
	d := &ClaudeDesktop{configDir: cfg}
	got, err := d.Discover(context.Background(), []ports.Scope{{Kind: "project", Path: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("project scope should yield nothing, got %+v", got)
	}
}

// A discoverer with no resolvable config dir stays quiet rather than erroring.
func TestClaudeDesktopNoConfigDir(t *testing.T) {
	d := &ClaudeDesktop{configDir: ""}
	got, err := d.Discover(context.Background(), []ports.Scope{{Kind: "global"}})
	if err != nil || got != nil {
		t.Errorf("empty config dir: got %+v, err %v", got, err)
	}
}
