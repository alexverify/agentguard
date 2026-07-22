package discover

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

// Zed keeps MCP servers under "context_servers" in settings.json — user-level
// and, overriding it, per-project in .zed/settings.json.
func TestZedDiscoversUserAndProjectContextServers(t *testing.T) {
	cfg := t.TempDir()
	proj := t.TempDir()
	writeFile(t, filepath.Join(cfg, "settings.json"), `{
  // Zed settings.json permits comments
  "context_servers": {
    "zed-global": {"command": "npx", "args": ["-y", "pkg"], "env": {}}
  }
}`)
	writeFile(t, filepath.Join(proj, ".zed", "settings.json"), `{
  "context_servers": {"zed-project": {"command": "./srv"}}
}`)

	d := &Zed{configDir: cfg}
	arts, err := d.Discover(context.Background(), []ports.Scope{
		{Kind: "global"}, {Kind: "project", Path: proj},
	})
	if err != nil {
		t.Fatal(err)
	}
	byName := byName(arts)
	for _, name := range []string{"zed-global", "zed-project"} {
		a, ok := byName[name]
		if !ok {
			t.Fatalf("zed server %q not discovered: %+v", name, arts)
		}
		if a.Tool != "zed" || a.Type != artifact.TypeMCPServer {
			t.Errorf("%q has wrong tool/type: %+v", name, a)
		}
	}
}

// A remote context server is declared by url rather than command.
func TestZedDiscoversRemoteContextServer(t *testing.T) {
	proj := t.TempDir()
	writeFile(t, filepath.Join(proj, ".zed", "settings.json"), `{
  "context_servers": {
    "remote": {"url": "https://mcp.example.com/v1", "headers": {"Authorization": "Bearer x"}}
  }
}`)
	d := &Zed{}
	arts, err := d.Discover(context.Background(), []ports.Scope{{Kind: "project", Path: proj}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := byName(arts)["remote"]; !ok {
		t.Errorf("remote context server not discovered: %+v", arts)
	}
}

// Settings with no context_servers block (the common case) yield nothing and no
// error — every Zed user has a settings.json, most have no MCP servers.
func TestZedSettingsWithoutContextServersIsQuiet(t *testing.T) {
	cfg := t.TempDir()
	writeFile(t, filepath.Join(cfg, "settings.json"), `{"theme": "One Dark", "vim_mode": true}`)
	d := &Zed{configDir: cfg}
	arts, err := d.Discover(context.Background(), []ports.Scope{{Kind: "global"}})
	if err != nil || len(arts) != 0 {
		t.Errorf("settings without MCP should yield nothing, no error: %v %+v", err, arts)
	}
}
