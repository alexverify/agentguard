package discover

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

// Kiro carries both halves at each scope: MCP servers in settings/mcp.json and
// steering files (markdown context/rules) in steering/*.md — workspace under
// .kiro/, user under ~/.kiro/.
func TestKiroDiscoversMCPAndSteeringAtBothScopes(t *testing.T) {
	home := t.TempDir()
	proj := t.TempDir()
	writeFile(t, filepath.Join(home, ".kiro", "settings", "mcp.json"), `{
  "mcpServers": {"kiro-global": {"command": "uvx", "args": ["pkg@latest"]}}
}`)
	writeFile(t, filepath.Join(home, ".kiro", "steering", "house-style.md"), "# house style\nalways review\n")
	writeFile(t, filepath.Join(proj, ".kiro", "settings", "mcp.json"), `{
  "mcpServers": {"kiro-project": {"command": "./srv"}}
}`)
	writeFile(t, filepath.Join(proj, ".kiro", "steering", "product.md"), "# product\ncontext here\n")

	d := &Kiro{home: home}
	arts, err := d.Discover(context.Background(), []ports.Scope{
		{Kind: "global"}, {Kind: "project", Path: proj},
	})
	if err != nil {
		t.Fatal(err)
	}
	byName := byName(arts)
	for _, name := range []string{"kiro-global", "kiro-project"} {
		if a, ok := byName[name]; !ok || a.Type != artifact.TypeMCPServer || a.Tool != "kiro" {
			t.Errorf("kiro server %q not discovered: %+v", name, arts)
		}
	}
	// Steering files are rules: they steer the agent, so they are exactly the
	// prompt-injection surface the analyzer needs to see.
	for _, name := range []string{"house-style", "product"} {
		if a, ok := byName[name]; !ok || a.Type != artifact.TypeRules {
			t.Errorf("kiro steering file %q not discovered as rules: %+v", name, arts)
		}
	}
}

// Nothing installed is not an error.
func TestKiroAbsentIsQuiet(t *testing.T) {
	d := &Kiro{home: t.TempDir()}
	arts, err := d.Discover(context.Background(), []ports.Scope{
		{Kind: "global"}, {Kind: "project", Path: t.TempDir()},
	})
	if err != nil || len(arts) != 0 {
		t.Errorf("absent config should yield nothing, no error: %v %+v", err, arts)
	}
}
