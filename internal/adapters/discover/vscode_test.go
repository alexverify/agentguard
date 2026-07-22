package discover

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

// VS Code keeps MCP servers under "servers" (not "mcpServers"), in a project
// .vscode/mcp.json and a user-level <config>/Code/User/mcp.json.
func TestVSCodeDiscoversUserAndProjectServers(t *testing.T) {
	cfg := t.TempDir()
	proj := t.TempDir()
	writeFile(t, filepath.Join(cfg, "Code", "User", "mcp.json"), `{
  // user-level servers may carry comments — mcp.json is JSONC
  "servers": {"vsc-global": {"type": "stdio", "command": "npx", "args": ["-y", "pkg"]}}
}`)
	writeFile(t, filepath.Join(proj, ".vscode", "mcp.json"), `{
  "inputs": [],
  "servers": {"vsc-project": {"command": "./srv"}}
}`)

	d := &VSCode{configDir: cfg}
	arts, err := d.Discover(context.Background(), []ports.Scope{
		{Kind: "global"}, {Kind: "project", Path: proj},
	})
	if err != nil {
		t.Fatal(err)
	}
	byName := byName(arts)
	for _, name := range []string{"vsc-global", "vsc-project"} {
		a, ok := byName[name]
		if !ok {
			t.Fatalf("vscode server %q not discovered: %+v", name, arts)
		}
		if a.Tool != "vscode" || a.Type != artifact.TypeMCPServer {
			t.Errorf("%q has wrong tool/type: %+v", name, a)
		}
	}
}

// A remote server declared by URL still resolves, and the "mcpServers" key is
// NOT read here — that shape belongs to other tools.
func TestVSCodeIgnoresMCPServersKey(t *testing.T) {
	proj := t.TempDir()
	writeFile(t, filepath.Join(proj, ".vscode", "mcp.json"), `{
  "mcpServers": {"wrong-key": {"command": "x"}},
  "servers": {"remote": {"type": "http", "url": "https://mcp.example.com/v1"}}
}`)

	d := &VSCode{}
	arts, err := d.Discover(context.Background(), []ports.Scope{{Kind: "project", Path: proj}})
	if err != nil {
		t.Fatal(err)
	}
	byName := byName(arts)
	if _, ok := byName["wrong-key"]; ok {
		t.Errorf("must not read the mcpServers key for VS Code: %+v", arts)
	}
	if _, ok := byName["remote"]; !ok {
		t.Errorf("remote (url) server not discovered: %+v", arts)
	}
}

// No config anywhere is not an error — discovery stays tolerant.
func TestVSCodeAbsentIsQuiet(t *testing.T) {
	d := &VSCode{configDir: t.TempDir()}
	arts, err := d.Discover(context.Background(), []ports.Scope{
		{Kind: "global"}, {Kind: "project", Path: t.TempDir()},
	})
	if err != nil || len(arts) != 0 {
		t.Errorf("absent config should yield nothing, no error: %v %+v", err, arts)
	}
}
