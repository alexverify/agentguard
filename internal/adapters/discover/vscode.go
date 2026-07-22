package discover

import (
	"context"
	"os"
	"path/filepath"

	"github.com/alexverify/eyebrow/internal/adapters/parse"
	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

// VSCode discovers Visual Studio Code's native MCP servers. Two locations: a
// per-project .vscode/mcp.json and a user-level <user-config-dir>/Code/User/
// mcp.json — Application Support on macOS, %AppData% on Windows, ~/.config on
// Linux, which os.UserConfigDir already maps for us.
//
// VS Code nests declarations under "servers" rather than the "mcpServers" key
// every other tool uses, and the file is JSONC (the editor writes comments into
// it), so it needs its own parse step but shares all downstream normalization.
type VSCode struct {
	configDir string
}

// NewVSCode constructs the discoverer, resolving the per-OS config dir.
func NewVSCode() *VSCode {
	dir, _ := os.UserConfigDir()
	return &VSCode{configDir: dir}
}

// Tool returns the canonical tool id.
func (v *VSCode) Tool() string { return "vscode" }

// Discover satisfies ports.Discoverer.
func (v *VSCode) Discover(_ context.Context, scopes []ports.Scope) ([]artifact.Artifact, error) {
	var out []artifact.Artifact
	for _, sc := range scopes {
		switch sc.Kind {
		case "project":
			out = append(out, v.serversFrom(filepath.Join(sc.Path, ".vscode", "mcp.json"), sc.String())...)
		case "global":
			if v.configDir != "" {
				out = append(out, v.serversFrom(filepath.Join(v.configDir, "Code", "User", "mcp.json"), "global")...)
			}
		}
	}
	return out, nil
}

// vsCodeConfig is mcp.json's shape. Only "servers" is read: a stray
// "mcpServers" key here is another tool's convention, not VS Code's, and
// claiming it would attribute artifacts to the wrong tool.
type vsCodeConfig struct {
	Servers map[string]mcpDecl `json:"servers"`
}

// serversFrom parses one mcp.json. A missing or unparseable file yields nothing
// and no error — discovery stays tolerant, same as every other adapter.
func (v *VSCode) serversFrom(path, scope string) []artifact.Artifact {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var cfg vsCodeConfig
	if err := parse.JSONC(b, &cfg); err != nil {
		return nil
	}
	return mcpArtifactsFrom(v.Tool(), path, scope, cfg.Servers)
}
