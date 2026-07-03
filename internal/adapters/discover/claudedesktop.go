package discover

import (
	"context"
	"os"
	"path/filepath"

	"github.com/alexverify/eyebrow/internal/adapters/parse"
	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

// ClaudeDesktop discovers Claude Desktop's MCP servers. Unlike Claude Code
// (project + user config), Claude Desktop is a single global app config at
// <user-config-dir>/Claude/claude_desktop_config.json — Application Support on
// macOS, %AppData% on Windows, ~/.config on Linux — in the canonical mcpServers
// shape.
type ClaudeDesktop struct {
	configDir string
}

// NewClaudeDesktop constructs the discoverer, resolving the per-OS config dir.
func NewClaudeDesktop() *ClaudeDesktop {
	dir, _ := os.UserConfigDir()
	return &ClaudeDesktop{configDir: dir}
}

// Tool returns the canonical tool id.
func (d *ClaudeDesktop) Tool() string { return "claude-desktop" }

// Discover satisfies ports.Discoverer. Claude Desktop has no project-scoped
// config, so only the global scope contributes.
func (d *ClaudeDesktop) Discover(_ context.Context, scopes []ports.Scope) ([]artifact.Artifact, error) {
	if d.configDir == "" {
		return nil, nil
	}
	config := filepath.Join(d.configDir, "Claude", "claude_desktop_config.json")
	var out []artifact.Artifact
	for _, sc := range scopes {
		if sc.Kind == "global" {
			out = append(out, mcpServersFromConfig(d.Tool(), config, "global", parse.JSON)...)
		}
	}
	return out, nil
}
