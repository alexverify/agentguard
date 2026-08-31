package discover

import (
	"context"
	"os"
	"path/filepath"

	"github.com/alexverify/eyebrow/internal/adapters/parse"
	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

// Kimi discovers Kimi CLI MCP servers. Kimi is launch-scoped: it has no project
// config file, only a user-scope ~/.kimi/mcp.json in the canonical mcpServers
// shape. So only the global scope resolves a path; a project scope carries no
// kimi config.
type Kimi struct {
	home string
}

// NewKimi constructs the discoverer.
func NewKimi() *Kimi {
	home, _ := os.UserHomeDir()
	return &Kimi{home: home}
}

// Tool returns the canonical tool id.
func (k *Kimi) Tool() string { return "kimi" }

// Discover satisfies ports.Discoverer.
func (k *Kimi) Discover(_ context.Context, scopes []ports.Scope) ([]artifact.Artifact, error) {
	var out []artifact.Artifact
	for _, sc := range scopes {
		if sc.Kind == "global" && k.home != "" {
			out = append(out, mcpServersFromConfig(k.Tool(), filepath.Join(k.home, ".kimi", "mcp.json"), "global", parse.JSON)...)
		}
	}
	return out, nil
}
