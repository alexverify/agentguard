package discover

import (
	"context"
	"os"
	"path/filepath"

	"github.com/alexverify/eyebrow/internal/adapters/parse"
	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

// Droid discovers Factory Droid MCP servers from mcp.json
// (~/.factory/mcp.json user-scope, .factory/mcp.json project), in the canonical
// mcpServers shape.
type Droid struct {
	home string
}

// NewDroid constructs the discoverer.
func NewDroid() *Droid {
	home, _ := os.UserHomeDir()
	return &Droid{home: home}
}

// Tool returns the canonical tool id.
func (d *Droid) Tool() string { return "droid" }

// Discover satisfies ports.Discoverer.
func (d *Droid) Discover(_ context.Context, scopes []ports.Scope) ([]artifact.Artifact, error) {
	var out []artifact.Artifact
	for _, sc := range scopes {
		switch sc.Kind {
		case "project":
			out = append(out, mcpServersFromConfig(d.Tool(), filepath.Join(sc.Path, ".factory", "mcp.json"), sc.String(), parse.JSON)...)
		case "global":
			if d.home != "" {
				out = append(out, mcpServersFromConfig(d.Tool(), filepath.Join(d.home, ".factory", "mcp.json"), "global", parse.JSON)...)
			}
		}
	}
	return out, nil
}
