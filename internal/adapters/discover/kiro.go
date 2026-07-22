package discover

import (
	"context"
	"os"
	"path/filepath"

	"github.com/alexverify/eyebrow/internal/adapters/parse"
	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

// Kiro discovers Kiro's MCP servers and steering files. Both are mirrored at
// two scopes: a workspace .kiro/ and a user-level ~/.kiro/ — settings/mcp.json
// in the canonical mcpServers shape, and steering/*.md, the markdown files that
// steer the agent (and so carry the same prompt-injection risk as any rules).
type Kiro struct {
	home string
}

// NewKiro constructs the discoverer.
func NewKiro() *Kiro {
	home, _ := os.UserHomeDir()
	return &Kiro{home: home}
}

// Tool returns the canonical tool id.
func (k *Kiro) Tool() string { return "kiro" }

// Discover satisfies ports.Discoverer.
func (k *Kiro) Discover(_ context.Context, scopes []ports.Scope) ([]artifact.Artifact, error) {
	var out []artifact.Artifact
	for _, sc := range scopes {
		switch sc.Kind {
		case "project":
			out = append(out, k.from(filepath.Join(sc.Path, ".kiro"), sc.String())...)
		case "global":
			if k.home != "" {
				out = append(out, k.from(filepath.Join(k.home, ".kiro"), "global")...)
			}
		}
	}
	return out, nil
}

// from reads both halves of one .kiro root, so the workspace and user scopes
// stay identical by construction.
func (k *Kiro) from(root, scope string) []artifact.Artifact {
	out := mcpServersFromConfig(k.Tool(), filepath.Join(root, "settings", "mcp.json"), scope, parse.JSON)
	return append(out, rulesFromDir(k.Tool(), filepath.Join(root, "steering"), scope, ".md")...)
}
