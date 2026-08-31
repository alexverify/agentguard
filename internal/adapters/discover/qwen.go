package discover

import (
	"context"
	"os"
	"path/filepath"

	"github.com/alexverify/eyebrow/internal/adapters/parse"
	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

// Qwen discovers Qwen Code MCP servers from settings.json
// (~/.qwen/settings.json user-scope, .qwen/settings.json project), the same
// canonical mcpServers shape Gemini CLI uses.
type Qwen struct {
	home string
}

// NewQwen constructs the discoverer.
func NewQwen() *Qwen {
	home, _ := os.UserHomeDir()
	return &Qwen{home: home}
}

// Tool returns the canonical tool id.
func (q *Qwen) Tool() string { return "qwen-code" }

// Discover satisfies ports.Discoverer.
func (q *Qwen) Discover(_ context.Context, scopes []ports.Scope) ([]artifact.Artifact, error) {
	var out []artifact.Artifact
	for _, sc := range scopes {
		switch sc.Kind {
		case "project":
			out = append(out, mcpServersFromConfig(q.Tool(), filepath.Join(sc.Path, ".qwen", "settings.json"), sc.String(), parse.JSON)...)
		case "global":
			if q.home != "" {
				out = append(out, mcpServersFromConfig(q.Tool(), filepath.Join(q.home, ".qwen", "settings.json"), "global", parse.JSON)...)
			}
		}
	}
	return out, nil
}
