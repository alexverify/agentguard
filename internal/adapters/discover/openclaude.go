package discover

import (
	"context"
	"os"
	"path/filepath"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

// OpenClaude discovers OpenClaude skills. Installs land in
// .openclaude/skills (project) and ~/.openclaude/skills (global), one
// directory per skill with a SKILL.md; registry installs also persist a
// skill.json sidecar carrying the registry's sha256 pin. MCP servers are
// configured through .mcp.json, which the Claude Code discoverer already
// reports, so this adapter covers skills only.
type OpenClaude struct {
	home string
}

// NewOpenClaude constructs the discoverer.
func NewOpenClaude() *OpenClaude {
	home, _ := os.UserHomeDir()
	return &OpenClaude{home: home}
}

// Tool returns the canonical tool id.
func (o *OpenClaude) Tool() string { return "openclaude" }

// Discover satisfies ports.Discoverer.
func (o *OpenClaude) Discover(_ context.Context, scopes []ports.Scope) ([]artifact.Artifact, error) {
	var out []artifact.Artifact
	for _, sc := range scopes {
		switch sc.Kind {
		case "project":
			out = append(out, o.skills(filepath.Join(sc.Path, ".openclaude", "skills"), sc.String())...)
		case "global":
			if o.home != "" {
				out = append(out, o.skills(filepath.Join(o.home, ".openclaude", "skills"), "global")...)
			}
		}
	}
	return out, nil
}

// skills enumerates one skills directory and fingerprints each skill's egress
// the same way the AEON adapter does. OpenClaude verifies the registry hash at
// install time only, so the fingerprint is what makes a later edit that adds a
// call to a new host read as a capability change rather than plain drift.
func (o *OpenClaude) skills(dir, scope string) []artifact.Artifact {
	skills := skillsFromDir(o.Tool(), dir, scope)
	for i := range skills {
		skills[i].Capabilities = capabilitiesFromSkill(skills[i].DiscoveredFrom)
	}
	return skills
}
