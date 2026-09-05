package discover

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

// OpenClaudeRegistry discovers the catalog of an OpenClaude skill registry
// repo (Gitlawb/openclaude-skills). The registry publishes registry.json, an
// array with one entry per skill carrying the path of its SKILL.md and the
// sha256 the openclaude client checks at install. That pin covers SKILL.md
// alone and is checked once; the adapter hashes the whole skill directory,
// fingerprints its egress, and carries the registry's own pin as
// Source.Integrity so the lockfile records what the registry promised beside
// what the tree hashes to.
//
// Discovery is gated on a root registry.json of that exact shape: an array
// whose entries name a SKILL.md path and a 64-hex sha256. Any other
// registry.json belongs to another project and the adapter stays inert.
type OpenClaudeRegistry struct{}

// NewOpenClaudeRegistry constructs the discoverer.
func NewOpenClaudeRegistry() *OpenClaudeRegistry { return &OpenClaudeRegistry{} }

// Tool returns the canonical tool id.
func (o *OpenClaudeRegistry) Tool() string { return "openclaude-registry" }

type registryEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

var sha256Hex = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// Discover satisfies ports.Discoverer. It only reports for project scopes
// whose root carries a registry.json in the OpenClaude registry shape.
func (o *OpenClaudeRegistry) Discover(_ context.Context, scopes []ports.Scope) ([]artifact.Artifact, error) {
	var out []artifact.Artifact
	for _, sc := range scopes {
		if sc.Kind != "project" || sc.Path == "" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(sc.Path, "registry.json"))
		if err != nil {
			continue
		}
		var entries []registryEntry
		if err := json.Unmarshal(raw, &entries); err != nil {
			continue // not an array: some other project's registry
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Path, "/SKILL.md") || !sha256Hex.MatchString(e.SHA256) {
				continue
			}
			rel := filepath.Clean(filepath.FromSlash(e.Path))
			if rel == "." || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
				continue // path escapes the repo
			}
			skillMd := filepath.Join(sc.Path, rel)
			if _, err := os.Stat(skillMd); err != nil {
				continue // listed but absent on disk
			}
			dir := filepath.Dir(skillMd)
			a := artifact.Artifact{
				Tool:  o.Tool(),
				Scope: sc.String(),
				Type:  artifact.TypeSkill,
				Name:  filepath.Base(dir),
				Source: artifact.Source{
					Kind:      artifact.SourceLocal,
					Ref:       dir,
					Integrity: "sha256-" + strings.ToLower(e.SHA256),
				},
				Capabilities:   capabilitiesFromSkill(skillMd),
				DiscoveredFrom: skillMd,
				Description:    frontmatterDescription(skillMd),
			}
			a.ID = artifact.MakeID(a.Tool, a.Scope, a.Type, a.Name)
			out = append(out, a)
		}
	}
	return out, nil
}
