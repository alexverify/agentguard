package discover

import (
	"context"
	"os"
	"path/filepath"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

// Aeon discovers skills published by an AEON agent repo. AEON keeps its skills
// at a top-level skills/<slug>/SKILL.md — not under .claude/skills like the
// per-tool adapters expect — so without this a scan of an AEON checkout sees
// almost nothing. Discovery is gated on AEON's aeon.yml marker so the adapter
// is inert for every other repo: a plain skills/ directory elsewhere must not
// get AEON artifacts injected into its scan.
type Aeon struct{}

// NewAeon constructs the AEON skills discoverer.
func NewAeon() *Aeon { return &Aeon{} }

// Tool returns the canonical tool id.
func (a *Aeon) Tool() string { return "aeon" }

// Discover satisfies ports.Discoverer. It only reports for project scopes whose
// root carries the aeon.yml marker.
func (a *Aeon) Discover(_ context.Context, scopes []ports.Scope) ([]artifact.Artifact, error) {
	var out []artifact.Artifact
	for _, sc := range scopes {
		if sc.Kind != "project" || sc.Path == "" {
			continue
		}
		if _, err := os.Stat(filepath.Join(sc.Path, "aeon.yml")); err != nil {
			continue // not an AEON repo — stay inert
		}
		out = append(out, skillsFromDir(a.Tool(), filepath.Join(sc.Path, "skills"), sc.String())...)
	}
	return out, nil
}
