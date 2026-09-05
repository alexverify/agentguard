package discover

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

const testRegistry = `[
  {"id":"gitlawb/ci-fix","name":"ci-fix","path":"skills/ci-fix/SKILL.md",
   "sha256":"28265c02bc9b9283693d4ecf477e58999c59ae4287245d98d42211f64c0a0311"},
  {"id":"gitlawb/pr-review","name":"pr-review","path":"skills/pr-review/SKILL.md",
   "sha256":"b6511b0dd67c9283693d4ecf477e58999c59ae4287245d98d42211f64c0a0311"}
]`

// An OpenClaude registry repo (Gitlawb/openclaude-skills) publishes
// registry.json: one entry per skill with the path of its SKILL.md and the
// sha256 the client checks at install. The adapter reports one artifact per
// entry and carries the registry's own pin so the lockfile records what the
// registry promised next to what the tree hashes to.
func TestOpenClaudeRegistryDiscoversEntries(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "registry.json"), testRegistry)
	writeFile(t, filepath.Join(dir, "skills", "ci-fix", "SKILL.md"), "---\nname: ci-fix\n---\nbody")
	writeFile(t, filepath.Join(dir, "skills", "ci-fix", "README.md"), "readme")
	writeFile(t, filepath.Join(dir, "skills", "pr-review", "SKILL.md"), "---\nname: pr-review\n---\nbody")
	// On disk but not in the registry: not published, not reported.
	writeFile(t, filepath.Join(dir, "skills", "draft", "SKILL.md"), "---\nname: draft\n---\nbody")

	d := NewOpenClaudeRegistry()
	if d.Tool() != "openclaude-registry" {
		t.Fatalf("Tool() = %q", d.Tool())
	}
	got, err := d.Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 artifacts, got %d: %+v", len(got), got)
	}
	m := byName(got)
	a, ok := m["ci-fix"]
	if !ok {
		t.Fatalf("ci-fix missing: %+v", got)
	}
	if a.Type != artifact.TypeSkill || a.Tool != "openclaude-registry" {
		t.Errorf("type/tool wrong: %+v", a)
	}
	if a.Source.Kind != artifact.SourceLocal || a.Source.Ref != filepath.Join(dir, "skills", "ci-fix") {
		t.Errorf("source wrong: %+v", a.Source)
	}
	if want := "sha256-28265c02bc9b9283693d4ecf477e58999c59ae4287245d98d42211f64c0a0311"; a.Source.Integrity != want {
		t.Errorf("Integrity = %q, want %q", a.Source.Integrity, want)
	}
	if a.DiscoveredFrom != filepath.Join(dir, "skills", "ci-fix", "SKILL.md") {
		t.Errorf("DiscoveredFrom = %q", a.DiscoveredFrom)
	}
	if _, ok := m["draft"]; ok {
		t.Errorf("unlisted skill must not be reported")
	}
}

func TestOpenClaudeRegistryExtractsEgressCapabilityFromCallLines(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "registry.json"), testRegistry)
	writeFile(t, filepath.Join(dir, "skills", "ci-fix", "SKILL.md"),
		"See https://docs.example.com/ci for background.\n"+
			"Run: curl -s https://ci-helper.example.net/collect\n")
	writeFile(t, filepath.Join(dir, "skills", "pr-review", "SKILL.md"), "no calls")

	got, err := NewOpenClaudeRegistry().Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	m := byName(got)
	if want := []string{"ci-helper.example.net"}; !reflect.DeepEqual(m["ci-fix"].Capabilities.Network, want) {
		t.Errorf("Network = %v, want %v", m["ci-fix"].Capabilities.Network, want)
	}
	if n := m["pr-review"].Capabilities.Network; len(n) != 0 {
		t.Errorf("pr-review Network = %v, want none", n)
	}
}

// A registry.json of another shape (an object, or entries without a SKILL.md
// path and a sha256 pin) belongs to some other project. The adapter must stay
// inert rather than inject artifacts into an unrelated scan.
func TestOpenClaudeRegistryInertForOtherRegistries(t *testing.T) {
	cases := map[string]string{
		"object":       `{"skills":[{"path":"skills/a/SKILL.md"}]}`,
		"no sha256":    `[{"id":"x/a","path":"skills/a/SKILL.md"}]`,
		"not skill.md": `[{"id":"x/a","path":"packages/a/index.js","sha256":"28265c02bc9b9283693d4ecf477e58999c59ae4287245d98d42211f64c0a0311"}]`,
		"malformed":    `[{`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "registry.json"), body)
			writeFile(t, filepath.Join(dir, "skills", "a", "SKILL.md"), "body")
			got, err := NewOpenClaudeRegistry().Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
			if err != nil {
				t.Fatalf("Discover: %v", err)
			}
			if len(got) != 0 {
				t.Errorf("want 0 artifacts, got %+v", got)
			}
		})
	}
	// No registry at all.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "skills", "a", "SKILL.md"), "body")
	got, _ := NewOpenClaudeRegistry().Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if len(got) != 0 {
		t.Errorf("no registry.json: want 0 artifacts, got %+v", got)
	}
	// Global scope carries no registry.
	got, _ = NewOpenClaudeRegistry().Discover(context.Background(), []ports.Scope{{Kind: "global"}})
	if len(got) != 0 {
		t.Errorf("global scope: want 0 artifacts, got %+v", got)
	}
}

// An entry whose SKILL.md is missing on disk, or whose path escapes the repo,
// is skipped; the remaining entries still report.
func TestOpenClaudeRegistrySkipsBadEntries(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "registry.json"), `[
	  {"id":"x/ok","path":"skills/ok/SKILL.md","sha256":"28265c02bc9b9283693d4ecf477e58999c59ae4287245d98d42211f64c0a0311"},
	  {"id":"x/gone","path":"skills/gone/SKILL.md","sha256":"28265c02bc9b9283693d4ecf477e58999c59ae4287245d98d42211f64c0a0311"},
	  {"id":"x/escape","path":"../outside/SKILL.md","sha256":"28265c02bc9b9283693d4ecf477e58999c59ae4287245d98d42211f64c0a0311"}
	]`)
	writeFile(t, filepath.Join(dir, "skills", "ok", "SKILL.md"), "body")
	writeFile(t, filepath.Join(filepath.Dir(dir), "outside", "SKILL.md"), "body")

	got, err := NewOpenClaudeRegistry().Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(got) != 1 || got[0].Name != "ok" {
		t.Errorf("want only 'ok', got %+v", got)
	}
}
