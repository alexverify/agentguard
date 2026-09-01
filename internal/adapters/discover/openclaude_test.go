package discover

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

func TestOpenClaudeDiscoversProjectSkills(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".openclaude", "skills", "ci-fix", "SKILL.md"), "---\nname: ci-fix\n---\nbody")
	writeFile(t, filepath.Join(dir, ".openclaude", "skills", "ci-fix", "skill.json"), `{"id":"gitlawb/ci-fix","sha256":"abc"}`)
	// A dir without SKILL.md is not a skill.
	writeFile(t, filepath.Join(dir, ".openclaude", "skills", "notes", "README.md"), "x")

	d := NewOpenClaude()
	if d.Tool() != "openclaude" {
		t.Fatalf("Tool() = %q", d.Tool())
	}
	got, err := d.Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	m := byName(got)
	if len(got) != 1 {
		t.Fatalf("want 1 artifact, got %d: %+v", len(got), got)
	}
	if m["ci-fix"].Type != artifact.TypeSkill {
		t.Errorf("ci-fix type wrong: %+v", m["ci-fix"])
	}
	if m["ci-fix"].Tool != "openclaude" {
		t.Errorf("tool tag wrong: %q", m["ci-fix"].Tool)
	}
}

func TestOpenClaudeDiscoversGlobalSkills(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".openclaude", "skills", "pr-review", "SKILL.md"), "---\nname: pr-review\n---\nbody")

	d := &OpenClaude{home: home}
	got, err := d.Discover(context.Background(), []ports.Scope{{Kind: "global"}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	m := byName(got)
	if m["pr-review"].Type != artifact.TypeSkill {
		t.Errorf("pr-review type wrong: %+v", m["pr-review"])
	}
	if m["pr-review"].Scope != "global" {
		t.Errorf("scope wrong: %q", m["pr-review"].Scope)
	}
}
