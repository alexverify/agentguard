package discover

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

// AEON keeps its skills at a top-level skills/<slug>/SKILL.md — not under
// .claude/skills. The adapter activates only when it sees AEON's aeon.yml
// marker, so it stays inert for every other repo.
func TestAeonDiscoversSkillsWhenMarkerPresent(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "aeon.yml"), "version: 1\n")
	writeFile(t, filepath.Join(dir, "skills", "token-movers", "SKILL.md"),
		"---\nname: token-movers\ndescription: moves tokens\n---\nbody\n")
	writeFile(t, filepath.Join(dir, "skills", "okf-ingest", "SKILL.md"),
		"---\nname: okf-ingest\ndescription: ingests knowledge\n---\nbody\n")

	a := NewAeon()
	if a.Tool() != "aeon" {
		t.Fatalf("Tool() = %q, want aeon", a.Tool())
	}
	got, err := a.Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	m := byName(got)
	if len(m) != 2 {
		t.Fatalf("discovered %d skills, want 2: %+v", len(m), got)
	}
	tm := m["token-movers"]
	if tm.Type != artifact.TypeSkill {
		t.Errorf("token-movers type = %q, want skill", tm.Type)
	}
	if tm.Tool != "aeon" {
		t.Errorf("token-movers tool = %q, want aeon", tm.Tool)
	}
	if tm.Source.Kind != artifact.SourceLocal {
		t.Errorf("token-movers source kind = %q, want local", tm.Source.Kind)
	}
	if tm.ID == "" {
		t.Errorf("token-movers has no ID: %+v", tm)
	}
}

// Without the aeon.yml marker the adapter must find nothing, even though the
// skills/ layout is present — otherwise any repo with a skills/ dir would get
// AEON artifacts injected into its scan.
func TestAeonInertWithoutMarker(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "skills", "token-movers", "SKILL.md"),
		"---\nname: token-movers\ndescription: moves tokens\n---\nbody\n")

	got, err := NewAeon().Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("discovered %d artifacts without aeon.yml marker, want 0: %+v", len(got), got)
	}
}
