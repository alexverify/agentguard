package discover

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

func TestDroidDiscoversMCPFromFactoryConfig(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".factory", "mcp.json"), `{
		"mcpServers": {
			"vex": { "command": "/abs/vex-mcp", "args": ["--project", "abc"] }
		}
	}`)

	d := NewDroid()
	if d.Tool() != "droid" {
		t.Fatalf("Tool() = %q", d.Tool())
	}
	got, err := d.Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	m := byName(got)
	if m["vex"].Type != artifact.TypeMCPServer {
		t.Errorf("vex type wrong: %+v", m["vex"])
	}
	if m["vex"].Tool != "droid" {
		t.Errorf("tool tag wrong: %q", m["vex"].Tool)
	}
}
