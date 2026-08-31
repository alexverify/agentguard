package discover

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

func TestQwenDiscoversMCPFromSettings(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".qwen", "settings.json"), `{
		"mcpServers": {
			"vex": { "command": "/abs/vex-mcp", "args": ["--project", "abc"] }
		}
	}`)

	q := NewQwen()
	if q.Tool() != "qwen-code" {
		t.Fatalf("Tool() = %q", q.Tool())
	}
	got, err := q.Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	m := byName(got)
	if m["vex"].Type != artifact.TypeMCPServer {
		t.Errorf("vex type wrong: %+v", m["vex"])
	}
	if m["vex"].Tool != "qwen-code" {
		t.Errorf("tool tag wrong: %q", m["vex"].Tool)
	}
}
