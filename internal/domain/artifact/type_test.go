package artifact

import "testing"

func TestIsTypeAcceptsEveryKnownType(t *testing.T) {
	for _, ty := range Types() {
		if !IsType(string(ty)) {
			t.Errorf("IsType(%q) = false, want true", ty)
		}
	}
}

func TestIsTypeRejectsUnknown(t *testing.T) {
	for _, s := range []string{"", "mcp", "MCP_SERVER", "server", "rule"} {
		if IsType(s) {
			t.Errorf("IsType(%q) = true, want false", s)
		}
	}
}

func TestTypesCoversTheEnum(t *testing.T) {
	// A guard so a new Type constant is also surfaced here (filters, help text).
	want := []Type{TypeSkill, TypeMCPServer, TypePlugin, TypeSubagent, TypeHook, TypeRules, TypeContext}
	got := Types()
	if len(got) != len(want) {
		t.Fatalf("Types() has %d entries, want %d: %v", len(got), len(want), got)
	}
	set := map[Type]bool{}
	for _, ty := range got {
		set[ty] = true
	}
	for _, ty := range want {
		if !set[ty] {
			t.Errorf("Types() missing %q", ty)
		}
	}
}
