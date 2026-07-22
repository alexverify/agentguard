package dashboard

import "testing"

// Every tool the scanner discovers needs a display name; an unmapped tool leaks
// its raw id ("vscode") into the UI.
func TestAgentNameCoversEveryDiscoveredTool(t *testing.T) {
	want := map[string]string{
		"claude-code":    "Claude Code",
		"claude-desktop": "Claude Desktop",
		"cursor":         "Cursor",
		"gemini":         "Gemini",
		"opencode":       "OpenCode",
		"codex":          "Codex",
		"windsurf":       "Windsurf",
		"copilot-cli":    "GitHub Copilot",
		"vscode":         "VS Code",
		"zed":            "Zed",
		"kiro":           "Kiro",
	}
	for tool, name := range want {
		if got := agentName(tool); got != name {
			t.Errorf("agentName(%q) = %q, want %q", tool, got, name)
		}
	}
}

// An unknown tool still degrades to its id rather than blanking the column.
func TestAgentNameUnknownFallsBackToID(t *testing.T) {
	if got := agentName("some-new-tool"); got != "some-new-tool" {
		t.Errorf("unknown tool should fall back to its id, got %q", got)
	}
}
