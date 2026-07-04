package cli_test

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/alexverify/eyebrow/internal/cli"
)

// usageCommandLine matches a command entry in the help text's Commands section:
// two leading spaces, the command token, then its description. The "Usage:"
// example line (`  eyebrow <command> …`) is filtered out by name below.
var usageCommandLine = regexp.MustCompile(`(?m)^  ([a-z][a-z-]+) +\S`)

// usageCommands extracts the user-facing command names from `eyebrow help`,
// the single source that must stay in step with shell completion.
func usageCommands(t *testing.T) []string {
	t.Helper()
	app, _, errBuf := newApp()
	if code := app.Execute(context.Background(), []string{"help"}); code != cli.ExitOK {
		t.Fatalf("help exit = %d", code)
	}
	var cmds []string
	for _, m := range usageCommandLine.FindAllStringSubmatch(errBuf.String(), -1) {
		if m[1] != "eyebrow" { // the Usage: example, not a command
			cmds = append(cmds, m[1])
		}
	}
	if len(cmds) < 5 {
		t.Fatalf("parsed too few usage commands (%d): %v", len(cmds), cmds)
	}
	return cmds
}

// Completion must offer every command the help text advertises. Deriving the
// expectation from usage (not a second hand-kept list) means adding a command
// to help without wiring completion fails here — the drift that hid `doctor`.
func TestCompletionMatchesUsageCommands(t *testing.T) {
	want := usageCommands(t)
	for _, shell := range []string{"bash", "zsh", "fish"} {
		app, out, _ := newApp()
		if code := app.Execute(context.Background(), []string{"completion", shell}); code != cli.ExitOK {
			t.Fatalf("%s completion exit = %d", shell, code)
		}
		script := out.String()
		for _, c := range want {
			if !strings.Contains(script, c) {
				t.Errorf("%s completion is missing command %q (advertised in help)", shell, c)
			}
		}
	}
}

func TestCompletionRequiresShell(t *testing.T) {
	app, _, _ := newApp()
	if code := app.Execute(context.Background(), []string{"completion"}); code != cli.ExitUsage {
		t.Fatalf("completion without a shell exit = %d, want %d", code, cli.ExitUsage)
	}
}

func TestCompletionRejectsUnknownShell(t *testing.T) {
	app, _, _ := newApp()
	if code := app.Execute(context.Background(), []string{"completion", "powershell"}); code != cli.ExitUsage {
		t.Fatalf("unknown shell exit = %d, want %d", code, cli.ExitUsage)
	}
}

func TestCompletionScriptsListEveryCommand(t *testing.T) {
	// The subcommands a user expects to tab-complete. Mirrors the Execute
	// dispatch; if a command is added there and here but not offered by
	// completion, this catches it across all three shells.
	want := []string{
		"scan", "verify", "diff", "digest", "sbom", "list", "approve",
		"quarantine", "freeze", "sign", "key", "wrap", "unwrap", "audit",
		"alerts", "reputation", "record-use", "install-hooks", "dashboard",
		"fleet", "serve", "doctor", "completion",
	}
	for _, shell := range []string{"bash", "zsh", "fish"} {
		app, out, _ := newApp()
		if code := app.Execute(context.Background(), []string{"completion", shell}); code != cli.ExitOK {
			t.Fatalf("%s completion exit = %d", shell, code)
		}
		script := out.String()
		if strings.TrimSpace(script) == "" {
			t.Fatalf("%s completion produced no output", shell)
		}
		for _, c := range want {
			if !strings.Contains(script, c) {
				t.Errorf("%s completion is missing command %q", shell, c)
			}
		}
	}
}

func TestCompletionShellSpecificShape(t *testing.T) {
	// Each shell needs its own dispatch marker to actually register, so a
	// bash script pasted into zsh (or vice versa) is a real regression.
	markers := map[string]string{
		"bash": "complete -F",
		"zsh":  "#compdef",
		"fish": "complete -c",
	}
	for shell, marker := range markers {
		app, out, _ := newApp()
		if code := app.Execute(context.Background(), []string{"completion", shell}); code != cli.ExitOK {
			t.Fatalf("%s completion exit = %d", shell, code)
		}
		if !strings.Contains(out.String(), marker) {
			t.Errorf("%s completion missing expected marker %q", shell, marker)
		}
	}
}
