package cli_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexverify/eyebrow/internal/cli"
	"github.com/alexverify/eyebrow/internal/domain/doctor"
)

func TestDoctorJSONOutput(t *testing.T) {
	ctx := context.Background()
	dir, lock := fixtureProject(t)
	t.Setenv("EYEBROW_SERVER", "")
	t.Setenv("EYEBROW_TOKEN", "")

	app, out, _ := newApp()
	code := app.Execute(ctx, []string{"doctor", "--json", "--path", dir, "--lockfile", lock, "--settings", filepath.Join(dir, "settings.json")})
	if code != cli.ExitOK {
		t.Fatalf("doctor --json exit = %d", code)
	}
	var w doctor.Wire
	if err := json.Unmarshal(out.Bytes(), &w); err != nil {
		t.Fatalf("doctor --json is not valid JSON: %v\n%s", err, out.String())
	}
	if len(w.Checks) == 0 {
		t.Fatal("expected checks in the JSON report")
	}
	// No lockfile yet → at least one warning, reflected in the summary.
	if w.Warnings < 1 || w.Healthy {
		t.Errorf("expected warnings>=1 and healthy=false, got %+v", w)
	}
	// JSON mode must not leak the human-readable header.
	if strings.Contains(out.String(), "doctor\n\n") {
		t.Errorf("json output should not include the text header:\n%s", out.String())
	}
}

func TestDoctorStrictGatesOnWarnings(t *testing.T) {
	ctx := context.Background()
	dir, lock := fixtureProject(t)
	t.Setenv("EYEBROW_SERVER", "")
	t.Setenv("EYEBROW_TOKEN", "")
	settings := filepath.Join(dir, "settings.json")

	// Before scan the lockfile is missing → a warning → --strict exits non-zero,
	// even though plain doctor still exits 0.
	app, _, _ := newApp()
	if code := app.Execute(ctx, []string{"doctor", "--path", dir, "--lockfile", lock, "--settings", settings}); code != cli.ExitOK {
		t.Fatalf("plain doctor exit = %d, want 0", code)
	}
	app, _, _ = newApp()
	if code := app.Execute(ctx, []string{"doctor", "--strict", "--path", dir, "--lockfile", lock, "--settings", settings}); code != cli.ExitDrift {
		t.Errorf("strict doctor with a warning exit = %d, want %d", code, cli.ExitDrift)
	}

	// After scan there are no warnings, so --strict exits 0.
	app, _, _ = newApp()
	if code := app.Execute(ctx, []string{"scan", "--path", dir, "--lockfile", lock}); code != cli.ExitOK {
		t.Fatal("scan failed")
	}
	app, _, _ = newApp()
	if code := app.Execute(ctx, []string{"doctor", "--strict", "--path", dir, "--lockfile", lock, "--settings", settings}); code != cli.ExitOK {
		t.Errorf("strict doctor on a healthy env exit = %d, want 0", code)
	}
}

func TestDoctorReportsToolsAndLockfile(t *testing.T) {
	ctx := context.Background()
	dir, lock := fixtureProject(t)

	// Before scan: no lockfile is a warning, but doctor is a report, not a gate,
	// so it still exits 0.
	app, out, _ := newApp()
	if code := app.Execute(ctx, []string{"doctor", "--path", dir, "--lockfile", lock}); code != cli.ExitOK {
		t.Fatalf("doctor exit = %d, want 0", code)
	}
	s := out.String()
	for _, want := range []string{"doctor", "tools", "lockfile"} {
		if !strings.Contains(s, want) {
			t.Errorf("doctor output missing %q\n%s", want, s)
		}
	}
	if !strings.Contains(s, "warn") {
		t.Errorf("a missing lockfile should warn:\n%s", s)
	}

	// The fixture project has a discoverable MCP server, so the tools check is ok.
	if !strings.Contains(s, "discovered") {
		t.Errorf("expected a discovered-artifacts detail:\n%s", s)
	}

	// After scan the lockfile exists, so its check is no longer a warning.
	app, _, _ = newApp()
	if code := app.Execute(ctx, []string{"scan", "--path", dir, "--lockfile", lock}); code != cli.ExitOK {
		t.Fatal("scan failed")
	}
	app, out, _ = newApp()
	app.Execute(ctx, []string{"doctor", "--path", dir, "--lockfile", lock})
	if !strings.Contains(out.String(), "present") {
		t.Errorf("expected the lockfile check to report it present:\n%s", out.String())
	}
}

func TestDoctorReportsQuarantine(t *testing.T) {
	ctx := context.Background()
	dir, lock := fixtureProject(t)

	// A clean scan: the policy check is ok (nothing quarantined or frozen).
	app, _, _ := newApp()
	if code := app.Execute(ctx, []string{"scan", "--path", dir, "--lockfile", lock}); code != cli.ExitOK {
		t.Fatal("scan failed")
	}
	app, out, _ := newApp()
	app.Execute(ctx, []string{"doctor", "--path", dir, "--lockfile", lock})
	if !strings.Contains(out.String(), "policy") {
		t.Errorf("doctor should include a policy check:\n%s", out.String())
	}

	// Quarantine everything: the policy check becomes a warning naming the count.
	app, _, errBuf := newApp()
	if code := app.Execute(ctx, []string{"quarantine", "--all", "--lockfile", lock}); code != cli.ExitOK {
		t.Fatalf("quarantine exit = %d, stderr=%s", code, errBuf.String())
	}
	app, out, _ = newApp()
	app.Execute(ctx, []string{"doctor", "--path", dir, "--lockfile", lock})
	if !strings.Contains(out.String(), "quarantined") || !strings.Contains(out.String(), "warn") {
		t.Errorf("quarantined artifacts should raise a policy warning:\n%s", out.String())
	}
}

func TestDoctorReportsSigningKey(t *testing.T) {
	ctx := context.Background()
	dir, lock := fixtureProject(t)
	setHome(t, t.TempDir())
	keyPath := filepath.Join(t.TempDir(), "key")

	// No key yet: an informational note (signing is opt-in), doctor exits 0.
	app, out, _ := newApp()
	app.Execute(ctx, []string{"doctor", "--path", dir, "--lockfile", lock, "--key", keyPath})
	if !strings.Contains(out.String(), "signing") || !strings.Contains(out.String(), "no signing key") {
		t.Errorf("expected a 'no signing key' note:\n%s", out.String())
	}

	// After `key show` creates the identity, doctor reports it available.
	app, _, errBuf := newApp()
	if code := app.Execute(ctx, []string{"key", "show", "--key", keyPath}); code != cli.ExitOK {
		t.Fatalf("key show exit = %d, stderr=%s", code, errBuf.String())
	}
	app, out, _ = newApp()
	app.Execute(ctx, []string{"doctor", "--path", dir, "--lockfile", lock, "--key", keyPath})
	if !strings.Contains(out.String(), "signing key available") {
		t.Errorf("expected doctor to report the signing key available:\n%s", out.String())
	}
}

func TestDoctorReportsSandbox(t *testing.T) {
	dir, lock := fixtureProject(t)
	app, out, _ := newApp()
	app.Execute(context.Background(), []string{"doctor", "--path", dir, "--lockfile", lock})
	if !strings.Contains(out.String(), "sandbox") {
		t.Errorf("doctor should include a sandbox check:\n%s", out.String())
	}
}

func TestDoctorReportsHooks(t *testing.T) {
	ctx := context.Background()
	dir, lock := fixtureProject(t)
	settings := filepath.Join(dir, "settings.json")

	// No hooks yet: an informational note, and doctor still exits 0.
	app, out, _ := newApp()
	app.Execute(ctx, []string{"doctor", "--path", dir, "--lockfile", lock, "--settings", settings})
	if !strings.Contains(out.String(), "no usage-telemetry hooks installed") {
		t.Errorf("expected the 'no hooks' note:\n%s", out.String())
	}

	// After install-hooks writes them, doctor reports them installed.
	app, _, errBuf := newApp()
	if code := app.Execute(ctx, []string{"install-hooks", "--settings", settings}); code != cli.ExitOK {
		t.Fatalf("install-hooks exit = %d, stderr=%s", code, errBuf.String())
	}
	app, out, _ = newApp()
	app.Execute(ctx, []string{"doctor", "--path", dir, "--lockfile", lock, "--settings", settings})
	if !strings.Contains(out.String(), "hook(s) installed") {
		t.Errorf("expected doctor to report installed hooks:\n%s", out.String())
	}
}

func TestDoctorControlPlaneCheck(t *testing.T) {
	ctx := context.Background()
	dir, lock := fixtureProject(t)
	t.Setenv("EYEBROW_SERVER", "")
	t.Setenv("EYEBROW_TOKEN", "")

	// Unconfigured: an offline-first note, and doctor exits 0.
	app, out, _ := newApp()
	if code := app.Execute(ctx, []string{"doctor", "--path", dir, "--lockfile", lock}); code != cli.ExitOK {
		t.Fatalf("doctor exit = %d", code)
	}
	if !strings.Contains(out.String(), "control-plane") || !strings.Contains(out.String(), "not configured") {
		t.Errorf("expected an unconfigured control-plane note:\n%s", out.String())
	}

	// Configured but unreachable: a warning, still exit 0 (degrades to local).
	app, out, _ = newApp()
	if code := app.Execute(ctx, []string{"doctor", "--path", dir, "--lockfile", lock, "--server", "http://127.0.0.1:1"}); code != cli.ExitOK {
		t.Fatalf("doctor exit = %d, want 0 even when the server is down", code)
	}
	if !strings.Contains(out.String(), "unreachable") {
		t.Errorf("expected an unreachable control-plane warning:\n%s", out.String())
	}
}
