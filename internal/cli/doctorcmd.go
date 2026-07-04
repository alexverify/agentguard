package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alexverify/eyebrow/internal/adapters/discover"
	"github.com/alexverify/eyebrow/internal/adapters/hookconfig"
	"github.com/alexverify/eyebrow/internal/adapters/lockstore"
	"github.com/alexverify/eyebrow/internal/adapters/sign"
	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/buildinfo"
	"github.com/alexverify/eyebrow/internal/client"
	"github.com/alexverify/eyebrow/internal/domain/doctor"
	"github.com/alexverify/eyebrow/internal/sandbox"
)

// runDoctor prints an environment self-check: a rollup of the signals a user
// would otherwise gather by running several commands. It is read-only and
// always exits 0 — a report, not a gate (verify/fleet are the gates).
func (a *App) runDoctor(ctx context.Context, args []string) int {
	fs := a.flagSet("doctor")
	path := fs.String("path", ".", "project path to check")
	global := fs.Bool("global", false, "also check machine-wide (global) tool configs")
	lock := fs.String("lockfile", "eyebrowlock.json", "lockfile path")
	settings := fs.String("settings", "", "host-tool settings file to check for hooks (default: ~/.claude/settings.json)")
	key := fs.String("key", a.keyPath(), "local signing key path to check")
	server := fs.String("server", envOr("EYEBROW_SERVER", ""), "control-plane URL to probe (opt-in)")
	token := fs.String("token", envOr("EYEBROW_TOKEN", ""), "machine token for the control plane")
	jsonOut := fs.Bool("json", false, "machine-readable JSON output")
	strict := fs.Bool("strict", false, "exit non-zero (1) when any check warns — for CI gating")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	var r doctor.Report
	r = a.doctorTools(ctx, *path, *global, r)
	r = a.doctorLockfile(ctx, *lock, r)
	r = a.doctorPolicy(ctx, *lock, r)
	r = a.doctorSigning(*key, r)
	r = a.doctorSandbox(r)
	r = a.doctorHooks(*settings, r)
	r = a.doctorServer(ctx, *server, *token, r)
	// By default doctor is a report, not a gate (always 0); --strict opts into
	// the CI contract where an unhealthy environment fails the build.
	code := ExitOK
	if *strict && !r.Healthy() {
		code = ExitDrift
	}
	if *jsonOut {
		b, err := json.MarshalIndent(r.Wire(), "", "  ")
		if err != nil {
			return a.fail("doctor", err)
		}
		fmt.Fprintf(a.Stdout, "%s\n", b)
		return code
	}
	fmt.Fprintf(a.Stdout, "%s doctor\n\n", buildinfo.Name)
	fmt.Fprint(a.Stdout, r.Render())
	return code
}

// doctorTools reports how much of the attack surface discovery can see in scope.
func (a *App) doctorTools(ctx context.Context, path string, global bool, r doctor.Report) doctor.Report {
	arts, err := discover.Default().Discover(ctx, a.scopes(path, global))
	if err != nil {
		return r.Add("tools", doctor.StatusWarn, "discovery failed: "+err.Error())
	}
	if len(arts) == 0 {
		return r.Add("tools", doctor.StatusInfo, "no artifacts discovered in scope (try --global)")
	}
	tools := map[string]bool{}
	for _, art := range arts {
		if art.Tool != "" {
			tools[art.Tool] = true
		}
	}
	return r.Add("tools", doctor.StatusOK,
		fmt.Sprintf("discovered %d artifact(s) across %d tool(s)", len(arts), len(tools)))
}

// doctorServer probes the control plane only when one is configured. Unset is
// informational (offline-first is the default); a configured-but-unreachable
// server is a warning, though every command still degrades to local.
func (a *App) doctorServer(ctx context.Context, server, token string, r doctor.Report) doctor.Report {
	if server == "" {
		return r.Add("control-plane", doctor.StatusInfo, "not configured (offline-first; set --server to enable team features)")
	}
	if err := client.New(server, token).Health(ctx); err != nil {
		return r.Add("control-plane", doctor.StatusWarn, fmt.Sprintf("unreachable at %s: %v", server, err))
	}
	return r.Add("control-plane", doctor.StatusOK, "reachable at "+server)
}

// doctorHooks reports whether the usage-telemetry hooks (F1b) are installed in
// the host tool's settings. Not installed is informational — telemetry is an
// opt-in feature, not a broken state.
func (a *App) doctorHooks(settings string, r doctor.Report) doctor.Report {
	if settings == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return r.Add("hooks", doctor.StatusInfo, "settings path unknown: "+err.Error())
		}
		settings = filepath.Join(home, ".claude", "settings.json")
	}
	cfg, err := hookconfig.Load(settings)
	if err != nil {
		return r.Add("hooks", doctor.StatusInfo, "settings unreadable: "+err.Error())
	}
	cmds, err := cfg.Status()
	if err != nil {
		return r.Add("hooks", doctor.StatusInfo, "hook status unavailable: "+err.Error())
	}
	if len(cmds) == 0 {
		return r.Add("hooks", doctor.StatusInfo, "no usage-telemetry hooks installed (run '"+buildinfo.Name+" install-hooks')")
	}
	return r.Add("hooks", doctor.StatusOK, fmt.Sprintf("%d usage-telemetry hook(s) installed", len(cmds)))
}

// doctorSandbox reports whether this host can confine wrapped MCP servers.
// An absent sandbox is informational, not a warning: it is expected on Windows
// (Unix-only confinement), and wrap already degrades to observe-only there.
func (a *App) doctorSandbox(r doctor.Report) doctor.Report {
	be := sandbox.Select(sandbox.Profile{})
	if be.Available() {
		return r.Add("sandbox", doctor.StatusOK, be.Name()+" available (runtime confinement active)")
	}
	return r.Add("sandbox", doctor.StatusInfo, "no OS sandbox on this host (wrap runs unconfined)")
}

// doctorPolicy surfaces artifacts held under a manual policy state. Quarantined
// artifacts silently fail the gate, so an operator who forgot one is warned;
// frozen pins are intentional, so they are only noted. When no lockfile is
// readable the row is skipped — doctorLockfile already reported that.
func (a *App) doctorPolicy(ctx context.Context, path string, r doctor.Report) doctor.Report {
	lf, err := lockstore.New().Read(ctx, path)
	if err != nil {
		return r
	}
	quarantined, frozen := 0, 0
	for _, e := range lf.Artifacts {
		if e.Quarantined {
			quarantined++
		}
		if e.Frozen {
			frozen++
		}
	}
	switch {
	case quarantined > 0:
		return r.Add("policy", doctor.StatusWarn,
			fmt.Sprintf("%d artifact(s) quarantined (blocked from shipping); %d frozen", quarantined, frozen))
	case frozen > 0:
		return r.Add("policy", doctor.StatusInfo, fmt.Sprintf("%d artifact(s) frozen (pinned)", frozen))
	default:
		return r.Add("policy", doctor.StatusOK, "no quarantined or frozen artifacts")
	}
}

// doctorSigning reports whether a local signing key exists — the prerequisite
// for `eyebrow sign`. No key is informational, not a warning: signing is opt-in
// (a single user can verify their own unsigned lockfile), so an absent key is a
// normal state, not something broken.
func (a *App) doctorSigning(keyPath string, r doctor.Report) doctor.Report {
	s, err := sign.Load(keyPath)
	if err != nil {
		return r.Add("signing", doctor.StatusInfo, "no signing key yet (run '"+buildinfo.Name+" key show' to create one)")
	}
	pub := s.PublicKeyBase64()
	if len(pub) > 12 {
		pub = pub[:12]
	}
	return r.Add("signing", doctor.StatusOK, "signing key available ("+pub+"…)")
}

// doctorLockfile reports whether an approved baseline exists and is signed.
func (a *App) doctorLockfile(ctx context.Context, path string, r doctor.Report) doctor.Report {
	lf, err := lockstore.New().Read(ctx, path)
	switch {
	case errors.Is(err, ports.ErrNoLockfile):
		return r.Add("lockfile", doctor.StatusWarn, "not found — run '"+buildinfo.Name+" scan'")
	case err != nil:
		return r.Add("lockfile", doctor.StatusWarn, "unreadable: "+err.Error())
	case lf.Sig != "":
		return r.Add("lockfile", doctor.StatusOK,
			fmt.Sprintf("present and signed (%d artifact(s))", len(lf.Artifacts)))
	default:
		return r.Add("lockfile", doctor.StatusInfo,
			fmt.Sprintf("present, unsigned (%d artifact(s); run '%s sign')", len(lf.Artifacts), buildinfo.Name))
	}
}
