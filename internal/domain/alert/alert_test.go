package alert

import (
	"testing"

	"github.com/alexverify/eyebrow/internal/domain/audit"
	"github.com/alexverify/eyebrow/internal/domain/fleet"
)

func report(exps ...fleet.Exposure) fleet.Report {
	return fleet.Report{Exposures: exps}
}

func TestDeriveDriftAndQuarantine(t *testing.T) {
	rep := report(
		fleet.Exposure{Name: "feed", Kind: "skill", Installs: 4, Drifted: 3},
		fleet.Exposure{Name: "linter", Kind: "skill", Installs: 2, Quarantine: 1},
	)
	got := Derive(rep, nil)
	if len(got) != 2 {
		t.Fatalf("expected drift + quarantine, got %d: %+v", len(got), got)
	}
	// Quarantine (critical) sorts before drift (high).
	if got[0].Kind != KindQuarantine || got[0].Severity != SeverityCritical {
		t.Errorf("quarantine should be the top alert: %+v", got[0])
	}
	if got[1].Kind != KindDrift || got[1].Count != 3 {
		t.Errorf("drift alert wrong: %+v", got[1])
	}
}

func TestDeriveAuditDenials(t *testing.T) {
	events := []audit.Event{
		{Kind: audit.KindEgress, Host: "evil.example", Status: audit.StatusDenied},
		{Kind: audit.KindEgress, Host: "evil.example", Status: audit.StatusDenied},
		{Kind: audit.KindEgress, Host: "api.ok.example", Status: audit.StatusOK}, // not denied
		{Kind: audit.KindToolCall, Server: "github", Status: audit.StatusDenied},
	}
	got := Derive(fleet.Report{}, events)
	if len(got) != 2 {
		t.Fatalf("expected one egress + one tool alert, got %d: %+v", len(got), got)
	}
	// Egress (high) before tool-denied (info).
	if got[0].Kind != KindEgressDenied || got[0].Subject != "evil.example" || got[0].Count != 2 {
		t.Errorf("egress alert wrong: %+v", got[0])
	}
	if got[1].Kind != KindToolDenied || got[1].Severity != SeverityInfo {
		t.Errorf("tool-denied alert wrong: %+v", got[1])
	}
}

func TestDeriveOrdersBySeverityThenCount(t *testing.T) {
	rep := report(
		fleet.Exposure{Name: "a", Installs: 2, Drifted: 1},
		fleet.Exposure{Name: "b", Installs: 5, Drifted: 4},
		fleet.Exposure{Name: "z", Installs: 1, Quarantine: 1},
	)
	got := Derive(rep, []audit.Event{{Kind: audit.KindEgress, Host: "h", Status: audit.StatusDenied}})
	// critical first, then the two highs by count desc (drift b=4, egress h=1... wait egress=1, drift a=1)
	if got[0].Severity != SeverityCritical {
		t.Fatalf("critical must lead: %+v", got)
	}
	// Among highs: drift b (count 4) before drift a (count 1) / egress (count 1).
	if got[1].Subject != "b" || got[1].Count != 4 {
		t.Errorf("highest-count high should come first: %+v", got[1])
	}
}

func TestDeriveEmpty(t *testing.T) {
	if got := Derive(fleet.Report{}, nil); len(got) != 0 {
		t.Errorf("a clean fleet with no audit should yield no alerts, got %+v", got)
	}
}

func TestDeriveSleeperIsCriticalAndLeads(t *testing.T) {
	rep := report(
		fleet.Exposure{Name: "feed", Kind: "skill", Installs: 8, Drifted: 2, Sleeper: 2},
		fleet.Exposure{Name: "linter", Kind: "skill", Installs: 2, Quarantine: 1},
	)
	got := Derive(rep, nil)
	// Expect: sleeper (critical) + drift (high) for "feed", quarantine (critical) for "linter".
	if got[0].Kind != KindSleeper {
		t.Fatalf("sleeper should be the top alert, got %+v", got[0])
	}
	if got[0].Severity != SeverityCritical || got[0].Subject != "feed" || got[0].Count != 2 {
		t.Errorf("sleeper alert wrong: %+v", got[0])
	}
	var sawSleeper int
	for _, al := range got {
		if al.Kind == KindSleeper {
			sawSleeper++
		}
	}
	if sawSleeper != 1 {
		t.Errorf("expected exactly one sleeper alert, got %d in %+v", sawSleeper, got)
	}
}

func TestDeriveNoSleeperAtZero(t *testing.T) {
	got := Derive(report(fleet.Exposure{Name: "feed", Installs: 3, Drifted: 1, Sleeper: 0}), nil)
	for _, al := range got {
		if al.Kind == KindSleeper {
			t.Errorf("no sleeper alert expected when Sleeper==0: %+v", al)
		}
	}
}
