package timeline

import (
	"testing"
	"time"
)

func ts(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func kinds(evs []Event) []Kind {
	out := make([]Kind, len(evs))
	for i, e := range evs {
		out[i] = e.Kind
	}
	return out
}

func TestBuildOrdersByTime(t *testing.T) {
	evs := Build(Input{
		InstalledAt: ts("2026-04-01T00:00:00Z"),
		ApprovedAt:  ts("2026-04-02T00:00:00Z"),
		ApprovedBy:  "alice",
		FirstUsed:   ts("2026-05-20T00:00:00Z"),
		LastUsed:    ts("2026-05-25T00:00:00Z"),
		UseCount:    9,
		DriftedAt:   ts("2026-05-22T00:00:00Z"),
		DriftDetail: "content hash changed with no version bump",
		DriftDanger: true,
	})

	want := []Kind{KindInstalled, KindApproved, KindFirstUsed, KindDrifted, KindLastUsed}
	got := kinds(evs)
	if len(got) != len(want) {
		t.Fatalf("got %d events %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("event %d = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
	for i := 1; i < len(evs); i++ {
		if evs[i].At.Before(evs[i-1].At) {
			t.Errorf("events out of order at %d: %v before %v", i, evs[i].At, evs[i-1].At)
		}
	}
}

func TestBuildOmitsZeroTimes(t *testing.T) {
	// Only an install time is known: a single-event ribbon, nothing fabricated.
	evs := Build(Input{InstalledAt: ts("2026-04-01T00:00:00Z")})
	if k := kinds(evs); len(k) != 1 || k[0] != KindInstalled {
		t.Fatalf("want only [installed], got %v", k)
	}
}

func TestBuildEmptyWhenNothingKnown(t *testing.T) {
	if evs := Build(Input{}); len(evs) != 0 {
		t.Errorf("Build(zero) = %v, want no events", evs)
	}
}

func TestBuildSkipsRedundantLastUsed(t *testing.T) {
	// A single invocation: first==last, so "last invoked" would be noise.
	evs := Build(Input{
		InstalledAt: ts("2026-04-01T00:00:00Z"),
		FirstUsed:   ts("2026-05-01T00:00:00Z"),
		LastUsed:    ts("2026-05-01T00:00:00Z"),
		UseCount:    1,
	})
	for _, e := range evs {
		if e.Kind == KindLastUsed {
			t.Errorf("last_used must be omitted when it equals first_used: %v", kinds(evs))
		}
	}
}

func TestBuildDriftSeverity(t *testing.T) {
	danger := Build(Input{
		InstalledAt: ts("2026-04-01T00:00:00Z"),
		DriftedAt:   ts("2026-05-01T00:00:00Z"),
		DriftDetail: "mutated",
		DriftDanger: true,
	})
	if got := find(t, danger, KindDrifted).Severity; got != SeverityCritical {
		t.Errorf("dangerous drift severity = %q, want %q", got, SeverityCritical)
	}

	benign := Build(Input{
		InstalledAt: ts("2026-04-01T00:00:00Z"),
		DriftedAt:   ts("2026-05-01T00:00:00Z"),
		DriftDetail: "updated since last audit",
		DriftDanger: false,
	})
	if got := find(t, benign, KindDrifted).Severity; got != SeverityInfo {
		t.Errorf("benign drift severity = %q, want %q", got, SeverityInfo)
	}
}

func TestBuildApprovedCarriesActor(t *testing.T) {
	evs := Build(Input{
		InstalledAt: ts("2026-04-01T00:00:00Z"),
		ApprovedAt:  ts("2026-04-02T00:00:00Z"),
		ApprovedBy:  "alice",
	})
	e := find(t, evs, KindApproved)
	if e.Detail == "" {
		t.Errorf("approved event should name the approver")
	}
	if e.Severity != SeverityOK {
		t.Errorf("approval severity = %q, want %q", e.Severity, SeverityOK)
	}
}

func find(t *testing.T, evs []Event, k Kind) Event {
	t.Helper()
	for _, e := range evs {
		if e.Kind == k {
			return e
		}
	}
	t.Fatalf("no %q event in %v", k, kinds(evs))
	return Event{}
}

func TestBuildIncludesToolSurfaceChange(t *testing.T) {
	at := time.Date(2026, 7, 2, 10, 0, 0, 0, time.UTC)
	evs := Build(Input{SurfaceChangedAt: at, SurfaceDetail: "2 → 3 tools"})
	if len(evs) != 1 || evs[0].Kind != KindToolSurfaceChanged ||
		evs[0].Label != "Tool surface changed" || evs[0].Severity != SeverityHigh {
		t.Fatalf("Build() = %+v", evs)
	}
}
