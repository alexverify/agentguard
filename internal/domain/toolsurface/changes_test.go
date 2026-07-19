package toolsurface

import (
	"testing"
	"time"

	"github.com/alexverify/eyebrow/internal/domain/audit"
)

func surfaceEvent(server, dig string, names []string, at time.Time) audit.Event {
	return audit.Event{
		At: at, Server: server, Kind: audit.KindToolSurface,
		ArgsDigest: dig, ToolNames: names,
	}
}

func TestChangesDetectsDigestFlip(t *testing.T) {
	t0 := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(24 * time.Hour)
	evs := []audit.Event{
		surfaceEvent("gh", "sha256-aaa", []string{"a", "b"}, t0),
		surfaceEvent("gh", "sha256-bbb", []string{"a", "b", "c"}, t1),
	}
	got := Changes(evs)
	if len(got) != 1 {
		t.Fatalf("Changes() = %d changes, want 1", len(got))
	}
	c := got[0]
	if c.Server != "gh" || c.FromDigest != "sha256-aaa" || c.ToDigest != "sha256-bbb" ||
		c.FromCount != 2 || c.ToCount != 3 || !c.From.Equal(t0) || !c.To.Equal(t1) {
		t.Fatalf("Changes()[0] = %+v", c)
	}
}

func TestChangesIgnoresStableAndForeignKinds(t *testing.T) {
	t0 := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)
	evs := []audit.Event{
		surfaceEvent("gh", "sha256-aaa", []string{"a"}, t0),
		surfaceEvent("gh", "sha256-aaa", []string{"a"}, t0.Add(time.Hour)),
		{At: t0, Server: "gh", Kind: audit.KindToolCall, Tool: "a"},
	}
	if got := Changes(evs); len(got) != 0 {
		t.Fatalf("Changes() = %v, want none", got)
	}
}

func TestChangesHandlesInterleavedServersAndUnsortedInput(t *testing.T) {
	t0 := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)
	evs := []audit.Event{ // deliberately out of time order
		surfaceEvent("gh", "sha256-bbb", []string{"a"}, t0.Add(2*time.Hour)),
		surfaceEvent("db", "sha256-ccc", []string{"q"}, t0),
		surfaceEvent("gh", "sha256-aaa", []string{"a"}, t0),
	}
	got := Changes(evs)
	if len(got) != 1 || got[0].Server != "gh" || got[0].FromDigest != "sha256-aaa" {
		t.Fatalf("Changes() = %+v, want one gh change aaa→bbb", got)
	}
}

func TestSummarizeReportsLatestAndChange(t *testing.T) {
	t0 := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)
	evs := []audit.Event{
		surfaceEvent("gh", "sha256-aaa", []string{"a", "b"}, t0),
		surfaceEvent("gh", "sha256-bbb", []string{"a", "b", "c"}, t0.Add(time.Hour)),
		surfaceEvent("db", "sha256-ccc", []string{"q"}, t0),
	}
	m := Summarize(evs)
	gh := m["gh"]
	if gh.Digest != "sha256-bbb" || gh.Count != 3 || gh.Change == nil || !gh.SeenAt.Equal(t0.Add(time.Hour)) {
		t.Fatalf("Summarize()[gh] = %+v", gh)
	}
	if db := m["db"]; db.Change != nil || db.Digest != "sha256-ccc" {
		t.Fatalf("Summarize()[db] = %+v, want stable ccc", db)
	}
}
