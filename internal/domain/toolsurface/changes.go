package toolsurface

import (
	"sort"
	"time"

	"github.com/alexverify/eyebrow/internal/domain/audit"
)

// Change records the advertised surface differing between two observations of
// the same server — the runtime rug-pull signal. The first observed surface is
// the baseline (trust-on-first-use between sessions); scan never runs the
// server, so runtime observation is the only place this content signal exists.
type Change struct {
	Server     string    `json:"server"`
	From       time.Time `json:"from"`
	To         time.Time `json:"to"`
	FromDigest string    `json:"fromDigest"`
	ToDigest   string    `json:"toDigest"`
	FromCount  int       `json:"fromCount"`
	ToCount    int       `json:"toCount"`
}

// Status is the latest observed surface for one server, with its most recent
// change (nil when the surface never changed across the audited window).
type Status struct {
	Digest string
	Count  int
	Names  []string
	SeenAt time.Time
	Change *Change
}

// Changes walks tool_surface events per server in time order and reports every
// digest flip. Non-surface events are ignored; no events → no changes.
func Changes(events []audit.Event) []Change {
	var out []Change
	walk(events, func(c Change) { out = append(out, c) })
	return out
}

// Summarize folds tool_surface events into the latest per-server Status,
// carrying the most recent change if any.
func Summarize(events []audit.Event) map[string]Status {
	latestChange := map[string]Change{}
	walk(events, func(c Change) { latestChange[c.Server] = c })

	out := map[string]Status{}
	for _, e := range sortedSurfaceEvents(events) {
		st := Status{Digest: e.ArgsDigest, Count: len(e.ToolNames), Names: e.ToolNames, SeenAt: e.At}
		if c, ok := latestChange[e.Server]; ok {
			cc := c
			st.Change = &cc
		}
		out[e.Server] = st // later events overwrite: map ends at the latest
	}
	return out
}

// walk visits every digest flip in time order, calling fn per change.
func walk(events []audit.Event, fn func(Change)) {
	last := map[string]audit.Event{}
	for _, e := range sortedSurfaceEvents(events) {
		if p, ok := last[e.Server]; ok && p.ArgsDigest != e.ArgsDigest {
			fn(Change{
				Server: e.Server, From: p.At, To: e.At,
				FromDigest: p.ArgsDigest, ToDigest: e.ArgsDigest,
				FromCount: len(p.ToolNames), ToCount: len(e.ToolNames),
			})
		}
		last[e.Server] = e
	}
}

// sortedSurfaceEvents selects KindToolSurface events ordered by time.
func sortedSurfaceEvents(events []audit.Event) []audit.Event {
	sel := make([]audit.Event, 0, len(events))
	for _, e := range events {
		if e.Kind == audit.KindToolSurface {
			sel = append(sel, e)
		}
	}
	sort.SliceStable(sel, func(i, j int) bool { return sel[i].At.Before(sel[j].At) })
	return sel
}
