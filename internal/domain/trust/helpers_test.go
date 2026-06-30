package trust

import (
	"testing"

	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/finding"
	"github.com/alexverify/eyebrow/internal/domain/lockfile"
)

// The scoring helpers are the hand-recomputable weights the package promises;
// pin every rung of each ladder so a silent reweighting is caught.
func TestSeverityWeightLadder(t *testing.T) {
	cases := []struct {
		sev  finding.Severity
		want int
	}{
		{finding.SeverityCritical, 40},
		{finding.SeverityHigh, 20},
		{finding.SeverityMedium, 8},
		{finding.SeverityLow, 2},
		{finding.Severity("info"), 0}, // unknown → no weight
	}
	for _, c := range cases {
		if got := severityWeight(c.sev); got != c.want {
			t.Errorf("severityWeight(%q) = %d, want %d", c.sev, got, c.want)
		}
	}
}

func TestDriftPenaltyAndLabel(t *testing.T) {
	cases := []struct {
		drift     lockfile.DriftClass
		penalty   int
		wantLabel bool
	}{
		{lockfile.DriftClassMutated, 30, true},
		{lockfile.DriftClassBroken, 20, true},
		{lockfile.DriftClassAdded, 10, true},
		{lockfile.DriftClassUpdated, 5, true},
		{lockfile.DriftClassNone, 0, false},
	}
	for _, c := range cases {
		if got := driftPenalty(c.drift); got != c.penalty {
			t.Errorf("driftPenalty(%q) = %d, want %d", c.drift, got, c.penalty)
		}
		label := driftLabel(c.drift)
		if (label != "") != c.wantLabel {
			t.Errorf("driftLabel(%q) = %q, wantNonEmpty=%v", c.drift, label, c.wantLabel)
		}
	}
}

func TestPinnedByKind(t *testing.T) {
	cases := []struct {
		name string
		src  artifact.Source
		want bool
	}{
		{"npm with integrity", artifact.Source{Kind: artifact.SourceNPM, Integrity: "sha512-A"}, true},
		{"npm without integrity", artifact.Source{Kind: artifact.SourceNPM}, false},
		{"url with cert", artifact.Source{Kind: artifact.SourceURL, CertSPKI: "spki"}, true},
		{"url without cert", artifact.Source{Kind: artifact.SourceURL}, false},
		{"git always pinned", artifact.Source{Kind: artifact.SourceGit}, true},
		{"local always pinned", artifact.Source{Kind: artifact.SourceLocal}, true},
		{"inline always pinned", artifact.Source{Kind: artifact.SourceInline}, true},
		{"unknown kind", artifact.Source{Kind: artifact.SourceKind("mystery")}, false},
	}
	for _, c := range cases {
		if got := pinned(c.src); got != c.want {
			t.Errorf("%s: pinned = %v, want %v", c.name, got, c.want)
		}
	}
}
