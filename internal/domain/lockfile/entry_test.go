package lockfile

import (
	"testing"

	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/finding"
)

func entryWith(id, hash string, fs ...finding.Finding) Entry {
	return Entry{Artifact: artifact.Artifact{ID: id, ContentHash: hash, Findings: fs}}
}

// ApprovalSigningBytes binds the ID and the content hash, newline-joined, so an
// approval cannot be replayed onto a different artifact or survive a rug pull.
func TestApprovalSigningBytes(t *testing.T) {
	got := string(ApprovalSigningBytes(entryWith("skill:a", "sha256-xyz")))
	if got != "skill:a\nsha256-xyz" {
		t.Errorf("signing bytes = %q", got)
	}
	// A content change must change the committed bytes (invalidates the signature).
	if string(ApprovalSigningBytes(entryWith("skill:a", "sha256-NEW"))) == got {
		t.Error("changing the content hash must change the signing bytes")
	}
}

func TestIsFindingSafe(t *testing.T) {
	e := Entry{SafeFindings: []FindingAck{{Key: "k1"}, {Key: "k2"}}}
	if !e.IsFindingSafe("k1") {
		t.Error("a flagged key must read as safe")
	}
	if e.IsFindingSafe("missing") {
		t.Error("an unflagged key must not read as safe")
	}
	if (Entry{}).IsFindingSafe("k1") {
		t.Error("an entry with no acks has nothing safe")
	}
}

func TestHasFindingAtLeast(t *testing.T) {
	lf := Lockfile{Artifacts: []Entry{
		entryWith("a", "h1", finding.Finding{Severity: finding.SeverityLow}),
		entryWith("b", "h2", finding.Finding{Severity: finding.SeverityHigh}),
	}}
	if !lf.HasFindingAtLeast(finding.SeverityHigh) {
		t.Error("a high finding should satisfy a high threshold")
	}
	if lf.HasFindingAtLeast(finding.SeverityCritical) {
		t.Error("nothing reaches critical here")
	}
	if (Lockfile{}).HasFindingAtLeast(finding.SeverityLow) {
		t.Error("an empty lockfile has no findings")
	}
}
