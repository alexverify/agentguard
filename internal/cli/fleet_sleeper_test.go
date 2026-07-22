package cli

import (
	"testing"
	"time"

	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/lockfile"
	"github.com/alexverify/eyebrow/internal/domain/usage"
)

// A dormant-then-active, drifted artifact must snapshot as a sleeper, and the
// snapshot must stay content-free (a derived bool, no file bytes).
func TestSnapshotArtifactsFlagsSleeper(t *testing.T) {
	scanAt := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)

	locked := artifact.Artifact{
		ID: "m1", Tool: "cursor", Type: artifact.TypeMCPServer, Name: "db", ContentHash: "sha256-old",
		Source: artifact.Source{Kind: artifact.SourceNPM, Ref: "1.0.0", Integrity: "sha512-A"},
	}
	cur := artifact.Artifact{
		ID: "m1", Tool: "cursor", Type: artifact.TypeMCPServer, Name: "db", ContentHash: "sha256-NEW",
		Source:     artifact.Source{Kind: artifact.SourceNPM, Ref: "1.0.0", Integrity: "sha512-A"},
		ModifiedAt: scanAt.Add(-60 * 24 * time.Hour), // installed ~60 days ago
	}
	current := lockfile.Build([]artifact.Artifact{cur}, scanAt, "eyebrow/test")
	lockedLf := lockfile.Build([]artifact.Artifact{locked}, scanAt, "eyebrow/test")

	used := map[string]usage.Stat{
		"db": {FirstUsed: scanAt.Add(-24 * time.Hour), LastUsed: scanAt, Count: 1}, // first run yesterday
	}

	arts := snapshotArtifacts(current, lockedLf, used)
	if len(arts) != 1 {
		t.Fatalf("want 1 artifact, got %d", len(arts))
	}
	if !arts[0].Sleeper {
		t.Errorf("dormant-then-active drift should snapshot as a sleeper: %+v", arts[0])
	}
}

// Without usage stats (no audit log), no sleeper — degrade-never-crash.
func TestSnapshotArtifactsNoSleeperWithoutUsage(t *testing.T) {
	scanAt := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	cur := artifact.Artifact{
		ID: "m1", Tool: "cursor", Type: artifact.TypeMCPServer, Name: "db", ContentHash: "sha256-NEW",
		Source:     artifact.Source{Kind: artifact.SourceNPM, Ref: "1.0.0", Integrity: "sha512-A"},
		ModifiedAt: scanAt.Add(-60 * 24 * time.Hour),
	}
	locked := cur
	locked.ContentHash = "sha256-old"
	current := lockfile.Build([]artifact.Artifact{cur}, scanAt, "eyebrow/test")
	lockedLf := lockfile.Build([]artifact.Artifact{locked}, scanAt, "eyebrow/test")

	arts := snapshotArtifacts(current, lockedLf, nil)
	if len(arts) != 1 || arts[0].Sleeper {
		t.Errorf("no usage → no sleeper, got %+v", arts)
	}
}
