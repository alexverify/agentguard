package cpstore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/alexverify/eyebrow/internal/domain/fleet"
)

// Snapshots skips a corrupt or ownerless file but still returns the valid ones,
// so one bad submission never hides the rest of the fleet.
func TestSnapshotsSkipsCorruptFile(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)
	if err := s.PutSnapshot("acme", fleet.Snapshot{Owner: "alice",
		Artifacts: []fleet.Artifact{{ID: "x", Hash: "h"}}}); err != nil {
		t.Fatal(err)
	}
	snapDir := filepath.Join(dir, safeName("acme"), snapshotsSubdir)
	// A non-JSON file and an ownerless-but-valid-JSON file: both dropped.
	if err := os.WriteFile(filepath.Join(snapDir, "broken.json"), []byte("{nope"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snapDir, "ownerless.json"), []byte(`{"owner":""}`), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := s.Snapshots("acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Owner != "alice" {
		t.Fatalf("expected only the valid snapshot, got %+v", got)
	}
}

// The read-back accessors surface a parse error on a corrupt config file rather
// than silently returning a zero value.
func TestReadBackSurfacesCorruptJSON(t *testing.T) {
	dir := t.TempDir()
	orgDir := filepath.Join(dir, safeName("acme"))
	if err := os.MkdirAll(orgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{policyFile, keysFile, reputationFile} {
		if err := os.WriteFile(filepath.Join(orgDir, f), []byte("{not json"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s := New(dir)
	if _, _, err := s.Policy("acme"); err == nil {
		t.Error("Policy should error on corrupt JSON")
	}
	if _, err := s.TrustedKeys("acme"); err == nil {
		t.Error("TrustedKeys should error on corrupt JSON")
	}
	if _, err := s.Reputation("acme"); err == nil {
		t.Error("Reputation should error on corrupt JSON")
	}
}

func TestSafeNameSanitizes(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"acme", "acme"},
		{"Acme_Co.1-2", "Acme_Co.1-2"},
		{"../escape", "escape"}, // path separators replaced, leading ".-" trimmed
		{"a/b\\c", "a-b-c"},
		{"space here", "space-here"},
		{"...", "default"}, // trims to empty → safe default
		{"/", "default"},
	}
	for _, tt := range tests {
		if got := safeName(tt.in); got != tt.want {
			t.Errorf("safeName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
