package cli_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/alexverify/eyebrow/internal/cli"
	"github.com/alexverify/eyebrow/internal/domain/lockfile"
	"github.com/alexverify/eyebrow/internal/domain/reputation"
)

func decodeCorpus(t *testing.T, b []byte) reputation.Source {
	t.Helper()
	var s reputation.Source
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatalf("bad corpus json: %v\n%s", err, b)
	}
	return s
}

func hashedCount(lf lockfile.Lockfile) int {
	n := 0
	for _, e := range lf.Artifacts {
		if e.ContentHash != "" {
			n++
		}
	}
	return n
}

func TestReputationExportVouchesForApprovedOnly(t *testing.T) {
	ctx := context.Background()
	dir, lock := fixtureProject(t)

	app, _, _ := newApp()
	if code := app.Execute(ctx, []string{"scan", "--path", dir, "--lockfile", lock}); code != cli.ExitOK {
		t.Fatal("scan failed")
	}

	// Nothing approved yet → an empty, content-free corpus (not an error).
	app, out, _ := newApp()
	if code := app.Execute(ctx, []string{"reputation", "export", "--lockfile", lock}); code != cli.ExitOK {
		t.Fatalf("export exit = %d", code)
	}
	if got := decodeCorpus(t, out.Bytes()); len(got) != 0 {
		t.Fatalf("no approvals yet, want empty corpus, got %v", got)
	}

	// After approving, each approved artifact's hash is vouched for once.
	app, _, _ = newApp()
	if code := app.Execute(ctx, []string{"approve", "--all", "--lockfile", lock}); code != cli.ExitOK {
		t.Fatal("approve failed")
	}
	app, out, _ = newApp()
	if code := app.Execute(ctx, []string{"reputation", "export", "--lockfile", lock}); code != cli.ExitOK {
		t.Fatalf("export exit = %d", code)
	}
	corpus := decodeCorpus(t, out.Bytes())
	lf := readLockfile(t, lock)
	if want := hashedCount(lf); len(corpus) == 0 || len(corpus) != want {
		t.Fatalf("corpus size = %d, want %d approved hashes", len(corpus), want)
	}
	for h, sig := range corpus {
		if sig.Trusters != 1 {
			t.Errorf("hash %s trusters = %d, want 1", h, sig.Trusters)
		}
	}
}

func TestReputationExportAllIncludesUnapproved(t *testing.T) {
	ctx := context.Background()
	dir, lock := fixtureProject(t)
	app, _, _ := newApp()
	app.Execute(ctx, []string{"scan", "--path", dir, "--lockfile", lock})

	// No approvals, but --all vouches for the whole inventory.
	app, out, _ := newApp()
	if code := app.Execute(ctx, []string{"reputation", "export", "--all", "--lockfile", lock}); code != cli.ExitOK {
		t.Fatalf("export --all exit = %d", code)
	}
	corpus := decodeCorpus(t, out.Bytes())
	if want := hashedCount(readLockfile(t, lock)); len(corpus) != want || want == 0 {
		t.Fatalf("--all corpus size = %d, want %d (all hashed artifacts)", len(corpus), want)
	}
}

func TestReputationExportMergeAccumulatesTrusters(t *testing.T) {
	ctx := context.Background()
	dir, lock := fixtureProject(t)
	app, _, _ := newApp()
	app.Execute(ctx, []string{"scan", "--path", dir, "--lockfile", lock})

	shared := filepath.Join(dir, "corpus.json")

	// First member seeds the shared corpus (file does not exist yet → starts fresh).
	app, _, errBuf := newApp()
	if code := app.Execute(ctx, []string{"reputation", "export", "--all", "--lockfile", lock, "--merge", shared, "-o", shared}); code != cli.ExitOK {
		t.Fatalf("first export exit = %d, stderr=%s", code, errBuf.String())
	}
	// A second member merges into it; trusters for the same hashes climb to 2.
	app, _, _ = newApp()
	if code := app.Execute(ctx, []string{"reputation", "export", "--all", "--lockfile", lock, "--merge", shared, "-o", shared}); code != cli.ExitOK {
		t.Fatalf("second export exit = %d", code)
	}

	b, err := os.ReadFile(shared)
	if err != nil {
		t.Fatal(err)
	}
	corpus := decodeCorpus(t, b)
	if len(corpus) == 0 {
		t.Fatal("empty shared corpus")
	}
	for h, sig := range corpus {
		if sig.Trusters != 2 {
			t.Errorf("hash %s trusters = %d after two merges, want 2", h, sig.Trusters)
		}
	}
}

func TestReputationExportNoLockfileFails(t *testing.T) {
	app, _, _ := newApp()
	code := app.Execute(context.Background(), []string{"reputation", "export", "--lockfile", filepath.Join(t.TempDir(), "missing.json")})
	if code != cli.ExitError {
		t.Fatalf("export with no lockfile exit = %d, want %d", code, cli.ExitError)
	}
}
