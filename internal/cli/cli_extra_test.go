package cli_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexverify/eyebrow/internal/cli"
)

func TestKeyWithoutSubcommand(t *testing.T) {
	app, _, _ := newApp()
	if code := app.Execute(context.Background(), []string{"key"}); code != cli.ExitUsage {
		t.Errorf("bare `key` should be ExitUsage, got %d", code)
	}
}

func TestKeyUnknownSubcommand(t *testing.T) {
	app, _, _ := newApp()
	if code := app.Execute(context.Background(), []string{"key", "bogus"}); code != cli.ExitUsage {
		t.Errorf("unknown key subcommand should be ExitUsage, got %d", code)
	}
}

// sbom -o writes the CycloneDX document to a file instead of stdout.
func TestSBOMWritesToFile(t *testing.T) {
	ctx := context.Background()
	dir, lock := fixtureProject(t)

	app, _, errBuf := newApp()
	if code := app.Execute(ctx, []string{"scan", "--path", dir, "--lockfile", lock}); code != cli.ExitOK {
		t.Fatalf("scan exit = %d, stderr=%s", code, errBuf.String())
	}

	outPath := filepath.Join(dir, "bom.json")
	app, out, errBuf := newApp()
	if code := app.Execute(ctx, []string{"sbom", "--lockfile", lock, "-o", outPath}); code != cli.ExitOK {
		t.Fatalf("sbom -o exit = %d, stderr=%s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "component(s)") {
		t.Errorf("sbom -o should confirm the write on stdout:\n%s", out.String())
	}
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("sbom file not written: %v", err)
	}
	if !strings.Contains(string(raw), "bomFormat") && !strings.Contains(string(raw), "CycloneDX") {
		t.Errorf("written file is not a CycloneDX document:\n%s", string(raw))
	}
}

// sbom --format spdx emits an SPDX 2.3 document instead of CycloneDX.
func TestSBOMEmitsSPDX(t *testing.T) {
	ctx := context.Background()
	dir, lock := fixtureProject(t)

	app, _, errBuf := newApp()
	if code := app.Execute(ctx, []string{"scan", "--path", dir, "--lockfile", lock}); code != cli.ExitOK {
		t.Fatalf("scan exit = %d, stderr=%s", code, errBuf.String())
	}

	app, out, errBuf := newApp()
	if code := app.Execute(ctx, []string{"sbom", "--lockfile", lock, "--format", "spdx"}); code != cli.ExitOK {
		t.Fatalf("sbom --format spdx exit = %d, stderr=%s", code, errBuf.String())
	}
	var doc struct {
		SPDXVersion string `json:"spdxVersion"`
		DataLicense string `json:"dataLicense"`
		Packages    []struct {
			SPDXID string `json:"SPDXID"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("spdx output is not valid JSON: %v\n%s", err, out.String())
	}
	if doc.SPDXVersion != "SPDX-2.3" || doc.DataLicense != "CC0-1.0" {
		t.Errorf("not an SPDX 2.3 document: %+v", doc)
	}
	if len(doc.Packages) == 0 {
		t.Errorf("expected at least one package:\n%s", out.String())
	}
}

// An unknown --format is a usage error, not a silent fallback.
func TestSBOMRejectsUnknownFormat(t *testing.T) {
	dir, lock := fixtureProject(t)
	app, _, _ := newApp()
	if code := app.Execute(context.Background(), []string{"sbom", "--path", dir, "--lockfile", lock, "--format", "bogus"}); code != cli.ExitUsage {
		t.Errorf("unknown format exit = %d, want %d", code, cli.ExitUsage)
	}
}

// sbom over a missing lockfile fails rather than emitting an empty document.
func TestSBOMMissingLockfile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.json")
	app, _, _ := newApp()
	if code := app.Execute(context.Background(), []string{"sbom", "--lockfile", missing}); code == cli.ExitOK {
		t.Error("sbom over a missing lockfile should not exit 0")
	}
}
