package sbom

import (
	"strings"
	"testing"
	"time"

	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/finding"
	"github.com/alexverify/eyebrow/internal/domain/lockfile"
)

func hasExtRef(p Package, typ, locator string) bool {
	for _, r := range p.ExternalRefs {
		if r.ReferenceType == typ && r.ReferenceLocator == locator {
			return true
		}
	}
	return false
}

func TestBuildSPDXMapsPackages(t *testing.T) {
	a := artifact.Artifact{
		ID: "claude-code/npm:pg-mcp", Tool: "claude-code", Type: artifact.TypeMCPServer, Name: "pg-mcp",
		ContentHash: "sha256-deadbeef",
		Source: artifact.Source{
			Kind: artifact.SourceNPM, Ref: "pg-mcp@1.2.3",
			Integrity: "sha512-x", Provenance: "https://slsa.dev/provenance/v1",
		},
		Findings: []finding.Finding{{RuleID: "RCE", Severity: finding.SeverityCritical, Explanation: "bad"}},
	}
	lf := lockfile.Build([]artifact.Artifact{a}, time.Unix(0, 0).UTC(), "t")
	doc := BuildSPDX(lf, "2026-06-14T00:00:00Z")

	if doc.SPDXVersion != "SPDX-2.3" || doc.DataLicense != "CC0-1.0" || doc.SPDXID != "SPDXRef-DOCUMENT" {
		t.Fatalf("document header = %+v", doc)
	}
	if doc.CreationInfo.Created != "2026-06-14T00:00:00Z" {
		t.Errorf("created = %q", doc.CreationInfo.Created)
	}
	if len(doc.CreationInfo.Creators) != 1 || !strings.Contains(doc.CreationInfo.Creators[0], "eyebrow") {
		t.Errorf("creators = %+v", doc.CreationInfo.Creators)
	}

	if len(doc.Packages) != 1 {
		t.Fatalf("want 1 package, got %d", len(doc.Packages))
	}
	p := doc.Packages[0]
	// SPDXID must be constrained to [A-Za-z0-9.-] — the '/' and ':' must be gone.
	if strings.ContainsAny(p.SPDXID, "/:") || !strings.HasPrefix(p.SPDXID, "SPDXRef-") {
		t.Errorf("SPDXID not sanitized: %q", p.SPDXID)
	}
	if p.VersionInfo != "1.2.3" {
		t.Errorf("versionInfo = %q", p.VersionInfo)
	}
	if p.DownloadLocation != "NOASSERTION" || p.FilesAnalyzed {
		t.Errorf("download/filesAnalyzed = %q/%v", p.DownloadLocation, p.FilesAnalyzed)
	}
	if len(p.Checksums) != 1 || p.Checksums[0].Algorithm != "SHA256" || p.Checksums[0].ChecksumValue != "deadbeef" {
		t.Errorf("checksums = %+v", p.Checksums)
	}
	if !hasExtRef(p, "purl", "pkg:npm/pg-mcp@1.2.3") {
		t.Errorf("purl external ref missing: %+v", p.ExternalRefs)
	}
	if !strings.Contains(p.Comment, "https://slsa.dev/provenance/v1") {
		t.Errorf("provenance missing from package comment: %q", p.Comment)
	}

	// The single finding is carried as an SPDX annotation naming the rule.
	if len(p.Annotations) != 1 || !strings.Contains(p.Annotations[0].Comment, "RCE") {
		t.Errorf("finding annotation = %+v", p.Annotations)
	}

	// Every package is DESCRIBES-related to the document root.
	if len(doc.Relationships) != 1 {
		t.Fatalf("want 1 relationship, got %d", len(doc.Relationships))
	}
	rel := doc.Relationships[0]
	if rel.SPDXElementID != "SPDXRef-DOCUMENT" || rel.RelationshipType != "DESCRIBES" || rel.RelatedSPDXElement != p.SPDXID {
		t.Errorf("relationship = %+v", rel)
	}
}

func TestBuildSPDXNamespaceIsDeterministic(t *testing.T) {
	lf := lockfile.Build(nil, time.Unix(0, 0).UTC(), "t")
	a := BuildSPDX(lf, "2026-06-14T00:00:00Z")
	b := BuildSPDX(lf, "2026-06-14T00:00:00Z")
	if a.DocumentNamespace == "" || a.DocumentNamespace != b.DocumentNamespace {
		t.Errorf("namespace not stable: %q vs %q", a.DocumentNamespace, b.DocumentNamespace)
	}
	if strings.ContainsAny(a.SPDXID, " ") {
		t.Errorf("document SPDXID malformed: %q", a.SPDXID)
	}
}

func TestSpdxRefSanitizes(t *testing.T) {
	got := spdxRef("claude-code/npm:@scope/pkg")
	if strings.ContainsAny(got, "/:@") {
		t.Errorf("unsanitized ref: %q", got)
	}
	if !strings.HasPrefix(got, "SPDXRef-Package-") {
		t.Errorf("missing prefix: %q", got)
	}
}
