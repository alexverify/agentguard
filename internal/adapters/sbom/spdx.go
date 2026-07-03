package sbom

import (
	"fmt"
	"strings"

	"github.com/alexverify/eyebrow/internal/domain/finding"
	"github.com/alexverify/eyebrow/internal/domain/lockfile"
)

// Document is the subset of the SPDX 2.3 JSON schema eyebrow emits: one package
// per discovered artifact, each DESCRIBES-related to the document root. SPDX is
// an inventory format (unlike CycloneDX it has no first-class vulnerability
// model), so static-analysis findings ride along as package annotations and the
// eyebrow provenance metadata lives in the package comment.
type Document struct {
	SPDXVersion       string         `json:"spdxVersion"` // "SPDX-2.3"
	DataLicense       string         `json:"dataLicense"` // "CC0-1.0"
	SPDXID            string         `json:"SPDXID"`      // "SPDXRef-DOCUMENT"
	Name              string         `json:"name"`        // document name
	DocumentNamespace string         `json:"documentNamespace"`
	CreationInfo      CreationInfo   `json:"creationInfo"`
	Packages          []Package      `json:"packages"`
	Relationships     []Relationship `json:"relationships"`
}

type CreationInfo struct {
	Created  string   `json:"created"`  // RFC3339
	Creators []string `json:"creators"` // ["Tool: eyebrow"]
}

type Package struct {
	SPDXID           string        `json:"SPDXID"`
	Name             string        `json:"name"`
	VersionInfo      string        `json:"versionInfo,omitempty"`
	DownloadLocation string        `json:"downloadLocation"` // "NOASSERTION"
	FilesAnalyzed    bool          `json:"filesAnalyzed"`    // false: we describe the artifact, not its files
	LicenseConcluded string        `json:"licenseConcluded"` // "NOASSERTION"
	LicenseDeclared  string        `json:"licenseDeclared"`  // "NOASSERTION"
	CopyrightText    string        `json:"copyrightText"`    // "NOASSERTION"
	Comment          string        `json:"comment,omitempty"`
	Checksums        []Checksum    `json:"checksums,omitempty"`
	ExternalRefs     []ExternalRef `json:"externalRefs,omitempty"`
	Annotations      []Annotation  `json:"annotations,omitempty"`
}

type Checksum struct {
	Algorithm     string `json:"algorithm"` // "SHA256"
	ChecksumValue string `json:"checksumValue"`
}

type ExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"` // "PACKAGE-MANAGER"
	ReferenceType     string `json:"referenceType"`     // "purl"
	ReferenceLocator  string `json:"referenceLocator"`
}

type Annotation struct {
	AnnotationType string `json:"annotationType"` // "OTHER"
	Annotator      string `json:"annotator"`      // "Tool: eyebrow"
	AnnotationDate string `json:"annotationDate"` // RFC3339
	Comment        string `json:"comment"`
}

type Relationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"` // "DESCRIBES"
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

const spdxCreator = "Tool: eyebrow"

// BuildSPDX maps a lockfile to an SPDX 2.3 document. ts stamps the creation info
// and seeds the (deterministic) document namespace, so the same lockfile and
// timestamp always render byte-identical output.
func BuildSPDX(lf lockfile.Lockfile, ts string) Document {
	pkgs := make([]Package, 0, len(lf.Artifacts))
	rels := make([]Relationship, 0, len(lf.Artifacts))
	for _, e := range lf.Artifacts {
		p := spdxPackage(e, ts)
		pkgs = append(pkgs, p)
		rels = append(rels, Relationship{
			SPDXElementID:      "SPDXRef-DOCUMENT",
			RelationshipType:   "DESCRIBES",
			RelatedSPDXElement: p.SPDXID,
		})
	}
	return Document{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              "eyebrow-sbom",
		DocumentNamespace: "https://eyebrow.dev/spdx/eyebrow-sbom-" + ts,
		CreationInfo:      CreationInfo{Created: ts, Creators: []string{spdxCreator}},
		Packages:          pkgs,
		Relationships:     rels,
	}
}

func spdxPackage(e lockfile.Entry, ts string) Package {
	p := Package{
		SPDXID:           spdxRef(e.ID),
		Name:             e.Name,
		VersionInfo:      version(e.Source),
		DownloadLocation: "NOASSERTION",
		FilesAnalyzed:    false,
		LicenseConcluded: "NOASSERTION",
		LicenseDeclared:  "NOASSERTION",
		CopyrightText:    "NOASSERTION",
		Comment:          spdxComment(e),
	}
	if h := sha256Hex(e.ContentHash); h != "" {
		p.Checksums = []Checksum{{Algorithm: "SHA256", ChecksumValue: h}}
	}
	if pu := purl(e.Source); pu != "" {
		p.ExternalRefs = []ExternalRef{{
			ReferenceCategory: "PACKAGE-MANAGER",
			ReferenceType:     "purl",
			ReferenceLocator:  pu,
		}}
	}
	for _, f := range e.Findings {
		p.Annotations = append(p.Annotations, spdxAnnotation(f, ts))
	}
	return p
}

// spdxComment folds eyebrow's provenance metadata into the package comment,
// mirroring the CycloneDX properties (SPDX has no free-form property list).
func spdxComment(e lockfile.Entry) string {
	var kv []string
	add := func(name, val string) {
		if val != "" {
			kv = append(kv, name+"="+val)
		}
	}
	add("eyebrow:tool", e.Tool)
	add("eyebrow:type", string(e.Type))
	add("eyebrow:scope", e.Scope)
	add("eyebrow:sourceKind", string(e.Source.Kind))
	add("eyebrow:integrity", e.Source.Integrity)
	add("eyebrow:provenance", e.Source.Provenance)
	if e.Quarantined {
		add("eyebrow:quarantined", "true")
	}
	if e.Frozen {
		add("eyebrow:frozen", "true")
	}
	if e.Approval != nil && e.Approval.Status == "approved" {
		add("eyebrow:approved", "true")
	}
	return strings.Join(kv, "; ")
}

func spdxAnnotation(f finding.Finding, ts string) Annotation {
	return Annotation{
		AnnotationType: "OTHER",
		Annotator:      spdxCreator,
		AnnotationDate: ts,
		Comment:        fmt.Sprintf("finding %s (%s): %s", f.RuleID, f.Severity, f.Explanation),
	}
}

// spdxRef turns an artifact ID into a valid SPDX element identifier: the spec
// constrains SPDXID to letters, digits, '.' and '-', so any other rune (a path
// separator, an npm scope '@', a ':') collapses to '-'.
func spdxRef(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return "SPDXRef-Package-" + b.String()
}
