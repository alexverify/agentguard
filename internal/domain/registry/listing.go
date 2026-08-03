// Package registry holds the pure, IO-free rules for assessing an application
// published to a remote catalog (an app store listing).
//
// A listing is the weakest thing eyebrow can be asked to judge: the registry
// exposes what the publisher declared, never the code that runs. These rules
// therefore assess the *declaration* — whether it can be pinned, whether its
// provenance is establishable, and whether it plausibly describes what the
// application does. None of them can speak to the behaviour of the deployed
// code, and none should be read as doing so.
package registry

import (
	"strings"

	"github.com/alexverify/eyebrow/internal/domain/finding"
)

// Listing is the registry-neutral view of a published application record.
// Adapters map a catalog's own JSON shape onto it, so these rules stay
// independent of any one registry's schema.
type Listing struct {
	Slug            string
	Entrypoint      string
	RepositoryURL   string
	DistributionURL string
	Permissions     []string
	RequiredSecrets []string
	Commands        []string
	Verified        bool
}

// Assess applies the listing rules and returns the findings raised, in a
// stable order. An empty result means nothing in the declaration is
// objectionable — not that the application is safe.
func Assess(l Listing) []finding.Finding {
	var out []finding.Finding

	if !pinnable(l.Entrypoint) {
		out = append(out, finding.Finding{
			RuleID: "REGISTRY-ENTRYPOINT-UNPINNABLE", Severity: finding.SeverityHigh, OWASP: "ASK-02",
			Explanation: "entrypoint " + l.Entrypoint + " does not resolve to obtainable code, so no integrity anchor exists for what actually executes",
		})
	}

	if strings.TrimSpace(l.RepositoryURL) == "" {
		out = append(out, finding.Finding{
			RuleID: "REGISTRY-NO-SOURCE", Severity: finding.SeverityMedium, OWASP: "ASK-02",
			Explanation: "listing declares no source repository, so its provenance cannot be established or pinned to a commit",
		})
	}

	// Only meaningful when the app exposes commands: a listing that does
	// nothing and declares nothing is internally consistent.
	if len(l.Commands) > 0 && len(l.Permissions) == 0 && len(l.RequiredSecrets) == 0 {
		out = append(out, finding.Finding{
			RuleID: "REGISTRY-NO-CAPABILITY-DECL", Severity: finding.SeverityMedium, OWASP: "ASK-05",
			Explanation: "listing exposes commands but declares no permissions and no required secrets; the manifest either under-declares or does not model what the application runs",
		})
	}

	if !l.Verified {
		out = append(out, finding.Finding{
			RuleID: "REGISTRY-UNVERIFIED-PUBLISHER", Severity: finding.SeverityLow, OWASP: "ASK-02",
			Explanation: "listing is published by an unverified publisher",
		})
	}

	return out
}

// pinnable reports whether an entrypoint could, in principle, be fetched and
// hashed. Custom schemes (agentos://, ipfs://, and the like) name a resource
// inside someone else's runtime; nothing about the executing code follows from
// them. An empty entrypoint is equally unpinnable.
func pinnable(entrypoint string) bool {
	e := strings.TrimSpace(entrypoint)
	if e == "" {
		return false
	}
	if strings.HasPrefix(e, "https://") || strings.HasPrefix(e, "http://") {
		return true
	}
	// A bare relative path (dist/server.js) is pinnable when the package that
	// contains it is supplied; a scheme-qualified reference to a foreign
	// runtime is not.
	return !strings.Contains(e, "://")
}
