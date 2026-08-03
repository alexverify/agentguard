package registry

import (
	"testing"

	"github.com/alexverify/eyebrow/internal/domain/finding"
)

func has(fs []finding.Finding, ruleID string) *finding.Finding {
	for i := range fs {
		if fs[i].RuleID == ruleID {
			return &fs[i]
		}
	}
	return nil
}

// healthy is a listing with nothing to complain about, so each test can vary
// exactly one field and attribute the resulting finding to that change.
func healthy() Listing {
	return Listing{
		Slug:            "example",
		Entrypoint:      "https://app.example.com/server.js",
		RepositoryURL:   "https://github.com/example/app",
		DistributionURL: "https://app.example.com",
		Permissions:     []string{"workspace:read"},
		Commands:        []string{"launch"},
		Verified:        true,
	}
}

func TestHealthyListingRaisesNothing(t *testing.T) {
	if fs := Assess(healthy()); len(fs) != 0 {
		t.Fatalf("healthy listing raised %d findings: %+v", len(fs), fs)
	}
}

func TestEntrypointThatCannotResolveToBytesIsHigh(t *testing.T) {
	l := healthy()
	l.Entrypoint = "agentos://kernel/example"

	f := has(Assess(l), "REGISTRY-ENTRYPOINT-UNPINNABLE")
	if f == nil {
		t.Fatal("an opaque entrypoint scheme must be reported: no code can be obtained from it")
	}
	if f.Severity != finding.SeverityHigh {
		t.Errorf("severity = %q, want high", f.Severity)
	}
}

func TestMissingRepositoryIsReported(t *testing.T) {
	l := healthy()
	l.RepositoryURL = ""

	if has(Assess(l), "REGISTRY-NO-SOURCE") == nil {
		t.Fatal("a listing with no repository has no establishable provenance")
	}
}

func TestCommandsWithoutDeclaredCapabilitiesIsReported(t *testing.T) {
	// An app that exposes commands but declares neither permissions nor secrets
	// is either under-declaring or its manifest does not model what it runs.
	l := healthy()
	l.Permissions = nil
	l.RequiredSecrets = nil
	l.Commands = []string{"launch", "status"}

	if has(Assess(l), "REGISTRY-NO-CAPABILITY-DECL") == nil {
		t.Fatal("commands with zero declared capabilities must be reported")
	}
}

func TestNoCommandsAndNoCapabilitiesIsNotReported(t *testing.T) {
	// A listing that does nothing and declares nothing is consistent, so the
	// capability rule must not fire on it — otherwise the rule just detects
	// emptiness rather than under-declaration.
	l := healthy()
	l.Permissions = nil
	l.RequiredSecrets = nil
	l.Commands = nil

	if has(Assess(l), "REGISTRY-NO-CAPABILITY-DECL") != nil {
		t.Fatal("a listing with no commands must not raise the capability finding")
	}
}

func TestUnverifiedPublisherIsReported(t *testing.T) {
	l := healthy()
	l.Verified = false

	f := has(Assess(l), "REGISTRY-UNVERIFIED-PUBLISHER")
	if f == nil {
		t.Fatal("an unverified publisher must be visible in the findings")
	}
	if f.Severity != finding.SeverityLow {
		t.Errorf("severity = %q, want low", f.Severity)
	}
}
