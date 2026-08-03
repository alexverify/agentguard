package resolve

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/digest"
)

// appRecord is the shape the AgentOS per-app endpoint returns.
const appRecord = `{
  "app": {
    "slug": "derek",
    "manifest": {
      "schemaVersion": "agentos.app.v1",
      "version": "1.0.0",
      "runtime": "external-app",
      "entrypoint": "agentos://kernel/derek",
      "permissions": [],
      "requiredSecrets": [],
      "distribution": {"webUrl": "https://app.example.com", "androidUrl": null, "iosUrl": null}
    }
  }
}`

func serveJSON(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRegistryResolveDigestsTheManifest(t *testing.T) {
	srv := serveJSON(t, appRecord)
	r := Registry{Client: srv.Client(), Fetcher: fakeCertFetcher{pin: "sha256/AAAA"}}

	res, err := r.Resolve(context.Background(), artifact.Source{Kind: artifact.SourceRegistry, Ref: srv.URL})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// The anchor must be the digest of the manifest alone, canonicalized, so a
	// counter bump elsewhere in the record does not read as drift.
	want := digest.Inline([]byte(`{"distribution":{"androidUrl":null,"iosUrl":null,"webUrl":"https://app.example.com"},"entrypoint":"agentos://kernel/derek","permissions":[],"requiredSecrets":[],"runtime":"external-app","schemaVersion":"agentos.app.v1","version":"1.0.0"}`))
	if res.ContentHash != want {
		t.Errorf("ContentHash = %q, want %q", res.ContentHash, want)
	}
}

func TestRegistryResolvePinsTheDistributionHost(t *testing.T) {
	srv := serveJSON(t, appRecord)
	r := Registry{Client: srv.Client(), Fetcher: fakeCertFetcher{pin: "sha256/BBBB"}}

	res, err := r.Resolve(context.Background(), artifact.Source{Kind: artifact.SourceRegistry, Ref: srv.URL})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.CertSPKI != "sha256/BBBB" {
		t.Errorf("CertSPKI = %q, want the distribution host pin", res.CertSPKI)
	}
	if !hasRule(res.Warnings, "REGISTRY-METADATA-ONLY") {
		t.Error("a registry entry must be marked metadata-only: its code was never obtained")
	}
}

func TestRouterDispatchesRegistrySources(t *testing.T) {
	// No distribution.webUrl, so this exercises routing without a TLS dial.
	srv := serveJSON(t, `{"app":{"slug":"x","manifest":{"version":"1.0.0"}}}`)

	res, err := NewRouter().Resolve(context.Background(), artifact.Source{
		Kind: artifact.SourceRegistry, Ref: srv.URL,
	})
	if err != nil {
		t.Fatalf("router must handle registry sources: %v", err)
	}
	if res.ContentHash == "" {
		t.Error("registry resolution must yield a content hash")
	}
}

func TestRegistryResolveRaisesListingFindings(t *testing.T) {
	// The fixture's entrypoint is agentos://kernel/derek with no repository and
	// an unverified publisher, so resolution must surface those weaknesses
	// rather than reporting a clean pin.
	srv := serveJSON(t, appRecord)
	r := Registry{Client: srv.Client(), Fetcher: fakeCertFetcher{pin: "sha256/AAAA"}}

	res, err := r.Resolve(context.Background(), artifact.Source{Kind: artifact.SourceRegistry, Ref: srv.URL})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	for _, rule := range []string{"REGISTRY-ENTRYPOINT-UNPINNABLE", "REGISTRY-NO-SOURCE", "REGISTRY-UNVERIFIED-PUBLISHER"} {
		if !hasRule(res.Warnings, rule) {
			t.Errorf("missing finding %s", rule)
		}
	}
}

func TestRegistryResolveReadsCommandsForCapabilityRule(t *testing.T) {
	srv := serveJSON(t, `{"app":{"slug":"x","verified":true,"repositoryUrl":"https://github.com/x/x",
	  "manifest":{"entrypoint":"https://x.example/s.js","permissions":[],"requiredSecrets":[],
	  "commands":[{"name":"launch"},{"name":"status"}]}}}`)
	r := Registry{Client: srv.Client(), Fetcher: fakeCertFetcher{pin: "sha256/AAAA"}}

	res, err := r.Resolve(context.Background(), artifact.Source{Kind: artifact.SourceRegistry, Ref: srv.URL})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !hasRule(res.Warnings, "REGISTRY-NO-CAPABILITY-DECL") {
		t.Error("commands present with no declared capabilities must be reported")
	}
}

func TestRegistryResolveRejectsRecordsItCannotUnderstand(t *testing.T) {
	// A registry whose schema this resolver does not know must fail loudly.
	// Fabricating an anchor from an absent manifest would digest "null" — the
	// same value for every foreign registry — so verify could never see drift,
	// and the listing rules would report confident findings about fields they
	// never read.
	srv := serveJSON(t, `{"package":{"identifier":"acme","sourceRepo":"https://github.com/acme/tool",
	  "publisherVerified":true,"exec":{"start":"https://cdn.acme.io/tool.js"}}}`)
	r := Registry{Client: srv.Client(), Fetcher: fakeCertFetcher{pin: "sha256/AAAA"}}

	res, err := r.Resolve(context.Background(), artifact.Source{Kind: artifact.SourceRegistry, Ref: srv.URL})
	if err == nil {
		t.Fatalf("expected an error for an unrecognized record; got hash %q and %d findings",
			res.ContentHash, len(res.Warnings))
	}
	if res.ContentHash != "" {
		t.Errorf("must not emit an integrity anchor it cannot justify, got %q", res.ContentHash)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("must not emit listing findings about fields it never parsed, got %d", len(res.Warnings))
	}
}
