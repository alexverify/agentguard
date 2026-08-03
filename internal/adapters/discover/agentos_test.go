package discover

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

const catalogBody = `{
  "apps": [
    {"slug": "derek",    "name": "Derek",    "manifest": {"version": "1.0.0", "runtime": "external-app"}},
    {"slug": "dezypher", "name": "Dezypher", "manifest": {"version": "2.1.0", "runtime": "external-app"}}
  ],
  "pagination": {"total": 2}
}`

func catalogServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAgentOSDiscoversOneArtifactPerPublishedApp(t *testing.T) {
	srv := catalogServer(t, catalogBody)
	d := &AgentOS{Client: srv.Client()}

	arts, err := d.Discover(context.Background(), []ports.Scope{{Kind: "registry", Path: srv.URL}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(arts) != 2 {
		t.Fatalf("got %d artifacts, want 2", len(arts))
	}

	got := arts[0]
	if got.Name != "derek" {
		t.Errorf("Name = %q, want the slug", got.Name)
	}
	if got.Tool != "agentos" {
		t.Errorf("Tool = %q", got.Tool)
	}
	if got.Source.Kind != artifact.SourceRegistry {
		t.Errorf("Source.Kind = %q, want registry", got.Source.Kind)
	}
	if want := srv.URL + "/api/apps/derek"; got.Source.Ref != want {
		t.Errorf("Source.Ref = %q, want %q", got.Source.Ref, want)
	}
	if want := "registry:" + srv.URL; got.Scope != want {
		t.Errorf("Scope = %q, want %q", got.Scope, want)
	}
}

func TestAgentOSIgnoresLocalScopes(t *testing.T) {
	// A registry discoverer must stay silent for filesystem scopes, or every
	// ordinary local scan would start making network calls.
	d := &AgentOS{Client: http.DefaultClient}

	arts, err := d.Discover(context.Background(), []ports.Scope{
		{Kind: "global"},
		{Kind: "project", Path: t.TempDir()},
	})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(arts) != 0 {
		t.Fatalf("got %d artifacts from local scopes, want 0", len(arts))
	}
}

func TestAgentOSSurfacesRegistryFailure(t *testing.T) {
	// A catalog that cannot be read must not be reported as an empty catalog:
	// "nothing published" and "could not ask" are different answers.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	d := &AgentOS{Client: srv.Client()}

	if _, err := d.Discover(context.Background(), []ports.Scope{{Kind: "registry", Path: srv.URL}}); err == nil {
		t.Fatal("expected an error when the catalog cannot be read")
	}
}

func TestDefaultDiscoversRegistryScopes(t *testing.T) {
	// The composition root must include the registry discoverer, or --registry
	// would silently return nothing.
	srv := catalogServer(t, catalogBody)

	arts, err := Default().Discover(context.Background(), []ports.Scope{{Kind: "registry", Path: srv.URL}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(arts) != 2 {
		t.Fatalf("got %d artifacts from Default(), want 2", len(arts))
	}
}
