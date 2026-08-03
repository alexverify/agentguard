package cli

import "testing"

func TestScopesAddsRegistryWhenRequested(t *testing.T) {
	a := &App{}
	sc := a.scopes("/srv/app", false, "https://www.agentos.services")

	var found bool
	for _, s := range sc {
		if s.Kind == "registry" && s.Path == "https://www.agentos.services" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no registry scope in %+v", sc)
	}
}

func TestScopesOmitsRegistryByDefault(t *testing.T) {
	// Scanning must not reach the network unless a registry was explicitly named.
	a := &App{}
	for _, s := range a.scopes("/srv/app", true, "") {
		if s.Kind == "registry" {
			t.Fatalf("unexpected registry scope %+v without --registry", s)
		}
	}
}
