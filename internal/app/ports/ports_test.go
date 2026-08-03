package ports

import "testing"

func TestScopeStringKeepsRegistryURL(t *testing.T) {
	// Two registries must not collapse to the same scope string: artifact IDs
	// are derived from it, so collapsing them would alias distinct catalogs
	// onto one lockfile entry.
	a := Scope{Kind: "registry", Path: "https://one.example"}
	b := Scope{Kind: "registry", Path: "https://two.example"}

	if a.String() == b.String() {
		t.Fatalf("distinct registries share scope string %q", a.String())
	}
	if got, want := a.String(), "registry:https://one.example"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestScopeStringUnchangedForLocalScopes(t *testing.T) {
	if got := (Scope{Kind: "global"}).String(); got != "global" {
		t.Errorf("global scope = %q", got)
	}
	if got := (Scope{Kind: "project", Path: "/srv/app"}).String(); got != "project:/srv/app" {
		t.Errorf("project scope = %q", got)
	}
}
