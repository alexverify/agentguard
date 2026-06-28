package client_test

import (
	"context"
	"testing"

	"github.com/alexverify/eyebrow/internal/client"
	"github.com/alexverify/eyebrow/internal/domain/audit"
	"github.com/alexverify/eyebrow/internal/domain/fleet"
)

func TestClientGate(t *testing.T) {
	srv, tok := liveServer(t)
	c := client.New(srv.URL, tok)
	ctx := context.Background()

	if err := c.Submit(ctx, fleet.Snapshot{Owner: "alice", Artifacts: []fleet.Artifact{
		{ID: "x", Name: "feed", Kind: "skill", Hash: "h1", Drift: "clean", Verdict: "trusted"},
	}}); err != nil {
		t.Fatalf("submit: %v", err)
	}
	// Gate runs the CI gate server-side over the submitted snapshots.
	if _, err := c.Gate(ctx); err != nil {
		t.Fatalf("gate: %v", err)
	}
}

// Every server call surfaces an error on a rejected request (here: a bad token
// yielding 401) so the CLI can fall back to local behavior rather than hang.
func TestClientMethodsSurfaceServerErrors(t *testing.T) {
	srv, _ := liveServer(t)
	c := client.New(srv.URL, "wrong-token")
	ctx := context.Background()

	calls := map[string]func() error{
		"Submit":      func() error { return c.Submit(ctx, fleet.Snapshot{Owner: "a"}) },
		"Fleet":       func() error { _, err := c.Fleet(ctx); return err },
		"Conformance": func() error { _, err := c.Conformance(ctx); return err },
		"IngestAudit": func() error { return c.IngestAudit(ctx, []audit.Event{{Server: "srv", Tool: "x"}}) },
		"Alerts":      func() error { _, err := c.Alerts(ctx); return err },
		"Reputation":  func() error { _, err := c.Reputation(ctx, []string{"h1"}); return err },
		"Gate":        func() error { _, err := c.Gate(ctx); return err },
		"Policy":      func() error { _, _, err := c.Policy(ctx); return err },
		"TrustedKeys": func() error { _, err := c.TrustedKeys(ctx); return err },
	}
	for name, call := range calls {
		if err := call(); err == nil {
			t.Errorf("%s: expected an error on an unauthorized request", name)
		}
	}
}
