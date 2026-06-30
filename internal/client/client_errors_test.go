package client_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alexverify/eyebrow/internal/client"
	"github.com/alexverify/eyebrow/internal/domain/audit"
	"github.com/alexverify/eyebrow/internal/domain/fleet"
)

// readers are the methods that decode a server body; a 200 with malformed JSON
// must surface a decode error so the CLI falls back rather than acting on junk.
func readers(c *client.Client, ctx context.Context) map[string]func() error {
	return map[string]func() error{
		"Fleet":       func() error { _, err := c.Fleet(ctx); return err },
		"Conformance": func() error { _, err := c.Conformance(ctx); return err },
		"Alerts":      func() error { _, err := c.Alerts(ctx); return err },
		"Reputation":  func() error { _, err := c.Reputation(ctx, []string{"h1"}); return err },
		"Gate":        func() error { _, err := c.Gate(ctx); return err },
		"Policy":      func() error { _, _, err := c.Policy(ctx); return err },
		"TrustedKeys": func() error { _, err := c.TrustedKeys(ctx); return err },
	}
}

func TestClientDecodeErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{ this is not json"))
	}))
	t.Cleanup(srv.Close)
	c := client.New(srv.URL, "tok")
	ctx := context.Background()

	for name, call := range readers(c, ctx) {
		if err := call(); err == nil {
			t.Errorf("%s: a malformed 200 body should surface a decode error", name)
		}
	}
}

// When the server is unreachable, every method must return the transport error
// (not panic or hang) so the caller degrades to local behavior.
func TestClientTransportErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing is listening now → connection refused
	c := client.New(url, "tok")
	ctx := context.Background()

	calls := readers(c, ctx)
	calls["Submit"] = func() error { return c.Submit(ctx, fleet.Snapshot{Owner: "a"}) }
	calls["IngestAudit"] = func() error { return c.IngestAudit(ctx, []audit.Event{{Server: "s", Tool: "t"}}) }
	calls["Health"] = func() error { return c.Health(ctx) }

	for name, call := range calls {
		if err := call(); err == nil {
			t.Errorf("%s: an unreachable server should surface a transport error", name)
		}
	}
}
