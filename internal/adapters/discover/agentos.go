package discover

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

// maxCatalogBody caps how much of a catalog response is read.
const maxCatalogBody = 8 << 20 // 8 MiB

// AgentOS discovers applications published to an AgentOS Appstore.
//
// It is the first discoverer that reads a remote catalog rather than a local
// config tree, so it answers a different question from the rest: not "what is
// installed here?" but "what is this registry publishing to everyone?". Only
// scopes of kind "registry" activate it; local scans never reach the network.
//
// AgentOS apps are listings, not packages — the catalog exposes a manifest and
// a distribution URL, never the code. Each app therefore becomes a registry
// source, whose integrity anchor the resolver derives from the manifest digest
// and the distribution host's certificate.
type AgentOS struct {
	Client *http.Client
}

// NewAgentOS constructs the discoverer.
func NewAgentOS() *AgentOS { return &AgentOS{Client: http.DefaultClient} }

// Tool returns the canonical tool id.
func (a *AgentOS) Tool() string { return "agentos" }

// Discover satisfies ports.Discoverer.
func (a *AgentOS) Discover(ctx context.Context, scopes []ports.Scope) ([]artifact.Artifact, error) {
	var out []artifact.Artifact
	for _, sc := range scopes {
		if sc.Kind != "registry" || sc.Path == "" {
			continue
		}
		arts, err := a.fromCatalog(ctx, sc)
		if err != nil {
			return nil, err
		}
		out = append(out, arts...)
	}
	return out, nil
}

// fromCatalog reads one registry's published catalog.
//
// A read failure is returned, not swallowed: an unreachable catalog and an
// empty catalog mean opposite things, and reporting "no apps" for a registry
// that could not be asked would be the worse of the two errors.
func (a *AgentOS) fromCatalog(ctx context.Context, sc ports.Scope) ([]artifact.Artifact, error) {
	base := strings.TrimSuffix(sc.Path, "/")
	apps, err := a.fetchApps(ctx, base+"/api/apps?visibility=public&sort=recent")
	if err != nil {
		return nil, err
	}

	out := make([]artifact.Artifact, 0, len(apps))
	for _, app := range apps {
		slug, _ := app["slug"].(string)
		if slug == "" {
			continue
		}
		out = append(out, artifact.Artifact{
			ID:    artifact.MakeID(a.Tool(), sc.String(), artifact.TypePlugin, slug),
			Tool:  a.Tool(),
			Scope: sc.String(),
			// Typed as a plugin during the compatibility period: a dedicated
			// "app" type would change the lockfile's type vocabulary, which is
			// a schema decision rather than an adapter one.
			Type: artifact.TypePlugin,
			Name: slug,
			Source: artifact.Source{
				Kind: artifact.SourceRegistry,
				Ref:  base + "/api/apps/" + slug,
			},
			DiscoveredFrom: base + "/api/apps",
		})
	}
	return out, nil
}

// fetchApps GETs a catalog page and returns its app records.
func (a *AgentOS) fetchApps(ctx context.Context, url string) ([]map[string]any, error) {
	client := a.Client
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("agentos catalog: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agentos catalog %s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCatalogBody))
	if err != nil {
		return nil, err
	}
	var page struct {
		Apps []map[string]any `json:"apps"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, fmt.Errorf("agentos catalog %s: %w", url, err)
	}
	return page.Apps, nil
}
