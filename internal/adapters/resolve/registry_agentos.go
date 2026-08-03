package resolve

// This file holds everything that knows the AgentOS `agentos.app.v1` record
// shape. It is separated from registry.go deliberately: the anchoring strategy
// in registry.go (digest the manifest, pin the distribution host) generalizes
// to any catalog, but the field mapping below does not. Supporting a second
// registry means adding a sibling mapper here, not widening these functions.

import "github.com/alexverify/eyebrow/internal/domain/registry"

// toListing maps the AgentOS record shape onto the neutral domain view the
// listing rules operate on. The rules themselves are registry-agnostic; this
// mapping is not, and a different registry needs its own. Capability
// declarations are read from the manifest first, falling back to the listing's
// mirrored fields.
func toListing(rec, manifest map[string]any) registry.Listing {
	slug, _ := rec["slug"].(string)
	repo, _ := rec["repositoryUrl"].(string)
	entrypoint, _ := manifest["entrypoint"].(string)
	verified, _ := rec["verified"].(bool)

	perms := stringSlice(manifest["permissions"])
	if len(perms) == 0 {
		perms = stringSlice(rec["permissionsRequired"])
	}
	secrets := stringSlice(manifest["requiredSecrets"])
	if len(secrets) == 0 {
		secrets = stringSlice(rec["requiredSecrets"])
	}

	return registry.Listing{
		Slug:            slug,
		Entrypoint:      entrypoint,
		RepositoryURL:   repo,
		DistributionURL: distributionURL(manifest),
		Permissions:     perms,
		RequiredSecrets: secrets,
		Commands:        commandNames(manifest["commands"]),
		Verified:        verified,
	}
}

// stringSlice reads a JSON array of strings, ignoring non-string members.
func stringSlice(v any) []string {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		if s, ok := it.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// commandNames reads command declarations, which registries express either as
// bare strings or as objects carrying a name.
func commandNames(v any) []string {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		switch c := it.(type) {
		case string:
			out = append(out, c)
		case map[string]any:
			if name, ok := c["name"].(string); ok {
				out = append(out, name)
			}
		}
	}
	return out
}

// distributionURL reads the manifest's web distribution target, the host whose
// certificate stands in for the unobtainable code.
func distributionURL(manifest map[string]any) string {
	dist, ok := manifest["distribution"].(map[string]any)
	if !ok {
		return ""
	}
	url, _ := dist["webUrl"].(string)
	return url
}
