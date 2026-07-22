package discover

import (
	"context"
	"os"
	"path/filepath"
	"runtime"

	"github.com/alexverify/eyebrow/internal/adapters/parse"
	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

// Zed discovers Zed's MCP servers, which it calls "context servers". They live
// in settings.json — user-level, and per-project under .zed/settings.json.
//
// Zed nests them under "context_servers"; each entry is either a local server
// (command/args/env) or a remote one (url), which is exactly the shape every
// other tool declares, so only the key differs. settings.json permits comments,
// so it is read as JSONC.
type Zed struct {
	configDir string
}

// NewZed constructs the discoverer, resolving the per-OS config dir.
func NewZed() *Zed { return &Zed{configDir: zedConfigDir()} }

// zedConfigDir locates the directory holding Zed's settings.json. Zed follows
// XDG on macOS as well as Linux (~/.config/zed) — it does NOT use Application
// Support — so os.UserConfigDir is only correct on Windows (%AppData%\Zed).
func zedConfigDir() string {
	if runtime.GOOS == "windows" {
		dir, err := os.UserConfigDir()
		if err != nil {
			return ""
		}
		return filepath.Join(dir, "Zed")
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "zed")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "zed")
}

// Tool returns the canonical tool id.
func (z *Zed) Tool() string { return "zed" }

// Discover satisfies ports.Discoverer.
func (z *Zed) Discover(_ context.Context, scopes []ports.Scope) ([]artifact.Artifact, error) {
	var out []artifact.Artifact
	for _, sc := range scopes {
		switch sc.Kind {
		case "project":
			out = append(out, z.contextServersFrom(filepath.Join(sc.Path, ".zed", "settings.json"), sc.String())...)
		case "global":
			if z.configDir != "" {
				out = append(out, z.contextServersFrom(filepath.Join(z.configDir, "settings.json"), "global")...)
			}
		}
	}
	return out, nil
}

// zedConfig is the slice of settings.json we care about. Everything else in the
// file (themes, keymaps, language servers) is deliberately ignored.
type zedConfig struct {
	ContextServers map[string]mcpDecl `json:"context_servers"`
}

// contextServersFrom parses one settings.json. Missing or unparseable yields
// nothing and no error — discovery stays tolerant.
func (z *Zed) contextServersFrom(path, scope string) []artifact.Artifact {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var cfg zedConfig
	if err := parse.JSONC(b, &cfg); err != nil {
		return nil
	}
	return mcpArtifactsFrom(z.Tool(), path, scope, cfg.ContextServers)
}
