package dashboard

// This file holds the dashboard's security boundary: the guards that keep a
// loopback-only, read-only surface from becoming an attack vector. They live
// together (and have their own focused test file) so the confinement logic is
// easy to find and reason about, rather than scattered among the handlers.
//
//   - loopbackOnly      — rejects non-loopback Host headers (DNS rebinding).
//   - artifactRoot      — resolves an artifact's on-disk root.
//   - resolveWithinRoot — confines the source-file reader to that root.

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/alexverify/eyebrow/internal/domain/lockfile"
)

// loopbackOnly rejects requests whose Host is not a loopback name, defeating
// DNS-rebinding attempts from a page in the user's browser.
func loopbackOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if i := strings.LastIndexByte(host, ':'); i >= 0 && !strings.HasSuffix(host, "]") {
			host = host[:i]
		}
		host = strings.Trim(host, "[]")
		switch host {
		case "localhost", "127.0.0.1", "::1":
			next.ServeHTTP(w, r)
		default:
			http.Error(w, "eyebrow dashboard accepts loopback requests only", http.StatusForbidden)
		}
	})
}

// artifactRoot returns the on-disk directory that an artifact's relative file
// paths resolve against: the source dir for a multi-file artifact, or the
// containing dir for a single-file one (e.g. a CLAUDE.md). The bool is false
// when the id is unknown or the artifact has no readable local root.
func artifactRoot(inv lockfile.Lockfile, id string) (string, bool) {
	for _, e := range inv.Artifacts {
		if e.ID != id {
			continue
		}
		ref := e.Source.Ref
		if ref == "" {
			ref = e.DiscoveredFrom
		}
		if ref == "" {
			return "", false
		}
		if info, err := os.Stat(ref); err == nil && !info.IsDir() {
			return filepath.Dir(ref), true // single-file artifact: root is its dir
		}
		return ref, true
	}
	return "", false
}

// resolveWithinRoot resolves a relative file against root and verifies the
// result — symlinks resolved — stays inside root, rejecting absolute paths and
// `..` escapes. This is the guard that keeps the source endpoint confined.
func resolveWithinRoot(root, rel string) (string, error) {
	if filepath.IsAbs(rel) {
		return "", errors.New("absolute path not allowed")
	}
	clean := filepath.Clean(rel)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errors.New("path escapes artifact root")
	}
	target := filepath.Join(root, clean)

	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		realRoot = filepath.Clean(root)
	}
	realTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		realTarget = target // file may not exist; fall back to the lexical path
	}
	if realTarget != realRoot && !strings.HasPrefix(realTarget, realRoot+string(filepath.Separator)) {
		return "", errors.New("path escapes artifact root")
	}
	return realTarget, nil
}
