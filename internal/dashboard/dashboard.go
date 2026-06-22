// Package dashboard serves a local, read-only web view of what eyebrow sees
// on this machine: the inventory, drift against the lockfile, findings, and the
// MCP shim's audit timeline. It is the Go backend of the dashboard — the UI is
// a Next.js app embedded as a static export (see assets/).
//
// It binds loopback only and rejects requests whose Host header is not a
// loopback name, so a malicious page cannot drive it via DNS rebinding. There
// is no auth because there is no remotely reachable surface — a supply-chain
// tool must not expose an unauthenticated control plane.
//
// The package is split by responsibility: this file holds the server skeleton
// and route table; handlers.go the per-route HTTP layer; security.go the
// loopback/path guards; view.go the read-model derivation; dto.go the UI shape.
package dashboard

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"io/fs"
	"net/http"

	"github.com/alexverify/eyebrow/internal/adapters/auditlog"
	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/alert"
	"github.com/alexverify/eyebrow/internal/domain/audit"
	"github.com/alexverify/eyebrow/internal/domain/fleet"
	"github.com/alexverify/eyebrow/internal/domain/lockfile"
	"github.com/alexverify/eyebrow/internal/domain/policy"
	"github.com/alexverify/eyebrow/internal/domain/posture"
	"github.com/alexverify/eyebrow/internal/domain/reputation"
)

//go:embed all:assets
var assetsFS embed.FS

// Deps are the data sources the dashboard renders. Keeping them as functions
// lets the CLI wire in the real scan/verify/audit pipeline while tests inject
// fixtures, with no filesystem or subprocess access.
type Deps struct {
	// Inventory builds the current live inventory (the scan pipeline).
	Inventory func(context.Context) (lockfile.Lockfile, error)
	// Locked returns the committed lockfile, or a zero value when none exists.
	Locked func(context.Context) (lockfile.Lockfile, error)
	// Audit reads matching audit events.
	Audit func(auditlog.Filter) ([]audit.Event, error)
	// ApprovalVerifier checks each locked approval's signature against trusted
	// keys, so the dashboard distinguishes "verified" from merely "approved".
	// Optional: when nil, an approval bearing a signature is treated as trusted.
	ApprovalVerifier ports.ApprovalVerifier
	// Mutate applies a change to the committed lockfile under a read-modify-write,
	// backing the approve/quarantine/freeze write endpoints. Optional: when nil,
	// those endpoints are disabled and the dashboard is strictly read-only.
	Mutate func(ctx context.Context, fn func(lf *lockfile.Lockfile) error) error
	// SignApproval returns a detached signature over an entry's approval binding
	// (ID + content hash), produced with the local signing key, so a dashboard
	// approval is Verified rather than merely Unsigned — no separate `eyebrow sign`.
	// Optional: when nil, dashboard approvals are recorded unsigned.
	SignApproval func(e lockfile.Entry) (string, error)
	// Policy returns the committed policy, backing the Policy tab and the egress
	// allowlist view. Optional: when nil, GET /api/policy returns the default.
	Policy func(context.Context) (policy.Policy, error)
	// MutatePolicy applies a change to the committed policy file under a
	// read-modify-write, backing the policy-editor (C3), mute (C4), and egress
	// allowlist (D2) write endpoints. Optional: when nil they are disabled.
	MutatePolicy func(ctx context.Context, fn func(p *policy.Policy) error) error
	// History returns the counts-only posture trend (E2). Optional: when nil,
	// GET /api/history returns an empty trend.
	History func(context.Context) ([]posture.Posture, error)
	// Fleet returns the aggregated team blast-radius (G1) from committed
	// snapshots. Optional: when nil, GET /api/fleet returns an empty report.
	Fleet func(context.Context) (fleet.Report, error)
	// Conformance returns the fleet's policy-compliance rollup (G3): which
	// machines run blocked/unapproved artifacts. Optional: nil → empty.
	Conformance func(context.Context) (fleet.Conformance, error)
	// Alerts returns the org's team-level alerts (4d): drift, quarantine, blocked
	// egress, denied tool calls. Optional: nil → empty (the Alerts panel hides).
	Alerts func(context.Context) ([]alert.Alert, error)
	// Reputation resolves the opt-in community trust corpus (H3) for a set of
	// content hashes — from a local file or a live hash-only service (H3b).
	// Optional: when nil, no reputation signal is shown.
	Reputation func(hashes []string) (reputation.Source, error)
	// Blobs returns the captured bytes (path → content) for a content hash,
	// backing the line-level drift diff (H1b), or nil when that hash has no
	// stored baseline. Optional: when nil, the scan view falls back to the
	// content-free file-name list.
	Blobs func(contentHash string) (map[string][]byte, error)
	// TeamMode is true when a trusted-keys registry declares at least one key —
	// i.e. the user has opted into shared, signature-verified trust. When false
	// (solo), an approval counts as trusted on its status alone and the dashboard
	// hides the signed/unsigned/verified vocabulary entirely.
	TeamMode bool
	// Static overrides the embedded UI assets (used in tests); nil uses the
	// embedded Next.js export.
	Static fs.FS
}

// Server renders the dashboard.
type Server struct {
	deps   Deps
	static fs.FS
	token  string
}

// New constructs a Server. It mints a single random token that gates the write
// endpoints: a malicious page in the user's browser can issue a cross-origin
// POST but cannot read GET /api/token (same-origin policy), so it cannot forge
// the X-Eyebrow-Token header. Combined with the loopback-Host guard, this
// keeps the mutating surface same-origin only.
func New(d Deps) *Server {
	static := d.Static
	if static == nil {
		sub, err := fs.Sub(assetsFS, "assets")
		if err == nil {
			static = sub
		}
	}
	return &Server{deps: d, static: static, token: randomToken()}
}

// Token returns the per-process write token (printed at launch).
func (s *Server) Token() string { return s.token }

func randomToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// Handler returns the HTTP handler: JSON under /api, the embedded UI elsewhere,
// all behind the loopback-Host guard.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/inventory", s.handleInventory)
	mux.HandleFunc("/api/drift", s.handleDrift)
	mux.HandleFunc("/api/audit", s.handleAudit)
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/source", s.handleSource)
	mux.HandleFunc("/api/token", s.handleToken)
	mux.HandleFunc("/api/approve", s.handleApprove)
	mux.HandleFunc("/api/quarantine", s.handleQuarantine)
	mux.HandleFunc("/api/freeze", s.handleFreeze)
	mux.HandleFunc("/api/account-all", s.handleAccountAll)
	mux.HandleFunc("/api/finding-safe", s.handleFindingSafe)
	mux.HandleFunc("/api/policy", s.handlePolicy)
	mux.HandleFunc("/api/mute", s.handleMute)
	mux.HandleFunc("/api/egress-allow", s.handleEgressAllow)
	mux.HandleFunc("/api/history", s.handleHistory)
	mux.HandleFunc("/api/fleet", s.handleFleet)
	mux.HandleFunc("/api/alerts", s.handleAlerts)
	if s.static != nil {
		mux.Handle("/", http.FileServer(http.FS(s.static)))
	}
	return loopbackOnly(mux)
}
