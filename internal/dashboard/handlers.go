package dashboard

// This file holds the HTTP layer: one handler per /api route, the token-guarded
// write path they share, and the small JSON/error response helpers. The route
// table that wires these is Handler in dashboard.go; the security guards they
// lean on are in security.go; the read-model they assemble is in view.go.

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/alexverify/eyebrow/internal/adapters/auditlog"
	"github.com/alexverify/eyebrow/internal/domain/alert"
	"github.com/alexverify/eyebrow/internal/domain/audit"
	"github.com/alexverify/eyebrow/internal/domain/fleet"
	"github.com/alexverify/eyebrow/internal/domain/lockfile"
	"github.com/alexverify/eyebrow/internal/domain/policy"
	"github.com/alexverify/eyebrow/internal/domain/posture"
)

func (s *Server) handleInventory(w http.ResponseWriter, r *http.Request) {
	lf, err := s.deps.Inventory(r.Context())
	if err != nil {
		httpError(w, err)
		return
	}
	writeJSON(w, lf)
}

func (s *Server) handleDrift(w http.ResponseWriter, r *http.Request) {
	current, err := s.deps.Inventory(r.Context())
	if err != nil {
		httpError(w, err)
		return
	}
	locked, err := s.deps.Locked(r.Context())
	if err != nil {
		httpError(w, err)
		return
	}
	writeJSON(w, lockfile.Compare(locked, current))
}

// handleScan assembles the dashboard-shaped view (the UI's primary data
// source): the live inventory joined with the locked snapshot, with drift
// status, kind/agent mapping, and findings categorized for display.
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	current, err := s.deps.Inventory(r.Context())
	if err != nil {
		httpError(w, err)
		return
	}
	locked, err := s.deps.Locked(r.Context())
	if err != nil {
		httpError(w, err)
		return
	}
	arts := BuildScan(current, locked, s.approvedSet(locked), s.usageSummary(), s.reputationSource(inventoryHashes(current)))
	AttachLineDiffs(arts, s.deps.Blobs)
	writeJSON(w, struct {
		Artifacts []DashArtifact `json:"artifacts"`
	}{Artifacts: arts})
}

// maxSourceBytes caps the file size the code-view endpoint will read, so a huge
// or binary file can't be loaded into the browser. ~1 MiB covers any skill/rule.
const maxSourceBytes = 1 << 20

// handleSource serves the raw text of one file belonging to an artifact, backing
// the click-through code view for a finding. It is a read-only, loopback-only
// file reader confined to the artifact's own on-disk root: the requested path is
// resolved within that root (symlinks included) so it can never become an
// arbitrary-file-read oracle.
func (s *Server) handleSource(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	file := r.URL.Query().Get("file")
	if id == "" || file == "" {
		http.Error(w, "id and file are required", http.StatusBadRequest)
		return
	}
	inv, err := s.deps.Inventory(r.Context())
	if err != nil {
		httpError(w, err)
		return
	}
	root, ok := artifactRoot(inv, id)
	if !ok {
		http.Error(w, "artifact not found", http.StatusNotFound)
		return
	}
	target, err := resolveWithinRoot(root, file)
	if err != nil {
		http.Error(w, "invalid file path", http.StatusBadRequest)
		return
	}
	info, err := os.Stat(target)
	if err != nil || info.IsDir() {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}
	if info.Size() > maxSourceBytes {
		http.Error(w, "file too large to preview", http.StatusRequestEntityTooLarge)
		return
	}
	b, err := os.ReadFile(target)
	if err != nil {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}
	writeJSON(w, struct {
		Path    string `json:"path"`
		AbsPath string `json:"absPath"`
		Content string `json:"content"`
	}{Path: file, AbsPath: target, Content: string(b)})
}

// handleToken returns the write token to the same-origin UI. A cross-origin
// page can request this but cannot read the response (same-origin policy), so
// it never learns the token.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, struct {
		Token          string `json:"token"`
		Writable       bool   `json:"writable"`
		PolicyWritable bool   `json:"policyWritable"`
		TeamMode       bool   `json:"teamMode"`
	}{Token: s.token, Writable: s.deps.Mutate != nil, PolicyWritable: s.deps.MutatePolicy != nil, TeamMode: s.deps.TeamMode})
}

// markRequest is the body of a write endpoint: which artifact, and whether to
// set or clear the flag/approval.
type markRequest struct {
	ID string `json:"id"`
	On bool   `json:"on"`
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	s.mutate(w, r, func(e *lockfile.Entry, on bool) {
		if on {
			e.Approval = &lockfile.Approval{Status: "approved", By: "dashboard"}
			s.signApproval(e)
		} else {
			e.Approval = nil
		}
	})
}

// signApproval attaches a signature to an approved entry when a local signing
// key is wired, so the approval reads as Verified instead of Unsigned without a
// separate `eyebrow sign` step. The signature commits to the entry's current
// content hash, so it must run after the hash is set. Best-effort: a missing key
// or signing error leaves the approval unsigned and never blocks the approve.
func (s *Server) signApproval(e *lockfile.Entry) {
	if s.deps.SignApproval == nil || e.Approval == nil {
		return
	}
	if sig, err := s.deps.SignApproval(*e); err == nil {
		e.Approval.Sig = sig
	}
}

func (s *Server) handleQuarantine(w http.ResponseWriter, r *http.Request) {
	s.mutate(w, r, func(e *lockfile.Entry, on bool) { e.Quarantined = on })
}

func (s *Server) handleFreeze(w http.ResponseWriter, r *http.Request) {
	s.mutate(w, r, func(e *lockfile.Entry, on bool) { e.Frozen = on })
}

// handleAccountAll accounts for every unaccounted artifact (B3) in one
// read-modify-write: it adds each shadow (a live artifact absent from the
// lockfile — exactly what the dashboard's banner counts) to the lockfile and
// marks it approved. Token-guarded; a no-op (count 0) when nothing is shadow.
func (s *Server) handleAccountAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("X-Eyebrow-Token") != s.token || s.token == "" {
		http.Error(w, "missing or invalid write token", http.StatusForbidden)
		return
	}
	if s.deps.Mutate == nil {
		http.Error(w, "dashboard is read-only (no lockfile to write)", http.StatusForbidden)
		return
	}
	live, err := s.deps.Inventory(r.Context())
	if err != nil {
		httpError(w, err)
		return
	}
	count := 0
	err = s.deps.Mutate(r.Context(), func(lf *lockfile.Lockfile) error {
		shadows := shadowEntries(live, *lf)
		for _, e := range shadows {
			lf.Artifacts = append(lf.Artifacts, e)
			added := &lf.Artifacts[len(lf.Artifacts)-1]
			added.Approval = &lockfile.Approval{Status: "approved", By: "dashboard"}
			s.signApproval(added)
		}
		count = len(shadows)
		return nil
	})
	if err != nil {
		httpError(w, err)
		return
	}
	writeJSON(w, struct {
		Count int `json:"count"`
	}{Count: count})
}

// mutate is the shared, token-guarded write path: it applies set to the entry
// whose ID matches the request body, persisting via Deps.Mutate.
func (s *Server) mutate(w http.ResponseWriter, r *http.Request, set func(*lockfile.Entry, bool)) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("X-Eyebrow-Token") != s.token || s.token == "" {
		http.Error(w, "missing or invalid write token", http.StatusForbidden)
		return
	}
	if s.deps.Mutate == nil {
		http.Error(w, "dashboard is read-only (no lockfile to write)", http.StatusForbidden)
		return
	}
	var body markRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	// Fetch the live inventory once so an unaccounted artifact (absent from the
	// lockfile) can be upserted from it inside the atomic read-modify-write — the
	// client sends only an ID; the server owns the recorded hash.
	live, err := s.deps.Inventory(r.Context())
	if err != nil {
		httpError(w, err)
		return
	}
	found := false
	err = s.deps.Mutate(r.Context(), func(lf *lockfile.Lockfile) error {
		for i := range lf.Artifacts {
			if lf.Artifacts[i].ID == body.ID {
				set(&lf.Artifacts[i], body.On)
				found = true
				return nil
			}
		}
		// Not yet accounted: account for it by copying its live entry (with its
		// current content hash) into the lockfile, then apply the change.
		for _, e := range live.Artifacts {
			if e.ID == body.ID {
				lf.Artifacts = append(lf.Artifacts, e)
				set(&lf.Artifacts[len(lf.Artifacts)-1], body.On)
				found = true
				return nil
			}
		}
		return nil
	})
	if err != nil {
		httpError(w, err)
		return
	}
	if !found {
		http.Error(w, "artifact not found", http.StatusNotFound)
		return
	}
	writeJSON(w, struct {
		Status string `json:"status"`
	}{Status: "ok"})
}

// safeRequest flags (or clears) one finding as an accepted false positive.
type safeRequest struct {
	ID  string `json:"id"`
	Key string `json:"key"`
	On  bool   `json:"on"`
}

// handleFindingSafe records or clears a per-finding "flagged safe" sign-off on
// the artifact's lockfile entry. A flagged finding stays visible but no longer
// fails the policy gate. Token-guarded; persists via Deps.Mutate.
func (s *Server) handleFindingSafe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("X-Eyebrow-Token") != s.token || s.token == "" {
		http.Error(w, "missing or invalid write token", http.StatusForbidden)
		return
	}
	if s.deps.Mutate == nil {
		http.Error(w, "dashboard is read-only (no lockfile to write)", http.StatusForbidden)
		return
	}
	var body safeRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" || body.Key == "" {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	// The live inventory gives the content hash at flag time (so the UI can note
	// when the flagged code later changed) and lets us account for an artifact
	// not yet in the lockfile, the same upsert the approve path uses.
	live, err := s.deps.Inventory(r.Context())
	if err != nil {
		httpError(w, err)
		return
	}
	var liveEntry *lockfile.Entry
	for i := range live.Artifacts {
		if live.Artifacts[i].ID == body.ID {
			liveEntry = &live.Artifacts[i]
			break
		}
	}
	curHash := ""
	if liveEntry != nil {
		curHash = liveEntry.ContentHash
	}
	found := false
	err = s.deps.Mutate(r.Context(), func(lf *lockfile.Lockfile) error {
		for i := range lf.Artifacts {
			if lf.Artifacts[i].ID != body.ID {
				continue
			}
			found = true
			setFindingSafe(&lf.Artifacts[i], body.Key, body.On, curHash)
			return nil
		}
		// Not yet in the lockfile: account for it from the live inventory first.
		if liveEntry != nil {
			lf.Artifacts = append(lf.Artifacts, *liveEntry)
			setFindingSafe(&lf.Artifacts[len(lf.Artifacts)-1], body.Key, body.On, curHash)
			found = true
		}
		return nil
	})
	if err != nil {
		httpError(w, err)
		return
	}
	if !found {
		http.Error(w, "artifact not found", http.StatusNotFound)
		return
	}
	writeJSON(w, struct {
		Status string `json:"status"`
	}{Status: "ok"})
}

// setFindingSafe adds or removes a finding's safe sign-off on an entry,
// idempotently.
func setFindingSafe(e *lockfile.Entry, key string, on bool, hash string) {
	out := e.SafeFindings[:0:0]
	for _, s := range e.SafeFindings {
		if s.Key != key {
			out = append(out, s)
		}
	}
	if on {
		out = append(out, lockfile.FindingAck{Key: key, By: "dashboard", At: time.Now().UTC(), Hash: hash})
	}
	e.SafeFindings = out
}

// handleHistory serves the posture trend (E2) for the dashboard sparkline.
func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	var hist []posture.Posture
	if s.deps.History != nil {
		got, err := s.deps.History(r.Context())
		if err != nil {
			httpError(w, err)
			return
		}
		hist = got
	}
	writeJSON(w, struct {
		History []posture.Posture `json:"history"`
	}{History: hist})
}

// handleAlerts serves the org's team-level alerts (4d). Empty when no Alerts dep
// is wired (e.g. the local dashboard with no control plane).
func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	alerts := []alert.Alert{}
	if s.deps.Alerts != nil {
		got, err := s.deps.Alerts(r.Context())
		if err != nil {
			httpError(w, err)
			return
		}
		if got != nil {
			alerts = got
		}
	}
	writeJSON(w, struct {
		Alerts []alert.Alert `json:"alerts"`
	}{Alerts: alerts})
}

// handleFleet serves the aggregated team blast-radius (G1): which artifacts are
// installed across how many machines, and where they have drifted. Built from
// committed snapshots — no live telemetry upload, same offline-first contract
// as the rest of the dashboard.
func (s *Server) handleFleet(w http.ResponseWriter, r *http.Request) {
	var rep fleet.Report
	if s.deps.Fleet != nil {
		got, err := s.deps.Fleet(r.Context())
		if err != nil {
			httpError(w, err)
			return
		}
		rep = got
	}
	var con fleet.Conformance
	if s.deps.Conformance != nil {
		got, err := s.deps.Conformance(r.Context())
		if err != nil {
			httpError(w, err)
			return
		}
		con = got
	}
	// Embed the report (owners/artifacts/exposures/grid) and add conformance so
	// the Fleet tab gets blast radius (G1), heatmap (G2), and compliance (G3) in
	// one fetch.
	writeJSON(w, struct {
		fleet.Report
		Conformance fleet.Conformance `json:"conformance"`
	}{Report: rep, Conformance: con})
}

// handlePolicy serves the committed policy (GET) and edits its allow/block
// lists (POST, token-guarded) — the Policy tab (C3).
func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		p := policy.Default()
		if s.deps.Policy != nil {
			got, err := s.deps.Policy(r.Context())
			if err != nil {
				httpError(w, err)
				return
			}
			p = got
		}
		writeJSON(w, p)
		return
	}
	if !s.allowPolicyWrite(w, r) {
		return
	}
	var body struct {
		AllowPublishers []string `json:"allowPublishers"`
		BlockPublishers []string `json:"blockPublishers"`
		BlockArtifacts  []string `json:"blockArtifacts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	s.applyPolicy(w, r, func(p *policy.Policy) error {
		p.AllowPublishers = cleanList(body.AllowPublishers)
		p.BlockPublishers = cleanList(body.BlockPublishers)
		p.BlockArtifacts = cleanList(body.BlockArtifacts)
		return nil
	})
}

// handleMute appends a finding-suppression with a rationale to the policy (C4).
func (s *Server) handleMute(w http.ResponseWriter, r *http.Request) {
	if !s.allowPolicyWrite(w, r) {
		return
	}
	var body struct {
		Rule   string `json:"rule"`
		Reason string `json:"reason"`
		By     string `json:"by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Rule == "" {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.By == "" {
		body.By = "dashboard"
	}
	s.applyPolicy(w, r, func(p *policy.Policy) error {
		for _, m := range p.Mutes {
			if m.Rule == body.Rule {
				return nil // already muted — idempotent
			}
		}
		p.Mutes = append(p.Mutes, policy.Mute{Rule: body.Rule, Reason: body.Reason, By: body.By})
		return nil
	})
}

// handleEgressAllow adds a host to a server's egress allowlist (D2). The proxy
// enforces the same per-server rule via policy.DecideHost.
func (s *Server) handleEgressAllow(w http.ResponseWriter, r *http.Request) {
	if !s.allowPolicyWrite(w, r) {
		return
	}
	var body struct {
		Server string `json:"server"`
		Host   string `json:"host"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Server == "" || body.Host == "" {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	s.applyPolicy(w, r, func(p *policy.Policy) error {
		if p.MCP.Servers == nil {
			p.MCP.Servers = map[string]policy.ToolRule{}
		}
		rule := p.MCP.Servers[body.Server]
		for _, h := range rule.AllowHosts {
			if h == body.Host {
				return nil // already allowed — idempotent
			}
		}
		rule.AllowHosts = append(rule.AllowHosts, body.Host)
		p.MCP.Servers[body.Server] = rule
		return nil
	})
}

// allowPolicyWrite enforces POST + the write token + a writable policy, the
// shared guard for the policy-mutating endpoints. It writes the error response
// and returns false when the request must be refused.
func (s *Server) allowPolicyWrite(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	if r.Header.Get("X-Eyebrow-Token") != s.token || s.token == "" {
		http.Error(w, "missing or invalid write token", http.StatusForbidden)
		return false
	}
	if s.deps.MutatePolicy == nil {
		http.Error(w, "dashboard is read-only (no policy to write)", http.StatusForbidden)
		return false
	}
	return true
}

// applyPolicy runs fn under the read-modify-write and reports the outcome.
func (s *Server) applyPolicy(w http.ResponseWriter, r *http.Request, fn func(*policy.Policy) error) {
	if err := s.deps.MutatePolicy(r.Context(), fn); err != nil {
		httpError(w, err)
		return
	}
	writeJSON(w, struct {
		Status string `json:"status"`
	}{Status: "ok"})
}

// cleanList trims whitespace and drops empty entries from a user-supplied list.
func cleanList(in []string) []string {
	var out []string
	for _, s := range in {
		if t := strings.TrimSpace(s); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	f := auditlog.Filter{
		Server: r.URL.Query().Get("server"),
		Tool:   r.URL.Query().Get("tool"),
		Status: r.URL.Query().Get("status"),
		Kind:   audit.Kind(r.URL.Query().Get("kind")),
	}
	events, err := s.deps.Audit(f)
	if err != nil {
		httpError(w, err)
		return
	}
	writeJSON(w, struct {
		Events  []audit.Event    `json:"events"`
		Summary auditlog.Summary `json:"summary"`
	}{Events: events, Summary: auditlog.Summarize(events)})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, err error) {
	http.Error(w, err.Error(), http.StatusInternalServerError)
}
