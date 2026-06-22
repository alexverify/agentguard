package dashboard

// This file holds the read-model derivation that the scan view is assembled
// from: pure helpers that fold the inventory, audit log, and trusted-keys state
// into the supplementary signals the UI renders. They take and return domain
// types (no http), so they read and test independently of the handlers.

import (
	"github.com/alexverify/eyebrow/internal/adapters/auditlog"
	"github.com/alexverify/eyebrow/internal/domain/lockfile"
	"github.com/alexverify/eyebrow/internal/domain/reputation"
	"github.com/alexverify/eyebrow/internal/domain/usage"
)

// inventoryHashes collects the content hashes of the current inventory, the keys
// a reputation lookup needs (whether served from a local corpus or a live
// hash-only service).
func inventoryHashes(lf lockfile.Lockfile) []string {
	out := make([]string, 0, len(lf.Artifacts))
	for _, e := range lf.Artifacts {
		if e.ContentHash != "" {
			out = append(out, e.ContentHash)
		}
	}
	return out
}

// reputationSource resolves the opt-in community trust corpus (H3) for the given
// hashes — from a local file or a live hash-only lookup (H3b), per the wired
// dep. A nil dep or a load error yields an empty corpus — the signal is
// supplementary, so it must never fail the scan view; a miss simply shows no
// reputation.
func (s *Server) reputationSource(hashes []string) reputation.Source {
	if s.deps.Reputation == nil {
		return nil
	}
	src, err := s.deps.Reputation(hashes)
	if err != nil {
		return nil
	}
	return src
}

// usageSummary reads the runtime audit log and folds it into per-artifact
// invocation stats (F1). A nil Audit dep or a read error yields no telemetry —
// usage is supplementary, so it must never fail the scan view.
//
// It reads all events (no kind filter) so both MCP tool calls and the hook-fed
// activation events of skills/subagents/plugins count; usage.Summarize selects
// the invocation kinds and ignores the rest.
func (s *Server) usageSummary() map[string]usage.Stat {
	if s.deps.Audit == nil {
		return nil
	}
	events, err := s.deps.Audit(auditlog.Filter{})
	if err != nil {
		return nil
	}
	return usage.Summarize(events)
}

// approvedSet returns the IDs of locked artifacts whose approval is trusted.
// In solo mode (no trusted-keys registry) a status of "approved" is enough —
// signatures are not surfaced. In team mode, "trusted" means a valid signature
// from a trusted key (or, with no verifier wired, a signature merely present).
func (s *Server) approvedSet(locked lockfile.Lockfile) map[string]bool {
	if !s.deps.TeamMode {
		out := make(map[string]bool)
		for _, e := range locked.Artifacts {
			if e.Approval != nil && e.Approval.Status == "approved" {
				out[e.ID] = true
			}
		}
		return out
	}
	if s.deps.ApprovalVerifier == nil {
		return approvedSet(locked)
	}
	out := make(map[string]bool)
	for _, e := range locked.Artifacts {
		if e.Approval != nil && e.Approval.Status == "approved" &&
			s.deps.ApprovalVerifier.VerifyApproval(e) == nil {
			out[e.ID] = true
		}
	}
	return out
}
