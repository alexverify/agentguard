package dashboard

// This file defines the JSON wire shapes the dashboard UI consumes — the
// contract mirrored by the TypeScript types in controlplane/web/lib/scan-data.ts.
// They are pure data; buildscan.go assembles them from the inventory and the
// locked snapshot.

import (
	"github.com/alexverify/eyebrow/internal/domain/lockfile"
	"github.com/alexverify/eyebrow/internal/domain/provenance"
	"github.com/alexverify/eyebrow/internal/domain/textdiff"
	"github.com/alexverify/eyebrow/internal/domain/timeline"
)

// DashArtifact is the artifact shape the dashboard UI consumes (mirrors the
// TypeScript Artifact in controlplane/web/lib/scan-data.ts). It is assembled
// from the live inventory joined with the locked lockfile, so the frontend
// stays a thin fetch-and-render.
type DashArtifact struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description,omitempty"` // stated purpose, from frontmatter
	Kind        string        `json:"kind"`                  // skill | mcp | plugin | <type>
	Agent       string        `json:"agent"`                 // display name of the tool
	Version     string        `json:"version"`
	Source      string        `json:"source"`
	InstalledAt string        `json:"installedAt"`
	Hash        string        `json:"hash"`
	LockedHash  string        `json:"lockedHash"`
	Drift       string        `json:"drift"` // verified | drifted | new | unsigned
	Findings    []DashFinding `json:"findings"`

	// Detail-view fields (the per-artifact security profile).
	Scope          string           `json:"scope"`
	SourceKind     string           `json:"sourceKind"`
	DiscoveredFrom string           `json:"discoveredFrom"`
	Command        string           `json:"command,omitempty"` // MCP launch command
	Args           []string         `json:"args,omitempty"`
	EnvKeys        []string         `json:"envKeys,omitempty"` // env var names only — values are never exposed
	Integrity      string           `json:"integrity,omitempty"`
	CertSPKI       string           `json:"certSpki,omitempty"`
	Capabilities   DashCapabilities `json:"capabilities"`
	Files          []DashFile       `json:"files"`
	Approval       *DashApproval    `json:"approval,omitempty"`

	// Trust verdict (A1) and drift interpretation (A3).
	Trust        int          `json:"trust"`
	Verdict      string       `json:"verdict"` // trusted | review | quarantine
	TrustReasons []DashReason `json:"trustReasons"`
	DriftClass   string       `json:"driftClass"`  // none|updated|mutated|broken|added|removed
	DriftDetail  string       `json:"driftDetail"` // human one-liner for the change card

	// Remediation state (C2) and provenance grade (B1).
	Quarantined bool              `json:"quarantined,omitempty"`
	Frozen      bool              `json:"frozen,omitempty"`
	Provenance  provenance.Ladder `json:"provenance"`

	// Shadow flags an unaccounted artifact (B3): newly present but not in the
	// lockfile and not pulled from a known registry/package source — an
	// "installed but never declared" extension (OWASP MCP09 / AST09).
	Shadow bool `json:"shadow,omitempty"`

	// FileChanges is the file-manifest diff against the locked snapshot (H1):
	// which files were added, removed, or modified in a drift. Populated only
	// when a locked prior exists and its manifest differs — the content-free,
	// offline core of the rug-pull diff view. nil when there is nothing to diff.
	FileChanges *lockfile.FileDiff `json:"fileChanges,omitempty"`

	// LineDiffs is the literal line-level change per file (H1b): the added/removed
	// lines of a drift, when the approved and current bytes are both in the local
	// blob store. Empty when the store has no baseline (degrades to FileChanges).
	LineDiffs []DashLineDiff `json:"lineDiffs,omitempty"`

	// Usage is the runtime invocation summary (F1): when this artifact last ran,
	// when it first ran, and how many times. Sourced from the MCP shim's audit
	// log, joined by server name; nil for artifacts with no telemetry path yet
	// (skills/plugins/hooks have no runtime hook surface — an honest gap).
	Usage *DashUsage `json:"usage,omitempty"`

	// Sleeper flags the dormant-then-active triple (F2): an old install that lay
	// unused, drifted, then fired for the first time. nil unless the rule trips.
	Sleeper *DashSleeper `json:"sleeper,omitempty"`

	// Timeline is the per-artifact event ribbon (F4): installed → approved →
	// invoked → drifted, ordered in time. Empty when no dated milestone is known.
	Timeline []timeline.Event `json:"timeline,omitempty"`

	// Reputation is the opt-in community trust signal for this exact content
	// hash (H3): how many other users trust it and when it was first seen. nil
	// when the corpus is absent or has no entry (unknown, never a negative claim).
	Reputation *DashReputation `json:"reputation,omitempty"`
}

// DashLineDiff is the line-level change in one file of a drift (H1b): the actual
// `+`/`-` lines an auditor reads to confirm a rug pull, grouped into hunks.
type DashLineDiff struct {
	Path    string          `json:"path"`
	Status  string          `json:"status"` // modified | added | removed
	Added   int             `json:"added"`
	Removed int             `json:"removed"`
	Hunks   []textdiff.Hunk `json:"hunks"`
}

// DashReputation is the per-artifact community trust signal (H3).
type DashReputation struct {
	Trusters  int    `json:"trusters"`
	FirstSeen string `json:"firstSeen,omitempty"`
	Grade     string `json:"grade"` // unknown | emerging | established
}

// DashUsage is the per-artifact runtime invocation summary (F1).
type DashUsage struct {
	FirstUsed   string `json:"firstUsed,omitempty"`
	LastUsed    string `json:"lastUsed,omitempty"`
	LastUsedRel string `json:"lastUsedRel,omitempty"` // "3d ago" — relative to the scan
	Count       int    `json:"count"`
}

// DashSleeper carries the dormant-then-active finding for the drawer banner (F2).
type DashSleeper struct {
	DormantDays int    `json:"dormantDays"`
	Detail      string `json:"detail"`
}

// DashReason is one additive contribution to the trust score, for the breakdown.
type DashReason struct {
	Label string `json:"label"`
	Delta int    `json:"delta"`
}

// DashCapabilities mirrors the declared powers of an artifact, plus the diff
// against the locked snapshot (A2) so the UI can show capability expansion.
type DashCapabilities struct {
	Exec       bool     `json:"exec"`
	Network    []string `json:"network"`
	Filesystem []string `json:"filesystem"`

	ExecNewlyAdded    bool     `json:"execNewlyAdded,omitempty"`
	AddedNetwork      []string `json:"addedNetwork,omitempty"`
	RemovedNetwork    []string `json:"removedNetwork,omitempty"`
	AddedFilesystem   []string `json:"addedFilesystem,omitempty"`
	RemovedFilesystem []string `json:"removedFilesystem,omitempty"`
	SensitiveAdded    []string `json:"sensitiveAdded,omitempty"` // added FS paths that touch secrets
}

// DashFile is one entry in the artifact's file manifest.
type DashFile struct {
	Path string `json:"path"`
	Hash string `json:"hash"`
}

// DashApproval is the approval/sign-off state shown in the detail view.
type DashApproval struct {
	Status string `json:"status"`
	By     string `json:"by,omitempty"`
	At     string `json:"at,omitempty"`
	Signed bool   `json:"signed"`
}

// DashFinding mirrors the TS Finding.
type DashFinding struct {
	ID       string `json:"id"`
	RuleID   string `json:"ruleId"`
	Pattern  string `json:"pattern"`
	Severity string `json:"severity"`
	OWASP    string `json:"owasp,omitempty"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Evidence string `json:"evidence"`
	Location string `json:"location"`
	// File and Line are the structured anchor (File is POSIX-relative to the
	// artifact root) the code-view modal uses to fetch and scroll the source.
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`

	// Safe marks a finding flagged as an accepted false positive: it stays shown
	// (severity and all) but is badged "flagged safe" and passes the CI gate.
	// SafeBy/SafeAt record the sign-off; SafeStale is true when the content
	// changed since it was flagged (the flag persists but is worth re-checking).
	Safe      bool   `json:"safe,omitempty"`
	SafeBy    string `json:"safeBy,omitempty"`
	SafeAt    string `json:"safeAt,omitempty"`
	SafeStale bool   `json:"safeStale,omitempty"`
	// Key is the finding's stable identity (rule|file|line), sent back to the
	// flag-safe endpoint.
	Key string `json:"key,omitempty"`

	// Capability × usage fusion (F3): how exercised the carrying artifact is
	// (live | exercised | unknown), and the fused urgency rank that lifts a
	// finding on code that actually runs above the same finding on dormant code.
	Liveness string `json:"liveness,omitempty"`
	RiskRank int    `json:"riskRank,omitempty"`

	// Reachability (H2): "reachable" for a runtime file, "inert" for a finding in
	// a test/example/vendored path that is almost certainly noise. A location
	// heuristic, not a call graph — it demotes, never deletes.
	Reach string `json:"reach,omitempty"`
}
