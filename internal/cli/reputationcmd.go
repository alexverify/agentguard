package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/alexverify/eyebrow/internal/adapters/lockstore"
	"github.com/alexverify/eyebrow/internal/adapters/repstore"
	"github.com/alexverify/eyebrow/internal/client"
	"github.com/alexverify/eyebrow/internal/domain/lockfile"
	"github.com/alexverify/eyebrow/internal/domain/reputation"
)

// runReputation looks up one or more content hashes against the control plane's
// reputation corpus (H3b) and prints each one's truster count and grade. It
// sends only the hashes given — nothing about their content. Opt-in: requires a
// server. The "export" subcommand instead builds a corpus from local approvals.
func (a *App) runReputation(ctx context.Context, args []string) int {
	if len(args) > 0 && args[0] == "export" {
		return a.runReputationExport(ctx, args[1:])
	}
	fs := a.flagSet("reputation")
	server := fs.String("server", envOr("EYEBROW_SERVER", ""), "control-plane URL")
	token := fs.String("token", envOr("EYEBROW_TOKEN", ""), "machine token for the control plane")
	jsonOut := fs.Bool("json", false, "machine-readable JSON output")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if *server == "" {
		fmt.Fprintln(a.Stderr, "reputation: set --server (or EYEBROW_SERVER) to a control-plane URL")
		return ExitUsage
	}
	hashes := fs.Args()
	if len(hashes) == 0 {
		fmt.Fprintln(a.Stderr, "reputation: provide one or more content hashes to look up")
		return ExitUsage
	}

	src, err := client.New(*server, *token).Reputation(ctx, hashes)
	if err != nil {
		return a.fail("reputation", err)
	}
	if *jsonOut {
		return a.emitJSON(src)
	}
	for _, h := range hashes {
		if sig, ok := src.Lookup(h); ok {
			fmt.Fprintf(a.Stdout, "%-20s %s (trusted by %d)\n", h, sig.Grade(), sig.Trusters)
		} else {
			fmt.Fprintf(a.Stdout, "%-20s unknown\n", h)
		}
	}
	return ExitOK
}

// runReputationExport builds a content-free reputation corpus from this
// machine's approved artifacts — the hashes the local user vouches for — in the
// exact Source shape repstore.Load reads. It ships the network-effect trust
// signal (H3) without any server: a team accumulates trust by each member
// merging their export into a shared corpus (--merge FILE), whose truster count
// then reflects how many teammates vouch for each exact content hash.
func (a *App) runReputationExport(ctx context.Context, args []string) int {
	fs := a.flagSet("reputation export")
	lock := fs.String("lockfile", "eyebrowlock.json", "lockfile to export from")
	all := fs.Bool("all", false, "vouch for every artifact, not just approved ones")
	merge := fs.String("merge", "", "union into this existing corpus file (accumulates trusters)")
	outPath := fs.String("o", "", "write to this file instead of stdout")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	lf, err := lockstore.New().Read(ctx, *lock)
	if err != nil {
		return a.fail("reputation", err)
	}
	corpus := reputation.Build(vouchedHashes(lf, *all), a.Clock.Now().UTC())
	if *merge != "" {
		// A missing file starts a fresh shared corpus (like the advisory feed
		// offline); a malformed one is a real error worth surfacing.
		prior, lerr := repstore.Load(*merge)
		if lerr != nil {
			return a.fail("reputation", lerr)
		}
		corpus = reputation.Merge(prior, corpus)
	}
	b, err := json.MarshalIndent(corpus, "", "  ")
	if err != nil {
		return a.fail("reputation", err)
	}
	b = append(b, '\n')
	if *outPath != "" {
		if err := os.WriteFile(*outPath, b, 0o644); err != nil {
			return a.fail("reputation", err)
		}
		fmt.Fprintf(a.Stdout, "wrote %s (%d hash(es))\n", *outPath, len(corpus))
		return ExitOK
	}
	_, _ = a.Stdout.Write(b)
	return ExitOK
}

// vouchedHashes returns the content hashes to vouch for: approved artifacts by
// default, or every artifact when all is set. Artifacts without a content hash
// are skipped (there is nothing to vouch for).
func vouchedHashes(lf lockfile.Lockfile, all bool) []string {
	var out []string
	for _, e := range lf.Artifacts {
		if e.ContentHash == "" {
			continue
		}
		if all || (e.Approval != nil && e.Approval.Status == "approved") {
			out = append(out, e.ContentHash)
		}
	}
	return out
}
