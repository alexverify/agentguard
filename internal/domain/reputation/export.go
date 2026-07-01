package reputation

import (
	"strings"
	"time"
)

// Build constructs a corpus in which the local user vouches for each of the
// given content hashes — their own approved artifacts. Every distinct hash gets
// Trusters: 1 (this one user) and FirstSeen: firstSeen. Hashes are lowercased to
// match Lookup, blanks are dropped, and duplicates collapse to a single entry
// (one user vouching once). The result is exactly the Source shape repstore.Load
// reads, so one member's content-free export merges into anyone's local corpus.
func Build(hashes []string, firstSeen time.Time) Source {
	out := Source{}
	for _, h := range hashes {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		out[h] = Signal{Hash: h, Trusters: 1, FirstSeen: firstSeen}
	}
	return out
}

// Merge unions any number of corpora into one. A hash's Trusters is the sum of
// its counts across sources — so merging N teammates' content-free exports
// yields "how many of us vouch for this exact content" — and its FirstSeen is
// the earliest non-zero timestamp across them. Merge is how a team builds a
// shared reputation signal from committed exports with no server. Keys are
// normalized to lowercase so case variants collapse, matching Lookup.
func Merge(sources ...Source) Source {
	out := Source{}
	for _, src := range sources {
		for k, sig := range src {
			key := strings.ToLower(strings.TrimSpace(k))
			if key == "" {
				continue
			}
			cur, ok := out[key]
			if !ok {
				cur = Signal{Hash: key}
			}
			cur.Trusters += sig.Trusters
			cur.FirstSeen = earliest(cur.FirstSeen, sig.FirstSeen)
			out[key] = cur
		}
	}
	return out
}

// earliest returns the earlier of two timestamps, ignoring the zero value so an
// unset FirstSeen never masks a real one.
func earliest(a, b time.Time) time.Time {
	switch {
	case a.IsZero():
		return b
	case b.IsZero():
		return a
	case b.Before(a):
		return b
	default:
		return a
	}
}
