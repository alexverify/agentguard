package reputation

import (
	"testing"
	"time"
)

func TestBuildVouchesEachHashOnce(t *testing.T) {
	seen := time.Date(2026, 6, 10, 0, 0, 0, 0, time.UTC)
	// "AbC"/"abc" collapse (case-insensitive), the blank is dropped, and the
	// repeated "def" stays a single entry: one user vouches once.
	src := Build([]string{"AbC", "def", "abc", "", "def"}, seen)
	if len(src) != 2 {
		t.Fatalf("len = %d, want 2 (%v)", len(src), src)
	}
	sig, ok := src.Lookup("abc")
	if !ok {
		t.Fatal("expected abc in the corpus")
	}
	if sig.Trusters != 1 {
		t.Errorf("trusters = %d, want 1 (one local user vouches)", sig.Trusters)
	}
	if !sig.FirstSeen.Equal(seen) {
		t.Errorf("firstSeen = %v, want %v", sig.FirstSeen, seen)
	}
	if sig.Hash != "abc" {
		t.Errorf("hash = %q, want lowercased", sig.Hash)
	}
}

func TestBuildEmptyIsEmptyCorpus(t *testing.T) {
	if got := Build(nil, time.Unix(0, 0)); len(got) != 0 {
		t.Errorf("nil hashes must build an empty corpus, got %v", got)
	}
}

func TestMergeSumsTrustersAndKeepsEarliest(t *testing.T) {
	early := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	late := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	a := Source{"x": {Hash: "x", Trusters: 1, FirstSeen: late}}
	b := Source{
		"x": {Hash: "x", Trusters: 1, FirstSeen: early},
		"y": {Hash: "y", Trusters: 3, FirstSeen: late},
	}
	m := Merge(a, b)
	if got := m["x"].Trusters; got != 2 {
		t.Errorf("x trusters = %d, want 2 (summed across distinct sources)", got)
	}
	if !m["x"].FirstSeen.Equal(early) {
		t.Errorf("x firstSeen = %v, want earliest %v", m["x"].FirstSeen, early)
	}
	if got := m["y"].Trusters; got != 3 {
		t.Errorf("y trusters = %d, want 3", got)
	}
}

func TestMergeIgnoresZeroFirstSeen(t *testing.T) {
	real := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	m := Merge(
		Source{"x": {Hash: "x", Trusters: 1}}, // no FirstSeen
		Source{"x": {Hash: "x", Trusters: 1, FirstSeen: real}},
	)
	if !m["x"].FirstSeen.Equal(real) {
		t.Errorf("firstSeen = %v, want the real timestamp %v (zero must not mask it)", m["x"].FirstSeen, real)
	}
}

func TestMergeIsCaseInsensitive(t *testing.T) {
	m := Merge(
		Source{"AbC": {Hash: "AbC", Trusters: 1}},
		Source{"abc": {Hash: "abc", Trusters: 1}},
	)
	if len(m) != 1 {
		t.Fatalf("case variants must collapse, got %v", m)
	}
	if got := m["abc"].Trusters; got != 2 {
		t.Errorf("trusters = %d, want 2", got)
	}
}

func TestMergeNoSourcesIsEmpty(t *testing.T) {
	if got := Merge(); len(got) != 0 {
		t.Errorf("Merge() = %v, want empty", got)
	}
}
