package cli

import (
	"os"
	"testing"
)

// envOr prefers a set environment value and falls back only when it is unset or
// empty — the precedence flag defaults (e.g. EYEBROW_SERVER) rely on.
func TestEnvOr(t *testing.T) {
	const key = "EYEBROW_TEST_ENVOR"
	t.Setenv(key, "from-env")
	if got := envOr(key, "fallback"); got != "from-env" {
		t.Errorf("a set value must win: got %q", got)
	}
	if err := os.Unsetenv(key); err != nil {
		t.Fatal(err)
	}
	if got := envOr(key, "fallback"); got != "fallback" {
		t.Errorf("an unset value must fall back: got %q", got)
	}
}

func TestHostnameNeverEmpty(t *testing.T) {
	if hostname() == "" {
		t.Error("hostname must never return empty (defaults to \"unknown\")")
	}
}

// topN caps a ranked list, leaving a short list untouched — the "top tools"
// summary relies on both branches.
func TestTopN(t *testing.T) {
	items := []kv{{"a", 5}, {"b", 4}, {"c", 3}}
	if got := topN(items, 2); len(got) != 2 || got[0].k != "a" {
		t.Errorf("topN should truncate to 2 keeping order: %+v", got)
	}
	if got := topN(items, 10); len(got) != 3 {
		t.Errorf("topN should return all when fewer than n: %+v", got)
	}
}
