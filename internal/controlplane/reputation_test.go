package controlplane

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alexverify/eyebrow/internal/domain/reputation"
)

// The reputation endpoint resolves a batch of hashes against the org corpus,
// returning only the matches — a hash-only lookup that reveals nothing else.
func TestReputationEndpointReturnsMatches(t *testing.T) {
	cfg := NewMemConfig()
	cfg.SetReputation("acme", reputation.Source{
		"sha256-aaa": {Hash: "sha256-aaa", Trusters: 9},
	})
	h := NewServer(NewService(NewMemStore(), cfg), StaticAuth{"tok-acme": "acme"})

	rec := do(t, h, "POST", "/v1/reputation", "tok-acme", []string{"sha256-aaa", "sha256-miss"})
	if rec.Code != http.StatusOK {
		t.Fatalf("reputation = %d, body=%s", rec.Code, rec.Body)
	}
	var src reputation.Source
	if err := json.Unmarshal(rec.Body.Bytes(), &src); err != nil {
		t.Fatal(err)
	}
	if sig, ok := src.Lookup("sha256-aaa"); !ok || sig.Trusters != 9 {
		t.Errorf("hit = %+v ok=%v", sig, ok)
	}
	if _, ok := src.Lookup("sha256-miss"); ok {
		t.Error("a miss must not be returned")
	}
}

// With no corpus configured the lookup is a clean empty result, never an error.
func TestReputationEndpointEmptyCorpus(t *testing.T) {
	h := testHandler()
	rec := do(t, h, "POST", "/v1/reputation", "tok-acme", []string{"sha256-x"})
	if rec.Code != http.StatusOK {
		t.Fatalf("reputation = %d", rec.Code)
	}
	var src reputation.Source
	if err := json.Unmarshal(rec.Body.Bytes(), &src); err != nil {
		t.Fatalf("an empty corpus must still emit a JSON object: %v", err)
	}
	if len(src) != 0 {
		t.Errorf("expected no matches, got %+v", src)
	}
}

func TestReputationEndpointRejectsBadJSONAndAuth(t *testing.T) {
	h := testHandler()
	req := httptest.NewRequest("POST", "/v1/reputation", bytes.NewReader([]byte("{not json")))
	req.Header.Set("Authorization", "Bearer tok-acme")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad hashes json = %d, want 400", rec.Code)
	}
	if rec := do(t, h, "POST", "/v1/reputation", "", []string{"h"}); rec.Code != http.StatusUnauthorized {
		t.Errorf("reputation without token = %d, want 401", rec.Code)
	}
}
