package demodata_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alexverify/eyebrow/internal/dashboard"
	"github.com/alexverify/eyebrow/internal/dashboard/demodata"
)

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:7113"+path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// Every tab's data source must be populated: a demo with an empty tab is a bug.
func TestDemoPopulatesEveryTab(t *testing.T) {
	srv := dashboard.New(demodata.Deps())
	h := srv.Handler()

	scan := get(t, h, "/api/scan")
	if scan.Code != http.StatusOK {
		t.Fatalf("/api/scan = %d", scan.Code)
	}
	body := scan.Body.String()
	for _, want := range []string{
		`"demo":true`,              // Task 1 flag set
		`"sleeper":{"dormantDays"`, // Activity: the dormant-then-active story (Sleeper is an object, not a bool — dto.go DashSleeper)
		`"critical"`,               // Findings tab has a critical
		`"quarantined":true`,
		`"frozen":true`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/api/scan missing %s", want)
		}
	}
	var scanResp struct {
		Artifacts []json.RawMessage `json:"artifacts"`
	}
	if err := json.Unmarshal(scan.Body.Bytes(), &scanResp); err != nil {
		t.Fatalf("scan json: %v", err)
	}
	if len(scanResp.Artifacts) < 8 {
		t.Fatalf("want >=8 demo artifacts, got %d", len(scanResp.Artifacts))
	}

	for path, want := range map[string]string{
		"/api/fleet":   `"exposures"`,
		"/api/alerts":  `"alerts":[{`,
		"/api/history": `"history":[{`,
		"/api/policy":  `"mutes"`,
		"/api/audit":   `"ts"`,
	} {
		rec := get(t, h, path)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("%s = %d, body missing %s: %.200s", path, rec.Code, want, rec.Body.String())
		}
	}
}

// The drifted artifact must carry a line-level diff (Blobs wired for both hashes).
func TestDemoDriftHasLineDiff(t *testing.T) {
	srv := dashboard.New(demodata.Deps())
	body := get(t, srv.Handler(), "/api/scan").Body.String()
	if !strings.Contains(body, `"lineDiffs"`) {
		t.Fatalf("drifted demo artifact has no line-level diff; body: %.300s", body)
	}
}

// Mutations work in-memory: approve via the real endpoint, observe via re-fetch.
func TestDemoApproveIsInMemory(t *testing.T) {
	srv := dashboard.New(demodata.Deps())
	h := srv.Handler()

	// find the unapproved (new) artifact's id from the scan
	var scanResp struct {
		Artifacts []struct {
			ID       string `json:"id"`
			Approval *struct {
				Status string `json:"status"`
			} `json:"approval"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(get(t, h, "/api/scan").Body.Bytes(), &scanResp); err != nil {
		t.Fatalf("scan json: %v", err)
	}
	target := ""
	for _, a := range scanResp.Artifacts {
		if a.Approval == nil || a.Approval.Status != "approved" {
			target = a.ID
			break
		}
	}
	if target == "" {
		t.Fatal("demo dataset has no unapproved artifact to demo the approve flow")
	}

	payload, _ := json.Marshal(map[string]any{"id": target, "on": true})
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:7113/api/approve", bytes.NewReader(payload))
	req.Header.Set("X-Eyebrow-Token", srv.Token())
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve = %d: %s", rec.Code, rec.Body.String())
	}

	if err := json.Unmarshal(get(t, h, "/api/scan").Body.Bytes(), &scanResp); err != nil {
		t.Fatalf("re-scan json: %v", err)
	}
	for _, a := range scanResp.Artifacts {
		if a.ID == target {
			if a.Approval == nil || a.Approval.Status != "approved" {
				t.Fatalf("artifact %s not approved after in-memory mutation: %+v", target, a.Approval)
			}
			return
		}
	}
	t.Fatalf("artifact %s vanished after approve", target)
}
