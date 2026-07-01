package doctor

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestWireCarriesChecksAndSummary(t *testing.T) {
	r := Report{}.Add("tools", StatusOK, "found 3").Add("lockfile", StatusWarn, "missing")
	w := r.Wire()
	if w.Warnings != 1 {
		t.Errorf("warnings = %d, want 1", w.Warnings)
	}
	if w.Healthy {
		t.Error("a report with a warning is not healthy")
	}
	if len(w.Checks) != 2 {
		t.Fatalf("checks = %d, want 2", len(w.Checks))
	}
}

func TestWireMarshalsLowercaseFields(t *testing.T) {
	w := Report{}.Add("tools", StatusOK, "found 3").Add("lockfile", StatusWarn, "missing").Wire()
	b, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"checks"`, `"warnings":1`, `"healthy":false`, `"name":"tools"`, `"status":"ok"`, `"detail":"missing"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("json missing %s:\n%s", want, b)
		}
	}
}
