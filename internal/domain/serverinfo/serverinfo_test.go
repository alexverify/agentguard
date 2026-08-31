package serverinfo

import "testing"

func TestExtractReadsInitializeResult(t *testing.T) {
	info, ok := Extract([]byte(`{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"github-mcp","version":"1.2.0"}}`))
	if !ok {
		t.Fatal("a well-formed initialize result must extract")
	}
	if info.Name != "github-mcp" || info.Version != "1.2.0" || info.Protocol != "2025-06-18" {
		t.Errorf("info = %+v", info)
	}
}

func TestExtractToleratesMissingServerInfo(t *testing.T) {
	// Older servers may omit serverInfo; the protocol version alone is still
	// worth recording.
	info, ok := Extract([]byte(`{"protocolVersion":"2024-11-05","capabilities":{}}`))
	if !ok || info.Protocol != "2024-11-05" || info.Name != "" {
		t.Errorf("info = %+v, ok = %v", info, ok)
	}
}

func TestExtractRejectsNonInitializeResults(t *testing.T) {
	for _, raw := range []string{
		``,
		`{not json`,
		`{"content":[]}`,           // a tools/call result
		`{"tools":[{"name":"a"}]}`, // a tools/list result
	} {
		if _, ok := Extract([]byte(raw)); ok {
			t.Errorf("Extract(%q) accepted a non-initialize result", raw)
		}
	}
}

func TestDetailRendersIdentity(t *testing.T) {
	d := Info{Name: "github-mcp", Version: "1.2.0", Protocol: "2025-06-18"}.Detail()
	if d != "name=github-mcp version=1.2.0 protocol=2025-06-18" {
		t.Errorf("Detail() = %q", d)
	}
	partial := Info{Protocol: "2024-11-05"}.Detail()
	if partial != "protocol=2024-11-05" {
		t.Errorf("Detail() = %q", partial)
	}
}
