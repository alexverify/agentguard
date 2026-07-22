// Package toolsurface models an MCP server's advertised tool surface — the
// tool names, descriptions, and input schemas a tools/list response carries.
// These are the words the agent actually reads and obeys, so a post-review
// mutation ("tool poisoning") is a rug pull the at-rest scan cannot see —
// for remote servers this digest is the only possible content signal.
//
// Pure domain: the shim passes in raw result bytes; nothing here does IO.
// Content never leaves this package un-digested — callers record the digest,
// the count, and the names, never descriptions or schemas.
package toolsurface

import (
	"bytes"
	"encoding/json"
	"sort"

	"github.com/alexverify/eyebrow/internal/domain/digest"
)

// Tool is one advertised tool: exactly the fields an agent consumes.
type Tool struct {
	Name        string
	Description string
	InputSchema json.RawMessage
}

// Surface is a server's advertised tool surface at one observation, tools
// sorted by name.
type Surface struct {
	Tools []Tool
}

// Extract parses a tools/list result. It never errors: malformed JSON or a
// missing "tools" member returns ok=false (the relay forwards the line
// regardless). An empty tool list is a valid surface.
func Extract(resultJSON []byte) (Surface, bool) {
	var w struct {
		Tools []struct {
			Name        string          `json:"name"`
			Description string          `json:"description"`
			InputSchema json.RawMessage `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(resultJSON, &w); err != nil || w.Tools == nil {
		return Surface{}, false
	}
	s := Surface{Tools: make([]Tool, 0, len(w.Tools))}
	for _, t := range w.Tools {
		s.Tools = append(s.Tools, Tool{Name: t.Name, Description: t.Description, InputSchema: t.InputSchema})
	}
	sort.Slice(s.Tools, func(i, j int) bool { return s.Tools[i].Name < s.Tools[j].Name })
	return s, true
}

// Digest folds the surface into one canonical content digest, reusing the
// lockfile's Merkle primitive: each tool is a "file" whose path is the tool
// name and whose leaf hash covers description ‖ 0x00 ‖ canonical(inputSchema).
// digest.Root sorts by path, so the result is independent of advertisement
// order; canonicalJSON makes it independent of schema key order.
func (s Surface) Digest() string {
	files := make([]digest.FileHash, 0, len(s.Tools))
	for _, t := range s.Tools {
		leaf := make([]byte, 0, len(t.Description)+1+len(t.InputSchema))
		leaf = append(leaf, t.Description...)
		leaf = append(leaf, 0x00)
		leaf = append(leaf, canonicalJSON(t.InputSchema)...)
		files = append(files, digest.FileHash{Path: t.Name, Hash: digest.Sum(leaf)})
	}
	return digest.Root(files)
}

// Names returns the advertised tool names, sorted.
func (s Surface) Names() []string {
	out := make([]string, len(s.Tools))
	for i, t := range s.Tools {
		out[i] = t.Name
	}
	return out
}

// Count reports the number of advertised tools.
func (s Surface) Count() int { return len(s.Tools) }

// canonicalJSON re-encodes raw JSON with Go's deterministic map-key ordering,
// so semantically identical schemas digest identically. Unparseable input
// falls back to compacted (then raw) bytes — never an error.
func canonicalJSON(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		var buf bytes.Buffer
		if json.Compact(&buf, raw) == nil {
			return buf.Bytes()
		}
		return raw
	}
	b, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return b
}
