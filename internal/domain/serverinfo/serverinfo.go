// Package serverinfo models the identity an MCP server declares in its
// initialize response: implementation name, version, and protocol version.
// Recording it per session lets an investigator tie audited behavior to a
// specific server build — the answer to "which version was running when this
// happened" after an upgrade or a rug pull.
//
// Pure domain: the shim passes in raw result bytes; nothing here does IO.
// Names and versions are identifiers, not content, so they may appear in the
// audit log in the clear.
package serverinfo

import (
	"encoding/json"
	"strings"
)

// Info is the identity one initialize result declares.
type Info struct {
	Name     string // serverInfo.name
	Version  string // serverInfo.version
	Protocol string // protocolVersion
}

// Extract parses an initialize result. It never errors: malformed JSON, or a
// result carrying neither serverInfo nor protocolVersion (i.e. not an
// initialize result at all), returns ok=false.
func Extract(resultJSON []byte) (Info, bool) {
	var w struct {
		ProtocolVersion string `json:"protocolVersion"`
		ServerInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
	}
	if err := json.Unmarshal(resultJSON, &w); err != nil {
		return Info{}, false
	}
	info := Info{Name: w.ServerInfo.Name, Version: w.ServerInfo.Version, Protocol: w.ProtocolVersion}
	if info.Name == "" && info.Version == "" && info.Protocol == "" {
		return Info{}, false
	}
	return info, true
}

// Detail renders the identity in the audit trail's key=value style, omitting
// empty fields.
func (i Info) Detail() string {
	parts := make([]string, 0, 3)
	if i.Name != "" {
		parts = append(parts, "name="+i.Name)
	}
	if i.Version != "" {
		parts = append(parts, "version="+i.Version)
	}
	if i.Protocol != "" {
		parts = append(parts, "protocol="+i.Protocol)
	}
	return strings.Join(parts, " ")
}
