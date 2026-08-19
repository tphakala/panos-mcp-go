package tools

import (
	"context"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"

	"github.com/PaloAltoNetworks/pango/xmlapi"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// maxIPProtocol is the largest valid IP protocol number (the protocol field is a
// single byte). maxPort is the largest valid TCP/UDP port number.
const (
	maxIPProtocol = 255
	maxPort       = 65535
)

// asNumberOrString returns s parsed as an int when it is a clean integer, the
// trimmed string when it is non-empty non-numeric text, and nil when empty. It
// keeps a numeric device field (a rule index) numeric in the JSON output while
// still surfacing an unexpected non-numeric value verbatim.
func asNumberOrString(s string) any {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return s
}

// portInRange reports whether p is a usable TCP/UDP port. Zero means "unset"
// (omitempty drops it from the wire), so it is accepted; a negative value or one
// above maxPort is rejected before it reaches the device.
func portInRange(p int) bool {
	return p >= 0 && p <= maxPort
}

// communicateOp sends an operational command and decodes the <response> into
// resp (a pointer). On success it returns ok=true and the caller proceeds; on
// failure it logs, builds an error result, and returns ok=false, so callers
// write `if res, v, ok := communicateOp(...); !ok { return res, v, nil }`. The
// single //nolint:bodyclose directive lives here: pango's sendRequest already
// drained and closed the response body (client.go:1230 @ efa4357).
func communicateOp(ctx context.Context, d *Deps, tool string, cmd *xmlapi.Op, resp any) (res *mcp.CallToolResult, anyVal any, ok bool) {
	//nolint:bodyclose // pango's sendRequest already drained and closed the response body (client.go:1230 @ efa4357).
	if _, _, err := d.Client.Communicate(ctx, cmd, false, resp); err != nil {
		d.Logger.Error("failed: "+tool, "error", err)
		r, v := errorResult("failed: %s: %v", tool, err)
		return r, v, false
	}
	return nil, nil, true
}

// rawResultFallback surfaces an unrecognized op <result> verbatim instead of
// reporting a false-empty verdict (issue #42). When inner is non-empty it builds
// a text result and returns ok=true; an empty inner returns ok=false so the
// caller falls through to its normal empty/parsed handling.
func rawResultFallback(tool, inner string) (res *mcp.CallToolResult, anyVal any, ok bool) {
	if raw := strings.TrimSpace(inner); raw != "" {
		r, v := textResult("unrecognized %s response; raw result: %s", tool, raw)
		return r, v, true
	}
	return nil, nil, false
}

// SessionListInput filters the firewall session table. Every field is optional;
// with none set the tool lists all sessions.
type SessionListInput struct {
	Source          string `json:"source,omitempty" jsonschema:"Filter: source IP"`
	Destination     string `json:"destination,omitempty" jsonschema:"Filter: destination IP"`
	DestinationPort int    `json:"destination_port,omitempty" jsonschema:"Filter: destination port"`
	Protocol        int    `json:"protocol,omitempty" jsonschema:"Filter: IP protocol number (6=TCP, 17=UDP)"`
	Application     string `json:"application,omitempty" jsonschema:"Filter: application name"`
	From            string `json:"from,omitempty" jsonschema:"Filter: source (ingress) zone"`
	To              string `json:"to,omitempty" jsonschema:"Filter: destination (egress) zone"`
	Limit           int    `json:"limit,omitempty" jsonschema:"Max results (default 50, max 200)"`
	Offset          int    `json:"offset,omitempty" jsonschema:"Skip this many results"`
}

// sessionFilter marshals the optional <filter> under <session><all>. The field
// order is the order PAN-OS expects on the wire; every field is omitempty so
// only the set filters appear.
type sessionFilter struct {
	Source          string `xml:"source,omitempty"`
	Destination     string `xml:"destination,omitempty"`
	DestinationPort int    `xml:"destination-port,omitempty"`
	Protocol        int    `xml:"protocol,omitempty"`
	Application     string `xml:"application,omitempty"`
	From            string `xml:"from,omitempty"`
	To              string `xml:"to,omitempty"`
}

// sessionListReq marshals <show><session><all>[<filter>...]</all></session></show>.
// All is a value struct so <session><all> is always emitted; Filter is a nil
// pointer (dropped by the marshaler) when no filter is set, which yields the
// no-filter wire form rather than a bare <filter></filter> that PAN-OS rejects.
type sessionListReq struct {
	XMLName xml.Name `xml:"show"`
	All     struct {
		Filter *sessionFilter `xml:"filter"`
	} `xml:"session>all"`
}

// buildSessionFilter returns the wire filter for the set input fields, or nil
// when no filter field is set (so the command marshals to the no-filter form).
func buildSessionFilter(in *SessionListInput) *sessionFilter {
	f := sessionFilter{
		Source:          in.Source,
		Destination:     in.Destination,
		DestinationPort: in.DestinationPort,
		Protocol:        in.Protocol,
		Application:     in.Application,
		From:            in.From,
		To:              in.To,
	}
	if f == (sessionFilter{}) {
		return nil
	}
	return &f
}

// sessionEntry is one <result><entry> from "show session all". The numeric
// columns are kept as strings: PAN-OS emits empty numeric elements (e.g.
// <xsport></xsport> for a session with no NAT), which an int would read as 0,
// losing the empty-versus-zero distinction; a string also tolerates any
// non-numeric token the device might emit (a non-numeric value fails an int
// unmarshal and would drop the whole response).
type sessionEntry struct {
	Idx         string `xml:"idx"`
	Source      string `xml:"source"`
	SPort       string `xml:"sport"`
	Dst         string `xml:"dst"`
	DPort       string `xml:"dport"`
	Proto       string `xml:"proto"`
	From        string `xml:"from"`
	To          string `xml:"to"`
	Application string `xml:"application"`
	State       string `xml:"state"`
	Type        string `xml:"type"`
	StartTime   string `xml:"start-time"`
	XSource     string `xml:"xsource"`
	XSPort      string `xml:"xsport"`
	XDst        string `xml:"xdst"`
	XDPort      string `xml:"xdport"`
	Vsys        string `xml:"vsys"`
}

// sessionSummary projects one session entry to the JSON output shape.
func sessionSummary(e *sessionEntry) map[string]any {
	return map[string]any{
		"id":                   e.Idx,
		"source":               e.Source,
		"source_port":          e.SPort,
		"destination":          e.Dst,
		"destination_port":     e.DPort,
		"protocol":             e.Proto,
		"from":                 e.From,
		"to":                   e.To,
		"application":          e.Application,
		"state":                e.State,
		typeKey:                e.Type,
		"start_time":           e.StartTime,
		"nat_source":           e.XSource,
		"nat_source_port":      e.XSPort,
		"nat_destination":      e.XDst,
		"nat_destination_port": e.XDPort,
		"vsys":                 e.Vsys,
	}
}

// sessionListHandler lists the firewall session table (firewall only).
func sessionListHandler(d *Deps) func(context.Context, *mcp.CallToolRequest, SessionListInput) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in SessionListInput) (*mcp.CallToolResult, any, error) {
		defer d.RLockReads()()
		var req sessionListReq
		req.All.Filter = buildSessionFilter(&in)
		var resp struct {
			XMLName xml.Name `xml:"response"`
			Result  struct {
				Entries []sessionEntry `xml:"entry"`
				Inner   string         `xml:",innerxml"`
			} `xml:"result"`
		}
		cmd := &xmlapi.Op{Command: req}
		if res, v, ok := communicateOp(ctx, d, "panos_session_list", cmd, &resp); !ok {
			return res, v, nil
		}
		entries := resp.Result.Entries
		// An empty session table is a valid, empty result. Only a success response
		// whose <result> is non-empty but not the entry shape falls to the raw
		// fallback, so an unrecognized shape is surfaced rather than reported as an
		// empty table (issue #42).
		if len(entries) == 0 {
			if res, v, ok := rawResultFallback("panos_session_list", resp.Result.Inner); ok {
				return res, v, nil
			}
		}
		total := len(entries)
		lo, hi := clampList(in.Limit, in.Offset, total)
		out := make([]any, 0, hi-lo)
		for i := lo; i < hi; i++ {
			out = append(out, sessionSummary(&entries[i]))
		}
		res, v := jsonResult(map[string]any{totalKey: total, offsetKey: lo, countKey: len(out), "sessions": out})
		return res, v, nil
	}
}

// InterfaceStatusInput optionally narrows the interface list to one name.
type InterfaceStatusInput struct {
	Name string `json:"name,omitempty" jsonschema:"Filter to this exact interface name (e.g. ethernet1/1)"`
}

// interfaceReq marshals <show><interface>all</interface></show>. "all" is the
// text content of <interface>, not an <all/> child.
type interfaceReq struct {
	XMLName   xml.Name `xml:"show"`
	Interface string   `xml:"interface"`
}

// hwEntry is one <result><hw><entry> (physical interface).
type hwEntry struct {
	Name  string `xml:"name"`
	State string `xml:"state"`
	MAC   string `xml:"mac"`
	St    string `xml:"st"`
}

// ifnetEntry is one <result><ifnet><entry> (Layer 3 configured interface).
type ifnetEntry struct {
	Name string `xml:"name"`
	IP   string `xml:"ip"`
	Zone string `xml:"zone"`
	Fwd  string `xml:"fwd"`
	Vsys string `xml:"vsys"`
}

// joinInterfaces merges the hw and ifnet lists by name into one uniform record
// per interface, preserving first-seen order. A logical interface that appears
// only in ifnet still gets a record, with an empty hardware state.
func joinInterfaces(hw []hwEntry, ifnet []ifnetEntry) []map[string]any {
	byName := make(map[string]map[string]any, len(hw)+len(ifnet))
	order := make([]string, 0, len(hw)+len(ifnet))
	record := func(name string) map[string]any {
		if m, ok := byName[name]; ok {
			return m
		}
		m := map[string]any{
			tagNameKey: name, "state": "", "mac": "", "status": "",
			"ip": "", "zone": "", "forwarding": "", "vsys": "",
		}
		byName[name] = m
		order = append(order, name)
		return m
	}
	for i := range hw {
		h := &hw[i]
		m := record(h.Name)
		m["state"] = h.State
		m["mac"] = h.MAC
		m["status"] = h.St
	}
	for _, n := range ifnet {
		m := record(n.Name)
		m["ip"] = n.IP
		m["zone"] = n.Zone
		m["forwarding"] = n.Fwd
		m["vsys"] = n.Vsys
	}
	out := make([]map[string]any, 0, len(order))
	for _, name := range order {
		out = append(out, byName[name])
	}
	return out
}

// filterInterfaceByName keeps only the interface whose name equals want.
func filterInterfaceByName(ifaces []map[string]any, want string) []map[string]any {
	out := make([]map[string]any, 0, 1)
	for _, m := range ifaces {
		if m[tagNameKey] == want {
			out = append(out, m)
		}
	}
	return out
}

// interfaceStatusHandler shows interface operational status (firewall only).
func interfaceStatusHandler(d *Deps) func(context.Context, *mcp.CallToolRequest, InterfaceStatusInput) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in InterfaceStatusInput) (*mcp.CallToolResult, any, error) {
		defer d.RLockReads()()
		var resp struct {
			XMLName xml.Name `xml:"response"`
			Result  struct {
				HW    []hwEntry    `xml:"hw>entry"`
				Ifnet []ifnetEntry `xml:"ifnet>entry"`
				Inner string       `xml:",innerxml"`
			} `xml:"result"`
		}
		cmd := &xmlapi.Op{Command: interfaceReq{Interface: "all"}}
		if res, v, ok := communicateOp(ctx, d, "panos_interface_status", cmd, &resp); !ok {
			return res, v, nil
		}
		ifaces := joinInterfaces(resp.Result.HW, resp.Result.Ifnet)
		if len(ifaces) == 0 {
			if res, v, ok := rawResultFallback("panos_interface_status", resp.Result.Inner); ok {
				return res, v, nil
			}
		}
		if in.Name != "" {
			ifaces = filterInterfaceByName(ifaces, in.Name)
		}
		res, v := jsonResult(map[string]any{totalKey: len(ifaces), "interfaces": ifaces})
		return res, v, nil
	}
}

// RouteListInput optionally narrows the route listing to one virtual router.
type RouteListInput struct {
	VirtualRouter string `json:"virtual_router,omitempty" jsonschema:"Limit to this virtual router"`
	Limit         int    `json:"limit,omitempty" jsonschema:"Max results (default 50, max 200)"`
	Offset        int    `json:"offset,omitempty" jsonschema:"Skip this many results"`
}

// routeReq marshals <show><routing><route>[<virtual-router>..]</route></routing></show>.
type routeReq struct {
	XMLName xml.Name `xml:"show"`
	Route   struct {
		VR string `xml:"virtual-router,omitempty"`
	} `xml:"routing>route"`
}

// routeEntry is one <result><entry> from "show routing route".
type routeEntry struct {
	VirtualRouter string `xml:"virtual-router"`
	Destination   string `xml:"destination"`
	Nexthop       string `xml:"nexthop"`
	Metric        string `xml:"metric"`
	Flags         string `xml:"flags"`
	Interface     string `xml:"interface"`
	RouteTable    string `xml:"route-table"`
}

// routeSummary projects one route entry to the JSON output shape. PAN-OS pads
// the flags column, so it is trimmed.
func routeSummary(e *routeEntry) map[string]any {
	return map[string]any{
		"virtual_router": e.VirtualRouter,
		"destination":    e.Destination,
		"nexthop":        e.Nexthop,
		"metric":         e.Metric,
		"flags":          strings.TrimSpace(e.Flags),
		"interface":      e.Interface,
		"route_table":    e.RouteTable,
	}
}

// routeListHandler lists the legacy virtual-router routing table (firewall only).
func routeListHandler(d *Deps) func(context.Context, *mcp.CallToolRequest, RouteListInput) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in RouteListInput) (*mcp.CallToolResult, any, error) {
		defer d.RLockReads()()
		var req routeReq
		req.Route.VR = in.VirtualRouter
		var resp struct {
			XMLName xml.Name `xml:"response"`
			Result  struct {
				Entries []routeEntry `xml:"entry"`
				Inner   string       `xml:",innerxml"`
			} `xml:"result"`
		}
		cmd := &xmlapi.Op{Command: req}
		if res, v, ok := communicateOp(ctx, d, "panos_route_list", cmd, &resp); !ok {
			return res, v, nil
		}
		entries := resp.Result.Entries
		if len(entries) == 0 {
			if res, v, ok := rawResultFallback("panos_route_list", resp.Result.Inner); ok {
				return res, v, nil
			}
		}
		total := len(entries)
		lo, hi := clampList(in.Limit, in.Offset, total)
		out := make([]any, 0, hi-lo)
		for i := lo; i < hi; i++ {
			out = append(out, routeSummary(&entries[i]))
		}
		res, v := jsonResult(map[string]any{totalKey: total, offsetKey: lo, countKey: len(out), "routes": out})
		return res, v, nil
	}
}

// sysResourcesReq marshals <show><system><resources></resources></system></show>.
type sysResourcesReq struct {
	XMLName xml.Name `xml:"show"`
	Cmd     string   `xml:"system>resources"`
}

// systemResourcesHandler returns the raw top(1) resource text (firewall and
// Panorama). The <result> is unstructured text, so it is returned verbatim.
func systemResourcesHandler(d *Deps) func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		defer d.RLockReads()()
		var resp struct {
			XMLName xml.Name `xml:"response"`
			Result  string   `xml:"result"`
		}
		cmd := &xmlapi.Op{Command: sysResourcesReq{}}
		if res, v, ok := communicateOp(ctx, d, "panos_system_resources", cmd, &resp); !ok {
			return res, v, nil
		}
		res, v := textResult("%s", strings.TrimSpace(resp.Result))
		return res, v, nil
	}
}

// haStateReq marshals <show><high-availability><state></state></high-availability></show>.
type haStateReq struct {
	XMLName xml.Name `xml:"show"`
	Cmd     string   `xml:"high-availability>state"`
}

// haInfo holds the HA state fields shared by the firewall (<group>-wrapped) and
// Panorama (flat) response shapes.
type haInfo struct {
	LocalState  string `xml:"local-info>state"`
	LocalMode   string `xml:"local-info>mode"`
	PeerState   string `xml:"peer-info>state"`
	PeerConn    string `xml:"peer-info>conn-status"`
	RunningSync string `xml:"running-sync"`
}

// empty reports whether no HA state field was populated.
func (h *haInfo) empty() bool {
	return h.LocalState == "" && h.LocalMode == "" && h.PeerState == "" &&
		h.PeerConn == "" && h.RunningSync == ""
}

// haStatusHandler reports high-availability state (firewall and Panorama).
func haStatusHandler(d *Deps) func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		defer d.RLockReads()()
		// The firewall nests state under <group>; Panorama returns local-info and
		// peer-info directly under <result>. Both shapes are parsed, then whichever
		// is populated is used.
		var resp struct {
			XMLName xml.Name `xml:"response"`
			Result  struct {
				Enabled     string  `xml:"enabled"`
				Group       *haInfo `xml:"group"`
				LocalState  string  `xml:"local-info>state"`
				LocalMode   string  `xml:"local-info>mode"`
				PeerState   string  `xml:"peer-info>state"`
				PeerConn    string  `xml:"peer-info>conn-status"`
				RunningSync string  `xml:"running-sync"`
				Inner       string  `xml:",innerxml"`
			} `xml:"result"`
		}
		cmd := &xmlapi.Op{Command: haStateReq{}}
		if res, v, ok := communicateOp(ctx, d, "panos_ha_status", cmd, &resp); !ok {
			return res, v, nil
		}
		enabled := strings.TrimSpace(resp.Result.Enabled)
		// An absent <enabled> alongside other content is an unrecognized shape, not
		// a disabled HA: surface it raw rather than a false "disabled" verdict
		// (issue #42). An explicit "no", or a genuinely empty result, is disabled.
		if enabled == "" {
			if res, v, ok := rawResultFallback("panos_ha_status", resp.Result.Inner); ok {
				return res, v, nil
			}
		}
		if enabled == "" || strings.EqualFold(enabled, "no") {
			res, v := jsonResult(map[string]any{"enabled": false})
			return res, v, nil
		}
		info := haInfo{
			LocalState:  resp.Result.LocalState,
			LocalMode:   resp.Result.LocalMode,
			PeerState:   resp.Result.PeerState,
			PeerConn:    resp.Result.PeerConn,
			RunningSync: resp.Result.RunningSync,
		}
		if g := resp.Result.Group; g != nil && !g.empty() {
			info = *g
		}
		// HA is enabled but no state field parsed: surface the raw result rather
		// than a misleadingly empty structured response (issue #42).
		if info.empty() {
			if res, v, ok := rawResultFallback("panos_ha_status", resp.Result.Inner); ok {
				return res, v, nil
			}
		}
		res, v := jsonResult(map[string]any{
			"enabled":         true,
			"mode":            info.LocalMode,
			"local_state":     info.LocalState,
			"peer_state":      info.PeerState,
			"peer_connection": info.PeerConn,
			"running_sync":    info.RunningSync,
		})
		return res, v, nil
	}
}

// SecurityPolicyMatchInput describes a hypothetical flow to evaluate against the
// running security policy.
type SecurityPolicyMatchInput struct {
	Source          string `json:"source" jsonschema:"Source IP (required)"`
	Destination     string `json:"destination" jsonschema:"Destination IP (required)"`
	Protocol        int    `json:"protocol" jsonschema:"IP protocol number 1-255 (required; 6=TCP, 17=UDP)"`
	DestinationPort int    `json:"destination_port,omitempty" jsonschema:"Destination port"`
	Application     string `json:"application,omitempty" jsonschema:"Application name"`
	From            string `json:"from,omitempty" jsonschema:"Source (ingress) zone"`
	To              string `json:"to,omitempty" jsonschema:"Destination (egress) zone"`
	SourceUser      string `json:"source_user,omitempty" jsonschema:"Source user"`
	Category        string `json:"category,omitempty" jsonschema:"URL category"`
	ShowAll         bool   `json:"show_all,omitempty" jsonschema:"Return all matching rules, not just the first"`
	Vsys            string `json:"vsys,omitempty" jsonschema:"Firewall vsys (default vsys1)"`
}

// securityPolicyMatchReq marshals <test><security-policy-match>...</security-policy-match></test>.
// The field order is the wire order; the three required leaves come first.
type securityPolicyMatchReq struct {
	XMLName xml.Name `xml:"test"`
	Match   struct {
		Source          string `xml:"source"`
		Destination     string `xml:"destination"`
		Protocol        int    `xml:"protocol"`
		DestinationPort int    `xml:"destination-port,omitempty"`
		Application     string `xml:"application,omitempty"`
		From            string `xml:"from,omitempty"`
		To              string `xml:"to,omitempty"`
		SourceUser      string `xml:"source-user,omitempty"`
		Category        string `xml:"category,omitempty"`
		ShowAll         string `xml:"show-all,omitempty"`
	} `xml:"security-policy-match"`
}

// securityMatchRule is one matched rule. Modern PAN-OS returns a structured
// <entry name="..."><index>..</index><action>..</action>; older versions return
// a bare <entry>rulename</entry>. Both shapes are parsed.
type securityMatchRule struct {
	Name     string `xml:"name,attr"`
	Chardata string `xml:",chardata"`
	Index    string `xml:"index"`
	Action   string `xml:"action"`
}

// policyMatchName returns the rule name from a policy-match entry: the name
// attribute on the modern shape, or the trimmed chardata on the legacy shape.
func policyMatchName(nameAttr, chardata string) string {
	name := strings.TrimSpace(nameAttr)
	if name == "" {
		name = strings.TrimSpace(chardata)
	}
	return name
}

// securityMatchRuleSummary projects one matched security rule to the output shape.
func securityMatchRuleSummary(r *securityMatchRule) map[string]any {
	m := map[string]any{tagNameKey: policyMatchName(r.Name, r.Chardata)}
	if idx := asNumberOrString(r.Index); idx != nil {
		m["index"] = idx
	}
	if act := strings.TrimSpace(r.Action); act != "" {
		m["action"] = act
	}
	return m
}

// securityPolicyMatchHandler evaluates a hypothetical flow against the running
// security policy (firewall only).
func securityPolicyMatchHandler(d *Deps) func(context.Context, *mcp.CallToolRequest, SecurityPolicyMatchInput) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in SecurityPolicyMatchInput) (*mcp.CallToolResult, any, error) {
		defer d.RLockReads()()
		if in.Source == "" || in.Destination == "" {
			res, v := errorResult("panos_test_security_policy_match: source and destination are required")
			return res, v, nil
		}
		if in.Protocol < 1 || in.Protocol > maxIPProtocol {
			res, v := errorResult("panos_test_security_policy_match: protocol is required and must be 1-255, got %d", in.Protocol)
			return res, v, nil
		}
		if !portInRange(in.DestinationPort) {
			res, v := errorResult("panos_test_security_policy_match: destination_port must be between 1 and 65535, got %d", in.DestinationPort)
			return res, v, nil
		}
		var req securityPolicyMatchReq
		req.Match.Source = in.Source
		req.Match.Destination = in.Destination
		req.Match.Protocol = in.Protocol
		req.Match.DestinationPort = in.DestinationPort
		req.Match.Application = in.Application
		req.Match.From = in.From
		req.Match.To = in.To
		req.Match.SourceUser = in.SourceUser
		req.Match.Category = in.Category
		if in.ShowAll {
			req.Match.ShowAll = "yes"
		}
		var resp struct {
			XMLName xml.Name `xml:"response"`
			Result  struct {
				Rules []securityMatchRule `xml:"rules>entry"`
				Inner string              `xml:",innerxml"`
			} `xml:"result"`
		}
		cmd := &xmlapi.Op{Command: req, Vsys: in.Vsys}
		if res, v, ok := communicateOp(ctx, d, "panos_test_security_policy_match", cmd, &resp); !ok {
			return res, v, nil
		}
		rules := resp.Result.Rules
		if len(rules) == 0 {
			if res, v, ok := rawResultFallback("panos_test_security_policy_match", resp.Result.Inner); ok {
				return res, v, nil
			}
			res, v := jsonResult(map[string]any{matchedKey: false, "note": "no security rule matched this flow"})
			return res, v, nil
		}
		out := make([]any, 0, len(rules))
		for i := range rules {
			out = append(out, securityMatchRuleSummary(&rules[i]))
		}
		res, v := jsonResult(map[string]any{matchedKey: true, "rules": out})
		return res, v, nil
	}
}

// NatPolicyMatchInput describes a hypothetical flow to evaluate against the
// running NAT policy.
type NatPolicyMatchInput struct {
	Source          string `json:"source" jsonschema:"Source IP (required)"`
	Destination     string `json:"destination" jsonschema:"Destination IP (required)"`
	Protocol        int    `json:"protocol,omitempty" jsonschema:"IP protocol number (6=TCP, 17=UDP)"`
	SourcePort      int    `json:"source_port,omitempty" jsonschema:"Source port"`
	DestinationPort int    `json:"destination_port,omitempty" jsonschema:"Destination port"`
	From            string `json:"from,omitempty" jsonschema:"Source (ingress) zone"`
	To              string `json:"to,omitempty" jsonschema:"Destination (egress) zone"`
	ToInterface     string `json:"to_interface,omitempty" jsonschema:"Egress interface (e.g. ethernet1/1)"`
	Vsys            string `json:"vsys,omitempty" jsonschema:"Firewall vsys (default vsys1)"`
}

// natPolicyMatchReq marshals <test><nat-policy-match>...</nat-policy-match></test>.
type natPolicyMatchReq struct {
	XMLName xml.Name `xml:"test"`
	Match   struct {
		Source          string `xml:"source"`
		Destination     string `xml:"destination"`
		Protocol        int    `xml:"protocol,omitempty"`
		SourcePort      int    `xml:"source-port,omitempty"`
		DestinationPort int    `xml:"destination-port,omitempty"`
		From            string `xml:"from,omitempty"`
		To              string `xml:"to,omitempty"`
		ToInterface     string `xml:"to-interface,omitempty"`
	} `xml:"nat-policy-match"`
}

// natMatchRule is the matched NAT rule with its translation subtree. Name and
// index parse the same dual shape as securityMatchRule.
type natMatchRule struct {
	Name              string `xml:"name,attr"`
	Chardata          string `xml:",chardata"`
	Index             string `xml:"index"`
	SourceTranslation struct {
		StaticIP struct {
			TranslatedAddress string `xml:"translated-address"`
		} `xml:"static-ip"`
		DynamicIPAndPort struct {
			TranslatedAddress struct {
				Members []string `xml:"member"`
			} `xml:"translated-address"`
			InterfaceAddress struct {
				Interface string `xml:"interface"`
				IP        string `xml:"ip"`
			} `xml:"interface-address"`
		} `xml:"dynamic-ip-and-port"`
		DynamicIP struct {
			TranslatedAddress struct {
				Members []string `xml:"member"`
			} `xml:"translated-address"`
		} `xml:"dynamic-ip"`
		Inner string `xml:",innerxml"`
	} `xml:"source-translation"`
	DestinationTranslation struct {
		TranslatedAddress string `xml:"translated-address"`
		TranslatedPort    string `xml:"translated-port"`
		Inner             string `xml:",innerxml"`
	} `xml:"destination-translation"`
}

// trimMembers returns the non-empty, trimmed members of a translated-address list.
func trimMembers(members []string) []string {
	out := make([]string, 0, len(members))
	for _, m := range members {
		if t := strings.TrimSpace(m); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// natTranslatedSource extracts the source translation as a string (static IP or
// interface address) or a list (dynamic IP pools), or nil when there is none.
func natTranslatedSource(r *natMatchRule) any {
	st := r.SourceTranslation
	if v := strings.TrimSpace(st.StaticIP.TranslatedAddress); v != "" {
		return v
	}
	if m := trimMembers(st.DynamicIPAndPort.TranslatedAddress.Members); len(m) > 0 {
		return m
	}
	if m := trimMembers(st.DynamicIP.TranslatedAddress.Members); len(m) > 0 {
		return m
	}
	ia := st.DynamicIPAndPort.InterfaceAddress
	iface, ip := strings.TrimSpace(ia.Interface), strings.TrimSpace(ia.IP)
	switch {
	case iface != "" && ip != "":
		return iface + " (" + ip + ")"
	case ip != "":
		return ip
	case iface != "":
		return iface
	}
	return nil
}

// natTranslatedDestination formats the destination translation as address or
// address:port, or "" when there is none.
func natTranslatedDestination(r *natMatchRule) string {
	dt := r.DestinationTranslation
	addr := strings.TrimSpace(dt.TranslatedAddress)
	port := strings.TrimSpace(dt.TranslatedPort)
	switch {
	case addr != "" && port != "":
		return addr + ":" + port
	case addr != "":
		return addr
	}
	return ""
}

// validateNatMatchInput returns an error message for an invalid
// nat-policy-match input, or "" when it is usable. Source and destination are
// required; a set protocol or port must be in range (an unset 0 is allowed and
// omitted from the wire).
func validateNatMatchInput(in *NatPolicyMatchInput) string {
	switch {
	case in.Source == "" || in.Destination == "":
		return "source and destination are required"
	case in.Protocol != 0 && (in.Protocol < 1 || in.Protocol > maxIPProtocol):
		return fmt.Sprintf("protocol must be between 1 and 255, got %d", in.Protocol)
	case !portInRange(in.SourcePort):
		return fmt.Sprintf("source_port must be between 1 and 65535, got %d", in.SourcePort)
	case !portInRange(in.DestinationPort):
		return fmt.Sprintf("destination_port must be between 1 and 65535, got %d", in.DestinationPort)
	}
	return ""
}

// natMatchResult projects a matched NAT rule to the output map: the rule name
// and index, plus the source and destination translations. When a translation
// subtree is present but in a shape none of the known paths matched, its raw
// XML is surfaced rather than silently reporting no translation (a false-empty
// verdict on a matched NAT rule; the same safety principle as issue #42).
func natMatchResult(r *natMatchRule) map[string]any {
	rule := map[string]any{tagNameKey: policyMatchName(r.Name, r.Chardata)}
	if idx := asNumberOrString(r.Index); idx != nil {
		rule["index"] = idx
	}
	out := map[string]any{matchedKey: true, "rule": rule}
	if ts := natTranslatedSource(r); ts != nil {
		out["translated_source"] = ts
	} else if raw := strings.TrimSpace(r.SourceTranslation.Inner); raw != "" {
		out["source_translation_raw"] = raw
	}
	if td := natTranslatedDestination(r); td != "" {
		out["translated_destination"] = td
	} else if raw := strings.TrimSpace(r.DestinationTranslation.Inner); raw != "" {
		out["destination_translation_raw"] = raw
	}
	return out
}

// natPolicyMatchHandler evaluates a hypothetical flow against the running NAT
// policy and reports the translation it would apply (firewall only).
func natPolicyMatchHandler(d *Deps) func(context.Context, *mcp.CallToolRequest, NatPolicyMatchInput) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in NatPolicyMatchInput) (*mcp.CallToolResult, any, error) {
		defer d.RLockReads()()
		if msg := validateNatMatchInput(&in); msg != "" {
			res, v := errorResult("panos_test_nat_policy_match: %s", msg)
			return res, v, nil
		}
		var req natPolicyMatchReq
		req.Match.Source = in.Source
		req.Match.Destination = in.Destination
		req.Match.Protocol = in.Protocol
		req.Match.SourcePort = in.SourcePort
		req.Match.DestinationPort = in.DestinationPort
		req.Match.From = in.From
		req.Match.To = in.To
		req.Match.ToInterface = in.ToInterface
		var resp struct {
			XMLName xml.Name `xml:"response"`
			Result  struct {
				Rules []natMatchRule `xml:"rules>entry"`
				Inner string         `xml:",innerxml"`
			} `xml:"result"`
		}
		cmd := &xmlapi.Op{Command: req, Vsys: in.Vsys}
		if res, v, ok := communicateOp(ctx, d, "panos_test_nat_policy_match", cmd, &resp); !ok {
			return res, v, nil
		}
		rules := resp.Result.Rules
		if len(rules) == 0 {
			if res, v, ok := rawResultFallback("panos_test_nat_policy_match", resp.Result.Inner); ok {
				return res, v, nil
			}
			res, v := jsonResult(map[string]any{matchedKey: false, "note": "no NAT rule matched (no translation applied)"})
			return res, v, nil
		}
		res, v := jsonResult(natMatchResult(&rules[0]))
		return res, v, nil
	}
}

// RegisterOpTools registers read-only operational-visibility and policy-match
// test tools. All are read-only: no d.ReadOnly gate. The firewall-only tools
// (sessions, interfaces, routes, and the two policy-match tests) need a
// dataplane or a running firewall policy that Panorama does not have, so they
// are not registered on Panorama.
func RegisterOpTools(s *mcp.Server, d *Deps) {
	// The "both" tools are registered first, before the Panorama early return.
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_system_resources",
		Description: "Show system resource utilization (the top command output: CPU, memory, and per-process load). Read-only.",
		Annotations: readOnlyTool("System resources"),
	}, systemResourcesHandler(d))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_ha_status",
		Description: "Show high-availability state: whether HA is enabled, plus local and peer state, mode, peer connection status, and running-config sync. Read-only.",
		Annotations: readOnlyTool("HA status"),
	}, haStatusHandler(d))
	if d.IsPanorama {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_session_list",
		Description: "List active sessions from the firewall session table, optionally filtered by source, destination, port, protocol, application, or zone. Firewall only. Read-only.",
		Annotations: readOnlyTool("List sessions"),
	}, sessionListHandler(d))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_interface_status",
		Description: "Show interface operational status: link state, MAC, and hardware status, plus per-interface IP, zone, forwarding, and vsys. Firewall only. Read-only.",
		Annotations: readOnlyTool("Interface status"),
	}, interfaceStatusHandler(d))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_route_list",
		Description: "List routes from the legacy virtual-router routing table (destination, next hop, metric, flags, egress interface). Advanced Routing Engine devices instead use \"show advanced-routing route\", which this tool does not cover. Firewall only. Read-only.",
		Annotations: readOnlyTool("List routes"),
	}, routeListHandler(d))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_test_security_policy_match",
		Description: "Test which security rule a hypothetical flow would match, evaluated against the RUNNING (committed) config without sending traffic. Firewall only. Read-only.",
		Annotations: readOnlyTool("Test security policy"),
	}, securityPolicyMatchHandler(d))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_test_nat_policy_match",
		Description: "Test which NAT rule a hypothetical flow would match and what translation it would apply, evaluated against the RUNNING (committed) config without sending traffic. Firewall only. Read-only.",
		Annotations: readOnlyTool("Test NAT policy"),
	}, natPolicyMatchHandler(d))
}
