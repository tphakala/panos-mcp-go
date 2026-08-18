package tools

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Pinned wire commands. These are written first, by hand, so production and
// tests must agree by construction: opExact routing rejects any drift, the same
// way a real device rejects an unknown command (issue #42).
const (
	sessionListAllCmd    = `<show><session><all></all></session></show>`
	sessionListFilterCmd = `<show><session><all><filter>` +
		`<source>10.0.0.5</source><destination>8.8.8.8</destination>` +
		`<destination-port>443</destination-port><protocol>6</protocol>` +
		`<application>ssl</application><from>trust</from><to>untrust</to>` +
		`</filter></all></session></show>`
	interfaceAllCmd    = `<show><interface>all</interface></show>`
	routeListAllCmd    = `<show><routing><route></route></routing></show>`
	routeListVRCmd     = `<show><routing><route><virtual-router>default</virtual-router></route></routing></show>`
	systemResourcesCmd = `<show><system><resources></resources></system></show>`
	haStateCmd         = `<show><high-availability><state></state></high-availability></show>`
	secPolicyMatchCmd  = `<test><security-policy-match>` +
		`<source>10.0.0.5</source><destination>8.8.8.8</destination><protocol>6</protocol>` +
		`</security-policy-match></test>`
	secPolicyMatchFullCmd = `<test><security-policy-match>` +
		`<source>10.0.0.5</source><destination>8.8.8.8</destination><protocol>6</protocol>` +
		`<destination-port>443</destination-port><application>ssl</application>` +
		`<from>trust</from><to>untrust</to><source-user>alice</source-user>` +
		`<category>any</category><show-all>yes</show-all>` +
		`</security-policy-match></test>`
	natPolicyMatchCmd = `<test><nat-policy-match>` +
		`<source>10.0.0.5</source><destination>203.0.113.9</destination>` +
		`</nat-policy-match></test>`
	natPolicyMatchFullCmd = `<test><nat-policy-match>` +
		`<source>10.0.0.5</source><destination>203.0.113.9</destination><protocol>6</protocol>` +
		`<source-port>40000</source-port><destination-port>443</destination-port>` +
		`<from>trust</from><to>untrust</to><to-interface>ethernet1/1</to-interface>` +
		`</nat-policy-match></test>`
)

// opDecodeJSON decodes a non-error JSON tool result into a map.
func opDecodeJSON(t *testing.T, res *mcp.CallToolResult) map[string]any {
	t.Helper()
	if res.IsError {
		t.Fatalf("unexpected error result: %s", textContent(t, res))
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(textContent(t, res)), &m); err != nil {
		t.Fatalf("result is not a JSON object: %v; text=%s", err, textContent(t, res))
	}
	return m
}

// firstEntry returns element 0 of a JSON array field as a map.
func firstEntry(t *testing.T, m map[string]any, key string) map[string]any {
	t.Helper()
	arr, ok := m[key].([]any)
	if !ok || len(arr) == 0 {
		t.Fatalf("%q is not a non-empty array: %#v", key, m[key])
	}
	return opAsObject(t, arr[0])
}

// opAsObject asserts v is a JSON object.
func opAsObject(t *testing.T, v any) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("value is not a JSON object: %#v", v)
	}
	return m
}

// opAsString asserts v is a string.
func opAsString(t *testing.T, v any) string {
	t.Helper()
	s, ok := v.(string)
	if !ok {
		t.Fatalf("value is not a string: %#v", v)
	}
	return s
}

// jsonArray asserts m[key] is a JSON array.
func jsonArray(t *testing.T, m map[string]any, key string) []any {
	t.Helper()
	arr, ok := m[key].([]any)
	if !ok {
		t.Fatalf("%q is not an array: %#v", key, m[key])
	}
	return arr
}

const sessionListBody = `<response status="success"><result>` +
	`<entry><idx>1</idx><source>10.0.0.5</source><sport>40000</sport>` +
	`<dst>8.8.8.8</dst><dport>443</dport><proto>6</proto>` +
	`<from>trust</from><to>untrust</to><application>ssl</application>` +
	`<state>ACTIVE</state><type>FLOW</type><start-time>Mon Aug 18 12:00:00</start-time>` +
	`<xsource>203.0.113.9</xsource><xsport>50000</xsport>` +
	`<xdst>8.8.8.8</xdst><xdport>443</xdport><vsys>vsys1</vsys></entry>` +
	// Second entry has empty NAT fields, proving the numeric columns decode as
	// strings: an int would read the empty elements as 0, losing the
	// empty-versus-zero distinction.
	`<entry><idx>2</idx><source>10.0.0.6</source><sport>1234</sport>` +
	`<dst>1.1.1.1</dst><dport>53</dport><proto>17</proto>` +
	`<from>trust</from><to>untrust</to><application>dns</application>` +
	`<state>ACTIVE</state><type>FLOW</type><start-time>Mon Aug 18 12:00:01</start-time>` +
	`<xsource></xsource><xsport></xsport><xdst></xdst><xdport></xdport><vsys>vsys1</vsys></entry>` +
	`</result></response>`

func TestSessionList(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: opExact(sessionListAllCmd), Body: sessionListBody})
	res, _, _ := sessionListHandler(d)(t.Context(), nil, SessionListInput{})
	assertRequestSent(t, f, opExact(sessionListAllCmd), "session list must emit the show-session-all op verbatim")
	m := opDecodeJSON(t, res)
	if m["total"] != float64(2) {
		t.Fatalf("total = %v, want 2", m["total"])
	}
	e := firstEntry(t, m, "sessions")
	for key, want := range map[string]any{
		"id": "1", "source": "10.0.0.5", "source_port": "40000",
		"destination": "8.8.8.8", "destination_port": "443", "protocol": "6",
		"from": "trust", "to": "untrust", "application": "ssl",
		"state": "ACTIVE", "type": "FLOW", "start_time": "Mon Aug 18 12:00:00",
		"nat_source": "203.0.113.9", "nat_source_port": "50000",
		"nat_destination": "8.8.8.8", "nat_destination_port": "443", "vsys": "vsys1",
	} {
		if e[key] != want {
			t.Errorf("session[0][%q] = %v, want %v", key, e[key], want)
		}
	}
}

func TestSessionListFiltered(t *testing.T) {
	// A response body is not needed to pin the wire form: routing on the exact
	// filtered command proves the filter marshaled in the expected order.
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: opExact(sessionListFilterCmd), Body: `<response status="success"><result></result></response>`})
	in := SessionListInput{
		Source: "10.0.0.5", Destination: "8.8.8.8", DestinationPort: 443,
		Protocol: 6, Application: "ssl", From: "trust", To: "untrust",
	}
	res, _, _ := sessionListHandler(d)(t.Context(), nil, in)
	assertRequestSent(t, f, opExact(sessionListFilterCmd), "filtered session list must emit the full <filter> wire form in field order")
	if res.IsError {
		t.Fatalf("filtered session list errored: %s", textContent(t, res))
	}
}

func TestSessionListEmpty(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: opExact(sessionListAllCmd), Body: `<response status="success"><result></result></response>`})
	res, _, _ := sessionListHandler(d)(t.Context(), nil, SessionListInput{})
	m := opDecodeJSON(t, res)
	if m["total"] != float64(0) {
		t.Fatalf("empty session table total = %v, want 0", m["total"])
	}
	arr, ok := m["sessions"].([]any)
	if !ok || len(arr) != 0 {
		t.Fatalf("empty session table must return an empty sessions array, got %#v", m["sessions"])
	}
}

const interfaceStatusBody = `<response status="success"><result>` +
	`<hw>` +
	`<entry><name>ethernet1/1</name><state>up</state><mac>00:11:22:33:44:55</mac>` +
	`<st>1000/full</st><speed>1000</speed><duplex>full</duplex></entry>` +
	`<entry><name>ethernet1/2</name><state>down</state><mac>00:11:22:33:44:56</mac><st>unknown</st></entry>` +
	`</hw>` +
	`<ifnet>` +
	`<entry><name>ethernet1/1</name><ip>10.0.0.1/24</ip><zone>trust</zone><fwd>vr:default</fwd><vsys>vsys1</vsys></entry>` +
	// loopback.1 appears only in ifnet: a logical interface with no hardware row.
	`<entry><name>loopback.1</name><ip>1.1.1.1/32</ip><zone>trust</zone><fwd>vr:default</fwd><vsys>vsys1</vsys></entry>` +
	`</ifnet>` +
	`</result></response>`

func TestInterfaceStatus(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: opExact(interfaceAllCmd), Body: interfaceStatusBody})
	res, _, _ := interfaceStatusHandler(d)(t.Context(), nil, InterfaceStatusInput{})
	assertRequestSent(t, f, opExact(interfaceAllCmd), "interface status must emit <show><interface>all</interface></show>")
	m := opDecodeJSON(t, res)
	if m["total"] != float64(3) {
		t.Fatalf("total = %v, want 3 (2 hw + 1 logical)", m["total"])
	}
	byName := map[string]map[string]any{}
	for _, raw := range jsonArray(t, m, "interfaces") {
		iface := opAsObject(t, raw)
		byName[opAsString(t, iface["name"])] = iface
	}
	// The hw+ifnet join: ethernet1/1 carries both hardware state and L3 config.
	eth1 := byName["ethernet1/1"]
	for key, want := range map[string]any{
		"state": "up", "mac": "00:11:22:33:44:55", "status": "1000/full",
		"ip": "10.0.0.1/24", "zone": "trust", "forwarding": "vr:default", "vsys": "vsys1",
	} {
		if eth1[key] != want {
			t.Errorf("ethernet1/1[%q] = %v, want %v", key, eth1[key], want)
		}
	}
	// A logical interface (ifnet only) has an empty hardware state but full L3 fields.
	lo := byName["loopback.1"]
	if lo["state"] != "" {
		t.Errorf("loopback.1 state = %v, want empty (no hardware row)", lo["state"])
	}
	if lo["ip"] != "1.1.1.1/32" {
		t.Errorf("loopback.1 ip = %v, want 1.1.1.1/32", lo["ip"])
	}
}

func TestInterfaceStatusNameFilter(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: opExact(interfaceAllCmd), Body: interfaceStatusBody})
	res, _, _ := interfaceStatusHandler(d)(t.Context(), nil, InterfaceStatusInput{Name: "ethernet1/1"})
	m := opDecodeJSON(t, res)
	if m["total"] != float64(1) {
		t.Fatalf("filtered total = %v, want 1", m["total"])
	}
	e := firstEntry(t, m, "interfaces")
	if e["name"] != "ethernet1/1" {
		t.Fatalf("filtered interface = %v, want ethernet1/1", e["name"])
	}
}

const routeListBody = `<response status="success"><result>` +
	// flags are padded with surrounding spaces, as PAN-OS emits them.
	`<entry><virtual-router>default</virtual-router><destination>0.0.0.0/0</destination>` +
	`<nexthop>10.0.0.254</nexthop><metric>10</metric><flags>  A S  </flags><age>100</age>` +
	`<interface>ethernet1/1</interface><route-table>unicast</route-table></entry>` +
	`<entry><virtual-router>default</virtual-router><destination>10.0.0.0/24</destination>` +
	`<nexthop>0.0.0.0</nexthop><metric>0</metric><flags>A C</flags>` +
	`<interface>ethernet1/1</interface><route-table>unicast</route-table></entry>` +
	`</result></response>`

func TestRouteList(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: opExact(routeListAllCmd), Body: routeListBody})
	res, _, _ := routeListHandler(d)(t.Context(), nil, RouteListInput{})
	assertRequestSent(t, f, opExact(routeListAllCmd), "route list must emit the no-VR routing op verbatim")
	m := opDecodeJSON(t, res)
	if m["total"] != float64(2) {
		t.Fatalf("total = %v, want 2", m["total"])
	}
	e := firstEntry(t, m, "routes")
	for key, want := range map[string]any{
		"virtual_router": "default", "destination": "0.0.0.0/0",
		"nexthop": "10.0.0.254", "metric": "10",
		"interface": "ethernet1/1", "route_table": "unicast",
	} {
		if e[key] != want {
			t.Errorf("route[0][%q] = %v, want %v", key, e[key], want)
		}
	}
	// The padded flags must be trimmed.
	if e["flags"] != "A S" {
		t.Errorf("route[0][flags] = %q, want %q (padding trimmed)", e["flags"], "A S")
	}
}

func TestRouteListVR(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: opExact(routeListVRCmd), Body: `<response status="success"><result></result></response>`})
	res, _, _ := routeListHandler(d)(t.Context(), nil, RouteListInput{VirtualRouter: "default"})
	assertRequestSent(t, f, opExact(routeListVRCmd), "route list with a VR must emit the <virtual-router> wire form")
	if res.IsError {
		t.Fatalf("route list with VR errored: %s", textContent(t, res))
	}
}

func TestSystemResources(t *testing.T) {
	body := `<response status="success"><result>` +
		"top - 12:00:00 up 5 days\nCPU: 3.2% user\nMem: 8000M total\n" +
		`</result></response>`
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: opExact(systemResourcesCmd), Body: body})
	res, _, _ := systemResourcesHandler(d)(t.Context(), nil, struct{}{})
	assertRequestSent(t, f, opExact(systemResourcesCmd), "system resources must emit the show-system-resources op verbatim")
	if res.IsError {
		t.Fatalf("system resources errored: %s", textContent(t, res))
	}
	out := textContent(t, res)
	for _, want := range []string{"top -", "CPU: 3.2% user", "Mem: 8000M total"} {
		if !strings.Contains(out, want) {
			t.Errorf("system resources output missing %q: %s", want, out)
		}
	}
}

func TestHAStatus(t *testing.T) {
	// Firewall shape: state nested under <group>.
	body := `<response status="success"><result>` +
		`<enabled>yes</enabled>` +
		`<group>` +
		`<local-info><state>active</state><mode>Active-Passive</mode></local-info>` +
		`<peer-info><state>passive</state><conn-status>up</conn-status></peer-info>` +
		`<running-sync>synchronized</running-sync>` +
		`</group>` +
		`</result></response>`
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: opExact(haStateCmd), Body: body})
	res, _, _ := haStatusHandler(d)(t.Context(), nil, struct{}{})
	assertRequestSent(t, f, opExact(haStateCmd), "HA status must emit the show-high-availability-state op verbatim")
	m := opDecodeJSON(t, res)
	for key, want := range map[string]any{
		"enabled": true, "mode": "Active-Passive", "local_state": "active",
		"peer_state": "passive", "peer_connection": "up", "running_sync": "synchronized",
	} {
		if m[key] != want {
			t.Errorf("ha[%q] = %v, want %v", key, m[key], want)
		}
	}
}

func TestHAStatusDisabled(t *testing.T) {
	body := `<response status="success"><result><enabled>no</enabled></result></response>`
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: opExact(haStateCmd), Body: body})
	res, _, _ := haStatusHandler(d)(t.Context(), nil, struct{}{})
	m := opDecodeJSON(t, res)
	if m["enabled"] != false {
		t.Fatalf("disabled HA enabled = %v, want false", m["enabled"])
	}
	if _, ok := m["local_state"]; ok {
		t.Errorf("disabled HA must not report state fields, got local_state=%v", m["local_state"])
	}
}

func TestHAStatusPanoramaShape(t *testing.T) {
	// Panorama shape: local-info and peer-info directly under <result>, no <group>.
	body := `<response status="success"><result>` +
		`<enabled>yes</enabled>` +
		`<local-info><state>primary-active</state><mode>Active-Passive</mode></local-info>` +
		`<peer-info><state>secondary-passive</state><conn-status>up</conn-status></peer-info>` +
		`<running-sync>synchronized</running-sync>` +
		`</result></response>`
	d, _ := newTestDeps(t, "Panorama", fakeRoute{Match: opExact(haStateCmd), Body: body})
	res, _, _ := haStatusHandler(d)(t.Context(), nil, struct{}{})
	m := opDecodeJSON(t, res)
	for key, want := range map[string]any{
		"enabled": true, "mode": "Active-Passive",
		"local_state": "primary-active", "peer_state": "secondary-passive",
		"peer_connection": "up", "running_sync": "synchronized",
	} {
		if m[key] != want {
			t.Errorf("panorama ha[%q] = %v, want %v", key, m[key], want)
		}
	}
}

func TestSecurityPolicyMatch(t *testing.T) {
	// Modern shape: <entry name="..."><index>..</index><action>..</action>.
	body := `<response status="success"><result><rules>` +
		`<entry name="allow-dns"><index>2</index><action>allow</action></entry>` +
		`</rules></result></response>`
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: opExact(secPolicyMatchFullCmd), Body: body})
	in := SecurityPolicyMatchInput{
		Source: "10.0.0.5", Destination: "8.8.8.8", Protocol: 6,
		DestinationPort: 443, Application: "ssl", From: "trust", To: "untrust",
		SourceUser: "alice", Category: "any", ShowAll: true, Vsys: "vsys2",
	}
	res, _, _ := securityPolicyMatchHandler(d)(t.Context(), nil, in)
	assertRequestSent(t, f, opExact(secPolicyMatchFullCmd), "security policy match must emit all fields in wire order")
	// Vsys is a separate form parameter, not part of the cmd.
	assertRequestSent(t, f, func(v url.Values) bool { return v.Get("vsys") == "vsys2" },
		"security policy match must send vsys as a form parameter")
	m := opDecodeJSON(t, res)
	if m["matched"] != true {
		t.Fatalf("matched = %v, want true", m["matched"])
	}
	e := firstEntry(t, m, "rules")
	if e["name"] != "allow-dns" {
		t.Errorf("rule name = %v, want allow-dns", e["name"])
	}
	if e["index"] != float64(2) {
		t.Errorf("rule index = %v, want 2", e["index"])
	}
	if e["action"] != "allow" {
		t.Errorf("rule action = %v, want allow", e["action"])
	}
}

func TestSecurityPolicyMatchLegacyShape(t *testing.T) {
	// Legacy shape: bare chardata rule name, no attributes or child elements.
	body := `<response status="success"><result><rules>` +
		`<entry>allow-dns</entry>` +
		`</rules></result></response>`
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: opExact(secPolicyMatchCmd), Body: body})
	in := SecurityPolicyMatchInput{Source: "10.0.0.5", Destination: "8.8.8.8", Protocol: 6}
	res, _, _ := securityPolicyMatchHandler(d)(t.Context(), nil, in)
	assertRequestSent(t, f, opExact(secPolicyMatchCmd), "minimal security policy match must emit only the required leaves")
	m := opDecodeJSON(t, res)
	if m["matched"] != true {
		t.Fatalf("matched = %v, want true", m["matched"])
	}
	e := firstEntry(t, m, "rules")
	if e["name"] != "allow-dns" {
		t.Errorf("legacy rule name = %v, want allow-dns (from chardata)", e["name"])
	}
}

func TestSecurityPolicyMatchNoMatch(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: opExact(secPolicyMatchCmd), Body: `<response status="success"><result></result></response>`})
	in := SecurityPolicyMatchInput{Source: "10.0.0.5", Destination: "8.8.8.8", Protocol: 6}
	res, _, _ := securityPolicyMatchHandler(d)(t.Context(), nil, in)
	m := opDecodeJSON(t, res)
	if m["matched"] != false {
		t.Fatalf("matched = %v, want false", m["matched"])
	}
	note, _ := m["note"].(string)
	if !strings.Contains(note, "no security rule matched") {
		t.Errorf("no-match note = %q, want a no-match explanation", note)
	}
}

func TestSecurityPolicyMatchRequired(t *testing.T) {
	sent := func(v url.Values) bool {
		return v.Get("type") == "op" && strings.Contains(v.Get("cmd"), "security-policy-match")
	}
	cases := map[string]SecurityPolicyMatchInput{
		"missing source":            {Destination: "8.8.8.8", Protocol: 6},
		"missing destination":       {Source: "10.0.0.5", Protocol: 6},
		"protocol zero":             {Source: "10.0.0.5", Destination: "8.8.8.8", Protocol: 0},
		"protocol too high":         {Source: "10.0.0.5", Destination: "8.8.8.8", Protocol: 256},
		"destination port too high": {Source: "10.0.0.5", Destination: "8.8.8.8", Protocol: 6, DestinationPort: 70000},
		"destination port negative": {Source: "10.0.0.5", Destination: "8.8.8.8", Protocol: 6, DestinationPort: -1},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			d, f := newTestDeps(t, "PA-VM")
			res, _, _ := securityPolicyMatchHandler(d)(t.Context(), nil, in)
			if !res.IsError {
				t.Fatalf("%s must be an input error, got: %s", name, textContent(t, res))
			}
			assertNoRequestSent(t, f, sent, "an invalid security policy match must not reach the device")
		})
	}
}

func TestNatPolicyMatch(t *testing.T) {
	t.Run("static source and destination translation", func(t *testing.T) {
		body := `<response status="success"><result><rules>` +
			`<entry name="nat-rule-1"><index>1</index>` +
			`<source-translation><static-ip><translated-address>203.0.113.9</translated-address></static-ip></source-translation>` +
			`<destination-translation><translated-address>10.1.1.5</translated-address><translated-port>8080</translated-port></destination-translation>` +
			`</entry></rules></result></response>`
		d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: opExact(natPolicyMatchFullCmd), Body: body})
		in := NatPolicyMatchInput{
			Source: "10.0.0.5", Destination: "203.0.113.9", Protocol: 6,
			SourcePort: 40000, DestinationPort: 443, From: "trust", To: "untrust",
			ToInterface: "ethernet1/1", Vsys: "vsys2",
		}
		res, _, _ := natPolicyMatchHandler(d)(t.Context(), nil, in)
		assertRequestSent(t, f, opExact(natPolicyMatchFullCmd), "nat policy match must emit all fields in wire order")
		assertRequestSent(t, f, func(v url.Values) bool { return v.Get("vsys") == "vsys2" },
			"nat policy match must send vsys as a form parameter")
		m := opDecodeJSON(t, res)
		if m["matched"] != true {
			t.Fatalf("matched = %v, want true", m["matched"])
		}
		rule := opAsObject(t, m["rule"])
		if rule["name"] != "nat-rule-1" {
			t.Errorf("rule name = %v, want nat-rule-1", rule["name"])
		}
		if rule["index"] != float64(1) {
			t.Errorf("rule index = %v, want 1", rule["index"])
		}
		if m["translated_source"] != "203.0.113.9" {
			t.Errorf("translated_source = %v, want 203.0.113.9", m["translated_source"])
		}
		if m["translated_destination"] != "10.1.1.5:8080" {
			t.Errorf("translated_destination = %v, want 10.1.1.5:8080", m["translated_destination"])
		}
	})

	t.Run("dynamic ip and port member list", func(t *testing.T) {
		body := `<response status="success"><result><rules>` +
			`<entry name="dipp-rule"><index>3</index>` +
			`<source-translation><dynamic-ip-and-port><translated-address>` +
			`<member>203.0.113.10</member><member>203.0.113.11</member>` +
			`</translated-address></dynamic-ip-and-port></source-translation>` +
			`</entry></rules></result></response>`
		d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: opExact(natPolicyMatchCmd), Body: body})
		in := NatPolicyMatchInput{Source: "10.0.0.5", Destination: "203.0.113.9"}
		res, _, _ := natPolicyMatchHandler(d)(t.Context(), nil, in)
		m := opDecodeJSON(t, res)
		members, ok := m["translated_source"].([]any)
		if !ok || len(members) != 2 {
			t.Fatalf("translated_source = %#v, want a 2-element member list", m["translated_source"])
		}
		if members[0] != "203.0.113.10" || members[1] != "203.0.113.11" {
			t.Errorf("translated_source members = %v, want [203.0.113.10 203.0.113.11]", members)
		}
	})
}

func TestNatPolicyMatchNoMatch(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: opExact(natPolicyMatchCmd), Body: `<response status="success"><result></result></response>`})
	in := NatPolicyMatchInput{Source: "10.0.0.5", Destination: "203.0.113.9"}
	res, _, _ := natPolicyMatchHandler(d)(t.Context(), nil, in)
	m := opDecodeJSON(t, res)
	if m["matched"] != false {
		t.Fatalf("matched = %v, want false", m["matched"])
	}
	note, _ := m["note"].(string)
	if !strings.Contains(note, "no NAT rule matched") {
		t.Errorf("no-match note = %q, want a no-match explanation", note)
	}
}

func TestNatPolicyMatchRequired(t *testing.T) {
	sent := func(v url.Values) bool {
		return v.Get("type") == "op" && strings.Contains(v.Get("cmd"), "nat-policy-match")
	}
	cases := map[string]NatPolicyMatchInput{
		"missing source":            {Destination: "203.0.113.9"},
		"missing destination":       {Source: "10.0.0.5"},
		"protocol too high":         {Source: "10.0.0.5", Destination: "203.0.113.9", Protocol: 256},
		"source port too high":      {Source: "10.0.0.5", Destination: "203.0.113.9", SourcePort: 70000},
		"destination port negative": {Source: "10.0.0.5", Destination: "203.0.113.9", DestinationPort: -1},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			d, f := newTestDeps(t, "PA-VM")
			res, _, _ := natPolicyMatchHandler(d)(t.Context(), nil, in)
			if !res.IsError {
				t.Fatalf("%s must be an input error, got: %s", name, textContent(t, res))
			}
			assertNoRequestSent(t, f, sent, "an invalid nat policy match must not reach the device")
		})
	}
}

// opToolNames registers the op tools for a model and mode and returns the
// exposed tool-name set.
func opToolNames(t *testing.T, model string, readOnly bool) map[string]bool {
	t.Helper()
	d, _ := newTestDeps(t, model)
	d.ReadOnly = readOnly
	s := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	RegisterOpTools(s, d)
	return serverToolNames(t, s)
}

// assertRegistered fails for any want name missing from names.
func assertRegistered(t *testing.T, names map[string]bool, want []string, ctx string) {
	t.Helper()
	for _, n := range want {
		if !names[n] {
			t.Errorf("%s: %q must be registered", ctx, n)
		}
	}
}

// assertAbsent fails for any unwanted name present in names.
func assertAbsent(t *testing.T, names map[string]bool, unwanted []string, ctx string) {
	t.Helper()
	for _, n := range unwanted {
		if names[n] {
			t.Errorf("%s: %q must NOT be registered", ctx, n)
		}
	}
}

func TestRegisterOpToolsGates(t *testing.T) {
	firewallTools := []string{
		"panos_system_resources", "panos_ha_status", "panos_session_list",
		"panos_interface_status", "panos_route_list",
		"panos_test_security_policy_match", "panos_test_nat_policy_match",
	}
	firewallOnly := []string{
		"panos_session_list", "panos_interface_status", "panos_route_list",
		"panos_test_security_policy_match", "panos_test_nat_policy_match",
	}
	both := []string{"panos_system_resources", "panos_ha_status"}

	// All seven tools are read-only, so mode must not change the surface.
	for _, readOnly := range []bool{false, true} {
		t.Run("firewall", func(t *testing.T) {
			names := opToolNames(t, "PA-VM", readOnly)
			assertRegistered(t, names, firewallTools, "firewall")
		})
		t.Run("panorama", func(t *testing.T) {
			names := opToolNames(t, "Panorama", readOnly)
			assertRegistered(t, names, both, "panorama")
			assertAbsent(t, names, firewallOnly, "panorama")
		})
	}
}

// TestOpRawFallback proves the issue-#42 safety net fires in every handler that
// carries it: a successful but unrecognized <result> is surfaced as raw text,
// never reported as an empty/no-match verdict. Deleting a handler's
// "unrecognized ... raw result" branch turns its subtest red.
func TestOpRawFallback(t *testing.T) {
	const foo = `<foo>bar</foo>`
	unrecognized := `<response status="success"><result>` + foo + `</result></response>`
	assertRaw := func(t *testing.T, res *mcp.CallToolResult, tool string) {
		t.Helper()
		if res.IsError {
			t.Fatalf("%s raw fallback must be a non-error text result: %s", tool, textContent(t, res))
		}
		out := textContent(t, res)
		if !strings.Contains(out, "unrecognized "+tool) || !strings.Contains(out, "raw result:") || !strings.Contains(out, "bar") {
			t.Errorf("%s raw fallback = %q, want an 'unrecognized ... raw result:' text carrying the raw body", tool, out)
		}
	}
	t.Run("session_list", func(t *testing.T) {
		d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: opExact(sessionListAllCmd), Body: unrecognized})
		res, _, _ := sessionListHandler(d)(t.Context(), nil, SessionListInput{})
		assertRaw(t, res, "panos_session_list")
	})
	t.Run("interface_status", func(t *testing.T) {
		d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: opExact(interfaceAllCmd), Body: unrecognized})
		res, _, _ := interfaceStatusHandler(d)(t.Context(), nil, InterfaceStatusInput{})
		assertRaw(t, res, "panos_interface_status")
	})
	t.Run("route_list", func(t *testing.T) {
		d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: opExact(routeListAllCmd), Body: unrecognized})
		res, _, _ := routeListHandler(d)(t.Context(), nil, RouteListInput{})
		assertRaw(t, res, "panos_route_list")
	})
	t.Run("ha_status", func(t *testing.T) {
		// HA enabled but no state field parses: the raw fallback must fire rather
		// than a misleadingly empty structured result.
		body := `<response status="success"><result><enabled>yes</enabled>` + foo + `</result></response>`
		d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: opExact(haStateCmd), Body: body})
		res, _, _ := haStatusHandler(d)(t.Context(), nil, struct{}{})
		assertRaw(t, res, "panos_ha_status")
	})
	t.Run("security_policy_match", func(t *testing.T) {
		d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: opExact(secPolicyMatchCmd), Body: unrecognized})
		in := SecurityPolicyMatchInput{Source: "10.0.0.5", Destination: "8.8.8.8", Protocol: 6}
		res, _, _ := securityPolicyMatchHandler(d)(t.Context(), nil, in)
		assertRaw(t, res, "panos_test_security_policy_match")
	})
	t.Run("nat_policy_match", func(t *testing.T) {
		d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: opExact(natPolicyMatchCmd), Body: unrecognized})
		in := NatPolicyMatchInput{Source: "10.0.0.5", Destination: "203.0.113.9"}
		res, _, _ := natPolicyMatchHandler(d)(t.Context(), nil, in)
		assertRaw(t, res, "panos_test_nat_policy_match")
	})
}

// TestNatTranslationVariants covers the natTranslatedSource/Destination branches
// the happy-path test does not reach: interface-address, the dynamic-ip pool,
// and a destination translation with no port.
func TestNatTranslationVariants(t *testing.T) {
	in := NatPolicyMatchInput{Source: "10.0.0.5", Destination: "203.0.113.9"}
	t.Run("interface address", func(t *testing.T) {
		body := `<response status="success"><result><rules>` +
			`<entry name="dipp-iface"><index>4</index>` +
			`<source-translation><dynamic-ip-and-port><interface-address>` +
			`<interface>ethernet1/1</interface><ip>1.2.3.4</ip>` +
			`</interface-address></dynamic-ip-and-port></source-translation>` +
			`</entry></rules></result></response>`
		d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: opExact(natPolicyMatchCmd), Body: body})
		res, _, _ := natPolicyMatchHandler(d)(t.Context(), nil, in)
		m := opDecodeJSON(t, res)
		if m["translated_source"] != "ethernet1/1 (1.2.3.4)" {
			t.Errorf("translated_source = %v, want \"ethernet1/1 (1.2.3.4)\"", m["translated_source"])
		}
	})
	t.Run("dynamic ip pool", func(t *testing.T) {
		body := `<response status="success"><result><rules>` +
			`<entry name="di-rule"><index>5</index>` +
			`<source-translation><dynamic-ip><translated-address>` +
			`<member>203.0.113.20</member>` +
			`</translated-address></dynamic-ip></source-translation>` +
			`</entry></rules></result></response>`
		d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: opExact(natPolicyMatchCmd), Body: body})
		res, _, _ := natPolicyMatchHandler(d)(t.Context(), nil, in)
		m := opDecodeJSON(t, res)
		members, ok := m["translated_source"].([]any)
		if !ok || len(members) != 1 || members[0] != "203.0.113.20" {
			t.Errorf("translated_source = %#v, want [203.0.113.20]", m["translated_source"])
		}
	})
	t.Run("destination address only", func(t *testing.T) {
		body := `<response status="success"><result><rules>` +
			`<entry name="dnat"><index>6</index>` +
			`<destination-translation><translated-address>10.1.1.5</translated-address></destination-translation>` +
			`</entry></rules></result></response>`
		d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: opExact(natPolicyMatchCmd), Body: body})
		res, _, _ := natPolicyMatchHandler(d)(t.Context(), nil, in)
		m := opDecodeJSON(t, res)
		if m["translated_destination"] != "10.1.1.5" {
			t.Errorf("translated_destination = %v, want 10.1.1.5 (no port, no colon)", m["translated_destination"])
		}
	})
}

// TestNatTranslationRaw proves a matched rule whose translation is in a shape
// none of the known paths parse surfaces the raw subtree rather than silently
// reporting no translation.
func TestNatTranslationRaw(t *testing.T) {
	body := `<response status="success"><result><rules>` +
		`<entry name="future-nat"><index>7</index>` +
		`<source-translation><some-future-scheme><addr>9.9.9.9</addr></some-future-scheme></source-translation>` +
		`<destination-translation><dynamic-translation><addr>8.8.8.8</addr></dynamic-translation></destination-translation>` +
		`</entry></rules></result></response>`
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: opExact(natPolicyMatchCmd), Body: body})
	in := NatPolicyMatchInput{Source: "10.0.0.5", Destination: "203.0.113.9"}
	res, _, _ := natPolicyMatchHandler(d)(t.Context(), nil, in)
	m := opDecodeJSON(t, res)
	if m["matched"] != true {
		t.Fatalf("matched = %v, want true", m["matched"])
	}
	if _, ok := m["translated_source"]; ok {
		t.Errorf("translated_source should be absent for an unknown shape, got %v", m["translated_source"])
	}
	sraw := opAsString(t, m["source_translation_raw"])
	if !strings.Contains(sraw, "some-future-scheme") || !strings.Contains(sraw, "9.9.9.9") {
		t.Errorf("source_translation_raw = %q, want the raw unknown subtree", sraw)
	}
	draw := opAsString(t, m["destination_translation_raw"])
	if !strings.Contains(draw, "dynamic-translation") || !strings.Contains(draw, "8.8.8.8") {
		t.Errorf("destination_translation_raw = %q, want the raw unknown subtree", draw)
	}
}

// TestSecurityPolicyMatchNonNumericIndex proves a non-numeric <index> is
// surfaced verbatim as a string rather than dropped.
func TestSecurityPolicyMatchNonNumericIndex(t *testing.T) {
	body := `<response status="success"><result><rules>` +
		`<entry name="odd"><index>n/a</index><action>allow</action></entry>` +
		`</rules></result></response>`
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: opExact(secPolicyMatchCmd), Body: body})
	in := SecurityPolicyMatchInput{Source: "10.0.0.5", Destination: "8.8.8.8", Protocol: 6}
	res, _, _ := securityPolicyMatchHandler(d)(t.Context(), nil, in)
	m := opDecodeJSON(t, res)
	e := firstEntry(t, m, "rules")
	if e["index"] != "n/a" {
		t.Errorf("index = %#v, want the string \"n/a\" (non-numeric surfaced verbatim)", e["index"])
	}
}

// TestInterfaceStatusEmpty proves an empty interface list is a valid empty
// result, not an error or a raw fallback.
func TestInterfaceStatusEmpty(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: opExact(interfaceAllCmd), Body: `<response status="success"><result></result></response>`})
	res, _, _ := interfaceStatusHandler(d)(t.Context(), nil, InterfaceStatusInput{})
	m := opDecodeJSON(t, res)
	if m["total"] != float64(0) {
		t.Fatalf("empty interface list total = %v, want 0", m["total"])
	}
	arr, ok := m["interfaces"].([]any)
	if !ok || len(arr) != 0 {
		t.Fatalf("empty interface list must return an empty interfaces array, got %#v", m["interfaces"])
	}
}

// TestOpCommunicateError proves a device-side error is surfaced as an error
// result, not an empty success. With no route for its command, the fake returns
// a PAN-OS error, exercising the Communicate error branch.
func TestOpCommunicateError(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM")
	res, _, _ := sessionListHandler(d)(t.Context(), nil, SessionListInput{})
	if !res.IsError {
		t.Fatalf("a device error must produce an error result, got: %s", textContent(t, res))
	}
}
