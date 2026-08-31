package tools

import (
	"net/url"
	"testing"

	"github.com/PaloAltoNetworks/pango/policies/rules/security"
)

// These tests pin issue #108: the read paths that do NOT route through the
// generic *Core functions (the zone family's flat vsys/template handlers and
// moveHandler's existence-check read) must collapse pango's raw-response
// fallback the same way the cores do, rather than echoing the raw device body.
//
// Each drives the real handler through the fake API with rawEchoBody, a device
// error whose <msg> is empty so pango substitutes the whole raw body (see
// redact_test.go). assertCollapsedRawResponse then checks the body reached
// neither the tool result nor the log sink and that the device code survived.
//
// They are separate tests rather than a table so that reverting any single
// handler's deviceErrorResult call (or moveHandler's redactDeviceError call) to
// hand the raw error to errorResult reddens exactly that one test.

// Sabotage: revert zoneGetHandler's deviceErrorResult call to pass the raw
// svc.Read error to errorResult.
func TestZoneGetCollapsesRawResponse(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: rawEchoBody})
	logs := captureLogs(t, d)
	h := zoneGetHandler(d)

	res, _, err := h(t.Context(), nil, ZoneNameInput{Name: "nope"})
	assertCollapsedRawResponse(t, res, err, logs)
}

// Sabotage: revert zoneListHandler's deviceErrorResult call (the non
// object-not-found branch) to pass the raw svc.List error to errorResult.
func TestZoneListCollapsesRawResponse(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: rawEchoBody})
	logs := captureLogs(t, d)
	h := zoneListHandler(d)

	res, _, err := h(t.Context(), nil, ZoneListInput{})
	assertCollapsedRawResponse(t, res, err, logs)
}

// Sabotage: revert zoneDeleteHandler's deviceErrorResult call to pass the raw
// svc.Delete error to errorResult. Any config request matches: pango batches the
// delete into a multi-config, so a route matching action=delete never fires (see
// TestDeleteCollapsesRawResponse for the same reason on the core).
func TestZoneDeleteCollapsesRawResponse(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{
		Match: func(v url.Values) bool { return v.Get("type") == "config" },
		Body:  rawEchoBody,
	})
	logs := captureLogs(t, d)
	h := zoneDeleteHandler(d)

	res, _, err := h(t.Context(), nil, ZoneNameInput{Name: "nope"})
	assertCollapsedRawResponse(t, res, err, logs)
}

// Sabotage: revert moveHandler's redactDeviceError call at the seed read to pass
// the raw svc.Read error to errorResult. The move never runs: the existence read
// fails first, which is exactly the read path #108 names.
func TestMoveCollapsesRawResponseOnSeedRead(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: rawEchoBody})
	logs := captureLogs(t, d)
	h := moveHandler[security.Location, security.Entry](d, "panos_security_rule_move",
		newSecurityRuleService(d), security.NewService(d.Client), securityResolve(d))

	res, _, err := h(t.Context(), nil, MoveInput{Name: "nope", Position: "top"})
	assertCollapsedRawResponse(t, res, err, logs)
}

// Sabotage: revert zoneUpdateHandler's redactDeviceError call at the seed read to
// pass the raw svc.Read error to errorResult. The overlay and write never run: the
// read-modify-write seed read fails first, the same read path #108 names. The
// write error below stays raw on purpose (non-secret write convention), so this
// pins only the seed read.
func TestZoneUpdateCollapsesRawResponseOnSeedRead(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: rawEchoBody})
	logs := captureLogs(t, d)
	h := zoneUpdateHandler(d)

	res, _, err := h(t.Context(), nil, ZoneWriteInput{Name: "nope"})
	assertCollapsedRawResponse(t, res, err, logs)
}
