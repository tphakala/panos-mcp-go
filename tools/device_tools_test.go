package tools

import (
	"context"
	"encoding/json"
	"log/slog"
	"maps"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PaloAltoNetworks/pango"
	"github.com/PaloAltoNetworks/pango/commit"
	"github.com/PaloAltoNetworks/pango/panorama/devicegroup"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// commitJobBody is the commit-enqueue acknowledgement; it carries the job id,
// not a progress field.
const commitJobBody = `<response status="success" code="19"><result>` +
	`<msg><line>Commit job enqueued with jobid 42</line></msg><job>42</job></result></response>`

// pango's WaitForJob ends its poll loop on progress == 100, not on status FIN
// (pango client.go:906 @ efa4357), so the three job-status bodies below must
// carry progress 100 when finished (jobFinBody, jobFailBody) and stay below it
// while still running (jobRunningBody).
const jobFinBody = `<response status="success"><result><job><id>42</id>` +
	`<status>FIN</status><result>OK</result><progress>100</progress></job></result></response>`

const jobRunningBody = `<response status="success"><result><job><id>42</id>` +
	`<status>ACT</status><result>PEND</result><progress>55</progress></job></result></response>`

const jobFailBody = `<response status="success"><result><job><id>42</id>` +
	`<status>FIN</status><result>FAIL</result><progress>100</progress></job></result></response>`

func commitRoute() fakeRoute {
	return fakeRoute{
		Match: func(v url.Values) bool { return v.Get("type") == "commit" && v.Get("action") == "" },
		Body:  commitJobBody,
	}
}

func jobRoute(body string) fakeRoute {
	return fakeRoute{Match: opContains("<jobs><id>42"), Body: body}
}

func revertRoute() fakeRoute {
	return fakeRoute{
		Match: opContains("running-config.xml"),
		Body:  `<response status="success"><result>ok</result></response>`,
	}
}

// jobEnqueuedBody acknowledges a job enqueue and carries job id 42, shared by
// the validate and push routes.
const jobEnqueuedBody = `<response status="success" code="19"><result>` +
	`<msg><line>job enqueued</line></msg><job>42</job></result></response>`

func pushRoute() fakeRoute {
	return fakeRoute{
		Match: func(v url.Values) bool { return v.Get("type") == "commit" && v.Get("action") == "all" },
		Body:  jobEnqueuedBody,
	}
}

func validateRoute() fakeRoute {
	return fakeRoute{Match: opContains("<validate>"), Body: jobEnqueuedBody}
}

// assertRequestSent fails the test unless some recorded request matches.
func assertRequestSent(t *testing.T, f *fakeAPI, match func(url.Values) bool, msg string) {
	t.Helper()
	if !slices.ContainsFunc(f.Requests(), match) {
		t.Fatal(msg)
	}
}

// assertNoRequestSent fails the test if any recorded request matches.
func assertNoRequestSent(t *testing.T, f *fakeAPI, match func(url.Values) bool, msg string) {
	t.Helper()
	if slices.ContainsFunc(f.Requests(), match) {
		t.Fatal(msg)
	}
}

func TestSystemInfo(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM")
	res, _, err := systemInfoHandler(d)(t.Context(), nil, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", textContent(t, res))
	}
	text := textContent(t, res)
	if !strings.Contains(text, "sw-version") || !strings.Contains(text, "11.0.2") {
		t.Fatalf("missing sw-version: %s", text)
	}
}

// TestSystemInfoError drives the one path where SystemInfo can fail: the info
// was never cached and the retrieval errors. The client is built by hand, not
// via newTestDeps, because newTestDeps always caches the info first.
// Initialize is skipped: it is a no-op when ApiKey is set.
func TestSystemInfoError(t *testing.T) {
	f := &fakeAPI{}
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	c := &pango.Client{Hostname: u.Hostname(), Port: port, Protocol: "http", ApiKey: "test-key"}
	if err := c.Setup(); err != nil {
		t.Fatal(err)
	}
	d := &Deps{Client: c, Logger: slog.New(slog.DiscardHandler)}
	res, _, err := systemInfoHandler(d)(t.Context(), nil, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("system info retrieval failure must surface as IsError")
	}
	if !strings.Contains(textContent(t, res), "failed: panos_system_info") {
		t.Fatalf("tool name lost: %s", textContent(t, res))
	}
}

func TestCommitWaitsForJob(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM", commitRoute(), jobRoute(jobFinBody))
	res, _, err := commitHandler(d)(t.Context(), nil, CommitInput{Description: "test change"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("commit failed: %s", textContent(t, res))
	}
	if !strings.Contains(textContent(t, res), "FIN") {
		t.Fatalf("missing job status: %s", textContent(t, res))
	}
	assertRequestSent(t, f, func(v url.Values) bool {
		return v.Get("type") == "commit" && strings.Contains(v.Get("cmd"), "test change")
	}, "commit request with description not recorded")
}

func TestCommitErrorSurfaces(t *testing.T) {
	errBody := `<response status="error" code="13"><msg><line>There are no changes to commit.</line></msg></response>`
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: func(v url.Values) bool { return v.Get("type") == "commit" }, Body: errBody})
	res, _, _ := commitHandler(d)(t.Context(), nil, CommitInput{})
	if !res.IsError {
		t.Fatal("no-changes commit must surface as IsError")
	}
	if !strings.Contains(textContent(t, res), "no changes") {
		t.Fatalf("PAN-OS message lost: %s", textContent(t, res))
	}
}

// TestCommitActionByPlatform pins the IsPanorama branch by type. A wire-level
// assertion cannot pin it: with only Description set, FirewallCommit and
// PanoramaCommit marshal to identical XML (pango commit/firewall.go:63,
// commit/panorama.go:75 @ efa4357).
func TestCommitActionByPlatform(t *testing.T) {
	pc, ok := commitAction(true, "d1").(commit.PanoramaCommit)
	if !ok {
		t.Fatal("Panorama deps must commit via commit.PanoramaCommit")
	}
	if pc.Description != "d1" {
		t.Fatalf("description lost: %q", pc.Description)
	}
	fc, ok := commitAction(false, "d2").(commit.FirewallCommit)
	if !ok {
		t.Fatal("firewall deps must commit via commit.FirewallCommit")
	}
	if fc.Description != "d2" {
		t.Fatalf("description lost: %q", fc.Description)
	}
}

func TestCommitPanorama(t *testing.T) {
	d, f := newTestDeps(t, "Panorama", commitRoute(), jobRoute(jobFinBody))
	res, _, err := commitHandler(d)(t.Context(), nil, CommitInput{Description: "pano change"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("panorama commit failed: %s", textContent(t, res))
	}
	if !strings.Contains(textContent(t, res), "FIN") {
		t.Fatalf("missing job status: %s", textContent(t, res))
	}
	assertRequestSent(t, f, func(v url.Values) bool {
		return v.Get("type") == "commit" && strings.Contains(v.Get("cmd"), "pano change")
	}, "panorama commit request not recorded")
}

func TestJobStatus(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM", jobRoute(jobFinBody))
	res, _, _ := jobStatusHandler(d)(t.Context(), nil, JobInput{JobID: 42})
	if res.IsError {
		t.Fatalf("job status failed: %s", textContent(t, res))
	}
	if !strings.Contains(textContent(t, res), "FIN") {
		t.Fatalf("missing status: %s", textContent(t, res))
	}
}

func TestJobStatusRequiresID(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM")
	res, _, _ := jobStatusHandler(d)(t.Context(), nil, JobInput{})
	if !res.IsError {
		t.Fatal("job_id 0 must be rejected")
	}
	if !strings.Contains(textContent(t, res), "job_id is required") {
		t.Fatalf("wrong rejection message: %s", textContent(t, res))
	}
	for _, req := range f.Requests() {
		if strings.Contains(req.Get("cmd"), "<jobs>") {
			t.Fatal("no job query may be sent when job_id is missing")
		}
	}
}

func TestJobStatusError(t *testing.T) {
	errBody := `<response status="error"><msg><line>job 99 not found</line></msg></response>`
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: opContains("<jobs><id>99"), Body: errBody})
	res, _, _ := jobStatusHandler(d)(t.Context(), nil, JobInput{JobID: 99})
	if !res.IsError {
		t.Fatal("op error must surface as IsError")
	}
	if !strings.Contains(textContent(t, res), "not found") {
		t.Fatalf("PAN-OS message lost: %s", textContent(t, res))
	}
}

// configListChangesCmd is the exact operational command PAN-OS accepts for
// listing pending candidate changes, as emitted by encoding/xml. The old
// <show><config><diff/></show> command does not exist in the PAN-OS op
// grammar and a real device (verified on 11.2.x) rejects it with "invalid
// client cli" (issue #42). The diff tests route on the exact command, not a
// substring, so any drift back to an unmodelled command hits the fake's
// unmatched-request error, the same way a real device rejects it.
const configListChangesCmd = "<show><config><list><changes></changes></list></config></show>"

func TestConfigDiff(t *testing.T) {
	diffBody := `<response status="success"><result>` +
		`/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='web-1']` +
		`</result></response>`
	d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: opExact(configListChangesCmd), Body: diffBody})
	res, _, _ := configDiffHandler(d)(t.Context(), nil, struct{}{})
	if res.IsError {
		t.Fatalf("diff failed: %s", textContent(t, res))
	}
	if !strings.Contains(textContent(t, res), "web-1") {
		t.Fatalf("diff content lost: %s", textContent(t, res))
	}
	// Assert the exact op command sent, not just that some request matched:
	// this is the check that would have caught "invalid client cli".
	var sent []string
	for _, req := range f.Requests() {
		if req.Get("type") == "op" && strings.Contains(req.Get("cmd"), "<config>") {
			sent = append(sent, req.Get("cmd"))
		}
	}
	if len(sent) != 1 || sent[0] != configListChangesCmd {
		t.Fatalf("handler must send exactly %q, sent %q", configListChangesCmd, sent)
	}
}

func TestConfigDiffEmpty(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: opExact(configListChangesCmd), Body: `<response status="success"><result></result></response>`})
	res, _, _ := configDiffHandler(d)(t.Context(), nil, struct{}{})
	if res.IsError {
		t.Fatalf("empty diff failed: %s", textContent(t, res))
	}
	if !strings.Contains(textContent(t, res), "no pending candidate changes") {
		t.Fatalf("empty diff must say so: %s", textContent(t, res))
	}
}

func TestConfigDiffError(t *testing.T) {
	errBody := `<response status="error"><msg><line>Unauthorized request</line></msg></response>`
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: opExact(configListChangesCmd), Body: errBody})
	res, _, _ := configDiffHandler(d)(t.Context(), nil, struct{}{})
	if !res.IsError {
		t.Fatal("op error must surface as IsError")
	}
	if !strings.Contains(textContent(t, res), "Unauthorized") {
		t.Fatalf("PAN-OS message lost: %s", textContent(t, res))
	}
}

func TestValidate(t *testing.T) {
	valBody := `<response status="success" code="19"><result>` +
		`<msg><line>job enqueued</line></msg><job>42</job></result></response>`
	d, f := newTestDeps(t, "PA-VM",
		fakeRoute{Match: opContains("<validate>"), Body: valBody},
		jobRoute(jobFinBody))
	res, _, _ := validateHandler(d)(t.Context(), nil, struct{}{})
	if res.IsError {
		t.Fatalf("validate failed: %s", textContent(t, res))
	}
	if !strings.Contains(textContent(t, res), "FIN") {
		t.Fatalf("missing job status: %s", textContent(t, res))
	}
	assertRequestSent(t, f, func(v url.Values) bool {
		return v.Get("type") == "op" && strings.Contains(v.Get("cmd"), "<validate>")
	}, "validate request not recorded")
}

func TestValidateError(t *testing.T) {
	errBody := `<response status="error"><msg><line>Validation Error: shared lock held</line></msg></response>`
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: opContains("<validate>"), Body: errBody})
	res, _, _ := validateHandler(d)(t.Context(), nil, struct{}{})
	if !res.IsError {
		t.Fatal("validate enqueue error must surface as IsError")
	}
	if !strings.Contains(textContent(t, res), "shared lock held") {
		t.Fatalf("PAN-OS message lost: %s", textContent(t, res))
	}
}

// TestWaitJobStillRunning drives the bounded-wait branch: the job never
// reaches progress 100, JobWait expires, the parent context is fine, and the
// result is a non-error pointer to panos_job_status. Deterministic: the poll
// interval is clamped to JobWait, so the second poll always starts after the
// deadline; whether the first or the second poll hits the deadline, both land
// in the same wctx branch.
func TestWaitJobStillRunning(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM", jobRoute(jobRunningBody))
	d.JobWait = 50 * time.Millisecond
	res, _ := waitJob(t.Context(), d, "panos_commit", 42)
	if res.IsError {
		t.Fatalf("wait expiry must not be an error: %s", textContent(t, res))
	}
	text := textContent(t, res)
	if !strings.Contains(text, "still running") || !strings.Contains(text, "panos_job_status") || !strings.Contains(text, "42") {
		t.Fatalf("still-running pointer missing: %s", text)
	}
}

func TestWaitJobFailSurfaces(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM", jobRoute(jobFailBody))
	res, _ := waitJob(t.Context(), d, "panos_commit", 42)
	if !res.IsError {
		t.Fatal("a FAIL job result must surface as IsError")
	}
	if !strings.Contains(textContent(t, res), "has failed") {
		t.Fatalf("failure detail lost: %s", textContent(t, res))
	}
}

// TestWaitJobParentDeadline pins the parent-context guard. When the caller's
// own deadline (shorter than JobWait) expires, WaitForJob returns a
// context.DeadlineExceeded exactly as it would for our own budget, so the
// errors.Is check alone cannot tell the two apart; the && ctx.Err() == nil
// operand is what routes a caller-deadline expiry to the error path instead of
// the "still running" pointer. Dropping that operand turns this result into the
// still-running text and reddens this test.
func TestWaitJobParentDeadline(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM", jobRoute(jobRunningBody))
	d.JobWait = 60 * time.Millisecond
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	res, _ := waitJob(ctx, d, "panos_commit", 42)
	if !res.IsError {
		t.Fatalf("a caller-deadline expiry must surface as error, not still-running: %s", textContent(t, res))
	}
}

func TestRevert(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM", revertRoute())
	res, _, err := revertHandler(d)(t.Context(), nil, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("revert failed: %s", textContent(t, res))
	}
	if !strings.Contains(textContent(t, res), "discard") {
		t.Fatalf("device-wide discard caveat missing: %s", textContent(t, res))
	}
	assertRequestSent(t, f, func(v url.Values) bool {
		return strings.Contains(v.Get("cmd"), "running-config.xml")
	}, "revert op request not recorded")
}

func TestRevertError(t *testing.T) {
	errBody := `<response status="error"><msg><line>config for scope shared is currently locked</line></msg></response>`
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: opContains("running-config.xml"), Body: errBody})
	res, _, _ := revertHandler(d)(t.Context(), nil, struct{}{})
	if !res.IsError {
		t.Fatal("revert error must surface as IsError")
	}
	if !strings.Contains(textContent(t, res), "locked") {
		t.Fatalf("PAN-OS message lost: %s", textContent(t, res))
	}
}

// assertHoldsWriteLock proves a handler takes the write lock before touching
// the device: with the lock held the handler must neither finish nor send any
// request. Assertions hold under any scheduling for a correct implementation
// (the test can never flake red); a lock-skipping handler is caught whenever
// the goroutine gets scheduled within the grace sleep.
func assertHoldsWriteLock(t *testing.T, d *Deps, f *fakeAPI, invoke func() (*mcp.CallToolResult, any, error)) {
	t.Helper()
	base := len(f.Requests())
	unlock := d.LockWrites()
	done := make(chan struct{})
	var res *mcp.CallToolResult
	var err error
	go func() {
		defer close(done)
		res, _, err = invoke()
	}()
	// While the lock is held the handler must neither finish nor reach the
	// device. Poll a bounded window instead of sleeping once, so a
	// lock-skipping handler is caught whenever its goroutine is scheduled,
	// even on a loaded runner. A correct handler stays blocked for every tick,
	// so this can never fail for the right implementation (no false RED).
	for range 20 {
		select {
		case <-done:
			t.Fatal("handler completed while the write lock was held")
		default:
		}
		if n := len(f.Requests()); n != base {
			t.Fatalf("handler sent %d request(s) while the write lock was held", n-base)
		}
		time.Sleep(10 * time.Millisecond)
	}
	unlock()
	<-done
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("handler failed after lock release: %s", textContent(t, res))
	}
}

func TestRevertHoldsWriteLock(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM", revertRoute())
	assertHoldsWriteLock(t, d, f, func() (*mcp.CallToolResult, any, error) {
		return revertHandler(d)(t.Context(), nil, struct{}{})
	})
}

func TestCommitHoldsWriteLock(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM", commitRoute(), jobRoute(jobFinBody))
	assertHoldsWriteLock(t, d, f, func() (*mcp.CallToolResult, any, error) {
		return commitHandler(d)(t.Context(), nil, CommitInput{Description: "locked change"})
	})
}

func TestValidateHoldsWriteLock(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM", validateRoute(), jobRoute(jobFinBody))
	assertHoldsWriteLock(t, d, f, func() (*mcp.CallToolResult, any, error) {
		return validateHandler(d)(t.Context(), nil, struct{}{})
	})
}

// zoneListBody lists two zones by name; the list xpath ends at .../zone/entry,
// so the entries bind directly under <result> with no <zone> wrapper.
const zoneListBody = `<response status="success"><result>` +
	`<entry name="trust"></entry><entry name="untrust"></entry></result></response>`

//nolint:gocognit // four independent zone-scoping scenarios (firewall default/custom vsys, Panorama requires/uses template), each assertion-heavy.
func TestZoneListFirewallAndPanorama(t *testing.T) {
	t.Run("firewall vsys scope", func(t *testing.T) {
		d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: zoneListBody})
		res, _, err := zoneListHandler(d)(t.Context(), nil, ZoneListInput{})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("firewall zone list failed: %s", textContent(t, res))
		}
		// "untrust" is the discriminating name; "trust" is also a substring of it.
		if !strings.Contains(textContent(t, res), "untrust") {
			t.Fatalf("missing zone: %s", textContent(t, res))
		}
		// The default vsys must scope the list xpath.
		if joined := strings.Join(getConfigXpaths(f), " "); !strings.Contains(joined, "vsys1") {
			t.Fatalf("firewall zone list must target the vsys xpath, got: %s", joined)
		}
	})

	t.Run("firewall custom vsys", func(t *testing.T) {
		d, f := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: zoneListBody})
		res, _, err := zoneListHandler(d)(t.Context(), nil, ZoneListInput{Vsys: "vsys2"})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("firewall zone list failed: %s", textContent(t, res))
		}
		// The requested vsys, not the default, must scope the xpath.
		if joined := strings.Join(getConfigXpaths(f), " "); !strings.Contains(joined, "vsys2") {
			t.Fatalf("zone list must honor in.Vsys in the xpath, got: %s", joined)
		}
	})

	t.Run("panorama requires template", func(t *testing.T) {
		d, f := newTestDeps(t, "Panorama", fakeRoute{Match: configAction("get"), Body: zoneListBody})
		res, _, err := zoneListHandler(d)(t.Context(), nil, ZoneListInput{})
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError {
			t.Fatal("Panorama zone list without a template must be an error")
		}
		if !strings.Contains(textContent(t, res), "panos_template_list") {
			t.Fatalf("error must point at panos_template_list: %s", textContent(t, res))
		}
		// The template guard must reject before any config get reaches the device.
		if xs := getConfigXpaths(f); len(xs) != 0 {
			t.Fatalf("no config get may be sent without a template, got: %v", xs)
		}
	})

	t.Run("panorama template scope", func(t *testing.T) {
		d, f := newTestDeps(t, "Panorama", fakeRoute{Match: configAction("get"), Body: zoneListBody})
		res, _, err := zoneListHandler(d)(t.Context(), nil, ZoneListInput{Template: "edge-template"})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("Panorama zone list with template failed: %s", textContent(t, res))
		}
		if joined := strings.Join(getConfigXpaths(f), " "); !strings.Contains(joined, "edge-template") {
			t.Fatalf("zone list must target the template xpath, got: %s", joined)
		}
	})
}

// TestZoneListError drives zoneListHandler's svc.List error branch: a PAN-OS
// error on the config get must surface as IsError carrying both the device
// message and the tool name.
func TestZoneListError(t *testing.T) {
	errBody := `<response status="error"><msg><line>Invalid zone query</line></msg></response>`
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: errBody})
	res, _, _ := zoneListHandler(d)(t.Context(), nil, ZoneListInput{})
	if !res.IsError {
		t.Fatal("zone list error must surface as IsError")
	}
	if body := textContent(t, res); !strings.Contains(body, "Invalid zone query") || !strings.Contains(body, "failed: panos_zone_list") {
		t.Fatalf("error must carry the PAN-OS line and the tool name: %s", body)
	}
}

func TestPushRequiresPanorama(t *testing.T) {
	d, f := newTestDeps(t, "PA-VM")
	res, _, err := pushHandler(d)(t.Context(), nil, PushInput{DeviceGroup: "dg1"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("push on a firewall must be an error")
	}
	if !strings.Contains(textContent(t, res), "requires a Panorama connection") {
		t.Fatalf("wrong rejection: %s", textContent(t, res))
	}
	assertNoRequestSent(t, f, func(v url.Values) bool { return v.Get("type") == "commit" },
		"no commit-all may be sent on a firewall")
}

func TestPushRequiresDeviceGroup(t *testing.T) {
	d, f := newTestDeps(t, "Panorama")
	res, _, err := pushHandler(d)(t.Context(), nil, PushInput{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("push without a device group must be an error")
	}
	if !strings.Contains(textContent(t, res), "device_group is required") {
		t.Fatalf("wrong rejection: %s", textContent(t, res))
	}
	assertNoRequestSent(t, f, func(v url.Values) bool { return v.Get("type") == "commit" },
		"no commit-all may be sent without a device group")
}

func TestPushCommitAll(t *testing.T) {
	d, f := newTestDeps(t, "Panorama", pushRoute(), jobRoute(jobFinBody))
	res, _, err := pushHandler(d)(t.Context(), nil, PushInput{DeviceGroup: "dg1", Description: "push it"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("push failed: %s", textContent(t, res))
	}
	if !strings.Contains(textContent(t, res), "FIN") {
		t.Fatalf("missing job status: %s", textContent(t, res))
	}
	assertRequestSent(t, f, func(v url.Values) bool {
		return v.Get("type") == "commit" && v.Get("action") == "all" && strings.Contains(v.Get("cmd"), "dg1")
	}, "commit-all request for the device group not recorded")
}

// TestPushErrorSurfaces drives pushHandler's StartJob error branch: a PAN-OS
// error on the commit-all enqueue must surface as IsError carrying both the
// device message and the tool name.
func TestPushErrorSurfaces(t *testing.T) {
	errBody := `<response status="error" code="13"><msg><line>commit-all rejected: device offline</line></msg></response>`
	d, _ := newTestDeps(t, "Panorama",
		fakeRoute{Match: func(v url.Values) bool { return v.Get("type") == "commit" && v.Get("action") == "all" }, Body: errBody})
	res, _, _ := pushHandler(d)(t.Context(), nil, PushInput{DeviceGroup: "dg1"})
	if !res.IsError {
		t.Fatal("a rejected commit-all must surface as IsError")
	}
	if body := textContent(t, res); !strings.Contains(body, "device offline") || !strings.Contains(body, "failed: panos_push") {
		t.Fatalf("error must carry the PAN-OS line and the tool name: %s", body)
	}
}

func TestPushHoldsWriteLock(t *testing.T) {
	d, f := newTestDeps(t, "Panorama", pushRoute(), jobRoute(jobFinBody))
	assertHoldsWriteLock(t, d, f, func() (*mcp.CallToolResult, any, error) {
		return pushHandler(d)(t.Context(), nil, PushInput{DeviceGroup: "dg1"})
	})
}

// deviceGroupListBody carries a device group with a description and a
// reference-templates member; pango unmarshals <reference-templates><member>
// into devicegroup.Entry.Templates.
const deviceGroupListBody = `<response status="success"><result>` +
	`<entry name="dg1"><description>border</description>` +
	`<reference-templates><member>edge-template</member></reference-templates></entry>` +
	`</result></response>`

func TestDeviceGroupList(t *testing.T) {
	d, _ := newTestDeps(t, "Panorama", fakeRoute{Match: configAction("get"), Body: deviceGroupListBody})
	res, _, err := deviceGroupListHandler(d)(t.Context(), nil, PanoramaListInput{})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("device group list failed: %s", textContent(t, res))
	}
	body := textContent(t, res)
	if !strings.Contains(body, "dg1") || !strings.Contains(body, "border") || !strings.Contains(body, "edge-template") {
		t.Fatalf("summary missing name, description or templates: %s", body)
	}

	// A case-insensitive filter that matches the entry name keeps it.
	res, _, err = deviceGroupListHandler(d)(t.Context(), nil, PanoramaListInput{Filter: "DG"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("filtered device group list failed: %s", textContent(t, res))
	}
	if body := textContent(t, res); !strings.Contains(body, `"total": 1`) || !strings.Contains(body, "dg1") {
		t.Fatalf("matching filter must return the entry: %s", body)
	}

	// A non-matching filter returns nothing.
	res, _, err = deviceGroupListHandler(d)(t.Context(), nil, PanoramaListInput{Filter: "zzz"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("filtered device group list failed: %s", textContent(t, res))
	}
	if body := textContent(t, res); !strings.Contains(body, `"total": 0`) {
		t.Fatalf("non-matching filter must return no entries: %s", body)
	}

	// PanoramaListInput carries no location, so the tool schema cannot advertise
	// one; panoramaFixedResolve still rejects a non-empty location for direct Go
	// callers, which keeps that guard covered after the schema change.
	if _, err := panoramaFixedResolve("panos_device_group_list",
		devicegroup.Location{Panorama: &devicegroup.PanoramaLocation{PanoramaDevice: defaultPanoramaDevice}})(LocationInput{Vsys: "vsys1"}); err == nil || !strings.Contains(err.Error(), "location does not apply") {
		t.Fatalf("panoramaFixedResolve must reject a non-empty location, got %v", err)
	}
}

// templateListBody carries one template with a description.
const templateListBody = `<response status="success"><result>` +
	`<entry name="edge-template"><description>edge sites</description></entry>` +
	`</result></response>`

func TestTemplateList(t *testing.T) {
	d, _ := newTestDeps(t, "Panorama", fakeRoute{Match: configAction("get"), Body: templateListBody})
	res, _, err := templateListHandler(d)(t.Context(), nil, PanoramaListInput{})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("template list failed: %s", textContent(t, res))
	}
	body := textContent(t, res)
	if !strings.Contains(body, "edge-template") || !strings.Contains(body, "edge sites") {
		t.Fatalf("summary missing name or description: %s", body)
	}

	// A case-insensitive filter that matches the entry name keeps it.
	res, _, err = templateListHandler(d)(t.Context(), nil, PanoramaListInput{Filter: "EDGE"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("filtered template list failed: %s", textContent(t, res))
	}
	if body := textContent(t, res); !strings.Contains(body, `"total": 1`) || !strings.Contains(body, "edge-template") {
		t.Fatalf("matching filter must return the entry: %s", body)
	}

	// A non-matching filter returns nothing.
	res, _, err = templateListHandler(d)(t.Context(), nil, PanoramaListInput{Filter: "zzz"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("filtered template list failed: %s", textContent(t, res))
	}
	if body := textContent(t, res); !strings.Contains(body, `"total": 0`) {
		t.Fatalf("non-matching filter must return no entries: %s", body)
	}
}

//nolint:gocognit // three independent registration-gate scenarios (firewall write, panorama read-only, panorama write), each a simple present/absent tool-name sweep.
func TestRegisterDeviceToolsGates(t *testing.T) {
	t.Run("firewall write mode", func(t *testing.T) {
		d, _ := newTestDeps(t, "PA-VM")
		s := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
		RegisterDeviceTools(s, d)
		names := serverToolNames(t, s)
		for _, n := range []string{
			"panos_system_info", "panos_job_status", "panos_config_diff", "panos_zone_list",
			"panos_commit", "panos_validate", "panos_revert",
		} {
			if !names[n] {
				t.Errorf("firewall write: %q must be registered", n)
			}
		}
		for _, n := range []string{"panos_device_group_list", "panos_template_list", "panos_push"} {
			if names[n] {
				t.Errorf("firewall write: %q must NOT be registered", n)
			}
		}
	})

	t.Run("panorama read-only mode", func(t *testing.T) {
		d, _ := newTestDeps(t, "Panorama")
		d.ReadOnly = true
		s := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
		RegisterDeviceTools(s, d)
		names := serverToolNames(t, s)
		for _, n := range []string{"panos_device_group_list", "panos_template_list", "panos_zone_list"} {
			if !names[n] {
				t.Errorf("panorama read-only: %q must be registered", n)
			}
		}
		for _, n := range []string{"panos_commit", "panos_validate", "panos_revert", "panos_push"} {
			if names[n] {
				t.Errorf("panorama read-only: %q must NOT be registered", n)
			}
		}
	})

	t.Run("panorama write mode", func(t *testing.T) {
		d, _ := newTestDeps(t, "Panorama")
		d.ReadOnly = false
		s := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
		RegisterDeviceTools(s, d)
		names := serverToolNames(t, s)
		for _, n := range []string{
			"panos_commit", "panos_validate", "panos_revert", "panos_push",
			"panos_device_group_list", "panos_template_list",
		} {
			if !names[n] {
				t.Errorf("panorama write: %q must be registered", n)
			}
		}
	})
}

// TestPanoramaListSchemasOmitLocation pins that the two Panorama list tools take
// PanoramaListInput, not ListInput: their advertised input schema must expose
// exactly the PanoramaListInput property set (filter, limit, offset) and no
// location parameter, since panoramaFixedResolve always rejects a non-empty
// location. Asserting the exact key set (not a substring) makes a revert to
// ListInput fail, because ListInput adds a "location" property.
func TestPanoramaListSchemasOmitLocation(t *testing.T) {
	ctx := t.Context()
	d, _ := newTestDeps(t, "Panorama")
	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	RegisterDeviceTools(srv, d)

	cs := connectInMemory(t, srv)

	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Index each tool's marshaled input schema by name so the two Panorama list
	// tools can be inspected directly.
	schemas := make(map[string][]byte, len(res.Tools))
	for _, tl := range res.Tools {
		b, err := json.Marshal(tl.InputSchema)
		if err != nil {
			t.Fatalf("marshal %s input schema: %v", tl.Name, err)
		}
		schemas[tl.Name] = b
	}
	// PanoramaListInput advertises exactly these property keys.
	want := []string{"filter", "limit", "offset"}
	for _, n := range []string{"panos_device_group_list", "panos_template_list"} {
		b, ok := schemas[n]
		if !ok {
			t.Fatalf("%s not registered on a Panorama server", n)
		}
		var schema struct {
			Properties map[string]json.RawMessage `json:"properties"`
		}
		if err := json.Unmarshal(b, &schema); err != nil {
			t.Fatalf("unmarshal %s input schema: %v", n, err)
		}
		got := slices.Sorted(maps.Keys(schema.Properties))
		if !slices.Equal(got, want) {
			t.Fatalf("%s schema properties = %v, want exactly %v", n, got, want)
		}
	}
}
