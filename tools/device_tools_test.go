package tools

import (
	"context"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PaloAltoNetworks/pango"
	"github.com/PaloAltoNetworks/pango/commit"
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

// assertRequestSent fails the test unless some recorded request matches.
func assertRequestSent(t *testing.T, f *fakeAPI, match func(url.Values) bool, msg string) {
	t.Helper()
	if !slices.ContainsFunc(f.Requests(), match) {
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

func TestConfigDiff(t *testing.T) {
	diffBody := `<response status="success"><result>+ address entry web-1 added</result></response>`
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: opContains("<diff"), Body: diffBody})
	res, _, _ := configDiffHandler(d)(t.Context(), nil, struct{}{})
	if res.IsError {
		t.Fatalf("diff failed: %s", textContent(t, res))
	}
	if !strings.Contains(textContent(t, res), "web-1") {
		t.Fatalf("diff content lost: %s", textContent(t, res))
	}
}

func TestConfigDiffEmpty(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: opContains("<diff"), Body: `<response status="success"><result></result></response>`})
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
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: opContains("<diff"), Body: errBody})
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
