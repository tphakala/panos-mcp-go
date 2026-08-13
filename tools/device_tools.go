package tools

import (
	"context"
	"encoding/xml"
	"errors"
	"time"

	"github.com/PaloAltoNetworks/pango/commit"
	"github.com/PaloAltoNetworks/pango/util"
	"github.com/PaloAltoNetworks/pango/xmlapi"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// jobPollInterval is the sleep between job status polls while waiting for a
// commit or validate job.
const jobPollInterval = 2 * time.Second

// CommitInput is the input for panos_commit.
type CommitInput struct {
	Description string `json:"description,omitempty" jsonschema:"Commit description shown in the device commit history"`
}

// JobInput is the input for panos_job_status.
type JobInput struct {
	JobID uint `json:"job_id" jsonschema:"Job ID returned by panos_commit, panos_push or panos_validate"`
}

// systemInfoHandler returns the device system info map.
func systemInfoHandler(d *Deps) func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		info, err := d.Client.SystemInfo(ctx)
		if err != nil {
			d.Logger.Error("failed: panos_system_info", "error", err)
			res, v := errorResult("failed: panos_system_info: %v", err)
			return res, v, nil
		}
		res, v := jsonResult(info)
		return res, v, nil
	}
}

// jobSummary is the JSON shape shared by waitJob and panos_job_status. The
// "job_id" key mirrors the panos_job_status input field so a client sees the
// same name on the way in and out.
func jobSummary(id uint, job *util.BasicJob) map[string]any {
	return map[string]any{
		"job_id": id, "status": job.Status, "result": job.Result,
		"progress": job.ProgressRaw, "details": job.Details.String(),
	}
}

// waitJob polls a job up to JobWait and formats the outcome. A wait that runs
// out is not an error: the result names the job for panos_job_status. It tells
// "our JobWait budget expired" apart from every other WaitForJob failure by
// inspecting the returned error, not the post-hoc state of wctx: only a
// context.DeadlineExceeded raised by wctx means we timed out. Testing
// wctx.Err() instead would misreport a job FAIL or a network error that landed
// in the same instant the deadline fired as "still running" (pango returns the
// job-FAIL error as a plain fmt.Errorf, client.go:920-925 @ efa4357, and the
// per-poll context error straight from Communicate, client.go:884). The
// parent-ctx guard keeps a caller whose own deadline or cancellation ended the
// wait on the error path. The poll interval is clamped to JobWait because
// pango's WaitForJob sleeps between polls without watching the context (pango
// client.go:915-916 @ efa4357); an unclamped interval would overshoot a
// shorter JobWait budget by up to a full interval.
func waitJob(ctx context.Context, d *Deps, tool string, id uint) (res *mcp.CallToolResult, anyVal any) {
	wctx, cancel := context.WithTimeout(ctx, d.JobWait)
	defer cancel()
	var job util.BasicJob
	if err := d.Client.WaitForJob(wctx, id, min(jobPollInterval, d.JobWait), &job); err != nil {
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			return textResult("%s: job %d still running after %s; poll with panos_job_status", tool, id, d.JobWait)
		}
		d.Logger.Error("failed: "+tool, "job", id, "error", err)
		return errorResult("failed: %s: job %d: %v", tool, id, err)
	}
	d.Logger.Info(tool+" job finished", "job", id, "result", job.Result)
	return jsonResult(jobSummary(id, &job))
}

// commitAction picks the platform-specific commit action. Only Description is
// exposed; pushing committed config to managed devices is Task 12's
// panos_push, not this commit.
func commitAction(isPanorama bool, description string) xmlapi.CommitAction {
	if isPanorama {
		return commit.PanoramaCommit{Description: description}
	}
	return commit.FirewallCommit{Description: description}
}

// commitHandler commits the candidate config and waits (bounded) for the job.
func commitHandler(d *Deps) func(context.Context, *mcp.CallToolRequest, CommitInput) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in CommitInput) (*mcp.CallToolResult, any, error) {
		defer d.LockWrites()()
		// pango's sendRequest drains and closes the response body before it
		// returns (pango client.go:1230 @ efa4357), and StartJob hands that same
		// response back, so its Body is already closed: nothing here to close.
		id, _, _, err := d.Client.StartJob(ctx, &xmlapi.Commit{Command: commitAction(d.IsPanorama, in.Description)}) //nolint:bodyclose // pango already closed the body (client.go:1230)
		if err != nil {
			d.Logger.Error("failed: panos_commit", "error", err)
			res, v := errorResult("failed: panos_commit: %v", err)
			return res, v, nil
		}
		d.Logger.Info("panos_commit job started", "job", id)
		res, v := waitJob(ctx, d, "panos_commit", id)
		return res, v, nil
	}
}

// jobStatusHandler polls one job by id without waiting.
func jobStatusHandler(d *Deps) func(context.Context, *mcp.CallToolRequest, JobInput) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in JobInput) (*mcp.CallToolResult, any, error) {
		if in.JobID == 0 {
			res, v := errorResult("panos_job_status: job_id is required")
			return res, v, nil
		}
		type jobsReq struct {
			XMLName xml.Name `xml:"show"`
			ID      uint     `xml:"jobs>id"`
		}
		var job util.BasicJob
		cmd := &xmlapi.Op{Command: jobsReq{ID: in.JobID}}
		//nolint:bodyclose // pango's sendRequest already drained and closed the response body (client.go:1230 @ efa4357).
		if _, _, err := d.Client.Communicate(ctx, cmd, false, &job); err != nil {
			d.Logger.Error("failed: panos_job_status", "error", err)
			res, v := errorResult("failed: panos_job_status: %v", err)
			return res, v, nil
		}
		res, v := jsonResult(jobSummary(in.JobID, &job))
		return res, v, nil
	}
}

// configDiffHandler shows candidate changes versus the running config.
func configDiffHandler(d *Deps) func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		type diffReq struct {
			XMLName xml.Name `xml:"show"`
			Cmd     string   `xml:"config>diff"`
		}
		var resp struct {
			Result string `xml:"result"`
		}
		cmd := &xmlapi.Op{Command: diffReq{}}
		//nolint:bodyclose // pango's sendRequest already drained and closed the response body (client.go:1230 @ efa4357).
		if _, _, err := d.Client.Communicate(ctx, cmd, false, &resp); err != nil {
			d.Logger.Error("failed: panos_config_diff", "error", err)
			res, v := errorResult("failed: panos_config_diff: %v", err)
			return res, v, nil
		}
		if resp.Result == "" {
			res, v := textResult("no pending candidate changes")
			return res, v, nil
		}
		res, v := textResult("%s", resp.Result)
		return res, v, nil
	}
}

// validateHandler validates the candidate config without committing. Validate
// runs a device job but does not mutate the candidate config, so for locking it
// is treated as a read: it deliberately does not take the write lock and is not
// one of the serialized mutations (commit, revert). See the writeMu doc in
// tools.go. Whether it should still serialize behind writes to avoid
// device-side config-lock contention is a registration-time design question
// (Task 12), left unlocked per the approved design.
func validateHandler(d *Deps) func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		// ValidateConfig only enqueues the job; its sleep param is unused by
		// pango (client.go:782 @ efa4357). The real wait happens in waitJob.
		id, err := d.Client.ValidateConfig(ctx, jobPollInterval)
		if err != nil {
			d.Logger.Error("failed: panos_validate", "error", err)
			res, v := errorResult("failed: panos_validate: %v", err)
			return res, v, nil
		}
		res, v := waitJob(ctx, d, "panos_validate", id)
		return res, v, nil
	}
}

// revertHandler reverts the whole candidate config to the running config.
func revertHandler(d *Deps) func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		defer d.LockWrites()()
		if err := d.Client.RevertToRunningConfig(ctx, ""); err != nil {
			d.Logger.Error("failed: panos_revert", "error", err)
			res, v := errorResult("failed: panos_revert: %v", err)
			return res, v, nil
		}
		res, v := successResult(d.Logger, "panos_revert", "candidate config reverted to running config (device-wide, all pending changes discarded)")
		return res, v, nil
	}
}
