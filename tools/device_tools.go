package tools

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/PaloAltoNetworks/pango/commit"
	"github.com/PaloAltoNetworks/pango/network/zone"
	"github.com/PaloAltoNetworks/pango/panorama/devicegroup"
	"github.com/PaloAltoNetworks/pango/panorama/template"
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
		// SystemInfo returns the map cached by run()'s startup RetrieveSystemInfo;
		// the read lock keeps it ordered against writers (issue #14). It never
		// re-fetches here (systemInfo is non-nil post-startup), so RLock, not Lock.
		defer d.RLockReads()()
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
		defer d.RLockReads()()
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
		// Hold the read lock so the diff observes a stable candidate config and
		// never a half-applied one while a commit or edit holds the write lock
		// (issue #14).
		defer d.RLockReads()()
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
// starts a device-side job that takes the same config locks a commit does, so
// it serializes behind the other mutations via LockWrites even though it does
// not itself change the candidate config: a validate racing a commit, revert
// or push would contend for the device-side config lock, and its result would
// describe a moving target. The tool is registered only in write mode, so no
// read path pays for the lock (issue #30 item 3, settled in Task 12).
func validateHandler(d *Deps) func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		defer d.LockWrites()()
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

// ZoneListInput is the input for panos_zone_list. Zone locations differ from
// the object tools' LocationInput: a firewall scopes zones by vsys and
// Panorama scopes them by template, so this input replaces LocationInput.
type ZoneListInput struct {
	Vsys     string `json:"vsys,omitempty" jsonschema:"Firewall vsys (default vsys1); firewall only, ignored on Panorama"`
	Template string `json:"template,omitempty" jsonschema:"Template name; required on Panorama (see panos_template_list)"`
	Limit    int    `json:"limit,omitempty" jsonschema:"Max results (default 50, max 200)"`
	Offset   int    `json:"offset,omitempty" jsonschema:"Skip this many results"`
	Filter   string `json:"filter,omitempty" jsonschema:"Case-insensitive name substring filter"`
}

// PanoramaListInput is ListInput without a location: device groups and
// templates each live at exactly one Panorama-level location, so exposing a
// location parameter would advertise an argument panoramaFixedResolve always
// rejects.
type PanoramaListInput struct {
	Limit  int    `json:"limit,omitempty" jsonschema:"Max results (default 50, max 200)"`
	Offset int    `json:"offset,omitempty" jsonschema:"Skip this many results"`
	Filter string `json:"filter,omitempty" jsonschema:"Case-insensitive name substring filter"`
}

// zoneListHandler lists zones: vsys scope on a firewall, template scope on
// Panorama. Read-only; zone writes are out of scope.
func zoneListHandler(d *Deps) func(context.Context, *mcp.CallToolRequest, ZoneListInput) (*mcp.CallToolResult, any, error) {
	svc := zone.NewService(d.Client)
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ZoneListInput) (*mcp.CallToolResult, any, error) {
		defer d.RLockReads()()
		var loc zone.Location
		if d.IsPanorama {
			if in.Template == "" {
				res, v := errorResult("panos_zone_list: template is required on Panorama; list templates with panos_template_list")
				return res, v, nil
			}
			loc = zone.Location{Template: &zone.TemplateLocation{
				PanoramaDevice: defaultPanoramaDevice, NgfwDevice: defaultNgfwDevice,
				Template: in.Template, Vsys: defaultVsys,
			}}
		} else {
			vsys := in.Vsys
			if vsys == "" {
				vsys = defaultVsys
			}
			loc = zone.Location{Vsys: &zone.VsysLocation{NgfwDevice: defaultNgfwDevice, Vsys: vsys}}
		}
		entries, err := svc.List(ctx, loc, "get", "", "")
		if err != nil {
			d.Logger.Error("failed: panos_zone_list", "error", err)
			res, v := errorResult("failed: panos_zone_list: %v", err)
			return res, v, nil
		}
		names := make([]string, 0, len(entries))
		needle := strings.ToLower(in.Filter)
		for _, e := range entries {
			if in.Filter == "" || strings.Contains(strings.ToLower(e.Name), needle) {
				names = append(names, e.Name)
			}
		}
		total := len(names)
		lo, hi := clampList(in.Limit, in.Offset, total)
		res, v := jsonResult(map[string]any{"total": total, "offset": lo, "count": hi - lo, "zones": names[lo:hi]})
		return res, v, nil
	}
}

// PushInput is the input for panos_push.
type PushInput struct {
	DeviceGroup      string `json:"device_group" jsonschema:"Device group to push to (see panos_device_group_list)"`
	Description      string `json:"description,omitempty" jsonschema:"Push description shown in the device commit history"`
	IncludeTemplates bool   `json:"include_templates,omitempty" jsonschema:"Also push associated template config"`
}

// pushHandler runs a Panorama commit-all to one device group. It does NOT
// commit to Panorama first; panos_commit must have run beforehand.
func pushHandler(d *Deps) func(context.Context, *mcp.CallToolRequest, PushInput) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in PushInput) (*mcp.CallToolResult, any, error) {
		if !d.IsPanorama {
			res, v := errorResult("panos_push requires a Panorama connection")
			return res, v, nil
		}
		if in.DeviceGroup == "" {
			res, v := errorResult("panos_push: device_group is required")
			return res, v, nil
		}
		defer d.LockWrites()()
		cmd := &xmlapi.Commit{Command: commit.PanoramaCommitAll{
			Type: commit.TypeDeviceGroup, Name: in.DeviceGroup,
			Description: in.Description, IncludeTemplate: in.IncludeTemplates,
		}}
		id, _, _, err := d.Client.StartJob(ctx, cmd) //nolint:bodyclose // pango already closed the body (client.go:1230)
		if err != nil {
			d.Logger.Error("failed: panos_push", "error", err)
			res, v := errorResult("failed: panos_push: %v", err)
			return res, v, nil
		}
		d.Logger.Info("panos_push job started", "job", id, "device_group", in.DeviceGroup)
		res, v := waitJob(ctx, d, "panos_push", id)
		return res, v, nil
	}
}

// panoramaFixedResolve adapts a fixed Panorama-level location to listHandler's
// resolve signature. Device groups and templates live at exactly one place in
// the config, so any location scoping in the input is a caller error and is
// rejected rather than silently ignored.
func panoramaFixedResolve[L any](tool string, loc L) func(LocationInput) (L, error) {
	return func(in LocationInput) (L, error) {
		if in != (LocationInput{}) {
			var zero L
			return zero, fmt.Errorf("%s lists Panorama-level config; location does not apply", tool)
		}
		return loc, nil
	}
}

// deviceGroupSummary reduces a device group entry to the list view fields.
func deviceGroupSummary(e *devicegroup.Entry) any {
	m := nameDescription(e.Name, e.Description)
	m["templates"] = e.Templates
	return m
}

// deviceGroupListHandler lists Panorama device groups via the shared
// listHandler at the fixed Panorama location. The public handler takes
// PanoramaListInput (no location) so the tool schema does not advertise a
// location parameter panoramaFixedResolve always rejects; the inner listHandler
// still resolves through panoramaFixedResolve, which supplies the fixed
// Panorama location.
func deviceGroupListHandler(d *Deps) func(context.Context, *mcp.CallToolRequest, PanoramaListInput) (*mcp.CallToolResult, any, error) {
	inner := listHandler[devicegroup.Location, devicegroup.Entry](
		d, "panos_device_group_list", devicegroup.NewService(d.Client),
		panoramaFixedResolve("panos_device_group_list",
			devicegroup.Location{Panorama: &devicegroup.PanoramaLocation{PanoramaDevice: defaultPanoramaDevice}}),
		func(e *devicegroup.Entry) string { return e.Name }, deviceGroupSummary)
	return func(ctx context.Context, req *mcp.CallToolRequest, in PanoramaListInput) (*mcp.CallToolResult, any, error) {
		return inner(ctx, req, ListInput{Limit: in.Limit, Offset: in.Offset, Filter: in.Filter})
	}
}

// templateSummary reduces a template entry to the list view fields.
func templateSummary(e *template.Entry) any {
	return nameDescription(e.Name, e.Description)
}

// templateListHandler lists Panorama templates (zone discovery for
// panos_zone_list) via the shared listHandler at the fixed Panorama location.
// The public handler takes PanoramaListInput (no location) so the tool schema
// does not advertise a location parameter panoramaFixedResolve always rejects;
// the inner listHandler still resolves through panoramaFixedResolve, which
// supplies the fixed Panorama location.
func templateListHandler(d *Deps) func(context.Context, *mcp.CallToolRequest, PanoramaListInput) (*mcp.CallToolResult, any, error) {
	inner := listHandler[template.Location, template.Entry](
		d, "panos_template_list", template.NewService(d.Client),
		panoramaFixedResolve("panos_template_list",
			template.Location{Panorama: &template.PanoramaLocation{PanoramaDevice: defaultPanoramaDevice}}),
		func(e *template.Entry) string { return e.Name }, templateSummary)
	return func(ctx context.Context, req *mcp.CallToolRequest, in PanoramaListInput) (*mcp.CallToolResult, any, error) {
		return inner(ctx, req, ListInput{Limit: in.Limit, Offset: in.Offset, Filter: in.Filter})
	}
}

// RegisterDeviceTools registers device ops tools, gating Panorama-only
// tools on the connected device type and write tools on read-only mode.
func RegisterDeviceTools(s *mcp.Server, d *Deps) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_system_info",
		Description: "Show device system info (model, serial, versions). Also the connection test. Read-only.",
		Annotations: readOnlyTool("System info"),
	}, systemInfoHandler(d))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_job_status",
		Description: "Poll a device job (commit, push, validate) by ID. Read-only.",
		Annotations: readOnlyTool("Job status"),
	}, jobStatusHandler(d))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_config_diff",
		Description: "Show pending candidate changes versus the running config. Check before panos_commit; other admins' changes commit too. Read-only.",
		Annotations: readOnlyTool("Config diff"),
	}, configDiffHandler(d))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_zone_list",
		Description: "List security zone names for use in rules. On Panorama requires template (see panos_template_list). Read-only.",
		Annotations: readOnlyTool("List zones"),
	}, zoneListHandler(d))
	if d.IsPanorama {
		mcp.AddTool(s, &mcp.Tool{
			Name:        "panos_device_group_list",
			Description: "List Panorama device groups. Read-only.",
			Annotations: readOnlyTool("List device groups"),
		}, deviceGroupListHandler(d))
		mcp.AddTool(s, &mcp.Tool{
			Name:        "panos_template_list",
			Description: "List Panorama templates (zone and network config scopes). Read-only.",
			Annotations: readOnlyTool("List templates"),
		}, templateListHandler(d))
	}
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_commit",
		Description: "Commit the candidate config to the running config. Waits up to the configured window, then returns the job ID for panos_job_status. On Panorama this commits to Panorama itself; push to firewalls afterwards with panos_push.",
		Annotations: updateTool("Commit"),
	}, commitHandler(d))
	// validate does not modify config, so it carries ReadOnlyHint; it is still
	// registered only in write mode and holds the write lock because it starts a
	// device job that contends for the config lock (see validateHandler).
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_validate",
		Description: "Validate the candidate config without committing. Returns the validation job result.",
		Annotations: readOnlyTool("Validate config"),
	}, validateHandler(d))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_revert",
		Description: "Revert the candidate config to the running config. DESTRUCTIVE: discards ALL pending changes device-wide, including other admins' work. Check panos_config_diff first.",
		Annotations: deleteTool("Revert candidate"),
	}, revertHandler(d))
	if d.IsPanorama {
		mcp.AddTool(s, &mcp.Tool{
			Name:        "panos_push",
			Description: "Push committed config to a device group's firewalls (commit-all). Does NOT commit first: run panos_commit before this.",
			Annotations: updateTool("Push to device group"),
		}, pushHandler(d))
	}
}
