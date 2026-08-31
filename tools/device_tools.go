package tools

import (
	"cmp"
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
		if res, v, ok := communicateOp(ctx, d, "panos_job_status", cmd, &job); !ok {
			return res, v, nil
		}
		res, v := jsonResult(jobSummary(in.JobID, &job))
		return res, v, nil
	}
}

// configDiffHandler lists pending candidate-config changes versus the running
// config via "show config list changes", which returns a change journal: one
// entry per touched xpath with the action taken and the change owner. The
// "show config diff" path this tool emitted before is rejected by the PAN-OS
// XML API as "invalid client cli" (issue #42, verified live against 11.2.6).
func configDiffHandler(d *Deps) func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		// Hold the read lock so the listing observes a stable candidate config and
		// never a half-applied one while a commit or edit holds the write lock
		// (issue #14).
		defer d.RLockReads()()
		type listChangesReq struct {
			XMLName xml.Name `xml:"show"`
			Cmd     string   `xml:"config>list>changes"`
		}
		// Communicate runs with strip=false, so pango unmarshals the whole
		// <response> envelope; the tags are rooted there. The changed nodes arrive
		// as a journal of <entry> elements under <result>, not as chardata (the
		// journal shape was captured live against 11.2.6). Inner keeps the raw
		// contents of <result> so a success response that does not match the journal
		// path is surfaced rather than mistaken for an empty candidate: a false
		// "nothing pending" on this pre-commit/pre-revert check could lead to a
		// destructive commit or revert of a candidate that was not actually clean.
		type change struct {
			XPath  string `xml:"xpath"`
			Action string `xml:"action"`
			Owner  string `xml:"owner"`
		}
		var resp struct {
			XMLName xml.Name `xml:"response"`
			Result  struct {
				Changes []change `xml:"journal>entry"`
				Inner   string   `xml:",innerxml"`
			} `xml:"result"`
		}
		cmd := &xmlapi.Op{Command: listChangesReq{}}
		if res, v, ok := communicateOp(ctx, d, "panos_config_diff", cmd, &resp); !ok {
			return res, v, nil
		}
		changes := resp.Result.Changes
		if len(changes) == 0 {
			// Success, but not the journal shape this parser expects. Surface the
			// raw result rather than claiming the candidate is clean.
			if res, v, ok := rawResultFallback("panos_config_diff", resp.Result.Inner); ok {
				return res, v, nil
			}
			res, v := textResult("no pending candidate changes")
			return res, v, nil
		}
		// A human/LLM-readable summary, not jsonResult: this is a pre-commit review
		// aid, and a compact list of changed paths is more token-efficient than a
		// nested JSON array (jsonResult is for tools with programmatic fields to
		// query, like panos_job_status).
		var b strings.Builder
		fmt.Fprintf(&b, "%d pending candidate change(s):", len(changes))
		for _, c := range changes {
			b.WriteString("\n- ")
			// PAN-OS pads the action with a leading space (" EDIT", " DELETE").
			if action := strings.TrimSpace(c.Action); action != "" {
				b.WriteString(action)
				b.WriteByte(' ')
			}
			b.WriteString(c.XPath)
			if owner := strings.TrimSpace(c.Owner); owner != "" {
				fmt.Fprintf(&b, " (by %s)", owner)
			}
		}
		res, v := textResult("%s", b.String())
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
	Vsys     string `json:"vsys,omitempty" jsonschema:"Firewall vsys (default vsys1); firewall only, rejected on Panorama"`
	Template string `json:"template,omitempty" jsonschema:"Template name; required on Panorama, rejected on a firewall (see panos_template_list)"`
	Limit    int    `json:"limit,omitempty" jsonschema:"Max results (default 50, max 200)"`
	Offset   int    `json:"offset,omitempty" jsonschema:"Skip this many results"`
	Filter   string `json:"filter,omitempty" jsonschema:"Case-insensitive name substring filter"`
}

// resolveZoneLocation maps flat vsys/template inputs onto a pango zone location:
// vsys scope on a firewall (default vsys1), template scope on Panorama (template
// required, its vsys pinned to vsys1). Unlike the object LocationInput, a zone
// has no shared or device-group location. A location selector for the wrong
// device type is rejected rather than silently ignored: on a write path a
// silently-ignored selector risks mutating the wrong node, and list follows the
// same rule for consistency.
func resolveZoneLocation(d *Deps, vsys, tmpl string) (zone.Location, error) {
	if d.IsPanorama {
		if vsys != "" {
			return zone.Location{}, errors.New("vsys applies to a firewall; on Panorama zones live in a template at vsys1")
		}
		if tmpl == "" {
			return zone.Location{}, errors.New("template is required on Panorama; list templates with panos_template_list")
		}
		return zone.Location{Template: &zone.TemplateLocation{
			PanoramaDevice: defaultPanoramaDevice, NgfwDevice: defaultNgfwDevice,
			Template: tmpl, Vsys: defaultVsys,
		}}, nil
	}
	if tmpl != "" {
		return zone.Location{}, errors.New("template requires a Panorama connection")
	}
	v := cmp.Or(vsys, defaultVsys)
	return zone.Location{Vsys: &zone.VsysLocation{NgfwDevice: defaultNgfwDevice, Vsys: v}}, nil
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
		loc, err := resolveZoneLocation(d, in.Vsys, in.Template)
		if err != nil {
			res, v := errorResult("panos_zone_list: %v", err)
			return res, v, nil
		}
		entries, err := svc.List(ctx, loc, "get", "", "")
		if err != nil {
			if !isObjectNotFound(err) {
				res, v := deviceErrorResult(d, "panos_zone_list", err)
				return res, v, nil
			}
			// No zones configured: PAN-OS returns code 7 for the empty node.
			// Treat it as an empty list rather than a failure.
			entries = nil
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
		res, v := jsonResult(map[string]any{totalKey: total, offsetKey: lo, countKey: hi - lo, "zones": names[lo:hi]})
		return res, v, nil
	}
}

// --- Zone write (network/zone) ----------------------------------------------

const (
	zoneTypeLayer3      = "layer3"
	zoneTypeLayer2      = "layer2"
	zoneTypeVirtualWire = "virtual-wire"
	zoneTypeTap         = "tap"
	zoneTypeExternal    = "external"
	zoneTypeTunnel      = "tunnel"
	zoneTypeListStr     = "layer3, layer2, virtual-wire, tap, external, tunnel"
)

var validZoneNetworkTypes = map[string]bool{
	zoneTypeLayer3:      true,
	zoneTypeLayer2:      true,
	zoneTypeVirtualWire: true,
	zoneTypeTap:         true,
	zoneTypeExternal:    true,
	zoneTypeTunnel:      true,
}

// ZoneWriteInput is the input for zone create and update. Zone locations are
// flat vsys/template like ZoneListInput, not the object LocationInput. The
// network type is a oneof: exactly one of the interface-list branches (or the
// interface-less tunnel branch) is active at a time.
type ZoneWriteInput struct {
	Name                         string   `json:"name" jsonschema:"Zone name"`
	Vsys                         string   `json:"vsys,omitempty" jsonschema:"Firewall vsys (default vsys1); firewall only, rejected on Panorama"`
	Template                     string   `json:"template,omitempty" jsonschema:"Template name; required on Panorama, rejected on a firewall"`
	NetworkType                  string   `json:"network_type,omitempty" jsonschema:"layer3, layer2, virtual-wire, tap, external, or tunnel. Required on create; on update a provided value replaces the type and its interface list"`
	Interfaces                   []string `json:"interfaces,omitempty" jsonschema:"Member interfaces of the network type (for external: the external zone members); replaces fully when provided (an explicit empty list clears them, keeping the type), not allowed with tunnel"`
	ZoneProtectionProfile        string   `json:"zone_protection_profile,omitempty"`
	LogSetting                   string   `json:"log_setting,omitempty" jsonschema:"Log forwarding profile for zone-protection logs"`
	EnablePacketBufferProtection *bool    `json:"enable_packet_buffer_protection,omitempty"`
	EnableUserIdentification     *bool    `json:"enable_user_identification,omitempty"`
	EnableDeviceIdentification   *bool    `json:"enable_device_identification,omitempty"`
}

// ZoneNameInput is the input for panos_zone_get and panos_zone_delete: a name
// plus the flat zone location selectors.
type ZoneNameInput struct {
	Name     string `json:"name" jsonschema:"Zone name"`
	Vsys     string `json:"vsys,omitempty" jsonschema:"Firewall vsys (default vsys1); firewall only"`
	Template string `json:"template,omitempty" jsonschema:"Template name; required on Panorama"`
}

func newZoneService(d *Deps) nameFixAdapter[zone.Location, zone.Entry] {
	return nameFixAdapter[zone.Location, zone.Entry]{
		svc:    zone.NewService(d.Client),
		client: d.Client,
		name:   func(e *zone.Entry) string { return e.Name },
	}
}

// nonNilStrings copies in into a slice that is non-nil even when empty. A zone's
// network type is conveyed solely by which interface element exists on the wire,
// and util.StrToMem returns nil for a nil slice (dropping the type marker), so a
// type with zero interfaces still needs a non-nil empty slice. slices.Clone is
// unusable here: it returns nil for a nil input.
func nonNilStrings(in []string) []string {
	return append(make([]string, 0, len(in)), in...)
}

// zoneSetNetworkType clears every network-type branch and sets the chosen one,
// reusing n so the protection fields and Network.Misc survive a type switch (the
// nested-Misc lesson from PR #62).
func zoneSetNetworkType(n *zone.Network, networkType string, interfaces []string) {
	// Capture the tunnel branch before clearing so a tunnel-to-tunnel rebuild
	// keeps its unknown XML (the interface branches are []string and carry no
	// Misc, so only tunnel needs this).
	oldTunnel := n.Tunnel
	n.Layer3, n.Layer2, n.VirtualWire, n.Tap, n.External, n.Tunnel = nil, nil, nil, nil, nil, nil
	switch networkType {
	case zoneTypeLayer3:
		n.Layer3 = nonNilStrings(interfaces)
	case zoneTypeLayer2:
		n.Layer2 = nonNilStrings(interfaces)
	case zoneTypeVirtualWire:
		n.VirtualWire = nonNilStrings(interfaces)
	case zoneTypeTap:
		n.Tap = nonNilStrings(interfaces)
	case zoneTypeExternal:
		n.External = nonNilStrings(interfaces)
	case zoneTypeTunnel:
		if oldTunnel != nil {
			n.Tunnel = oldTunnel
		} else {
			n.Tunnel = &zone.NetworkTunnel{}
		}
	}
}

// zoneReplaceInterfaces replaces the members of the zone's current interface
// branch when no network_type is provided. It errors if no branch is set.
func zoneReplaceInterfaces(n *zone.Network, interfaces []string) error {
	ifs := nonNilStrings(interfaces)
	switch {
	case n.Layer3 != nil:
		n.Layer3 = ifs
	case n.Layer2 != nil:
		n.Layer2 = ifs
	case n.VirtualWire != nil:
		n.VirtualWire = ifs
	case n.Tap != nil:
		n.Tap = ifs
	case n.External != nil:
		n.External = ifs
	case n.Tunnel != nil:
		return errors.New("the tunnel zone type takes no interfaces")
	default:
		return errors.New("this zone has no network_type set; provide network_type")
	}
	return nil
}

// applyZoneNetwork validates and applies the zone network oneof plus the
// protection and user/device-identification toggles, shared by build and
// overlay. The tunnel/interfaces conflict is checked before any early return so
// a bad combination is never silently dropped.
//
//nolint:gocyclo // straight-line: validate, then apply each optional field.
func applyZoneNetwork(e *zone.Entry, in *ZoneWriteInput) error {
	if in.NetworkType != "" && !validZoneNetworkTypes[in.NetworkType] {
		return fmt.Errorf("network_type must be one of %s, got %q", zoneTypeListStr, in.NetworkType)
	}
	if len(in.Interfaces) > 0 && in.NetworkType == zoneTypeTunnel {
		return errors.New("the tunnel zone type takes no interfaces")
	}
	if in.EnableUserIdentification != nil {
		e.EnableUserIdentification = in.EnableUserIdentification
	}
	if in.EnableDeviceIdentification != nil {
		e.EnableDeviceIdentification = in.EnableDeviceIdentification
	}
	networkFieldProvided := in.NetworkType != "" || in.Interfaces != nil ||
		in.ZoneProtectionProfile != "" || in.LogSetting != "" || in.EnablePacketBufferProtection != nil
	if !networkFieldProvided {
		return nil
	}
	n := e.Network
	if n == nil {
		n = &zone.Network{}
		e.Network = n
	}
	setStrPtr(&n.ZoneProtectionProfile, in.ZoneProtectionProfile)
	setStrPtr(&n.LogSetting, in.LogSetting)
	if in.EnablePacketBufferProtection != nil {
		n.EnablePacketBufferProtection = in.EnablePacketBufferProtection
	}
	if in.NetworkType != "" {
		zoneSetNetworkType(n, in.NetworkType, in.Interfaces)
		return nil
	}
	// A provided interfaces list (including an explicit empty list, which clears
	// the members while keeping the type) replaces the current branch. An omitted
	// list (nil) leaves it untouched.
	if in.Interfaces != nil {
		return zoneReplaceInterfaces(n, in.Interfaces)
	}
	return nil
}

func buildZoneEntry(in *ZoneWriteInput) (*zone.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	if in.NetworkType == "" {
		return nil, errors.New("network_type is required; one of " + zoneTypeListStr)
	}
	e := &zone.Entry{Name: in.Name}
	if err := applyZoneNetwork(e, in); err != nil {
		return nil, err
	}
	return e, nil
}

func overlayZone(e *zone.Entry, in *ZoneWriteInput) error {
	return applyZoneNetwork(e, in)
}

// zoneNetworkTypeString maps the zone Network oneof back to the tool-level type
// string. A non-nil empty interface slice counts as set (the wire type marker).
func zoneNetworkTypeString(n *zone.Network) string {
	switch {
	case n == nil:
		return ""
	case n.Layer3 != nil:
		return zoneTypeLayer3
	case n.Layer2 != nil:
		return zoneTypeLayer2
	case n.VirtualWire != nil:
		return zoneTypeVirtualWire
	case n.Tap != nil:
		return zoneTypeTap
	case n.External != nil:
		return zoneTypeExternal
	case n.Tunnel != nil:
		return zoneTypeTunnel
	default:
		return ""
	}
}

// zoneInterfaces returns the members of the active interface branch, or nil for
// the tunnel or no branch.
func zoneInterfaces(n *zone.Network) []string {
	switch {
	case n == nil:
		return nil
	case n.Layer3 != nil:
		return n.Layer3
	case n.Layer2 != nil:
		return n.Layer2
	case n.VirtualWire != nil:
		return n.VirtualWire
	case n.Tap != nil:
		return n.Tap
	case n.External != nil:
		return n.External
	default:
		return nil
	}
}

func zoneSummary(e *zone.Entry) any {
	n := e.Network
	var zpp, logSetting string
	var pbp bool
	if n != nil {
		zpp, logSetting, pbp = strVal(n.ZoneProtectionProfile), strVal(n.LogSetting), boolVal(n.EnablePacketBufferProtection)
	}
	return map[string]any{
		tagNameKey:                        e.Name,
		"network_type":                    zoneNetworkTypeString(n),
		"interfaces":                      zoneInterfaces(n),
		"zone_protection_profile":         zpp,
		"log_setting":                     logSetting,
		"enable_packet_buffer_protection": pbp,
		"enable_user_identification":      boolVal(e.EnableUserIdentification),
		"enable_device_identification":    boolVal(e.EnableDeviceIdentification),
	}
}

// zoneCreateHandler creates a zone. It mirrors the generic createHandler but
// resolves the flat zone location instead of a LocationInput.
func zoneCreateHandler(d *Deps) func(context.Context, *mcp.CallToolRequest, ZoneWriteInput) (*mcp.CallToolResult, any, error) {
	svc := newZoneService(d)
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ZoneWriteInput) (*mcp.CallToolResult, any, error) {
		entry, err := buildZoneEntry(&in)
		if err != nil {
			res, v := errorResult("panos_zone_create: %v", err)
			return res, v, nil
		}
		loc, err := resolveZoneLocation(d, in.Vsys, in.Template)
		if err != nil {
			res, v := errorResult("panos_zone_create: %v", err)
			return res, v, nil
		}
		defer d.LockWrites()()
		created, err := svc.Create(ctx, loc, entry)
		if err != nil {
			d.Logger.Error("failed: panos_zone_create", "error", err)
			res, v := errorResult("failed: panos_zone_create: %v", err)
			return res, v, nil
		}
		d.Logger.Info("panos_zone_create succeeded", "name", in.Name)
		res, v := jsonResult(zoneSummary(created))
		return res, v, nil
	}
}

// zoneUpdateHandler updates a zone via read-modify-write, mirroring the generic
// updateHandler with the flat zone location.
func zoneUpdateHandler(d *Deps) func(context.Context, *mcp.CallToolRequest, ZoneWriteInput) (*mcp.CallToolResult, any, error) {
	svc := newZoneService(d)
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ZoneWriteInput) (*mcp.CallToolResult, any, error) {
		if in.Name == "" {
			res, v := errorResult("panos_zone_update: name is required")
			return res, v, nil
		}
		loc, err := resolveZoneLocation(d, in.Vsys, in.Template)
		if err != nil {
			res, v := errorResult("panos_zone_update: %v", err)
			return res, v, nil
		}
		defer d.LockWrites()()
		entry, err := svc.Read(ctx, loc, in.Name, "get")
		if err != nil {
			d.Logger.Error("failed: panos_zone_update", "error", err)
			res, v := errorResult("failed: panos_zone_update: read %q: %v", in.Name, err)
			return res, v, nil
		}
		if err := overlayZone(entry, &in); err != nil {
			res, v := errorResult("panos_zone_update: %v", err)
			return res, v, nil
		}
		updated, err := svc.Update(ctx, loc, entry, in.Name)
		if err != nil {
			d.Logger.Error("failed: panos_zone_update", "error", err)
			res, v := errorResult("failed: panos_zone_update: %v", err)
			return res, v, nil
		}
		d.Logger.Info("panos_zone_update succeeded", "name", in.Name)
		res, v := jsonResult(zoneSummary(updated))
		return res, v, nil
	}
}

// zoneDeleteHandler deletes a zone from the candidate config.
func zoneDeleteHandler(d *Deps) func(context.Context, *mcp.CallToolRequest, ZoneNameInput) (*mcp.CallToolResult, any, error) {
	svc := newZoneService(d)
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ZoneNameInput) (*mcp.CallToolResult, any, error) {
		if in.Name == "" {
			res, v := errorResult("panos_zone_delete: name is required")
			return res, v, nil
		}
		loc, err := resolveZoneLocation(d, in.Vsys, in.Template)
		if err != nil {
			res, v := errorResult("panos_zone_delete: %v", err)
			return res, v, nil
		}
		defer d.LockWrites()()
		if err := svc.Delete(ctx, loc, in.Name); err != nil {
			res, v := deviceErrorResult(d, "panos_zone_delete", err)
			return res, v, nil
		}
		res, v := successResult(d.Logger, "panos_zone_delete", "deleted %q from candidate config; run panos_commit to apply", in.Name)
		return res, v, nil
	}
}

// zoneGetHandler returns one zone's full detail (network type, interfaces,
// protection settings, and the user/device-id toggles) through zoneSummary,
// completing the zone CRUD set that panos_zone_list (names only) leaves
// incomplete. It uses the flat vsys/template location the other zone tools share,
// so it cannot reuse the generic getHandler (which takes NameInput/LocationInput).
// The Read goes through newZoneService so the raw entry name is xpath-wrapped like
// the other zone reads. Read-only.
func zoneGetHandler(d *Deps) func(context.Context, *mcp.CallToolRequest, ZoneNameInput) (*mcp.CallToolResult, any, error) {
	svc := newZoneService(d)
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ZoneNameInput) (*mcp.CallToolResult, any, error) {
		defer d.RLockReads()()
		if in.Name == "" {
			res, v := errorResult("panos_zone_get: name is required")
			return res, v, nil
		}
		loc, err := resolveZoneLocation(d, in.Vsys, in.Template)
		if err != nil {
			res, v := errorResult("panos_zone_get: %v", err)
			return res, v, nil
		}
		entry, err := svc.Read(ctx, loc, in.Name, "get")
		if err != nil {
			res, v := deviceErrorResult(d, "panos_zone_get", err)
			return res, v, nil
		}
		res, v := jsonResult(zoneSummary(entry))
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
	m["templates"] = strList(e.Templates)
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
		Description: "List pending candidate changes versus the running config (changed config path, action, and owner per entry). Check before panos_commit; other admins' changes commit too. Read-only.",
		Annotations: readOnlyTool("Config diff"),
	}, configDiffHandler(d))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_zone_list",
		Description: "List security zone names for use in rules. On Panorama requires template (see panos_template_list). Read-only.",
		Annotations: readOnlyTool("List zones"),
	}, zoneListHandler(d))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_zone_get",
		Description: "Get one security zone's full detail (network type, interfaces, zone-protection profile, log setting, packet-buffer protection, and user/device-id flags). On Panorama requires template (see panos_template_list). Read-only.",
		Annotations: readOnlyTool("Get zone"),
	}, zoneGetHandler(d))
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
		Name:        "panos_zone_create",
		Description: "Create a security zone in the candidate config. network_type is required (layer3, layer2, virtual-wire, tap, external, or tunnel) and has no default. Firewall: vsys scope (default vsys1); Panorama: template is required. User and device ACLs are not managed by this server. Run panos_commit to apply.",
		Annotations: createTool("Create zone"),
	}, zoneCreateHandler(d))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_zone_update",
		Description: "Update a security zone: read-modify-write, only provided fields change. A provided network_type replaces the type and its interface list; a provided interfaces list replaces fully within the current type. Candidate config only; run panos_commit to apply.",
		Annotations: updateTool("Update zone"),
	}, zoneUpdateHandler(d))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_zone_delete",
		Description: "Delete a security zone from the candidate config. Fails while rules still reference it. Run panos_commit to apply.",
		Annotations: deleteTool("Delete zone"),
	}, zoneDeleteHandler(d))
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
