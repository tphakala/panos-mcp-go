// Package tools implements the PAN-OS MCP tool handlers.
package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/PaloAltoNetworks/pango"
	panoserr "github.com/PaloAltoNetworks/pango/errors"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Deps carries the shared dependencies for all tool handlers.
type Deps struct {
	Client     *pango.Client
	Logger     *slog.Logger
	IsPanorama bool
	ReadOnly   bool
	JobWait    time.Duration

	// writeMu guards the one shared candidate config per device and orders reads
	// against mutations. Writers (LockWrites) hold it exclusively: interleaved
	// read-modify-write cycles would race on the candidate config. Readers
	// (RLockReads) hold it shared, so a list or get never observes a half-applied
	// mutation while independent reads still run concurrently. A read arriving
	// during a commit, push, validate or revert waits until that job completes;
	// that is intended, since its result would otherwise describe a moving target.
	//
	// The lock is required, not precautionary: go-sdk v1.7.0 dispatches every
	// call except initialize asynchronously (mcp/server.go:1913 calls
	// jsonrpc2.Async, and internal/jsonrpc2/conn.go runs each handler in its own
	// goroutine), so handlers run concurrently even within one stdio session, and
	// the streamable HTTP transport shares one *pango.Client across concurrent
	// requests.
	//
	// Read handlers are also memory-safe on the shared *pango.Client: every
	// shared client field is written only during startup (Setup, Initialize,
	// RetrieveSystemInfo, IsPanorama in run()) and read-only afterwards. The read
	// path calls Versioning(), GetTarget() and Communicate()/sendRequest(), none
	// of which write client fields; LoadPanosConfig and RetrievePlugins, the only
	// post-startup writers of client state, are never called by this server.
	// VERIFIED against pango v0.10.3-0.20260731153743-efa43570c367 client.go, read
	// 2026-08-17. Revisit on any pango upgrade.
	writeMu sync.RWMutex
}

// LockWrites takes the mutation lock and returns the unlock function. Callers
// must capture the result and defer it:
//
//	unlock := d.LockWrites()
//	defer unlock()
//
// or defer the returned unlock directly with the double call:
//
//	defer d.LockWrites()()
//
// Do not write "defer d.LockWrites()" (single call): defer evaluates the call
// at function exit, so the body would run unlocked and the lock would then be
// taken and never released.
//
// Write handlers take this exclusive lock; read handlers take RLockReads.
func (d *Deps) LockWrites() func() {
	d.writeMu.Lock()
	return d.writeMu.Unlock
}

// RLockReads takes the shared (read) side of the mutation lock and returns the
// unlock function. It follows the same capture-and-defer contract as LockWrites:
//
//	defer d.RLockReads()()
//
// never "defer d.RLockReads()" (single call). Concurrent readers hold it at the
// same time; a writer waiting on LockWrites blocks until every reader releases.
func (d *Deps) RLockReads() func() {
	d.writeMu.RLock()
	return d.writeMu.RUnlock
}

const (
	defaultListLimit = 50
	maxListLimit     = 200

	defaultVsys = "vsys1"

	// Single-device PAN-OS configs hang off the literal device entry
	// "localhost.localdomain" in the config xpath. pango's location types reject
	// an empty NgfwDevice/PanoramaDevice (objects/address/location.go
	// IsValid/XpathPrefix), so the vsys and device-group constructors must set
	// NgfwDevice and PanoramaDevice respectively; the shared location has neither.
	// The two are kept distinct because they populate different pango location
	// fields (VsysLocation.NgfwDevice vs DeviceGroupLocation.PanoramaDevice), even
	// though PAN-OS uses the same literal for both on a single device.
	defaultNgfwDevice     = "localhost.localdomain"
	defaultPanoramaDevice = "localhost.localdomain"

	rulebasePre  = "pre-rulebase"
	rulebasePost = "post-rulebase"
)

// strVal dereferences s, mapping nil to the empty string.
func strVal(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// names maps each element of s through get, returning a non-nil empty slice for
// an empty input so a summary renders [] and not null (mirrors strList).
func names[T any](s []T, get func(T) string) []string {
	if len(s) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(s))
	for _, v := range s {
		out = append(out, get(v))
	}
	return out
}

// setPtr assigns src to *dst when src is non-nil, leaving *dst untouched
// otherwise. It collapses the read-modify-write "set only when provided" guard
// used across the overlay builders for optional pointer fields.
func setPtr[T any](dst **T, src *T) {
	if src != nil {
		*dst = src
	}
}

// setStrPtr sets *dst to a pointer to s when s is non-empty, leaving *dst
// untouched otherwise: a blank input leaves any existing value in place,
// matching the single-value field semantics (clearing in place is not
// supported).
func setStrPtr(dst **string, s string) {
	if s != "" {
		*dst = new(s)
	}
}

// readOnlyTool annotates a tool that only reads from the device (open world).
// DestructiveHint is set false explicitly (redundant under ReadOnlyHint, but
// unambiguous for scanners).
func readOnlyTool(title string) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{Title: title, ReadOnlyHint: true, DestructiveHint: new(false), OpenWorldHint: new(true)}
}

// createTool annotates a tool that additively creates candidate config.
func createTool(title string) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{Title: title, DestructiveHint: new(false), IdempotentHint: false, OpenWorldHint: new(true)}
}

// updateTool annotates a tool that overwrites existing candidate config.
func updateTool(title string) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{Title: title, DestructiveHint: new(true), IdempotentHint: true, OpenWorldHint: new(true)}
}

// deleteTool annotates a tool that deletes candidate config or applies a
// destructive device action.
func deleteTool(title string) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{Title: title, DestructiveHint: new(true), IdempotentHint: true, OpenWorldHint: new(true)}
}

// LocationInput selects where a config object lives.
type LocationInput struct {
	Vsys        string `json:"vsys,omitempty" jsonschema:"Firewall vsys name (firewall default: vsys1)"`
	Shared      bool   `json:"shared,omitempty" jsonschema:"Use the shared location (Panorama default)"`
	DeviceGroup string `json:"device_group,omitempty" jsonschema:"Panorama device group name"`
	Rulebase    string `json:"rulebase,omitempty" jsonschema:"Panorama rule placement: pre or post (default pre); rule tools only"`
}

// ListInput is the common input for list tools.
type ListInput struct {
	Location LocationInput `json:"location,omitzero"`
	Limit    int           `json:"limit,omitempty" jsonschema:"Max results (default 50, max 200)"`
	Offset   int           `json:"offset,omitempty" jsonschema:"Skip this many results"`
	Filter   string        `json:"filter,omitempty" jsonschema:"Case-insensitive name substring filter"`
}

// NameInput is the common input for single-object tools.
type NameInput struct {
	Name     string        `json:"name" jsonschema:"Object name"`
	Location LocationInput `json:"location,omitzero"`
}

// normalizeRulebase maps the tool-level pre/post values onto the PAN-OS
// xpath node names.
func normalizeRulebase(s string) (string, error) {
	switch s {
	case "", "pre", rulebasePre:
		return rulebasePre, nil
	case "post", rulebasePost:
		return rulebasePost, nil
	default:
		return "", fmt.Errorf("rulebase must be \"pre\" or \"post\", got %q", s)
	}
}

// clampList bounds limit and offset against n entries.
func clampList(limit, offset, n int) (lo, hi int) {
	if limit <= 0 {
		limit = defaultListLimit
	}
	if limit > maxListLimit {
		limit = maxListLimit
	}
	if offset < 0 {
		offset = 0
	}
	if offset > n {
		offset = n
	}
	hi = offset + limit
	if hi > n {
		hi = n
	}
	return offset, hi
}

// projectList applies the standard list post-processing shared by every list
// tool: a case-insensitive substring filter on the entry name, offset/limit
// clamping, and a per-entry summary projection. It returns the
// {total, offset, count, entries} envelope. total counts entries after the
// filter but before clamping; offset is the clamped start.
func projectList[E any](entries []*E, limit, offset int, filter string, name func(*E) string, summarize func(*E) any) map[string]any {
	if filter != "" {
		needle := strings.ToLower(filter)
		kept := entries[:0:0]
		for _, e := range entries {
			if strings.Contains(strings.ToLower(name(e)), needle) {
				kept = append(kept, e)
			}
		}
		entries = kept
	}
	total := len(entries)
	lo, hi := clampList(limit, offset, total)
	out := make([]any, 0, hi-lo)
	for _, e := range entries[lo:hi] {
		out = append(out, summarize(e))
	}
	return map[string]any{totalKey: total, offsetKey: lo, countKey: len(out), entriesKey: out}
}

// locParts supplies the per-resource location constructors for resolveLocation.
// The rulebase argument is meaningful only when rules is true; object
// resources ignore it. vsys may be nil: a few pango profile packages
// (urlfiltering, vulnerability, wildfireanalysis, secgroup) generate no vsys
// location at all, only shared and device_group. resolveLocation treats a nil
// vsys as "no vsys location for this type": an explicit vsys request errors, and
// the firewall default falls back to shared.
type locParts[L any] struct {
	shared      func(rulebase string) L
	vsys        func(vsys string) L
	deviceGroup func(dg, rulebase string) L
	rules       bool
}

// resolveLocation maps a LocationInput onto a pango location for the connected
// device type, applying the spec defaults: vsys1 on a firewall, shared on
// Panorama, pre-rulebase for rules.
func resolveLocation[L any](d *Deps, in LocationInput, p locParts[L]) (L, error) {
	var zero L
	rb := ""
	if p.rules {
		var err error
		if rb, err = normalizeRulebase(in.Rulebase); err != nil {
			return zero, err
		}
	} else if in.Rulebase != "" {
		return zero, errors.New("rulebase applies only to rule tools")
	}
	switch {
	case in.DeviceGroup != "":
		if !d.IsPanorama {
			return zero, errors.New("location device_group requires a Panorama connection")
		}
		return p.deviceGroup(in.DeviceGroup, rb), nil
	case in.Shared:
		if p.rules && !d.IsPanorama {
			return zero, errors.New("shared rulebases exist only on Panorama")
		}
		return p.shared(rb), nil
	case in.Vsys != "":
		if d.IsPanorama {
			return zero, errors.New("location vsys requires a firewall connection; use shared or device_group")
		}
		if p.vsys == nil {
			return zero, errors.New("location vsys is not supported for this object type; pango models it at shared or device_group only")
		}
		return p.vsys(in.Vsys), nil
	case d.IsPanorama:
		return p.shared(rb), nil
	case p.vsys == nil:
		// A firewall object type pango models only at shared (its SDK package
		// generates no vsys location): default to shared so the tool stays
		// usable on a firewall. Each affected tool documents this fallback.
		return p.shared(""), nil
	default:
		return p.vsys(defaultVsys), nil
	}
}

// textResult builds a simple text content result.
//
//nolint:unparam // anyVal is always nil; kept for signature consistency.
func textResult(format string, args ...any) (res *mcp.CallToolResult, anyVal any) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(format, args...)}},
	}, nil
}

// successResult logs a mutation success at INFO and builds a text result.
//
//nolint:unparam // anyVal is always nil; kept for signature consistency with jsonResult and errorResult.
func successResult(logger *slog.Logger, toolName, format string, args ...any) (res *mcp.CallToolResult, anyVal any) {
	text := fmt.Sprintf(format, args...)
	logger.Info(toolName+" succeeded", "result", text)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}, nil
}

// jsonResult builds a JSON-formatted text content result. The returned data
// value becomes the tool's structured content; callers must pass a JSON object
// (map or struct), never a bare array or primitive.
func jsonResult(data any) (res *mcp.CallToolResult, anyVal any) {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return errorResult("failed to marshal JSON: %v", err)
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(b)}},
	}, data
}

// errorResult builds an error result with IsError set.
func errorResult(format string, args ...any) (res *mcp.CallToolResult, anyVal any) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(format, args...)}},
		IsError: true,
	}, nil
}

// Shared JSON result-map keys, so the same literal is not repeated across the
// list handlers (listHandler, zoneListHandler) and the op handlers (goconst).
// The "name" key reuses tagNameKey.
const (
	totalKey   = "total"
	offsetKey  = "offset"
	countKey   = "count"
	entriesKey = "entries"
	matchedKey = "matched"
	// interfaceKey is the shared summary map key for an interface name, used by
	// the op tools and the VPN local-address projections.
	interfaceKey = "interface"
)

// replaceListOrRejectEmpty applies a replace-or-keep overlay for a list field
// where an empty list is INVALID config (group membership and the like): an
// explicit empty list is rejected with emptyErr, a non-empty list replaces
// *dst, and a nil (omitted) list leaves *dst untouched. Profile lists, where an
// empty list is valid and clears the field, must NOT use this; they assign on
// `in != nil` so an explicit empty list clears.
func replaceListOrRejectEmpty(dst *[]string, in []string, emptyErr string) error {
	if in != nil && len(in) == 0 {
		return errors.New(emptyErr)
	}
	if len(in) > 0 {
		*dst = in
	}
	return nil
}

// crudService is the five-method surface pango's CRUD config services expose;
// the generic handler builders below are written against it.
type crudService[L, E any] interface {
	Create(ctx context.Context, loc L, entry *E) (*E, error)
	Read(ctx context.Context, loc L, name, action string) (*E, error)
	Update(ctx context.Context, loc L, entry *E, name string) (*E, error)
	Delete(ctx context.Context, loc L, name ...string) error
	List(ctx context.Context, loc L, action, filter, quote string) ([]*E, error)
}

// isObjectNotFound reports whether err is PAN-OS's "object not found" (code 7).
// pango returns this from a config get when the target node has no entries, so
// a list of an empty object set arrives as an error; callers treat it as empty.
// AsType unwraps in case a caller ever wraps the pango error.
//
// PAN-OS also answers code 7 for a get on a nonexistent parent location: a
// missing vsys, device, or template all return code 7 (MEASURED against PAN-OS
// 12.1.7), indistinguishable from an empty node. So a list against a mistyped
// location reads as empty rather than an error; telling the two apart would
// need a separate existence check per call, not worth the extra round-trip.
func isObjectNotFound(err error) bool {
	pe, ok := errors.AsType[panoserr.Panos](err)
	return ok && pe.ObjectNotFound()
}

// listHandler builds a list tool handler: fetch all entries at the location
// (the XML API has no server-side pagination), filter by name substring,
// clamp, and summarize.
// The five *Core functions below hold the shared body of the object, net-scope
// and device-scope CRUD handlers, which differ only in how they resolve a scope
// and, for create/update, in whether they carry a write-only secret. Each
// family's public handler is a thin wrapper that binds a resolve closure and
// forwards here, so the read/write lock ordering and the write-error redaction
// seam live in one audited place (issue #90). resolve maps the tool input to a
// pango location; page and name extract the per-verb inputs; opts supplies the
// secret extractor for a secret-bearing family (it is empty for object families,
// where redactSecrets is a no-op that returns the message unchanged).

func listCore[L, E, In any](
	d *Deps, tool string, svc crudService[L, E],
	resolve func(In) (L, error),
	page func(In) (limit, offset int, filter string),
	name func(*E) string, summarize func(*E) any,
) func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, any, error) {
		defer d.RLockReads()()
		limit, offset, filter := page(in)
		d.Logger.Debug(tool, "limit", limit, "offset", offset, "filter", filter)
		loc, err := resolve(in)
		if err != nil {
			res, v := errorResult("%s: %v", tool, err)
			return res, v, nil
		}
		entries, err := svc.List(ctx, loc, "get", "", "")
		if err != nil {
			if !isObjectNotFound(err) {
				d.Logger.Error("failed: "+tool, "error", err)
				res, v := errorResult("failed: %s: %v", tool, err)
				return res, v, nil
			}
			// An empty object set: PAN-OS returns code 7 for a config get on a
			// node with no entries. That is not a failure, so continue with no
			// entries and return an empty list.
			entries = nil
		}
		res, v := jsonResult(projectList(entries, limit, offset, filter, name, summarize))
		return res, v, nil
	}
}

func getCore[L, E, In any](
	d *Deps, tool string, svc crudService[L, E],
	resolve func(In) (L, error),
	name func(In) string,
	summarize func(*E) any,
) func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, any, error) {
		defer d.RLockReads()()
		n := name(in)
		if n == "" {
			res, v := errorResult("%s: name is required", tool)
			return res, v, nil
		}
		loc, err := resolve(in)
		if err != nil {
			res, v := errorResult("%s: %v", tool, err)
			return res, v, nil
		}
		entry, err := svc.Read(ctx, loc, n, "get")
		if err != nil {
			d.Logger.Error("failed: "+tool, "error", err)
			res, v := errorResult("failed: %s: %v", tool, err)
			return res, v, nil
		}
		res, v := jsonResult(summarize(entry))
		return res, v, nil
	}
}

func deleteCore[L, E, In any](
	d *Deps, tool string, svc crudService[L, E],
	resolve func(In) (L, error),
	name func(In) string,
) func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, any, error) {
		n := name(in)
		if n == "" {
			res, v := errorResult("%s: name is required", tool)
			return res, v, nil
		}
		loc, err := resolve(in)
		if err != nil {
			res, v := errorResult("%s: %v", tool, err)
			return res, v, nil
		}
		defer d.LockWrites()()
		if err := svc.Delete(ctx, loc, n); err != nil {
			d.Logger.Error("failed: "+tool, "error", err)
			res, v := errorResult("failed: %s: %v", tool, err)
			return res, v, nil
		}
		res, v := successResult(d.Logger, tool, "deleted %q from candidate config; run panos_commit to apply", n)
		return res, v, nil
	}
}

func createCore[L, E, In any](
	d *Deps, tool string, svc crudService[L, E],
	resolve func(In) (L, error),
	build func(In) (*E, error),
	summarize func(*E) any,
	opts ...writeOption[In],
) func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, any, error) {
		entry, err := build(in)
		if err != nil {
			res, v := errorResult("%s: %v", tool, err)
			return res, v, nil
		}
		loc, err := resolve(in)
		if err != nil {
			res, v := errorResult("%s: %v", tool, err)
			return res, v, nil
		}
		defer d.LockWrites()()
		created, err := svc.Create(ctx, loc, entry)
		if err != nil {
			red := redactSecrets(err.Error(), gatherSecrets(&in, opts))
			d.Logger.Error("failed: "+tool, "error", red)
			res, v := errorResult("failed: %s: %s", tool, red)
			return res, v, nil
		}
		d.Logger.Info(tool + " succeeded")
		res, v := jsonResult(summarize(created))
		return res, v, nil
	}
}

func updateCore[L, E, In any](
	d *Deps, tool string, svc crudService[L, E],
	resolve func(In) (L, error),
	name func(In) string,
	overlay func(*E, In) error,
	summarize func(*E) any,
	opts ...writeOption[In],
) func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, any, error) {
		n := name(in)
		if n == "" {
			res, v := errorResult("%s: name is required", tool)
			return res, v, nil
		}
		loc, err := resolve(in)
		if err != nil {
			res, v := errorResult("%s: %v", tool, err)
			return res, v, nil
		}
		defer d.LockWrites()()
		entry, err := svc.Read(ctx, loc, n, "get")
		if err != nil {
			d.Logger.Error("failed: "+tool, "error", err)
			res, v := errorResult("failed: %s: read %q: %v", tool, n, err)
			return res, v, nil
		}
		if err := overlay(entry, in); err != nil {
			res, v := errorResult("%s: %v", tool, err)
			return res, v, nil
		}
		updated, err := svc.Update(ctx, loc, entry, n)
		if err != nil {
			red := redactSecrets(err.Error(), gatherSecrets(&in, opts))
			d.Logger.Error("failed: "+tool, "error", red)
			res, v := errorResult("failed: %s: %s", tool, red)
			return res, v, nil
		}
		d.Logger.Info(tool+" succeeded", "name", n)
		res, v := jsonResult(summarize(updated))
		return res, v, nil
	}
}

func listHandler[L, E any](
	d *Deps, tool string, svc crudService[L, E],
	resolve func(LocationInput) (L, error),
	name func(*E) string, summarize func(*E) any,
) func(context.Context, *mcp.CallToolRequest, ListInput) (*mcp.CallToolResult, any, error) {
	return listCore(d, tool, svc,
		func(in ListInput) (L, error) { return resolve(in.Location) },
		func(in ListInput) (int, int, string) { return in.Limit, in.Offset, in.Filter },
		name, summarize)
}

// getHandler builds a get tool handler returning the entry through summarize,
// a clean per-resource projection, so get, create, and update never leak
// pango's internal struct fields (issue #48). summarize is usually the same
// function list uses; the NAT tools pass natRuleDetail for get/create/update,
// a fuller projection than the compact NAT list summary.
func getHandler[L, E any](
	d *Deps, tool string, svc crudService[L, E],
	resolve func(LocationInput) (L, error),
	summarize func(*E) any,
) func(context.Context, *mcp.CallToolRequest, NameInput) (*mcp.CallToolResult, any, error) {
	return getCore(d, tool, svc,
		func(in NameInput) (L, error) { return resolve(in.Location) },
		func(in NameInput) string { return in.Name },
		summarize)
}

// deleteHandler builds a delete tool handler.
func deleteHandler[L, E any](
	d *Deps, tool string, svc crudService[L, E],
	resolve func(LocationInput) (L, error),
) func(context.Context, *mcp.CallToolRequest, NameInput) (*mcp.CallToolResult, any, error) {
	return deleteCore(d, tool, svc,
		func(in NameInput) (L, error) { return resolve(in.Location) },
		func(in NameInput) string { return in.Name })
}

// createHandler builds a create tool handler from a resource-specific entry
// builder. Unlike the net- and device-scope create/update handlers it takes no
// writeOption secret extractor: no object family carries a write-only secret, so
// there is nothing to redact from its device-error output (issue #92). A future
// secret-bearing object family would thread the same opts seam through here.
func createHandler[L, E, In any](
	d *Deps, tool string, svc crudService[L, E],
	resolve func(LocationInput) (L, error),
	location func(In) LocationInput,
	build func(In) (*E, error),
	summarize func(*E) any,
) func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, any, error) {
	return createCore(d, tool, svc,
		func(in In) (L, error) { return resolve(location(in)) },
		build, summarize)
}

// updateHandler builds a read-modify-write update tool handler. The overlay
// applies only the caller-provided fields; provided arrays replace the existing
// arrays entirely.
func updateHandler[L, E, In any](
	d *Deps, tool string, svc crudService[L, E],
	resolve func(LocationInput) (L, error),
	location func(In) LocationInput,
	name func(In) string,
	overlay func(*E, In) error,
	summarize func(*E) any,
) func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, any, error) {
	return updateCore(d, tool, svc,
		func(in In) (L, error) { return resolve(location(in)) },
		name, overlay, summarize)
}

// RegisterAll registers every tool for the connected device type.
func RegisterAll(s *mcp.Server, d *Deps) {
	RegisterAddressTools(s, d)
	RegisterAddressGroupTools(s, d)
	RegisterServiceTools(s, d)
	RegisterServiceGroupTools(s, d)
	RegisterTagTools(s, d)
	RegisterApplicationTools(s, d)
	RegisterApplicationGroupTools(s, d)
	RegisterEdlTools(s, d)
	RegisterCustomURLCategoryTools(s, d)
	RegisterScheduleTools(s, d)
	RegisterDynamicUserGroupTools(s, d)
	RegisterAntivirusProfileTools(s, d)
	RegisterVulnerabilityProfileTools(s, d)
	RegisterSpywareProfileTools(s, d)
	RegisterURLFilteringProfileTools(s, d)
	RegisterFileBlockingProfileTools(s, d)
	RegisterWildfireAnalysisProfileTools(s, d)
	RegisterProfileGroupTools(s, d)
	RegisterLogForwardingProfileTools(s, d)
	RegisterDecryptionProfileTools(s, d)
	RegisterSecurityRuleTools(s, d)
	RegisterNatRuleTools(s, d)
	RegisterDecryptionRuleTools(s, d)
	RegisterAuthenticationRuleTools(s, d)
	RegisterPbfRuleTools(s, d)
	RegisterDeviceTools(s, d)
	RegisterIkeCryptoProfileTools(s, d)
	RegisterIpsecCryptoProfileTools(s, d)
	RegisterIkeGatewayTools(s, d)
	RegisterIpsecTunnelTools(s, d)
	RegisterGreTunnelTools(s, d)
	RegisterDeviceGroupWriteTools(s, d)
	RegisterTemplateWriteTools(s, d)
	RegisterTemplateStackTools(s, d)
	RegisterTemplateVariableTools(s, d)
	// Tier 4: L3 network configuration (net-scoped to firewall, template, or template stack).
	RegisterEthernetInterfaceTools(s, d)
	RegisterAggregateInterfaceTools(s, d)
	RegisterLoopbackInterfaceTools(s, d)
	RegisterVlanInterfaceTools(s, d)
	RegisterTunnelInterfaceTools(s, d)
	RegisterVirtualRouterTools(s, d)
	RegisterLogicalRouterTools(s, d)
	RegisterInterfaceManagementProfileTools(s, d)
	RegisterLldpProfileTools(s, d)
	RegisterBfdProfileTools(s, d)
	RegisterMonitorProfileTools(s, d)
	RegisterZoneProtectionTools(s, d)
	RegisterVirtualWireTools(s, d)
	RegisterVlanTools(s, d)
	RegisterDhcpTools(s, d)
	RegisterDnsProxyTools(s, d)
	// Tier 5: device server profiles (device-scoped: firewall vsys/shared or Panorama template/stack/shared).
	RegisterLdapProfileTools(s, d)
	RegisterTacacsProfileTools(s, d)
	RegisterRadiusProfileTools(s, d)
	RegisterSyslogProfileTools(s, d)
	RegisterSnmpTrapProfileTools(s, d)
	RegisterEmailProfileTools(s, d)
	// Tier 5: device identity and auth (device-scoped): local users and SAML/MFA profiles.
	RegisterLocalUserTools(s, d)
	RegisterSamlIdpProfileTools(s, d)
	RegisterMfaProfileTools(s, d)
	RegisterOpTools(s, d)
}
