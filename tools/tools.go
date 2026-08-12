// Package tools implements the PAN-OS MCP tool handlers.
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/PaloAltoNetworks/pango"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Deps carries the shared dependencies for all tool handlers.
type Deps struct {
	Client     *pango.Client
	Logger     *slog.Logger
	IsPanorama bool
	ReadOnly   bool
	JobWait    time.Duration

	// writeMu serializes mutations: PAN-OS has one shared candidate config per
	// device, so interleaved read-modify-write cycles race on it. Read handlers
	// do NOT take this lock, and pango.Client is not goroutine-safe, so the
	// server wiring must serialize handler dispatch (or add read-side locking)
	// before running handlers concurrently.
	writeMu sync.Mutex
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
func (d *Deps) LockWrites() func() {
	d.writeMu.Lock()
	return d.writeMu.Unlock
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
	defaultNgfwDevice     = "localhost.localdomain"
	defaultPanoramaDevice = "localhost.localdomain"

	rulebasePre  = "pre-rulebase"
	rulebasePost = "post-rulebase"
)

// ptr returns a pointer to v; pango entry fields are mostly pointers.
func ptr[T any](v T) *T { return &v }

// strVal dereferences s, mapping nil to the empty string.
func strVal(s *string) string {
	if s == nil {
		return ""
	}
	return *s
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
	Location LocationInput `json:"location,omitempty"`
	Limit    int           `json:"limit,omitempty" jsonschema:"Max results (default 50, max 200)"`
	Offset   int           `json:"offset,omitempty" jsonschema:"Skip this many results"`
	Filter   string        `json:"filter,omitempty" jsonschema:"Case-insensitive name substring filter"`
}

// NameInput is the common input for single-object tools.
type NameInput struct {
	Name     string        `json:"name" jsonschema:"Object name"`
	Location LocationInput `json:"location,omitempty"`
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

// locParts supplies the per-resource location constructors for resolveLocation.
// The rulebase argument is meaningful only when rules is true; object
// resources ignore it.
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
		return zero, fmt.Errorf("rulebase applies only to rule tools")
	}
	switch {
	case in.DeviceGroup != "":
		if !d.IsPanorama {
			return zero, fmt.Errorf("location device_group requires a Panorama connection")
		}
		return p.deviceGroup(in.DeviceGroup, rb), nil
	case in.Shared:
		if p.rules && !d.IsPanorama {
			return zero, fmt.Errorf("shared rulebases exist only on Panorama")
		}
		return p.shared(rb), nil
	case in.Vsys != "":
		if d.IsPanorama {
			return zero, fmt.Errorf("location vsys requires a firewall connection; use shared or device_group")
		}
		return p.vsys(in.Vsys), nil
	case d.IsPanorama:
		return p.shared(rb), nil
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

// crudService is the five-method surface pango's CRUD config services expose;
// the generic handler builders below are written against it.
type crudService[L, E any] interface {
	Create(ctx context.Context, loc L, entry *E) (*E, error)
	Read(ctx context.Context, loc L, name, action string) (*E, error)
	Update(ctx context.Context, loc L, entry *E, name string) (*E, error)
	Delete(ctx context.Context, loc L, name ...string) error
	List(ctx context.Context, loc L, action, filter, quote string) ([]*E, error)
}

// listHandler builds a list tool handler: fetch all entries at the location
// (the XML API has no server-side pagination), filter by name substring,
// clamp, and summarize.
func listHandler[L, E any](
	d *Deps, tool string, svc crudService[L, E],
	resolve func(LocationInput) (L, error),
	name func(*E) string, summarize func(*E) any,
) func(context.Context, *mcp.CallToolRequest, ListInput) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ListInput) (*mcp.CallToolResult, any, error) {
		d.Logger.Debug(tool, "limit", in.Limit, "offset", in.Offset, "filter", in.Filter)
		loc, err := resolve(in.Location)
		if err != nil {
			res, v := errorResult("%s: %v", tool, err)
			return res, v, nil
		}
		entries, err := svc.List(ctx, loc, "get", "", "")
		if err != nil {
			d.Logger.Error("failed: "+tool, "error", err)
			res, v := errorResult("failed: %s: %v", tool, err)
			return res, v, nil
		}
		if in.Filter != "" {
			needle := strings.ToLower(in.Filter)
			kept := entries[:0:0]
			for _, e := range entries {
				if strings.Contains(strings.ToLower(name(e)), needle) {
					kept = append(kept, e)
				}
			}
			entries = kept
		}
		total := len(entries)
		lo, hi := clampList(in.Limit, in.Offset, total)
		out := make([]any, 0, hi-lo)
		for _, e := range entries[lo:hi] {
			out = append(out, summarize(e))
		}
		res, v := jsonResult(map[string]any{"total": total, "offset": lo, "count": len(out), "entries": out})
		return res, v, nil
	}
}

// getHandler builds a get tool handler returning the full entry as JSON.
func getHandler[L, E any](
	d *Deps, tool string, svc crudService[L, E],
	resolve func(LocationInput) (L, error),
) func(context.Context, *mcp.CallToolRequest, NameInput) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in NameInput) (*mcp.CallToolResult, any, error) {
		if in.Name == "" {
			res, v := errorResult("%s: name is required", tool)
			return res, v, nil
		}
		loc, err := resolve(in.Location)
		if err != nil {
			res, v := errorResult("%s: %v", tool, err)
			return res, v, nil
		}
		entry, err := svc.Read(ctx, loc, in.Name, "get")
		if err != nil {
			d.Logger.Error("failed: "+tool, "error", err)
			res, v := errorResult("failed: %s: %v", tool, err)
			return res, v, nil
		}
		res, v := jsonResult(entry)
		return res, v, nil
	}
}

// deleteHandler builds a delete tool handler.
func deleteHandler[L, E any](
	d *Deps, tool string, svc crudService[L, E],
	resolve func(LocationInput) (L, error),
) func(context.Context, *mcp.CallToolRequest, NameInput) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in NameInput) (*mcp.CallToolResult, any, error) {
		if in.Name == "" {
			res, v := errorResult("%s: name is required", tool)
			return res, v, nil
		}
		loc, err := resolve(in.Location)
		if err != nil {
			res, v := errorResult("%s: %v", tool, err)
			return res, v, nil
		}
		defer d.LockWrites()()
		if err := svc.Delete(ctx, loc, in.Name); err != nil {
			d.Logger.Error("failed: "+tool, "error", err)
			res, v := errorResult("failed: %s: %v", tool, err)
			return res, v, nil
		}
		res, v := successResult(d.Logger, tool, "deleted %q from candidate config; run panos_commit to apply", in.Name)
		return res, v, nil
	}
}

// createHandler builds a create tool handler from a resource-specific entry
// builder.
func createHandler[L, E, In any](
	d *Deps, tool string, svc crudService[L, E],
	resolve func(LocationInput) (L, error),
	location func(In) LocationInput,
	build func(In) (*E, error),
) func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, any, error) {
		entry, err := build(in)
		if err != nil {
			res, v := errorResult("%s: %v", tool, err)
			return res, v, nil
		}
		loc, err := resolve(location(in))
		if err != nil {
			res, v := errorResult("%s: %v", tool, err)
			return res, v, nil
		}
		defer d.LockWrites()()
		created, err := svc.Create(ctx, loc, entry)
		if err != nil {
			d.Logger.Error("failed: "+tool, "error", err)
			res, v := errorResult("failed: %s: %v", tool, err)
			return res, v, nil
		}
		d.Logger.Info(tool + " succeeded")
		res, v := jsonResult(created)
		return res, v, nil
	}
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
) func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, any, error) {
		n := name(in)
		if n == "" {
			res, v := errorResult("%s: name is required", tool)
			return res, v, nil
		}
		loc, err := resolve(location(in))
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
			d.Logger.Error("failed: "+tool, "error", err)
			res, v := errorResult("failed: %s: %v", tool, err)
			return res, v, nil
		}
		d.Logger.Info(tool+" succeeded", "name", n)
		res, v := jsonResult(updated)
		return res, v, nil
	}
}
