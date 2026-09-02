package tools

import (
	"context"
	"errors"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// System scope and singleton config handlers
// ---------------------------------------------------------------------------
//
// The device's own system services (DNS, NTP, host/general settings, the update
// proxy) are singletons, not named-entry lists: there is exactly one of each per
// device, and pango models them as a Config value with no Name, read and written
// whole. Their pango location is {System | Template | TemplateStack}: a
// device-local system scope on a firewall, or a Panorama template / template
// stack. That is the NetScopeInput shape with System replacing Ngfw, so it gets
// its own small resolver here rather than overloading resolveNetScope.
//
// Because a singleton has no name, it has no list, create-by-name or delete
// tool. Each family exposes exactly two tools: a get (read the whole config) and
// an update (read-modify-write, only the provided fields change). A device that
// has never had the setting configured makes the seed read fail (see
// isSingletonAbsent for the two shapes pango returns); both handlers treat that
// as an empty config to start from rather than an error, so the first update
// creates the node.

// SystemScopeInput selects where a device system service config lives. On a
// firewall both fields stay empty and the config resolves to the device-local
// System scope. On Panorama exactly one of template or template_stack is
// required.
type SystemScopeInput struct {
	Template      string `json:"template,omitempty" jsonschema:"Panorama template name (Panorama only; mutually exclusive with template_stack)"`
	TemplateStack string `json:"template_stack,omitempty" jsonschema:"Panorama template-stack name (Panorama only; mutually exclusive with template)"`
}

// systemScope returns the scope itself, so every input that embeds
// SystemScopeInput satisfies systemScoped through promotion.
func (in SystemScopeInput) systemScope() SystemScopeInput { return in }

// systemScoped lets an update handler pull the scope off any input that embeds
// SystemScopeInput.
type systemScoped interface{ systemScope() SystemScopeInput }

// systemScopeParts supplies the per-service pango location constructors for
// resolveSystemScope.
type systemScopeParts[L any] struct {
	system        func() L
	template      func(tmpl string) L
	templateStack func(stack string) L
}

// resolveSystemScope maps a SystemScopeInput onto a pango location for the
// connected device type. Firewall with neither field set resolves to the
// device-local System scope; Panorama requires exactly one of template or
// template_stack.
func resolveSystemScope[L any](d *Deps, in SystemScopeInput, p systemScopeParts[L]) (L, error) {
	var zero L
	switch {
	case in.Template != "" && in.TemplateStack != "":
		return zero, errors.New("set only one of template or template_stack, not both")
	case in.TemplateStack != "":
		if !d.IsPanorama {
			return zero, errors.New("template_stack requires a Panorama connection")
		}
		return p.templateStack(in.TemplateStack), nil
	case in.Template != "":
		if !d.IsPanorama {
			return zero, errors.New("template requires a Panorama connection")
		}
		return p.template(in.Template), nil
	case d.IsPanorama:
		return zero, errors.New("template or template_stack is required on Panorama; list templates with panos_template_list")
	default:
		return p.system(), nil
	}
}

// singletonService is the subset of a pango singleton config service the
// handlers need. It differs from crudService in that Read takes no entry name (a
// singleton has none) and there is no List or Delete.
type singletonService[L, C any] interface {
	Read(ctx context.Context, loc L, action string) (*C, error)
	Create(ctx context.Context, loc L, config *C) (*C, error)
	Update(ctx context.Context, loc L, config *C, name string) (*C, error)
}

// isSingletonAbsent reports whether a singleton config get failed because the
// setting is simply not present yet, which pango surfaces two ways for a
// candidate-config get: PAN-OS code 7 (object not found) when the parent
// location is missing, and its own `expected to "get" 1 entry, got 0` (a plain
// formatted error, no sentinel type) when the config node itself is empty. Both
// mean "start from an empty config": the get reports empty and the update seeds
// a fresh node. A `got 2` (more than one) is a genuine error and is not matched,
// so it still surfaces. The string match is pinned by
// TestSingletonAbsentMatchesEmptyGet so a pango wording change fails loudly.
func isSingletonAbsent(err error) bool {
	if err == nil {
		return false
	}
	return isObjectNotFound(err) || strings.Contains(err.Error(), "1 entry, got 0")
}

// systemGetHandler builds a get tool handler for a singleton system config. A
// device with the setting unconfigured (see isSingletonAbsent) is reported as an
// empty config rather than an error.
func systemGetHandler[L, C any](
	d *Deps, tool string, svc singletonService[L, C], p systemScopeParts[L],
	summarize func(*C) any,
) func(context.Context, *mcp.CallToolRequest, SystemScopeInput) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in SystemScopeInput) (*mcp.CallToolResult, any, error) {
		defer d.RLockReads()()
		loc, err := resolveSystemScope(d, in, p)
		if err != nil {
			res, v := errorResult("%s: %v", tool, err)
			return res, v, nil
		}
		cfg, err := svc.Read(ctx, loc, "get")
		if err != nil {
			if !isSingletonAbsent(err) {
				res, v := deviceErrorResult(d, tool, err)
				return res, v, nil
			}
			cfg = new(C)
		}
		res, v := jsonResult(summarize(cfg))
		return res, v, nil
	}
}

// systemUpdateHandler builds an update tool handler for a singleton system
// config: a read-modify-write overlay applying only the caller-provided fields.
// The seed read is a plain get; it collapses pango's raw-response fallback like
// the read cores. The update failure redacts any secret this call submitted.
func systemUpdateHandler[L, C any, In systemScoped](
	d *Deps, tool string, svc singletonService[L, C], p systemScopeParts[L],
	overlay func(*C, In) error,
	summarize func(*C) any,
	opts ...writeOption[In],
) func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, any, error) {
		loc, err := resolveSystemScope(d, in.systemScope(), p)
		if err != nil {
			res, v := errorResult("%s: %v", tool, err)
			return res, v, nil
		}
		defer d.LockWrites()()
		cfg, err := svc.Read(ctx, loc, "get")
		absent := false
		if err != nil {
			if !isSingletonAbsent(err) {
				// The seed read is a get and carries no submitted secret, so it
				// collapses the raw-response fallback like the read cores do.
				res, v := deviceErrorResult(d, tool, err)
				return res, v, nil
			}
			// The config node does not exist yet: overlay onto an empty config and
			// create it. pango's Update reads the existing node first and fails if
			// it is absent, so a first-time write must go through Create.
			absent = true
			cfg = new(C)
		}
		if err := overlay(cfg, in); err != nil {
			res, v := errorResult("%s: %v", tool, err)
			return res, v, nil
		}
		var updated *C
		if absent {
			updated, err = svc.Create(ctx, loc, cfg)
		} else {
			updated, err = svc.Update(ctx, loc, cfg, "")
		}
		if err != nil {
			red := redactWriteError(err, &in, opts)
			d.Logger.Error("failed: "+tool, "error", red)
			res, v := errorResult("failed: %s: %s", tool, red)
			return res, v, nil
		}
		d.Logger.Info(tool + " succeeded")
		res, v := jsonResult(summarize(updated))
		return res, v, nil
	}
}
