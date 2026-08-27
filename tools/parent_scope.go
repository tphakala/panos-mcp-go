package tools

import (
	"context"
	"errors"

	"github.com/PaloAltoNetworks/pango/util"
	"github.com/PaloAltoNetworks/pango/xmlapi"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Parent-scoped CRUD adapter (two-component xpath)
// ---------------------------------------------------------------------------
//
// A few pango resources are addressed by a two-component xpath: a parent entry
// (a virtual-router, or a physical/aggregate interface) and the child entry
// itself. Their Location.XpathWithComponents requires exactly two components,
// so every name-based SDK method (Create, Read, Delete, List, Update) fails
// client-side because those pass a single component. There is also no
// DeleteWithXpath on these services.
//
// parentFixAdapter bridges that gap: it assembles the two-component xpath
// itself, drives the SDK's *WithXpath methods for create/read/update/list, and
// implements Delete via client.MultiConfig, mirroring the SDK's own delete
// exactly. It is generic over the base net-scope location L and the entry E, so
// all four parent-scoped families (ipv4/ipv6 static routes, ethernet/aggregate
// layer3 subinterfaces) share this one adapter.

// parentScopeLoc pairs a net-scope pango location with the parent entry name
// (virtual-router or parent interface) so a two-component xpath can be built.
type parentScopeLoc[L xpathLocation] struct {
	loc    L
	parent string
}

// parentFixService is the *WithXpath surface a two-component pango service
// exposes. It deliberately omits every name-based method (all fail on a
// two-component location) and DeleteWithXpath (the SDK has none). A concrete
// pango *Service still satisfies this interface even though it also defines the
// omitted name-based methods, exactly as with nameFixService.
type parentFixService[E any] interface {
	CreateWithXpath(ctx context.Context, xpath string, entry *E) error
	ReadWithXpath(ctx context.Context, xpath, action string) (*E, error)
	UpdateWithXpath(ctx context.Context, xpath string, entry *E, name string) error
	ListWithXpath(ctx context.Context, xpath, action, filter, quote string) ([]*E, error)
}

// parentFixAdapter adapts a two-component pango service to crudService: it
// assembles the parent+child xpath itself, drives the *WithXpath methods, and
// deletes via client.MultiConfig, mirroring the SDK's own delete. The name
// accessor returns an entry's Name field, which generics cannot read off E
// directly.
type parentFixAdapter[L xpathLocation, E any] struct {
	svc    parentFixService[E]
	client util.PangoClient
	name   func(*E) string
}

// Create mirrors the SDK Create for a two-component service: build the full
// parent+child path, set at the child collection node (path without its last
// component), then read the full path back. Targeting path[:len(path)-1] is
// what makes the "set" land on the static-route / units collection rather than
// the child entry node.
func (a parentFixAdapter[L, E]) Create(ctx context.Context, ps parentScopeLoc[L], entry *E) (*E, error) {
	vn := a.client.Versioning()
	path, err := ps.loc.XpathWithComponents(vn, util.AsEntryXpath(ps.parent), util.AsEntryXpath(a.name(entry)))
	if err != nil {
		return nil, err
	}
	if err := a.svc.CreateWithXpath(ctx, util.AsXpath(path[:len(path)-1]), entry); err != nil {
		return nil, err
	}
	return a.svc.ReadWithXpath(ctx, util.AsXpath(path), "get")
}

// Read fetches one child entry by name at the full two-component path.
func (a parentFixAdapter[L, E]) Read(ctx context.Context, ps parentScopeLoc[L], name, action string) (*E, error) {
	vn := a.client.Versioning()
	path, err := ps.loc.XpathWithComponents(vn, util.AsEntryXpath(ps.parent), util.AsEntryXpath(name))
	if err != nil {
		return nil, err
	}
	return a.svc.ReadWithXpath(ctx, util.AsXpath(path), action)
}

// Update edits the child entry in place at the full two-component path, behind
// the shared checkNoRename guard that nameFixAdapter.Update also uses.
func (a parentFixAdapter[L, E]) Update(ctx context.Context, ps parentScopeLoc[L], entry *E, name string) (*E, error) {
	entryName := a.name(entry)
	if err := checkNoRename(name, entryName); err != nil {
		return nil, err
	}
	vn := a.client.Versioning()
	path, err := ps.loc.XpathWithComponents(vn, util.AsEntryXpath(ps.parent), util.AsEntryXpath(entryName))
	if err != nil {
		return nil, err
	}
	xpath := util.AsXpath(path)
	if err := a.svc.UpdateWithXpath(ctx, xpath, entry, name); err != nil {
		return nil, err
	}
	return a.svc.ReadWithXpath(ctx, xpath, "get")
}

// Delete removes each named child entry via client.MultiConfig, mirroring the
// SDK's own delete mechanics (there is no DeleteWithXpath): a "delete"
// xmlapi.Config per full two-component path, submitted as a non-strict
// multi-config. It is not byte-for-byte identical to the SDK: the path carries
// the extra parent component, and this guards each blank name up front (the SDK
// rejects a blank name the same way, via errors.NameNotSpecifiedError).
func (a parentFixAdapter[L, E]) Delete(ctx context.Context, ps parentScopeLoc[L], name ...string) error {
	vn := a.client.Versioning()
	deletes := xmlapi.NewMultiConfig(len(name))
	for _, n := range name {
		if n == "" {
			return errors.New("name is not specified")
		}
		path, err := ps.loc.XpathWithComponents(vn, util.AsEntryXpath(ps.parent), util.AsEntryXpath(n))
		if err != nil {
			return err
		}
		deletes.Add(&xmlapi.Config{
			Action: "delete",
			Xpath:  util.AsXpath(path),
			Target: a.client.GetTarget(),
		})
	}
	//nolint:bodyclose // pango already closed the body (client.go:1230)
	_, _, _, err := a.client.MultiConfig(ctx, deletes, false, nil)
	return err
}

// List returns the child entries at the parent, using util.AsEntryXpath("")
// (the literal "entry") for the child component, exactly as the SDK's own list.
func (a parentFixAdapter[L, E]) List(ctx context.Context, ps parentScopeLoc[L], action, filter, quote string) ([]*E, error) {
	vn := a.client.Versioning()
	path, err := ps.loc.XpathWithComponents(vn, util.AsEntryXpath(ps.parent), util.AsEntryXpath(""))
	if err != nil {
		return nil, err
	}
	return a.svc.ListWithXpath(ctx, util.AsXpath(path), action, filter, quote)
}

// resolveParentNetScope resolves the base net-scope location, then attaches a
// required parent entry name. A blank parent is an error so a two-component
// xpath is never built with a missing parent component.
func resolveParentNetScope[L xpathLocation](d *Deps, in NetScopeInput, parent string, p netScopeParts[L]) (parentScopeLoc[L], error) {
	if parent == "" {
		return parentScopeLoc[L]{}, errors.New("a parent entry name is required (virtual_router or parent_interface)")
	}
	loc, err := resolveNetScope(d, in, p)
	if err != nil {
		return parentScopeLoc[L]{}, err
	}
	return parentScopeLoc[L]{loc: loc, parent: parent}, nil
}

// The five parent*Handler wrappers mirror the net-scope handlers but over
// parentScopeLoc[L] and a per-input parent accessor. Each is generic over In so
// a family supplies its own input struct (list/name/full).

func parentListHandler[L xpathLocation, E any, In netScoped](
	d *Deps, tool string, svc crudService[parentScopeLoc[L], E], p netScopeParts[L],
	parent func(In) string,
	page func(In) (limit, offset int, filter string),
	name func(*E) string, summarize func(*E) any,
) func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, any, error) {
	return listCore(d, tool, svc,
		func(in In) (parentScopeLoc[L], error) { return resolveParentNetScope(d, in.netScope(), parent(in), p) },
		page, name, summarize)
}

func parentGetHandler[L xpathLocation, E any, In netScoped](
	d *Deps, tool string, svc crudService[parentScopeLoc[L], E], p netScopeParts[L],
	parent func(In) string,
	name func(In) string, summarize func(*E) any,
) func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, any, error) {
	return getCore(d, tool, svc,
		func(in In) (parentScopeLoc[L], error) { return resolveParentNetScope(d, in.netScope(), parent(in), p) },
		name, summarize)
}

func parentDeleteHandler[L xpathLocation, E any, In netScoped](
	d *Deps, tool string, svc crudService[parentScopeLoc[L], E], p netScopeParts[L],
	parent func(In) string,
	name func(In) string,
) func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, any, error) {
	return deleteCore(d, tool, svc,
		func(in In) (parentScopeLoc[L], error) { return resolveParentNetScope(d, in.netScope(), parent(in), p) },
		name)
}

func parentCreateHandler[L xpathLocation, E any, In netScoped](
	d *Deps, tool string, svc crudService[parentScopeLoc[L], E], p netScopeParts[L],
	parent func(In) string,
	build func(In) (*E, error), summarize func(*E) any,
	opts ...writeOption[In],
) func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, any, error) {
	return createCore(d, tool, svc,
		func(in In) (parentScopeLoc[L], error) { return resolveParentNetScope(d, in.netScope(), parent(in), p) },
		build, summarize, opts...)
}

func parentUpdateHandler[L xpathLocation, E any, In netScoped](
	d *Deps, tool string, svc crudService[parentScopeLoc[L], E], p netScopeParts[L],
	parent func(In) string,
	name func(In) string, overlay func(*E, In) error, summarize func(*E) any,
	opts ...writeOption[In],
) func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, any, error) {
	return updateCore(d, tool, svc,
		func(in In) (parentScopeLoc[L], error) { return resolveParentNetScope(d, in.netScope(), parent(in), p) },
		name, overlay, summarize, opts...)
}
