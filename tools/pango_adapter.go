package tools

import (
	"context"
	"fmt"

	"github.com/PaloAltoNetworks/pango/util"
	"github.com/PaloAltoNetworks/pango/version"
)

// xpathLocation is the one location capability the name-fix adapter needs:
// building the config xpath for a single entry component.
type xpathLocation interface {
	XpathWithComponents(version.Number, ...string) ([]string, error)
}

// nameFixService is the surface of a generated pango CRUD service that
// nameFixAdapter drives. It deliberately omits the SDK's name-based Update:
// that method, like name-based Read, passes the raw object name to
// Location.XpathWithComponents (objects/*/service.go read/Update), which rejects
// any component not shaped like "entry[...]" (objects/*/location.go
// XpathWithComponents), so both fail client-side on any real name. The adapter
// reaches an update only through the xpath-based methods, so leaving name-based
// Update out of the interface makes calling it a compile error rather than a
// latent runtime failure. A concrete pango service still satisfies this
// interface even though it also defines the omitted method.
type nameFixService[L xpathLocation, E any] interface {
	Create(ctx context.Context, loc L, entry *E) (*E, error)
	Read(ctx context.Context, loc L, name, action string) (*E, error)
	ReadWithXpath(ctx context.Context, xpath, action string) (*E, error)
	UpdateWithXpath(ctx context.Context, xpath string, entry *E, name string) error
	Delete(ctx context.Context, loc L, name ...string) error
	List(ctx context.Context, loc L, action, filter, quote string) ([]*E, error)
}

// checkNoRename rejects an update whose target name differs from the entry's
// own name. The update tools never rename (overlays do not touch Name) and
// updateCore passes name equal to the entry name, so a mismatch can only come
// from a direct-caller misuse; it is rejected rather than driving pango's
// rename path. A blank name means "use the entry's own name" and passes.
// Shared by nameFixAdapter.Update and parentFixAdapter.Update, which enforced
// this with identical inline blocks.
func checkNoRename(name, entryName string) error {
	if name != "" && name != entryName {
		return fmt.Errorf("renaming is not supported: the update name %q must match the entry name %q", name, entryName)
	}
	return nil
}

// nameFixAdapter adapts a generated pango CRUD service to crudService,
// pre-wrapping names with util.AsEntryXpath for Read and driving Update through
// the xpath-based SDK methods so both route around pango's raw-name rejection
// (see nameFixService). Create, Delete, and List wrap the name themselves in the
// SDK and pass through unchanged. Every object resource shares this one adapter;
// the name accessor returns an entry's Name field, which generics cannot read
// off E directly.
//
// Revisit on any pango upgrade: if the SDK starts wrapping names internally,
// this adapter would double-wrap. Every object resource's *APIErrorSurfaces test
// asserts via assertSingleWrappedGet that the get reaches the API wrapped exactly
// once, rejecting a double-wrapped entry[@name='entry[@name=...', which flags such
// a regression.
type nameFixAdapter[L xpathLocation, E any] struct {
	svc    nameFixService[L, E]
	client util.PangoClient
	name   func(*E) string
}

// Create passes through: the SDK wraps the entry name itself.
func (a nameFixAdapter[L, E]) Create(ctx context.Context, loc L, entry *E) (*E, error) {
	return a.svc.Create(ctx, loc, entry)
}

// Read fetches one entry by name using the given action ("get" or "show"),
// pre-wrapping the name into an entry xpath the SDK's name-based Read would
// otherwise reject.
func (a nameFixAdapter[L, E]) Read(ctx context.Context, loc L, name, action string) (*E, error) {
	return a.svc.Read(ctx, loc, util.AsEntryXpath(name), action)
}

// Update edits the entry in place, mirroring the SDK's name-based Update with
// the xpath built from a properly wrapped entry name, behind the shared
// checkNoRename guard.
func (a nameFixAdapter[L, E]) Update(ctx context.Context, loc L, entry *E, name string) (*E, error) {
	entryName := a.name(entry)
	if err := checkNoRename(name, entryName); err != nil {
		return nil, err
	}
	path, err := loc.XpathWithComponents(a.client.Versioning(), util.AsEntryXpath(entryName))
	if err != nil {
		return nil, err
	}
	xpath := util.AsXpath(path)
	if err := a.svc.UpdateWithXpath(ctx, xpath, entry, name); err != nil {
		return nil, err
	}
	return a.svc.ReadWithXpath(ctx, xpath, "get")
}

// Delete passes through: the SDK wraps each name itself.
func (a nameFixAdapter[L, E]) Delete(ctx context.Context, loc L, name ...string) error {
	return a.svc.Delete(ctx, loc, name...)
}

// List passes through: the SDK builds the location xpath without a per-entry
// name.
func (a nameFixAdapter[L, E]) List(ctx context.Context, loc L, action, filter, quote string) ([]*E, error) {
	return a.svc.List(ctx, loc, action, filter, quote)
}
