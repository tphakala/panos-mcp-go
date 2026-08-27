package tools

// Shared scope machinery
// ---------------------------------------------------------------------------
//
// Four scope families answer the same question in four different location
// trees: which pango location does this request name? Each owns a *ScopeInput
// struct (its public MCP schema), a resolver, and five thin handler wrappers
// over the generic *Core functions in tools.go.
//
// The resolvers stay separate on purpose. They are not four copies of one
// function: the input structs expose different tiers (the device scope has a
// vsys, the profile scope has a panorama scope, the net scope has neither), the
// firewall rejection messages are per-field in the net scope but combined in the
// device scope, and the cross-tier rules genuinely differ (the profile scope
// rejects a template combined with shared, while the device scope resolves it to
// the template). Merging them would either change tool input schemas, which are
// this server's public API, or change behaviour no test pins. Issue #98 allows
// that documented decision.
//
// What IS shared lives here: the scope accessors that let a handler pull a scope
// off any input that embeds one, and the Panorama template tier that the device
// and profile scopes implement identically.

// The scope accessor constraints. Every family input embeds its scope struct, so
// the single method defined on each scope struct is promoted to all of them and
// every input satisfies the matching constraint for free. That is what lets the
// create and update handlers take the scope off the input directly instead of
// each of the 45 registration sites passing a closure that does the same thing.
type (
	netScoped     interface{ netScope() NetScopeInput }
	deviceScoped  interface{ deviceScope() DeviceScopeInput }
	profileScoped interface{ profileScope() ProfileScopeInput }
)
