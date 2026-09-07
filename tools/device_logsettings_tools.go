package tools

import (
	"errors"

	lsconfig "github.com/PaloAltoNetworks/pango/device/logsettings/config"
	lscorrelation "github.com/PaloAltoNetworks/pango/device/logsettings/correlation"
	lsgp "github.com/PaloAltoNetworks/pango/device/logsettings/globalprotect"
	lship "github.com/PaloAltoNetworks/pango/device/logsettings/hipmatch"
	lsiptag "github.com/PaloAltoNetworks/pango/device/logsettings/iptag"
	lssystem "github.com/PaloAltoNetworks/pango/device/logsettings/system"
	lsuserid "github.com/PaloAltoNetworks/pango/device/logsettings/userid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Device log settings (device/logsettings/*)
// ---------------------------------------------------------------------------
//
// Each of the seven log-settings families (config, system, correlation,
// globalprotect, hipmatch, iptag, userid) is a named-entry "match-list": a rule
// that matches a slice of device logs by a filter and forwards them to email,
// HTTP, SNMP-trap and syslog server profiles. Most families can additionally
// forward to Panorama (send_to_panorama; absent on correlation) and most can
// quarantine the source device (quarantine; absent on config and system).
//
// pango models these only under Panorama (Location is Panorama, or a template /
// template-stack, optionally narrowed to a vsys). There is no firewall-local
// location, so these tools are registered on Panorama only. A firewall stores
// the same match lists under config/shared, which pango's Location cannot
// address; that is a documented follow-up, not exposed here.
//
// The seven families share most fields but are distinct pango types with no
// common interface, so the shared field handling below takes the entry's fields
// by pointer while the per-family overlay/summary map the family-specific
// toggles (send_to_panorama, quarantine). Six families (all but config) carry an
// Actions integration/tagging tree that this server does not model; the overlay
// never touches it, so it round-trips unchanged across a read-modify-write, the
// same stance the security rule tools take for individual security profiles.

const (
	filterKey         = "filter"
	quarantineKey     = "quarantine"
	sendToPanoramaKey = "send_to_panorama"
)

// LogMatchCommon holds the fields every log-settings match-list family shares.
// It is embedded in each family's create/update input so the shared overlay and
// summary can be written once.
type LogMatchCommon struct {
	Description  *string  `json:"description,omitzero" jsonschema:"Free-text description"`
	Filter       *string  `json:"filter,omitzero" jsonschema:"Log filter expression selecting which logs this entry matches"`
	SendEmail    []string `json:"send_email,omitempty" jsonschema:"Email server profile names to forward matching logs to; a provided list replaces the stored one and an empty list clears it"`
	SendHttp     []string `json:"send_http,omitempty" jsonschema:"HTTP server profile names to forward matching logs to; a provided list replaces the stored one and an empty list clears it"`
	SendSnmptrap []string `json:"send_snmptrap,omitempty" jsonschema:"SNMP-trap server profile names to forward matching logs to; a provided list replaces the stored one and an empty list clears it"`
	SendSyslog   []string `json:"send_syslog,omitempty" jsonschema:"Syslog server profile names to forward matching logs to; a provided list replaces the stored one and an empty list clears it"`
}

// LogSettingsStdInput is the input for the config and system families: the
// shared fields plus send_to_panorama. Those two families have no quarantine
// toggle.
type LogSettingsStdInput struct {
	DeviceScopeInput
	Name string `json:"name" jsonschema:"Match-list entry name"`
	LogMatchCommon
	SendToPanorama *bool `json:"send_to_panorama,omitzero" jsonschema:"Forward matching logs to Panorama"`
}

// LogSettingsFullInput is the input for the globalprotect, hipmatch, iptag and
// userid families: the shared fields plus both quarantine and send_to_panorama.
type LogSettingsFullInput struct {
	DeviceScopeInput
	Name string `json:"name" jsonschema:"Match-list entry name"`
	LogMatchCommon
	Quarantine     *bool `json:"quarantine,omitzero" jsonschema:"Add the source device of a matching log to the quarantine list"`
	SendToPanorama *bool `json:"send_to_panorama,omitzero" jsonschema:"Forward matching logs to Panorama"`
}

// LogSettingsCorrelationInput is the input for the correlation family: the
// shared fields plus quarantine. Correlation entries have no send_to_panorama
// toggle.
type LogSettingsCorrelationInput struct {
	DeviceScopeInput
	Name string `json:"name" jsonschema:"Match-list entry name"`
	LogMatchCommon
	Quarantine *bool `json:"quarantine,omitzero" jsonschema:"Add the source device of a matching log to the quarantine list"`
}

// setList replaces *dst with in when in is non-nil, so a provided list replaces
// the stored one and an explicit empty list clears it, while a nil (omitted)
// list leaves *dst untouched. Log-settings forwarding lists are valid when
// empty, so this uses the profile-list semantics rather than
// replaceListOrRejectEmpty.
func setList(dst *[]string, in []string) {
	if in != nil {
		*dst = in
	}
}

// applyLogMatchCommon overlays the shared match-list fields onto an entry's
// fields, taken by pointer because the seven pango families are distinct types
// with no common interface. setPtr keeps a stored scalar when the caller omits
// it; setList replaces a forwarding list only when one is provided.
func applyLogMatchCommon(desc, filter **string, email, http, snmptrap, syslog *[]string, in *LogMatchCommon) {
	setPtr(desc, in.Description)
	setPtr(filter, in.Filter)
	setList(email, in.SendEmail)
	setList(http, in.SendHttp)
	setList(snmptrap, in.SendSnmptrap)
	setList(syslog, in.SendSyslog)
}

// logMatchCommonSummary projects the shared match-list fields. A description or
// filter renders "" when unset and each forwarding list renders [] when unset,
// never null; the per-family toggles the caller appends with putBool are omitted
// entirely when nil (tri-state, issue #67).
func logMatchCommonSummary(name string, desc, filter *string, email, http, snmptrap, syslog []string) map[string]any {
	return map[string]any{
		tagNameKey:      name,
		descriptionKey:  strVal(desc),
		filterKey:       strVal(filter),
		"send_email":    strList(email),
		"send_http":     strList(http),
		"send_snmptrap": strList(snmptrap),
		"send_syslog":   strList(syslog),
	}
}

// registerLogSettingsFamily wires the five CRUD tools for one log-settings
// family. The read tools are always registered; the write tools are skipped in
// read-only mode. build is assembled from newEntry and overlayFn so the seven
// families need supply only their pango types and field mapping.
func registerLogSettingsFamily[L, E any, In deviceScoped](
	s *mcp.Server, d *Deps,
	prefix, human string,
	svc crudService[L, E], parts deviceScopeParts[L],
	nameFn func(*E) string,
	newEntry func(name string) *E,
	nameOf func(In) string,
	overlayFn func(*E, In) error,
	summarize func(*E) any,
) {
	build := func(in In) (*E, error) {
		n := nameOf(in)
		if n == "" {
			return nil, errors.New("name is required")
		}
		e := newEntry(n)
		if err := overlayFn(e, in); err != nil {
			return nil, err
		}
		return e, nil
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        prefix + "_list",
		Description: "List " + human + " log-settings match-list entries. Panorama only: set a template or template_stack (optionally narrowed to a template_vsys), or the panorama scope (list templates with panos_template_list). Read-only.",
		Annotations: readOnlyTool("List " + human + " log settings"),
	}, deviceListHandler(d, prefix+"_list", svc, parts, nameFn, summarize))
	mcp.AddTool(s, &mcp.Tool{
		Name:        prefix + "_get",
		Description: "Get one " + human + " log-settings match-list entry (filter, forwarding server-profile lists, and toggles). Read-only.",
		Annotations: readOnlyTool("Get " + human + " log settings"),
	}, deviceGetHandler(d, prefix+"_get", svc, parts, summarize))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        prefix + "_create",
		Description: "Create a " + human + " log-settings match-list entry in the candidate config. Only name is required. Run panos_commit to apply.",
		Annotations: createTool("Create " + human + " log settings"),
	}, deviceCreateHandler(d, prefix+"_create", svc, parts, build, summarize))
	mcp.AddTool(s, &mcp.Tool{
		Name:        prefix + "_update",
		Description: "Update a " + human + " log-settings match-list entry: read-modify-write, only provided fields change; a provided forwarding list replaces the stored one and an empty list clears it. Run panos_commit to apply.",
		Annotations: updateTool("Update " + human + " log settings"),
	}, deviceUpdateHandler(d, prefix+"_update", svc, parts, nameOf, overlayFn, summarize))
	mcp.AddTool(s, &mcp.Tool{
		Name:        prefix + "_delete",
		Description: "Delete a " + human + " log-settings match-list entry from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete " + human + " log settings"),
	}, deviceDeleteHandler(d, prefix+"_delete", svc, parts))
}

// logSettingsParts builds the device-scope constructors shared by every
// log-settings family: the Panorama management-plane scope and the four template
// tiers. shared and vsys are left nil, so resolveDeviceScope rejects a firewall
// or shared request for these Panorama-only families.
func logSettingsConfigParts() deviceScopeParts[lsconfig.Location] {
	return deviceScopeParts[lsconfig.Location]{
		panorama: func() lsconfig.Location { return lsconfig.Location{Panorama: &lsconfig.PanoramaLocation{}} },
		template: func(pano, tmpl string) lsconfig.Location {
			return lsconfig.Location{Template: &lsconfig.TemplateLocation{PanoramaDevice: pano, Template: tmpl}}
		},
		templateVsys: func(pano, tmpl, ngfw, vsys string) lsconfig.Location {
			return lsconfig.Location{TemplateVsys: &lsconfig.TemplateVsysLocation{PanoramaDevice: pano, Template: tmpl, NgfwDevice: ngfw, Vsys: vsys}}
		},
		templateStack: func(pano, stack string) lsconfig.Location {
			return lsconfig.Location{TemplateStack: &lsconfig.TemplateStackLocation{PanoramaDevice: pano, TemplateStack: stack}}
		},
		templateStackVsys: func(pano, stack, ngfw, vsys string) lsconfig.Location {
			return lsconfig.Location{TemplateStackVsys: &lsconfig.TemplateStackVsysLocation{PanoramaDevice: pano, TemplateStack: stack, NgfwDevice: ngfw, Vsys: vsys}}
		},
	}
}

func logSettingsSystemParts() deviceScopeParts[lssystem.Location] {
	return deviceScopeParts[lssystem.Location]{
		panorama: func() lssystem.Location { return lssystem.Location{Panorama: &lssystem.PanoramaLocation{}} },
		template: func(pano, tmpl string) lssystem.Location {
			return lssystem.Location{Template: &lssystem.TemplateLocation{PanoramaDevice: pano, Template: tmpl}}
		},
		templateVsys: func(pano, tmpl, ngfw, vsys string) lssystem.Location {
			return lssystem.Location{TemplateVsys: &lssystem.TemplateVsysLocation{PanoramaDevice: pano, Template: tmpl, NgfwDevice: ngfw, Vsys: vsys}}
		},
		templateStack: func(pano, stack string) lssystem.Location {
			return lssystem.Location{TemplateStack: &lssystem.TemplateStackLocation{PanoramaDevice: pano, TemplateStack: stack}}
		},
		templateStackVsys: func(pano, stack, ngfw, vsys string) lssystem.Location {
			return lssystem.Location{TemplateStackVsys: &lssystem.TemplateStackVsysLocation{PanoramaDevice: pano, TemplateStack: stack, NgfwDevice: ngfw, Vsys: vsys}}
		},
	}
}

func logSettingsCorrelationParts() deviceScopeParts[lscorrelation.Location] {
	return deviceScopeParts[lscorrelation.Location]{
		panorama: func() lscorrelation.Location {
			return lscorrelation.Location{Panorama: &lscorrelation.PanoramaLocation{}}
		},
		template: func(pano, tmpl string) lscorrelation.Location {
			return lscorrelation.Location{Template: &lscorrelation.TemplateLocation{PanoramaDevice: pano, Template: tmpl}}
		},
		templateVsys: func(pano, tmpl, ngfw, vsys string) lscorrelation.Location {
			return lscorrelation.Location{TemplateVsys: &lscorrelation.TemplateVsysLocation{PanoramaDevice: pano, Template: tmpl, NgfwDevice: ngfw, Vsys: vsys}}
		},
		templateStack: func(pano, stack string) lscorrelation.Location {
			return lscorrelation.Location{TemplateStack: &lscorrelation.TemplateStackLocation{PanoramaDevice: pano, TemplateStack: stack}}
		},
		templateStackVsys: func(pano, stack, ngfw, vsys string) lscorrelation.Location {
			return lscorrelation.Location{TemplateStackVsys: &lscorrelation.TemplateStackVsysLocation{PanoramaDevice: pano, TemplateStack: stack, NgfwDevice: ngfw, Vsys: vsys}}
		},
	}
}

func logSettingsGlobalProtectParts() deviceScopeParts[lsgp.Location] {
	return deviceScopeParts[lsgp.Location]{
		panorama: func() lsgp.Location { return lsgp.Location{Panorama: &lsgp.PanoramaLocation{}} },
		template: func(pano, tmpl string) lsgp.Location {
			return lsgp.Location{Template: &lsgp.TemplateLocation{PanoramaDevice: pano, Template: tmpl}}
		},
		templateVsys: func(pano, tmpl, ngfw, vsys string) lsgp.Location {
			return lsgp.Location{TemplateVsys: &lsgp.TemplateVsysLocation{PanoramaDevice: pano, Template: tmpl, NgfwDevice: ngfw, Vsys: vsys}}
		},
		templateStack: func(pano, stack string) lsgp.Location {
			return lsgp.Location{TemplateStack: &lsgp.TemplateStackLocation{PanoramaDevice: pano, TemplateStack: stack}}
		},
		templateStackVsys: func(pano, stack, ngfw, vsys string) lsgp.Location {
			return lsgp.Location{TemplateStackVsys: &lsgp.TemplateStackVsysLocation{PanoramaDevice: pano, TemplateStack: stack, NgfwDevice: ngfw, Vsys: vsys}}
		},
	}
}

func logSettingsHipMatchParts() deviceScopeParts[lship.Location] {
	return deviceScopeParts[lship.Location]{
		panorama: func() lship.Location { return lship.Location{Panorama: &lship.PanoramaLocation{}} },
		template: func(pano, tmpl string) lship.Location {
			return lship.Location{Template: &lship.TemplateLocation{PanoramaDevice: pano, Template: tmpl}}
		},
		templateVsys: func(pano, tmpl, ngfw, vsys string) lship.Location {
			return lship.Location{TemplateVsys: &lship.TemplateVsysLocation{PanoramaDevice: pano, Template: tmpl, NgfwDevice: ngfw, Vsys: vsys}}
		},
		templateStack: func(pano, stack string) lship.Location {
			return lship.Location{TemplateStack: &lship.TemplateStackLocation{PanoramaDevice: pano, TemplateStack: stack}}
		},
		templateStackVsys: func(pano, stack, ngfw, vsys string) lship.Location {
			return lship.Location{TemplateStackVsys: &lship.TemplateStackVsysLocation{PanoramaDevice: pano, TemplateStack: stack, NgfwDevice: ngfw, Vsys: vsys}}
		},
	}
}

func logSettingsIptagParts() deviceScopeParts[lsiptag.Location] {
	return deviceScopeParts[lsiptag.Location]{
		panorama: func() lsiptag.Location { return lsiptag.Location{Panorama: &lsiptag.PanoramaLocation{}} },
		template: func(pano, tmpl string) lsiptag.Location {
			return lsiptag.Location{Template: &lsiptag.TemplateLocation{PanoramaDevice: pano, Template: tmpl}}
		},
		templateVsys: func(pano, tmpl, ngfw, vsys string) lsiptag.Location {
			return lsiptag.Location{TemplateVsys: &lsiptag.TemplateVsysLocation{PanoramaDevice: pano, Template: tmpl, NgfwDevice: ngfw, Vsys: vsys}}
		},
		templateStack: func(pano, stack string) lsiptag.Location {
			return lsiptag.Location{TemplateStack: &lsiptag.TemplateStackLocation{PanoramaDevice: pano, TemplateStack: stack}}
		},
		templateStackVsys: func(pano, stack, ngfw, vsys string) lsiptag.Location {
			return lsiptag.Location{TemplateStackVsys: &lsiptag.TemplateStackVsysLocation{PanoramaDevice: pano, TemplateStack: stack, NgfwDevice: ngfw, Vsys: vsys}}
		},
	}
}

func logSettingsUseridParts() deviceScopeParts[lsuserid.Location] {
	return deviceScopeParts[lsuserid.Location]{
		panorama: func() lsuserid.Location { return lsuserid.Location{Panorama: &lsuserid.PanoramaLocation{}} },
		template: func(pano, tmpl string) lsuserid.Location {
			return lsuserid.Location{Template: &lsuserid.TemplateLocation{PanoramaDevice: pano, Template: tmpl}}
		},
		templateVsys: func(pano, tmpl, ngfw, vsys string) lsuserid.Location {
			return lsuserid.Location{TemplateVsys: &lsuserid.TemplateVsysLocation{PanoramaDevice: pano, Template: tmpl, NgfwDevice: ngfw, Vsys: vsys}}
		},
		templateStack: func(pano, stack string) lsuserid.Location {
			return lsuserid.Location{TemplateStack: &lsuserid.TemplateStackLocation{PanoramaDevice: pano, TemplateStack: stack}}
		},
		templateStackVsys: func(pano, stack, ngfw, vsys string) lsuserid.Location {
			return lsuserid.Location{TemplateStackVsys: &lsuserid.TemplateStackVsysLocation{PanoramaDevice: pano, TemplateStack: stack, NgfwDevice: ngfw, Vsys: vsys}}
		},
	}
}

// --- config -----------------------------------------------------------------

func newLogSettingsConfigService(d *Deps) nameFixAdapter[lsconfig.Location, lsconfig.Entry] {
	return nameFixAdapter[lsconfig.Location, lsconfig.Entry]{
		svc: lsconfig.NewService(d.Client), client: d.Client, name: func(e *lsconfig.Entry) string { return e.Name },
	}
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayLogSettingsConfig(e *lsconfig.Entry, in LogSettingsStdInput) error {
	applyLogMatchCommon(&e.Description, &e.Filter, &e.SendEmail, &e.SendHttp, &e.SendSnmptrap, &e.SendSyslog, &in.LogMatchCommon)
	setPtr(&e.SendToPanorama, in.SendToPanorama)
	return nil
}

func logSettingsConfigSummary(e *lsconfig.Entry) any {
	m := logMatchCommonSummary(e.Name, e.Description, e.Filter, e.SendEmail, e.SendHttp, e.SendSnmptrap, e.SendSyslog)
	putBool(m, sendToPanoramaKey, e.SendToPanorama)
	return m
}

// --- system -----------------------------------------------------------------

func newLogSettingsSystemService(d *Deps) nameFixAdapter[lssystem.Location, lssystem.Entry] {
	return nameFixAdapter[lssystem.Location, lssystem.Entry]{
		svc: lssystem.NewService(d.Client), client: d.Client, name: func(e *lssystem.Entry) string { return e.Name },
	}
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayLogSettingsSystem(e *lssystem.Entry, in LogSettingsStdInput) error {
	applyLogMatchCommon(&e.Description, &e.Filter, &e.SendEmail, &e.SendHttp, &e.SendSnmptrap, &e.SendSyslog, &in.LogMatchCommon)
	setPtr(&e.SendToPanorama, in.SendToPanorama)
	return nil
}

func logSettingsSystemSummary(e *lssystem.Entry) any {
	m := logMatchCommonSummary(e.Name, e.Description, e.Filter, e.SendEmail, e.SendHttp, e.SendSnmptrap, e.SendSyslog)
	putBool(m, sendToPanoramaKey, e.SendToPanorama)
	return m
}

// --- correlation ------------------------------------------------------------

func newLogSettingsCorrelationService(d *Deps) nameFixAdapter[lscorrelation.Location, lscorrelation.Entry] {
	return nameFixAdapter[lscorrelation.Location, lscorrelation.Entry]{
		svc: lscorrelation.NewService(d.Client), client: d.Client, name: func(e *lscorrelation.Entry) string { return e.Name },
	}
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayLogSettingsCorrelation(e *lscorrelation.Entry, in LogSettingsCorrelationInput) error {
	applyLogMatchCommon(&e.Description, &e.Filter, &e.SendEmail, &e.SendHttp, &e.SendSnmptrap, &e.SendSyslog, &in.LogMatchCommon)
	setPtr(&e.Quarantine, in.Quarantine)
	return nil
}

func logSettingsCorrelationSummary(e *lscorrelation.Entry) any {
	m := logMatchCommonSummary(e.Name, e.Description, e.Filter, e.SendEmail, e.SendHttp, e.SendSnmptrap, e.SendSyslog)
	putBool(m, quarantineKey, e.Quarantine)
	return m
}

// --- globalprotect ----------------------------------------------------------

func newLogSettingsGlobalProtectService(d *Deps) nameFixAdapter[lsgp.Location, lsgp.Entry] {
	return nameFixAdapter[lsgp.Location, lsgp.Entry]{
		svc: lsgp.NewService(d.Client), client: d.Client, name: func(e *lsgp.Entry) string { return e.Name },
	}
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayLogSettingsGlobalProtect(e *lsgp.Entry, in LogSettingsFullInput) error {
	applyLogMatchCommon(&e.Description, &e.Filter, &e.SendEmail, &e.SendHttp, &e.SendSnmptrap, &e.SendSyslog, &in.LogMatchCommon)
	setPtr(&e.Quarantine, in.Quarantine)
	setPtr(&e.SendToPanorama, in.SendToPanorama)
	return nil
}

func logSettingsGlobalProtectSummary(e *lsgp.Entry) any {
	m := logMatchCommonSummary(e.Name, e.Description, e.Filter, e.SendEmail, e.SendHttp, e.SendSnmptrap, e.SendSyslog)
	putBool(m, quarantineKey, e.Quarantine)
	putBool(m, sendToPanoramaKey, e.SendToPanorama)
	return m
}

// --- hipmatch ---------------------------------------------------------------

func newLogSettingsHipMatchService(d *Deps) nameFixAdapter[lship.Location, lship.Entry] {
	return nameFixAdapter[lship.Location, lship.Entry]{
		svc: lship.NewService(d.Client), client: d.Client, name: func(e *lship.Entry) string { return e.Name },
	}
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayLogSettingsHipMatch(e *lship.Entry, in LogSettingsFullInput) error {
	applyLogMatchCommon(&e.Description, &e.Filter, &e.SendEmail, &e.SendHttp, &e.SendSnmptrap, &e.SendSyslog, &in.LogMatchCommon)
	setPtr(&e.Quarantine, in.Quarantine)
	setPtr(&e.SendToPanorama, in.SendToPanorama)
	return nil
}

func logSettingsHipMatchSummary(e *lship.Entry) any {
	m := logMatchCommonSummary(e.Name, e.Description, e.Filter, e.SendEmail, e.SendHttp, e.SendSnmptrap, e.SendSyslog)
	putBool(m, quarantineKey, e.Quarantine)
	putBool(m, sendToPanoramaKey, e.SendToPanorama)
	return m
}

// --- iptag ------------------------------------------------------------------

func newLogSettingsIptagService(d *Deps) nameFixAdapter[lsiptag.Location, lsiptag.Entry] {
	return nameFixAdapter[lsiptag.Location, lsiptag.Entry]{
		svc: lsiptag.NewService(d.Client), client: d.Client, name: func(e *lsiptag.Entry) string { return e.Name },
	}
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayLogSettingsIptag(e *lsiptag.Entry, in LogSettingsFullInput) error {
	applyLogMatchCommon(&e.Description, &e.Filter, &e.SendEmail, &e.SendHttp, &e.SendSnmptrap, &e.SendSyslog, &in.LogMatchCommon)
	setPtr(&e.Quarantine, in.Quarantine)
	setPtr(&e.SendToPanorama, in.SendToPanorama)
	return nil
}

func logSettingsIptagSummary(e *lsiptag.Entry) any {
	m := logMatchCommonSummary(e.Name, e.Description, e.Filter, e.SendEmail, e.SendHttp, e.SendSnmptrap, e.SendSyslog)
	putBool(m, quarantineKey, e.Quarantine)
	putBool(m, sendToPanoramaKey, e.SendToPanorama)
	return m
}

// --- userid -----------------------------------------------------------------

func newLogSettingsUseridService(d *Deps) nameFixAdapter[lsuserid.Location, lsuserid.Entry] {
	return nameFixAdapter[lsuserid.Location, lsuserid.Entry]{
		svc: lsuserid.NewService(d.Client), client: d.Client, name: func(e *lsuserid.Entry) string { return e.Name },
	}
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayLogSettingsUserid(e *lsuserid.Entry, in LogSettingsFullInput) error {
	applyLogMatchCommon(&e.Description, &e.Filter, &e.SendEmail, &e.SendHttp, &e.SendSnmptrap, &e.SendSyslog, &in.LogMatchCommon)
	setPtr(&e.Quarantine, in.Quarantine)
	setPtr(&e.SendToPanorama, in.SendToPanorama)
	return nil
}

func logSettingsUseridSummary(e *lsuserid.Entry) any {
	m := logMatchCommonSummary(e.Name, e.Description, e.Filter, e.SendEmail, e.SendHttp, e.SendSnmptrap, e.SendSyslog)
	putBool(m, quarantineKey, e.Quarantine)
	putBool(m, sendToPanoramaKey, e.SendToPanorama)
	return m
}

// RegisterLogSettingsTools registers the seven device log-settings families.
// They exist only under Panorama, so nothing is registered on a firewall.
// Mutating tools are skipped in read-only mode.
func RegisterLogSettingsTools(s *mcp.Server, d *Deps) {
	if !d.IsPanorama {
		return
	}
	registerLogSettingsFamily(s, d, "panos_log_settings_config", "config",
		newLogSettingsConfigService(d), logSettingsConfigParts(),
		func(e *lsconfig.Entry) string { return e.Name },
		func(n string) *lsconfig.Entry { return &lsconfig.Entry{Name: n} },
		func(in LogSettingsStdInput) string { return in.Name },
		overlayLogSettingsConfig, logSettingsConfigSummary)
	registerLogSettingsFamily(s, d, "panos_log_settings_system", "system",
		newLogSettingsSystemService(d), logSettingsSystemParts(),
		func(e *lssystem.Entry) string { return e.Name },
		func(n string) *lssystem.Entry { return &lssystem.Entry{Name: n} },
		func(in LogSettingsStdInput) string { return in.Name },
		overlayLogSettingsSystem, logSettingsSystemSummary)
	registerLogSettingsFamily(s, d, "panos_log_settings_correlation", "correlation",
		newLogSettingsCorrelationService(d), logSettingsCorrelationParts(),
		func(e *lscorrelation.Entry) string { return e.Name },
		func(n string) *lscorrelation.Entry { return &lscorrelation.Entry{Name: n} },
		func(in LogSettingsCorrelationInput) string { return in.Name },
		overlayLogSettingsCorrelation, logSettingsCorrelationSummary)
	registerLogSettingsFamily(s, d, "panos_log_settings_globalprotect", "GlobalProtect",
		newLogSettingsGlobalProtectService(d), logSettingsGlobalProtectParts(),
		func(e *lsgp.Entry) string { return e.Name },
		func(n string) *lsgp.Entry { return &lsgp.Entry{Name: n} },
		func(in LogSettingsFullInput) string { return in.Name },
		overlayLogSettingsGlobalProtect, logSettingsGlobalProtectSummary)
	registerLogSettingsFamily(s, d, "panos_log_settings_hip_match", "HIP match",
		newLogSettingsHipMatchService(d), logSettingsHipMatchParts(),
		func(e *lship.Entry) string { return e.Name },
		func(n string) *lship.Entry { return &lship.Entry{Name: n} },
		func(in LogSettingsFullInput) string { return in.Name },
		overlayLogSettingsHipMatch, logSettingsHipMatchSummary)
	registerLogSettingsFamily(s, d, "panos_log_settings_ip_tag", "IP-tag",
		newLogSettingsIptagService(d), logSettingsIptagParts(),
		func(e *lsiptag.Entry) string { return e.Name },
		func(n string) *lsiptag.Entry { return &lsiptag.Entry{Name: n} },
		func(in LogSettingsFullInput) string { return in.Name },
		overlayLogSettingsIptag, logSettingsIptagSummary)
	registerLogSettingsFamily(s, d, "panos_log_settings_user_id", "User-ID",
		newLogSettingsUseridService(d), logSettingsUseridParts(),
		func(e *lsuserid.Entry) string { return e.Name },
		func(n string) *lsuserid.Entry { return &lsuserid.Entry{Name: n} },
		func(in LogSettingsFullInput) string { return in.Name },
		overlayLogSettingsUserid, logSettingsUseridSummary)
}
