package tools

import (
	"errors"

	"github.com/PaloAltoNetworks/pango/device/services/logexport"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Scheduled log export (device/services/logexport)
// ---------------------------------------------------------------------------
//
// A scheduled log-export profile periodically pushes device logs to an FTP or
// SCP server. Unlike the DNS/NTP/general/proxy system services (singletons),
// this is a named-entry list living at the same {System | Template |
// TemplateStack} scope, so it uses the system-scope named-entry handlers
// (systemEntry*Handler) rather than the singleton get/update pair.
//
// The transport is a one-of: an entry carries either an FTP block or an SCP
// block, never both. Setting one through create/update clears the other. Each
// transport carries a write-only password: it is submitted on a write, scrubbed
// from any device-error message (withSecrets), and never returned by a get. The
// get summary reports only whether a password is set, following the update-proxy
// settings precedent.

func newLogExportScheduleService(d *Deps) nameFixAdapter[logexport.Location, logexport.Entry] {
	return nameFixAdapter[logexport.Location, logexport.Entry]{
		svc:    logexport.NewService(d.Client),
		client: d.Client,
		name:   func(e *logexport.Entry) string { return e.Name },
	}
}

func logExportScheduleParts() systemScopeParts[logexport.Location] {
	return systemScopeParts[logexport.Location]{
		system: func() logexport.Location {
			return logexport.Location{System: &logexport.SystemLocation{Device: defaultNgfwDevice}}
		},
		template: func(tmpl string) logexport.Location {
			return logexport.Location{Template: &logexport.TemplateLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, Template: tmpl,
			}}
		},
		templateStack: func(stack string) logexport.Location {
			return logexport.Location{TemplateStack: &logexport.TemplateStackLocation{
				NgfwDevice: defaultNgfwDevice, PanoramaDevice: defaultPanoramaDevice, TemplateStack: stack,
			}}
		},
	}
}

// LogExportFtpInput is the FTP transport block for a scheduled log export. Every
// field is optional on update (read-modify-write); password is write-only.
type LogExportFtpInput struct {
	Hostname    *string `json:"hostname,omitzero" jsonschema:"FTP server hostname or IP address"`
	Username    *string `json:"username,omitzero" jsonschema:"FTP username"`
	Password    *string `json:"password,omitzero" jsonschema:"FTP password (write-only; never returned by a get, omit on update to keep the stored one)"`
	Path        *string `json:"path,omitzero" jsonschema:"Remote directory path for the exported logs"`
	Port        *int64  `json:"port,omitzero" jsonschema:"FTP port (device default 21)"`
	PassiveMode *bool   `json:"passive_mode,omitzero" jsonschema:"Use FTP passive mode"`
}

// LogExportScpInput is the SCP transport block for a scheduled log export.
type LogExportScpInput struct {
	Hostname *string `json:"hostname,omitzero" jsonschema:"SCP server hostname or IP address"`
	Username *string `json:"username,omitzero" jsonschema:"SCP username"`
	Password *string `json:"password,omitzero" jsonschema:"SCP password (write-only; never returned by a get, omit on update to keep the stored one)"`
	Path     *string `json:"path,omitzero" jsonschema:"Remote directory path for the exported logs"`
	Port     *int64  `json:"port,omitzero" jsonschema:"SCP port (device default 22)"`
}

// LogExportScheduleInput is the input for the scheduled log-export create and
// update tools. ftp and scp are mutually exclusive: an entry uses one transport.
type LogExportScheduleInput struct {
	SystemScopeInput
	Name        string             `json:"name" jsonschema:"Scheduled log-export profile name"`
	Description *string            `json:"description,omitzero" jsonschema:"Free-text description"`
	Enable      *bool              `json:"enable,omitzero" jsonschema:"Enable this scheduled export"`
	LogType     *string            `json:"log_type,omitzero" jsonschema:"Log type to export (e.g. traffic, threat, url, data, wildfire, tunnel, auth, decryption, gtp, sctp)"`
	StartTime   *string            `json:"start_time,omitzero" jsonschema:"Daily export start time HH:MM (24-hour clock)"`
	Ftp         *LogExportFtpInput `json:"ftp,omitzero" jsonschema:"FTP transport settings; mutually exclusive with scp. Providing this switches the transport to FTP and clears any SCP block."`
	Scp         *LogExportScpInput `json:"scp,omitzero" jsonschema:"SCP transport settings; mutually exclusive with ftp. Providing this switches the transport to SCP and clears any FTP block."`
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic builder contract.
func buildLogExportSchedule(in LogExportScheduleInput) (*logexport.Entry, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	e := &logexport.Entry{Name: in.Name}
	if err := overlayLogExportScheduleFields(e, in); err != nil {
		return nil, err
	}
	return e, nil
}

//nolint:gocritic // hugeParam: in is by value to satisfy the generic overlay contract.
func overlayLogExportSchedule(e *logexport.Entry, in LogExportScheduleInput) error {
	return overlayLogExportScheduleFields(e, in)
}

// overlayLogExportScheduleFields applies the caller-provided fields onto e. It is
// the shared body behind both build (onto a fresh entry) and update (onto the
// stored entry). The transport one-of clears the sibling block so a switch never
// leaves both FTP and SCP present, which the device would reject; the provided
// transport block is itself a read-modify-write so omitting its password keeps
// the stored one (issue #99).
//
//nolint:gocritic // hugeParam: in is by value to match the build/overlay contract that calls this.
func overlayLogExportScheduleFields(e *logexport.Entry, in LogExportScheduleInput) error {
	if in.Ftp != nil && in.Scp != nil {
		return errors.New("set only one transport: ftp or scp, not both")
	}
	setPtr(&e.Description, in.Description)
	setPtr(&e.Enable, in.Enable)
	setPtr(&e.LogType, in.LogType)
	setPtr(&e.StartTime, in.StartTime)
	switch {
	case in.Ftp != nil:
		if e.Protocol == nil {
			e.Protocol = &logexport.Protocol{}
		}
		e.Protocol.Scp = nil
		if e.Protocol.Ftp == nil {
			e.Protocol.Ftp = &logexport.ProtocolFtp{}
		}
		f := e.Protocol.Ftp
		setPtr(&f.Hostname, in.Ftp.Hostname)
		setPtr(&f.Username, in.Ftp.Username)
		setPtr(&f.Password, in.Ftp.Password)
		setPtr(&f.Path, in.Ftp.Path)
		setPtr(&f.Port, in.Ftp.Port)
		setPtr(&f.PassiveMode, in.Ftp.PassiveMode)
	case in.Scp != nil:
		if e.Protocol == nil {
			e.Protocol = &logexport.Protocol{}
		}
		e.Protocol.Ftp = nil
		if e.Protocol.Scp == nil {
			e.Protocol.Scp = &logexport.ProtocolScp{}
		}
		s := e.Protocol.Scp
		setPtr(&s.Hostname, in.Scp.Hostname)
		setPtr(&s.Username, in.Scp.Username)
		setPtr(&s.Password, in.Scp.Password)
		setPtr(&s.Path, in.Scp.Path)
		setPtr(&s.Port, in.Scp.Port)
	}
	return nil
}

func logExportScheduleSummary(e *logexport.Entry) any {
	m := map[string]any{
		tagNameKey:     e.Name,
		descriptionKey: strVal(e.Description),
		"log_type":     strVal(e.LogType),
		"start_time":   strVal(e.StartTime),
		"protocol":     "",
	}
	putBool(m, "enable", e.Enable)
	if p := e.Protocol; p != nil {
		switch {
		case p.Ftp != nil:
			m["protocol"] = "ftp"
			f := p.Ftp
			fm := map[string]any{
				hostnameKey:    strVal(f.Hostname),
				usernameKey:    strVal(f.Username),
				"path":         strVal(f.Path),
				"password_set": f.Password != nil,
			}
			putInt(fm, "port", f.Port)
			putBool(fm, "passive_mode", f.PassiveMode)
			m["ftp"] = fm
		case p.Scp != nil:
			m["protocol"] = "scp"
			s := p.Scp
			sm := map[string]any{
				hostnameKey:    strVal(s.Hostname),
				usernameKey:    strVal(s.Username),
				"path":         strVal(s.Path),
				"password_set": s.Password != nil,
			}
			putInt(sm, "port", s.Port)
			m["scp"] = sm
		}
	}
	return m
}

// RegisterLogExportScheduleTools registers the scheduled log-export tools.
// Mutating tools are skipped entirely in read-only mode.
func RegisterLogExportScheduleTools(s *mcp.Server, d *Deps) {
	svc := newLogExportScheduleService(d)
	parts := logExportScheduleParts()

	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_log_export_schedule_list",
		Description: "List scheduled log-export profiles (periodic FTP/SCP log export). Firewall: local system scope; Panorama: a template or template_stack is required (list templates with panos_template_list). Read-only.",
		Annotations: readOnlyTool("List scheduled log exports"),
	}, systemEntryListHandler(d, "panos_log_export_schedule_list", svc, parts, svc.name, logExportScheduleSummary))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_log_export_schedule_get",
		Description: "Get one scheduled log-export profile (transport, server host/user/path/port, log type, start time, enable state, and whether a transport password is set). Transport passwords are never returned. Read-only.",
		Annotations: readOnlyTool("Get scheduled log export"),
	}, systemEntryGetHandler(d, "panos_log_export_schedule_get", svc, parts, logExportScheduleSummary))
	if d.ReadOnly {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_log_export_schedule_create",
		Description: "Create a scheduled log-export profile in the candidate config. Only name is required; provide either ftp or scp (not both) for the transport. Run panos_commit to apply.",
		Annotations: createTool("Create scheduled log export"),
	}, systemEntryCreateHandler(d, "panos_log_export_schedule_create", svc, parts,
		buildLogExportSchedule, logExportScheduleSummary, withSecrets(logExportScheduleSecrets)))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_log_export_schedule_update",
		Description: "Update a scheduled log-export profile: read-modify-write, only provided fields change. Providing ftp or scp switches the transport and clears the other; omitting a transport password keeps the stored one. Run panos_commit to apply.",
		Annotations: updateTool("Update scheduled log export"),
	}, systemEntryUpdateHandler(d, "panos_log_export_schedule_update", svc, parts,
		func(in LogExportScheduleInput) string { return in.Name },
		overlayLogExportSchedule, logExportScheduleSummary, withSecrets(logExportScheduleSecrets)))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "panos_log_export_schedule_delete",
		Description: "Delete a scheduled log-export profile from the candidate config. Run panos_commit to apply.",
		Annotations: deleteTool("Delete scheduled log export"),
	}, systemEntryDeleteHandler(d, "panos_log_export_schedule_delete", svc, parts))
}
