package tools

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/PaloAltoNetworks/pango/util"
	"github.com/PaloAltoNetworks/pango/xmlapi"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	defaultLogCount = 50
	maxLogCount     = 500
	// logResultBudget caps the compact JSON bytes of the entries in one response.
	// A page over the budget is cut at the tail and reports truncated/next_skip.
	logResultBudget = 256 << 10
	logBudgetKiB    = logResultBudget >> 10
	// pollsPerBudget bounds the poll interval to JobWait/pollsPerBudget.
	pollsPerBudget = 2
	// logFinishTimeout bounds the request that drops an abandoned log job.
	logFinishTimeout = 5 * time.Second
	logTypeKey       = "log_type"
	logTypeURL       = "url"
)

// logPollInterval is the wait between log job polls. It is a var only so tests
// can shorten it (precedent: shutdownTimeout in server.go).
var logPollInterval = jobPollInterval

var (
	logTypes      = []string{"traffic", "threat", logTypeURL, "system", "config"}
	logDirections = []string{"backward", "forward"}
)

// LogQueryInput is the input for panos_log_query.
type LogQueryInput struct {
	LogType   string   `json:"log_type" jsonschema:"Log type to query: traffic, threat, url, system or config"`
	Query     string   `json:"query,omitempty" jsonschema:"PAN-OS log filter expression passed to the device unchanged, for example (action eq allow). Omit to match every entry"`
	Nlogs     int      `json:"nlogs,omitempty" jsonschema:"Number of entries to return, 1 to 500. Omit for the default of 50"`
	Skip      int      `json:"skip,omitempty" jsonschema:"Number of matching entries to skip, for paging. Use the next_skip value of the previous response"`
	Direction string   `json:"direction,omitempty" jsonschema:"backward returns the newest entries first, forward the oldest first. Omit for backward"`
	Fields    []string `json:"fields,omitempty" jsonschema:"Field names to keep in each entry, for example receive_time, src, dst; entry attribute keys such as @logid are always kept. Omit for every field the device sends"`
}

// logQueryInputSchema builds the tool input schema: the inferred one plus the
// enums and numeric bounds that struct tags cannot express (jsonschema-go
// v0.4.3 infer.go:329-337 sets only the description from a tag). It is stricter
// than the handler for an explicit value: the SDK validates the raw arguments
// against it before the handler runs (go-sdk v1.8.0 mcp/server.go:402-407), so
// an explicit "nlogs": 0 is rejected while an omitted nlogs gets the default.
func logQueryInputSchema() *jsonschema.Schema {
	s, err := jsonschema.For[LogQueryInput](nil)
	if err != nil {
		panic("panos_log_query: input schema: " + err.Error())
	}
	enum := func(vals []string) []any {
		out := make([]any, len(vals))
		for i, v := range vals {
			out[i] = v
		}
		return out
	}
	s.Properties[logTypeKey].Enum = enum(logTypes)
	s.Properties["direction"].Enum = enum(logDirections)
	s.Properties["nlogs"].Minimum = new(1.0)
	s.Properties["nlogs"].Maximum = new(float64(maxLogCount))
	s.Properties["skip"].Minimum = new(0.0)
	return s
}

// validateLogQuery returns a message for the first invalid input, "" when valid.
// It trims the field names in place so " src " matches src.
func validateLogQuery(in *LogQueryInput) string {
	if !slices.Contains(logTypes, in.LogType) {
		return "log_type must be one of " + strings.Join(logTypes, ", ")
	}
	if in.Direction != "" && !slices.Contains(logDirections, in.Direction) {
		return "direction must be backward or forward"
	}
	if in.Nlogs < 0 || in.Nlogs > maxLogCount {
		return fmt.Sprintf("nlogs must be between 1 and %d", maxLogCount)
	}
	if in.Skip < 0 {
		return "skip must be 0 or greater"
	}
	for i, f := range in.Fields {
		in.Fields[i] = strings.TrimSpace(f)
		if in.Fields[i] == "" {
			return "fields must not contain an empty name"
		}
	}
	return ""
}

// logField is one entry field. Keys are entry-local: "name" for a child
// element, "name@attr" for a child attribute and "@attr" for an entry attribute
// ("@" cannot appear in an XML name, so they never collide). Several values
// come from duplicate child elements.
type logField struct {
	key    string
	values []string
}

// logEntry is one <entry> of a log result, fields in document order.
type logEntry struct {
	fields []logField
}

// logChild decodes one child element of an entry: its attributes, its text,
// and whether it has element children (then the raw inner XML is kept).
type logChild struct {
	Attrs    []xml.Attr     `xml:",any,attr"`
	Text     string         `xml:",chardata"`
	Children []logChildName `xml:",any"`
	Inner    string         `xml:",innerxml"`
}

// logChildName captures only the name of a nested element.
type logChildName struct {
	XMLName xml.Name `xml:""`
}

func (e *logEntry) add(key, value string) {
	for i := range e.fields {
		if e.fields[i].key == key {
			e.fields[i].values = append(e.fields[i].values, value)
			return
		}
	}
	e.fields = append(e.fields, logField{key: key, values: []string{value}})
}

// UnmarshalXML records the entry attributes, then every child element and its
// attributes, in document order.
func (e *logEntry) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	e.fields = nil
	for _, a := range start.Attr {
		e.add("@"+a.Name.Local, a.Value)
	}
	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			var c logChild
			if err := d.DecodeElement(&c, &t); err != nil {
				return err
			}
			name := t.Name.Local
			value := c.Text
			if len(c.Children) > 0 {
				value = strings.TrimSpace(c.Inner)
			}
			e.add(name, value)
			for _, a := range c.Attrs {
				e.add(name+"@"+a.Name.Local, a.Value)
			}
		case xml.EndElement:
			return nil
		}
	}
}

// encodeLogEntry writes the fields as one JSON object in field order. A single
// value is a JSON string, several are an array of strings.
func encodeLogEntry(fields []logField) (json.RawMessage, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, f := range fields {
		if i > 0 {
			buf.WriteByte(',')
		}
		k, err := json.Marshal(f.key)
		if err != nil {
			return nil, err
		}
		var v []byte
		if len(f.values) == 1 {
			v, err = json.Marshal(f.values[0])
		} else {
			v, err = json.Marshal(f.values)
		}
		if err != nil {
			return nil, err
		}
		buf.Write(k)
		buf.WriteByte(':')
		buf.Write(v)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// projectLogFields keeps the entry attributes (keys starting with "@"), the
// fields named in want, and the attribute keys of a wanted element
// ("srcloc" keeps "srcloc@cc"). Asking for "srcloc@cc" keeps only that key.
// Every wanted name that equals a kept key is recorded in matched (a wanted
// element always has its own key, so "srcloc" matches without its attributes).
func projectLogFields(e *logEntry, want, matched map[string]bool) []logField {
	var out []logField
	for _, f := range e.fields {
		elem, _, hasAttr := strings.Cut(f.key, "@")
		keep := strings.HasPrefix(f.key, "@") || want[f.key] || (hasAttr && want[elem])
		if !keep {
			continue
		}
		out = append(out, f)
		if want[f.key] {
			matched[f.key] = true
		}
	}
	return out
}

// waitLogJob polls a log job until it finishes and returns the final response
// body. It owns its loop rather than calling pango's WaitForLogs so that a
// cancelled or expired ctx ends the wait at once instead of after the next
// sleep, and so a poll response with no job status fails at once instead of
// polling until the deadline. Between polls it waits logPollInterval, or
// JobWait/pollsPerBudget when that is shorter.
func waitLogJob(ctx context.Context, d *Deps, id uint) ([]byte, error) {
	cmd := &xmlapi.Log{Action: "get", JobId: id}
	// A short JobWait still gets a second poll instead of one poll and a sleep
	// that ends with the budget.
	interval := min(logPollInterval, d.JobWait/pollsPerBudget)
	for {
		var job util.BasicJob
		//nolint:bodyclose // pango's sendRequest already drained and closed the response body (client.go:1230 @ efa4357).
		body, _, err := d.Client.Communicate(ctx, cmd, false, &job)
		if err != nil {
			return nil, err
		}
		switch job.Status {
		case "FIN":
			if job.Result == "FAIL" {
				return nil, errors.New(cmp.Or(job.Details.String(), "log job failed"))
			}
			return body, nil
		case "":
			return nil, errors.New("log job poll response carries no job status")
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

// runLogJob submits the query and waits for the job, dropping the job on the
// device when the wait ends because ctx is done. It returns the job id (0 when
// the submit failed) with any error, so the caller can name the job.
func runLogJob(ctx context.Context, d *Deps, in *LogQueryInput, nlogs int) (body []byte, id uint, err error) {
	// pango's sendRequest drains and closes the response body before it
	// returns (client.go:1230 @ efa4357), so there is nothing to close.
	id, _, _, err = d.Client.StartJob(ctx, &xmlapi.Log{ //nolint:bodyclose // pango already closed the body (client.go:1230)
		LogType:   in.LogType,
		Query:     in.Query,
		Direction: cmp.Or(in.Direction, "backward"),
		Nlogs:     nlogs,
		Skip:      in.Skip,
	})
	if err != nil {
		return nil, 0, err
	}
	if id == 0 {
		return nil, 0, errors.New("device returned no log job id")
	}
	body, err = waitLogJob(ctx, d, id)
	if err != nil && ctx.Err() != nil {
		finishLogJob(ctx, d, id)
	}
	return body, id, err
}

// finishLogJob asks the device to drop a log job the query stopped waiting for
// (the caller cancelled or JobWait ran out), so the job does not stay queued on
// the device. ctx is already done, so the request runs on a detached context
// with its own short timeout. A failure is only logged, because the query has
// already failed.
func finishLogJob(ctx context.Context, d *Deps, id uint) {
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), logFinishTimeout)
	defer cancel()
	//nolint:bodyclose // pango's sendRequest already drained and closed the response body (client.go:1230 @ efa4357).
	if _, _, err := d.Client.Communicate(fctx, &xmlapi.Log{Action: "finish", JobId: id}, false, nil); err != nil {
		d.Logger.Warn("panos_log_query: finish log job", "job", id, "error", err)
	}
}

// logJobError maps a submit or poll error to a tool result. Our own JobWait
// budget expiring (and not the caller's ctx) is reported as not seen finished,
// because no other tool can collect a log job's result later.
func logJobError(ctx context.Context, d *Deps, tool string, id uint, err error) (res *mcp.CallToolResult, anyVal any) {
	label, name := "the log query", tool
	if id != 0 {
		label, name = fmt.Sprintf("log job %d", id), fmt.Sprintf("%s: job %d", tool, id)
	}
	if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
		d.Logger.Error("failed: "+tool, "job", id, "error", err)
		return errorResult("failed: %s: %s was not seen finished within %s (PANOS_JOB_WAIT); narrow the query or lower nlogs and retry", tool, label, d.JobWait)
	}
	return deviceErrorResult(d, name, err)
}

// logResponse is the finished-job body: Logs is nil when the result has no
// <log><logs> element at all.
type logResponse struct {
	XMLName xml.Name `xml:"response"`
	Result  struct {
		Logs *struct {
			Entries []logEntry `xml:"entry"`
		} `xml:"log>logs"`
		Inner string `xml:",innerxml"`
	} `xml:"result"`
}

// encodeLogEntries projects (when want is set) and encodes the entries in
// device order. The size budget cuts only the tail and always keeps the first
// entry, so paging advances. Every device entry is projected, cut or not, so
// matched describes the whole page.
func encodeLogEntries(entries []logEntry, want, matched map[string]bool) (out []json.RawMessage, truncated bool, err error) {
	out = make([]json.RawMessage, 0, len(entries))
	size := 0
	for i := range entries {
		fields := entries[i].fields
		if want != nil {
			fields = projectLogFields(&entries[i], want, matched)
		}
		if truncated {
			continue
		}
		raw, err := encodeLogEntry(fields)
		if err != nil {
			return nil, false, err
		}
		if i > 0 && size+len(raw) > logResultBudget {
			truncated = true
			continue
		}
		out = append(out, raw)
		size += len(raw)
	}
	return out, truncated, nil
}

// logPage builds the response map from the device's entries.
func logPage(in *LogQueryInput, nlogs int, entries []logEntry) (map[string]any, error) {
	var want, matched map[string]bool
	if len(in.Fields) > 0 {
		want = make(map[string]bool, len(in.Fields))
		matched = make(map[string]bool, len(in.Fields))
		for _, f := range in.Fields {
			want[f] = true
		}
	}
	out, truncated, err := encodeLogEntries(entries, want, matched)
	if err != nil {
		return nil, err
	}

	page := map[string]any{
		logTypeKey: in.LogType, "skip": in.Skip,
		countKey: len(out), entriesKey: out,
	}
	if truncated || len(entries) >= nlogs {
		page["next_skip"] = in.Skip + len(out)
	}
	if truncated {
		page["truncated"] = true
		page["note"] = fmt.Sprintf("response limited to %d KiB of entry JSON: returned %d of %d entries; "+
			"continue with skip = next_skip, or request fewer fields with fields",
			logBudgetKiB, len(out), len(entries))
	}
	if len(entries) > 0 {
		var unmatched []string
		for _, f := range in.Fields {
			if !matched[f] && !slices.Contains(unmatched, f) {
				unmatched = append(unmatched, f)
			}
		}
		if len(unmatched) > 0 {
			page["unmatched_fields"] = unmatched
		}
	}
	return page, nil
}

// logQueryHandler submits a type=log query, waits (bounded by JobWait) for the
// job, and returns the entries. When the wait ends because ctx is done it
// spends up to logFinishTimeout more asking the device to drop the job. It
// takes no lock: it reads the log database,
// not the candidate config, and a lock held across the poll would stall every
// commit and, through RWMutex writer preference, every other tool (see the
// writeMu doc in tools.go).
func logQueryHandler(d *Deps) func(context.Context, *mcp.CallToolRequest, LogQueryInput) (*mcp.CallToolResult, any, error) {
	const tool = "panos_log_query"
	return func(ctx context.Context, _ *mcp.CallToolRequest, in LogQueryInput) (*mcp.CallToolResult, any, error) {
		if msg := validateLogQuery(&in); msg != "" {
			res, v := errorResult("%s: %s", tool, msg)
			return res, v, nil
		}
		nlogs := cmp.Or(in.Nlogs, defaultLogCount)

		wctx, cancel := context.WithTimeout(ctx, d.JobWait)
		defer cancel()
		body, id, err := runLogJob(wctx, d, &in, nlogs)
		if err != nil {
			res, v := logJobError(ctx, d, tool, id, err)
			return res, v, nil
		}

		var resp logResponse
		if err := xml.Unmarshal(body, &resp); err != nil {
			d.Logger.Error("failed: "+tool, "job", id, "error", err)
			res, v := errorResult("failed: %s: decode job %d: %v", tool, id, err)
			return res, v, nil
		}
		var entries []logEntry
		if resp.Result.Logs != nil {
			entries = resp.Result.Logs.Entries
		} else if res, v, ok := rawResultFallback(tool, resp.Result.Inner); ok {
			return res, v, nil
		}
		page, err := logPage(&in, nlogs, entries)
		if err != nil {
			d.Logger.Error("failed: "+tool, "job", id, "error", err)
			res, v := errorResult("failed: %s: encode entry: %v", tool, err)
			return res, v, nil
		}
		res, v := jsonResult(page)
		return res, v, nil
	}
}
