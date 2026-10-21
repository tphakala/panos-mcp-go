package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Synthetic fixtures only: invented serials, documentation addresses and
// locations. The shape (flat children, attributes on srcloc, hyphenated names,
// a logid entry attribute) follows the PAN-OS log result format.

const logSubmitBody = `<response status="success" code="19"><result><msg><line>query job enqueued with jobid 7</line></msg><job>7</job></result></response>`

const logRunningBody = `<response status="success"><result><job><status>ACT</status><id>7</id></job></result></response>`

func logSubmit() func(url.Values) bool {
	return func(v url.Values) bool { return v.Get("type") == "log" && v.Get("action") == "" }
}

func logGet() func(url.Values) bool {
	return func(v url.Values) bool { return v.Get("type") == "log" && v.Get("action") == "get" }
}

// pendingOnce matches the first log poll only.
func pendingOnce() func(url.Values) bool {
	var n atomic.Int32
	get := logGet()
	return func(v url.Values) bool { return get(v) && n.Add(1) == 1 }
}

func logFinBody(entries ...string) string {
	return `<response status="success"><result>` +
		`<job><status>FIN</status><id>7</id></job>` +
		`<log><logs count="` + strconv.Itoa(len(entries)) + `" progress="100">` + strings.Join(entries, "") + `</logs></log>` +
		`</result></response>`
}

// logEntryXML builds one synthetic traffic entry.
func logEntryXML(id int, extra string) string {
	return fmt.Sprintf(`<entry logid="%d"><domain>1</domain><receive_time>2030/01/02 03:04:05</receive_time>`+
		`<src>192.0.2.%d</src><dst>198.51.100.7</dst><srcloc code="Exampleland" cc="EX">Exampleland</srcloc>`+
		`<is-logging-service>no</is-logging-service>%s</entry>`, id, id%250, extra)
}

// immediateLogRoutes answers the submit, then every poll with a finished job.
func immediateLogRoutes(entries ...string) []fakeRoute {
	return []fakeRoute{
		{Match: logSubmit(), Body: logSubmitBody},
		{Match: logGet(), Body: logFinBody(entries...)},
	}
}

func shortLogPoll(t *testing.T, interval time.Duration) {
	t.Helper()
	old := logPollInterval
	logPollInterval = interval
	t.Cleanup(func() { logPollInterval = old })
}

type logResult struct {
	LogType   string            `json:"log_type"`
	Skip      int               `json:"skip"`
	Count     int               `json:"count"`
	Entries   []json.RawMessage `json:"entries"`
	NextSkip  *int              `json:"next_skip"`
	Truncated bool              `json:"truncated"`
	Note      string            `json:"note"`
	Unmatched []string          `json:"unmatched_fields"`
}

func decodeLogResult(t *testing.T, res *mcp.CallToolResult) logResult {
	t.Helper()
	if res.IsError {
		t.Fatalf("unexpected error result: %s", textContent(t, res))
	}
	var out logResult
	if err := json.Unmarshal([]byte(textContent(t, res)), &out); err != nil {
		t.Fatalf("result is not JSON: %v", err)
	}
	return out
}

// orderedKeys returns the top-level keys of a JSON object in document order.
func orderedKeys(t *testing.T, raw json.RawMessage) []string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	if _, err := dec.Token(); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		key, _ := k.(string)
		keys = append(keys, key)
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			t.Fatal(err)
		}
	}
	return keys
}

// runLogQuery runs the handler and returns its result, error results included.
func runLogQuery(t *testing.T, d *Deps, in *LogQueryInput) *mcp.CallToolResult {
	t.Helper()
	res, _, err := logQueryHandler(d)(t.Context(), nil, *in)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func logRequests(f *fakeAPI) []url.Values {
	return slices.DeleteFunc(f.Requests(), func(v url.Values) bool { return v.Get("type") != "log" })
}

// assertLogWire checks the requests a log query sent: only type=log, a submit
// with the expected parameters, then polls of job 7 (at least two, so a pending
// status is not terminal).
func assertLogWire(t *testing.T, reqs []url.Values, wantSubmit map[string]string) {
	t.Helper()
	for _, r := range reqs {
		if r.Get("type") != "log" {
			t.Fatalf("log query sent a non-log request: %v", r)
		}
	}
	for k, want := range wantSubmit {
		if got := reqs[0].Get(k); got != want {
			t.Errorf("submit %s = %q, want %q", k, got, want)
		}
	}
	polls := reqs[1:]
	if len(polls) < 2 {
		t.Errorf("polls = %d, want at least 2 (ACT must not be terminal)", len(polls))
	}
	for _, r := range polls {
		if r.Get("action") != "get" || r.Get("job-id") != "7" {
			t.Errorf("poll = %v, want action=get job-id=7", r)
		}
	}
}

func TestLogQuerySubmitPollAndDecode(t *testing.T) {
	shortLogPoll(t, 10*time.Millisecond)
	routes := []fakeRoute{
		{Match: logSubmit(), Body: logSubmitBody},
		{Match: pendingOnce(), Body: logRunningBody},
		{Match: logGet(), Body: logFinBody(
			logEntryXML(11, `<rule>a &amp; b</rule>`),
			logEntryXML(12, ""),
		)},
	}
	d, f := newTestDeps(t, "Panorama", routes...)
	startup := len(f.Requests())

	res := runLogQuery(t, d, &LogQueryInput{LogType: "traffic", Query: "(action eq allow)", Nlogs: 2, Skip: 4})
	out := decodeLogResult(t, res)

	assertLogWire(t, f.Requests()[startup:], map[string]string{
		"log-type": "traffic", "query": "(action eq allow)", "nlogs": "2", "skip": "4", "dir": "backward",
	})
	if out.Count != 2 || len(out.Entries) != 2 || out.NextSkip == nil || *out.NextSkip != 6 {
		t.Fatalf("count=%d entries=%d next_skip=%v, want 2, 2, 6", out.Count, len(out.Entries), out.NextSkip)
	}
	wantKeys := []string{"@logid", "domain", "receive_time", "src", "dst", "srcloc", "srcloc@code", "srcloc@cc", "is-logging-service", "rule"}
	if got := orderedKeys(t, out.Entries[0]); !slices.Equal(got, wantKeys) {
		t.Errorf("entry 0 keys = %v, want %v", got, wantKeys)
	}
	var first map[string]string
	if err := json.Unmarshal(out.Entries[0], &first); err != nil {
		t.Fatal(err)
	}
	if first["@logid"] != "11" || first["rule"] != "a & b" || first["srcloc@cc"] != "EX" || first["srcloc"] != "Exampleland" {
		t.Errorf("entry 0 = %v", first)
	}
	if got := orderedKeys(t, out.Entries[1]); got[0] != "@logid" || len(got) != len(wantKeys)-1 {
		t.Errorf("entry 1 keys = %v", got)
	}
}

func TestLogQueryResultShapes(t *testing.T) {
	cases := []struct {
		name      string
		finBody   string
		nlogs     int
		wantCount int
		wantNext  bool
	}{
		{
			name:    "empty page",
			finBody: `<response status="success"><result><job><status>FIN</status><id>7</id></job><log><logs count="0" progress="0"/></log></result></response>`,
			nlogs:   5,
		},
		{
			name:      "fewer entries than nlogs",
			finBody:   logFinBody(logEntryXML(1, ""), logEntryXML(2, "")),
			nlogs:     5,
			wantCount: 2,
		},
		{
			name:      "full page",
			finBody:   logFinBody(logEntryXML(1, ""), logEntryXML(2, "")),
			nlogs:     2,
			wantCount: 2,
			wantNext:  true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, _ := newTestDeps(t, "PA-VM",
				fakeRoute{Match: logSubmit(), Body: logSubmitBody},
				fakeRoute{Match: logGet(), Body: c.finBody})
			res := runLogQuery(t, d, &LogQueryInput{LogType: "system", Nlogs: c.nlogs})
			out := decodeLogResult(t, res)
			if out.Count != c.wantCount {
				t.Errorf("count = %d, want %d", out.Count, c.wantCount)
			}
			if (out.NextSkip != nil) != c.wantNext {
				t.Errorf("next_skip = %v, want present=%v", out.NextSkip, c.wantNext)
			}
			if out.Entries == nil || !strings.Contains(textContent(t, res), `"entries": [`) {
				t.Errorf("entries must be a JSON array even when empty: %s", textContent(t, res))
			}
		})
	}
}

func TestLogQueryFieldsProjection(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM", immediateLogRoutes(logEntryXML(1, ""))...)
	res := runLogQuery(t, d, &LogQueryInput{LogType: "traffic", Fields: []string{" srcloc ", "nosuch"}})
	out := decodeLogResult(t, res)
	want := []string{"@logid", "srcloc", "srcloc@code", "srcloc@cc"}
	if got := orderedKeys(t, out.Entries[0]); !slices.Equal(got, want) {
		t.Errorf("projected keys = %v, want %v", got, want)
	}
	if !slices.Equal(out.Unmatched, []string{"nosuch"}) {
		t.Errorf("unmatched_fields = %v, want [nosuch]", out.Unmatched)
	}

	// An empty page proves nothing about a name, so it reports nothing unmatched.
	d2, _ := newTestDeps(t, "PA-VM", immediateLogRoutes()...)
	out2 := decodeLogResult(t, runLogQuery(t, d2, &LogQueryInput{LogType: "traffic", Fields: []string{"nosuch"}}))
	if out2.Unmatched != nil {
		t.Errorf("unmatched_fields on an empty page = %v, want none", out2.Unmatched)
	}
}

func TestLogQueryInputValidation(t *testing.T) {
	cases := map[string]LogQueryInput{
		"empty log_type":            {},
		"log_type outside the enum": {LogType: "auth"},
		"bad direction":             {LogType: "traffic", Direction: "sideways"},
		"nlogs negative":            {LogType: "traffic", Nlogs: -1},
		"nlogs over the cap":        {LogType: "traffic", Nlogs: 501},
		"skip negative":             {LogType: "traffic", Skip: -1},
		"blank field name":          {LogType: "traffic", Fields: []string{" "}},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			d, f := newTestDeps(t, "PA-VM", immediateLogRoutes(logEntryXML(1, ""))...)
			res := runLogQuery(t, d, &in)
			if !res.IsError {
				t.Fatalf("must be an input error, got: %s", textContent(t, res))
			}
			if n := len(logRequests(f)); n != 0 {
				t.Fatalf("an invalid query sent %d log request(s)", n)
			}
		})
	}
	t.Run("nlogs at the cap is accepted", func(t *testing.T) {
		d, f := newTestDeps(t, "PA-VM", immediateLogRoutes()...)
		decodeLogResult(t, runLogQuery(t, d, &LogQueryInput{LogType: "config", Nlogs: 500}))
		if got := logRequests(f)[0].Get("nlogs"); got != "500" {
			t.Errorf("nlogs on the wire = %q, want 500", got)
		}
	})
}

func TestLogQueryDeviceErrors(t *testing.T) {
	cases := []struct {
		name   string
		routes []fakeRoute
		want   string
	}{
		{
			name: "filter syntax error on submit",
			routes: []fakeRoute{{Match: logSubmit(),
				Body: `<response status="error" code="17"><msg><line>syntax error at )</line></msg></response>`}},
			want: "syntax error at )",
		},
		{
			name: "illegal parameter on submit",
			routes: []fakeRoute{{Match: logSubmit(),
				Body: `<response status = 'error' code = '400'><result><msg>Illegal value for parameter skip [x]. Should be a number</msg></result></response>`}},
			want: "Illegal value for parameter skip",
		},
		{
			name: "failed job keeps its details",
			routes: []fakeRoute{
				{Match: logSubmit(), Body: logSubmitBody},
				{Match: logGet(), Body: `<response status="success"><result><job><status>FIN</status><result>FAIL</result>` +
					`<details><line>collector disk 100% full</line></details></job></result></response>`},
			},
			want: "collector disk 100% full",
		},
		{
			name: "poll response without a job status",
			routes: []fakeRoute{
				{Match: logSubmit(), Body: logSubmitBody},
				{Match: logGet(), Body: `<response status="success"><result><job><id>7</id></job></result></response>`},
			},
			want: "no job status",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, _ := newTestDeps(t, "PA-VM", c.routes...)
			start := time.Now()
			res := runLogQuery(t, d, &LogQueryInput{LogType: "system"})
			if !res.IsError {
				t.Fatalf("must be an error result, got: %s", textContent(t, res))
			}
			if got := textContent(t, res); !strings.Contains(got, c.want) {
				t.Errorf("error = %q, want it to contain %q", got, c.want)
			}
			if time.Since(start) > time.Second {
				t.Errorf("error took %s, must not wait for JobWait (%s)", time.Since(start), d.JobWait)
			}
		})
	}
}

func TestLogQueryWaitBounds(t *testing.T) {
	running := []fakeRoute{
		{Match: logSubmit(), Body: logSubmitBody},
		{Match: logGet(), Body: logRunningBody},
	}
	t.Run("own budget expiring is reported as not finished", func(t *testing.T) {
		shortLogPoll(t, 10*time.Millisecond)
		d, _ := newTestDeps(t, "PA-VM", running...)
		d.JobWait = 50 * time.Millisecond
		res := runLogQuery(t, d, &LogQueryInput{LogType: "traffic"})
		got := textContent(t, res)
		if !res.IsError || !strings.Contains(got, "log job 7 was not seen finished") {
			t.Fatalf("want an error naming the unfinished job, got IsError=%v %q", res.IsError, got)
		}
	})
	t.Run("a job finishing in the second half of a short budget is still collected", func(t *testing.T) {
		shortLogPoll(t, time.Minute)
		d, _ := newTestDeps(t, "PA-VM",
			fakeRoute{Match: logSubmit(), Body: logSubmitBody},
			fakeRoute{Match: pendingOnce(), Body: logRunningBody},
			fakeRoute{Match: logGet(), Body: logFinBody(logEntryXML(1, ""))})
		d.JobWait = 2 * time.Second
		out := decodeLogResult(t, runLogQuery(t, d, &LogQueryInput{LogType: "traffic"}))
		if out.Count != 1 {
			t.Errorf("count = %d, want 1", out.Count)
		}
	})
	t.Run("caller deadline is not reported as our budget", func(t *testing.T) {
		shortLogPoll(t, 10*time.Millisecond)
		d, _ := newTestDeps(t, "PA-VM", running...)
		ctx, cancel := context.WithTimeout(t.Context(), 40*time.Millisecond)
		defer cancel()
		res, _, _ := logQueryHandler(d)(ctx, nil, LogQueryInput{LogType: "traffic"})
		got := textContent(t, res)
		if !res.IsError || strings.Contains(got, "not seen finished") {
			t.Fatalf("a caller deadline must be a plain error, got IsError=%v %q", res.IsError, got)
		}
	})
	t.Run("caller cancel during the wait returns promptly", func(t *testing.T) {
		shortLogPoll(t, time.Minute)
		d, _ := newTestDeps(t, "PA-VM", running...)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		// The first poll answers ACT at once, so the cancel lands while the loop
		// waits for the one-minute interval.
		time.AfterFunc(100*time.Millisecond, cancel)
		start := time.Now()
		res, _, _ := logQueryHandler(d)(ctx, nil, LogQueryInput{LogType: "traffic"})
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("handler returned after %s, want prompt return on cancel", elapsed)
		}
		got := textContent(t, res)
		if !res.IsError || strings.Contains(got, "not seen finished") {
			t.Fatalf("a caller cancel must be a plain error, got IsError=%v %q", res.IsError, got)
		}
	})
}

func decodeLogEntryXML(t *testing.T, entryXML string) logEntry {
	t.Helper()
	var w struct {
		Entries []logEntry `xml:"entry"`
	}
	if err := xml.Unmarshal([]byte("<logs>"+entryXML+"</logs>"), &w); err != nil || len(w.Entries) != 1 {
		t.Fatalf("decode: %v (%d entries)", err, len(w.Entries))
	}
	return w.Entries[0]
}

func TestLogEntryDecode(t *testing.T) {
	cases := []struct {
		name string
		xml  string
		want []string
	}{
		{
			name: "flat and attribute fields keep document order",
			xml:  `<entry logid="9"><a>1</a><srcloc code="X" cc="Y">Z</srcloc><b-c>t</b-c></entry>`,
			want: []string{"@logid=9", "a=1", "srcloc=Z", "srcloc@code=X", "srcloc@cc=Y", "b-c=t"},
		},
		{
			name: "entities and CDATA are text",
			xml:  `<entry><a>&lt;x&gt;</a><b><![CDATA[c&d]]></b></entry>`,
			want: []string{"a=<x>", "b=c&d"},
		},
		{
			name: "nested children are kept as raw inner xml",
			xml:  `<entry><n><x>1</x><y>2</y></n></entry>`,
			want: []string{"n=<x>1</x><y>2</y>"},
		},
		{
			name: "duplicate children share one key",
			xml:  `<entry><d>1</d><s>x</s><d>2</d></entry>`,
			want: []string{"d=1|2", "s=x"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := decodeLogEntryXML(t, c.xml)
			got := make([]string, 0, len(e.fields))
			for _, f := range e.fields {
				got = append(got, f.key+"="+strings.Join(f.values, "|"))
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("fields = %v, want %v", got, c.want)
			}
		})
	}
}

func TestEncodeLogEntry(t *testing.T) {
	e := decodeLogEntryXML(t, `<entry><d>1</d><s>x</s><d>2</d></entry>`)
	raw, err := encodeLogEntry(e.fields)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"d":["1","2"],"s":"x"}`; string(raw) != want {
		t.Errorf("encoded = %s, want %s", raw, want)
	}
}

func TestProjectLogFields(t *testing.T) {
	const full = `<entry logid="9"><receive_time>t</receive_time><src>s</src><srcloc code="X" cc="Y">Z</srcloc></entry>`
	cases := []struct {
		name       string
		want       []string
		wantKeys   []string
		wantMissed []string // wanted names that must stay unmatched
	}{
		{
			name:       "identity, wanted fields and their attributes",
			want:       []string{"receive_time", "srcloc", "nosuch"},
			wantKeys:   []string{"@logid", "receive_time", "srcloc", "srcloc@code", "srcloc@cc"},
			wantMissed: []string{"nosuch"},
		},
		{
			name:     "an attribute key keeps only that key",
			want:     []string{"srcloc@cc"},
			wantKeys: []string{"@logid", "srcloc@cc"},
		},
		{
			name:     "an entry attribute counts as matched",
			want:     []string{"@logid"},
			wantKeys: []string{"@logid"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := decodeLogEntryXML(t, full)
			want := map[string]bool{}
			for _, n := range c.want {
				want[n] = true
			}
			matched := map[string]bool{}
			projected := projectLogFields(&e, want, matched)
			keys := make([]string, 0, len(projected))
			for _, f := range projected {
				keys = append(keys, f.key)
			}
			if !slices.Equal(keys, c.wantKeys) {
				t.Errorf("keys = %v, want %v", keys, c.wantKeys)
			}
			for _, n := range c.want {
				if matched[n] != !slices.Contains(c.wantMissed, n) {
					t.Errorf("matched[%q] = %v, want %v", n, matched[n], !slices.Contains(c.wantMissed, n))
				}
			}
		})
	}
}

func bigLogEntry(id, size int) string {
	return logEntryXML(id, "<payload>"+strings.Repeat("x", size)+"</payload>")
}

func bigLogEntries(from, to, size int) []string {
	out := make([]string, 0, to-from)
	for i := from; i < to; i++ {
		out = append(out, bigLogEntry(i, size))
	}
	return out
}

func logIDOf(t *testing.T, raw json.RawMessage) int {
	t.Helper()
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(m["@logid"])
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// compactBytes sums the compact JSON length of the entries; the text result is
// indented, but the budget counts compact bytes.
func compactBytes(t *testing.T, entries []json.RawMessage) int {
	t.Helper()
	sum := 0
	for _, e := range entries {
		var c bytes.Buffer
		if err := json.Compact(&c, e); err != nil {
			t.Fatal(err)
		}
		sum += c.Len()
	}
	return sum
}

func TestLogQueryByteBudgetPaging(t *testing.T) {
	const total = 40
	d, _ := newTestDeps(t, "PA-VM", immediateLogRoutes(bigLogEntries(0, total, 10<<10)...)...)
	out := decodeLogResult(t, runLogQuery(t, d, &LogQueryInput{LogType: "traffic", Nlogs: total}))
	if !out.Truncated || out.Count <= 0 || out.Count >= total || out.NextSkip == nil || *out.NextSkip != out.Count {
		t.Fatalf("truncated=%v count=%d next_skip=%v, want a cut page with next_skip=count", out.Truncated, out.Count, out.NextSkip)
	}
	if !strings.Contains(out.Note, "next_skip") {
		t.Errorf("note = %q, want it to name next_skip", out.Note)
	}
	if sum := compactBytes(t, out.Entries); sum > logResultBudget {
		t.Errorf("entry bytes = %d, over the budget %d", sum, logResultBudget)
	}
	last := logIDOf(t, out.Entries[len(out.Entries)-1])

	// Second page: the device serves the entries after the cut for skip=next_skip.
	k := *out.NextSkip
	d2, f2 := newTestDeps(t, "PA-VM", immediateLogRoutes(bigLogEntries(k, total, 10<<10)...)...)
	out2 := decodeLogResult(t, runLogQuery(t, d2, &LogQueryInput{LogType: "traffic", Nlogs: total, Skip: k}))
	if got := logRequests(f2)[0].Get("skip"); got != strconv.Itoa(k) {
		t.Errorf("second page skip on the wire = %q, want %d", got, k)
	}
	if first := logIDOf(t, out2.Entries[0]); first != last+1 {
		t.Errorf("second page starts at %d, want %d", first, last+1)
	}
	if out2.Truncated || out2.NextSkip != nil {
		t.Errorf("final page: truncated=%v next_skip=%v, want neither", out2.Truncated, out2.NextSkip)
	}
}

func TestLogQueryByteBudgetEdges(t *testing.T) {
	cases := []struct {
		name          string
		entries       []string
		in            LogQueryInput
		wantTruncated bool
		wantCount     int // 0 means any count above zero
		wantNext      int
	}{
		{
			name:      "a single oversized entry is still returned",
			entries:   []string{bigLogEntry(1, 300<<10)},
			in:        LogQueryInput{Nlogs: 1, Skip: 3},
			wantCount: 1,
			wantNext:  4,
		},
		{
			name:          "two oversized entries keep the first and advance",
			entries:       []string{bigLogEntry(1, 300<<10), bigLogEntry(2, 300<<10)},
			in:            LogQueryInput{Nlogs: 2, Skip: 3},
			wantTruncated: true,
			wantCount:     1,
			wantNext:      4,
		},
		{
			name:          "a cut short final page still reports next_skip",
			entries:       bigLogEntries(0, 30, 10<<10),
			in:            LogQueryInput{},
			wantTruncated: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, _ := newTestDeps(t, "PA-VM", immediateLogRoutes(c.entries...)...)
			c.in.LogType = "traffic"
			out := decodeLogResult(t, runLogQuery(t, d, &c.in))
			if out.Truncated != c.wantTruncated {
				t.Errorf("truncated = %v, want %v", out.Truncated, c.wantTruncated)
			}
			if out.Count == 0 || (c.wantCount != 0 && out.Count != c.wantCount) {
				t.Errorf("count = %d, want %d", out.Count, c.wantCount)
			}
			if out.NextSkip == nil || *out.NextSkip != c.in.Skip+out.Count || (c.wantNext != 0 && *out.NextSkip != c.wantNext) {
				t.Errorf("next_skip = %v, want skip+count (%d)", out.NextSkip, c.wantNext)
			}
		})
	}
}

func TestLogQueryTakesNoLock(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM", immediateLogRoutes(logEntryXML(1, ""))...)
	defer d.LockWrites()()

	done := make(chan *mcp.CallToolResult, 1)
	go func() {
		res, _, _ := logQueryHandler(d)(t.Context(), nil, LogQueryInput{LogType: "traffic"})
		done <- res
	}()
	select {
	case res := <-done:
		decodeLogResult(t, res)
	case <-time.After(5 * time.Second):
		t.Fatal("panos_log_query blocked while the write lock was held")
	}
}

func TestLogQuerySchema(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM")
	s := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	RegisterOpTools(s, d)
	cs := connectInMemory(t, s)
	list, err := cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var schema *jsonschema.Schema
	for _, tl := range list.Tools {
		if tl.Name != "panos_log_query" {
			continue
		}
		raw, err := json.Marshal(tl.InputSchema)
		if err != nil {
			t.Fatal(err)
		}
		schema = new(jsonschema.Schema)
		if err := json.Unmarshal(raw, schema); err != nil {
			t.Fatal(err)
		}
	}
	if schema == nil {
		t.Fatal("panos_log_query is not listed")
	}
	enumOf := func(name string) []string {
		vals := schema.Properties[name].Enum
		out := make([]string, 0, len(vals))
		for _, v := range vals {
			out = append(out, fmt.Sprint(v))
		}
		return out
	}
	if got, want := enumOf("log_type"), []string{"traffic", "threat", "url", "system", "config"}; !slices.Equal(got, want) {
		t.Errorf("log_type enum = %v, want %v", got, want)
	}
	if got, want := enumOf("direction"), []string{"backward", "forward"}; !slices.Equal(got, want) {
		t.Errorf("direction enum = %v, want %v", got, want)
	}
	n := schema.Properties["nlogs"]
	if n.Minimum == nil || *n.Minimum != 1 || n.Maximum == nil || *n.Maximum != 500 {
		t.Errorf("nlogs bounds = %v..%v, want 1..500", n.Minimum, n.Maximum)
	}
	if !slices.Equal(schema.Required, []string{"log_type"}) {
		t.Errorf("required = %v, want [log_type]", schema.Required)
	}
}
