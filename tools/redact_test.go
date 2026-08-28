package tools

import (
	"net/url"
	"strings"
	"testing"

	panoserr "github.com/PaloAltoNetworks/pango/errors"
	"github.com/PaloAltoNetworks/pango/objects/address"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestRedactSecrets(t *testing.T) {
	t.Run("replaces a submitted secret", func(t *testing.T) {
		got := redactSecrets("set failed: value 'hunter2' rejected by schema", []string{"hunter2"}, true)
		if strings.Contains(got, "hunter2") {
			t.Fatalf("secret not scrubbed: %q", got)
		}
		if !strings.Contains(got, redactedPlaceholder) {
			t.Fatalf("expected the placeholder: %q", got)
		}
	})

	t.Run("collapses the raw-response fallback when a secret was submitted", func(t *testing.T) {
		got := redactSecrets("config failed (raw response: <entry><secret>hunter2</secret></entry>)", []string{"hunter2"}, true)
		if strings.Contains(got, "hunter2") {
			t.Fatalf("secret survived in raw response: %q", got)
		}
		if !strings.Contains(got, "(raw response: [redacted])") {
			t.Fatalf("raw response not collapsed: %q", got)
		}
	})

	// This is the issue #99 case: a read-modify-write update resends the stored
	// secret when the caller omits it, so the handler has no plaintext to replace
	// and the collapse is the only thing standing between the device's echo of
	// that stored value and the log sink. Sabotage: restore the old behaviour by
	// gating the collapse on a non-empty secrets slice, and this turns red while
	// every other subtest here stays green.
	t.Run("collapses the raw-response fallback even when the caller submitted nothing", func(t *testing.T) {
		const stored = "$1$abcdefgh$StoredHashTheCallerNeverSent"
		in := "config failed (raw response: <entry><phash>" + stored + "</phash></entry>)"
		got := redactSecrets(in, nil, true)
		if strings.Contains(got, stored) {
			t.Fatalf("stored secret survived with nothing submitted: %q", got)
		}
		if !strings.Contains(got, "(raw response: [redacted])") {
			t.Fatalf("raw response not collapsed: %q", got)
		}
	})

	// The other half of the same switch: a family that carries no secret keeps its
	// raw response, where the error code, xpath and schema message are the whole
	// value of the message. Sabotage: hardcode collapseRaw to true in
	// redactSecrets and this turns red.
	t.Run("leaves a non-secret family's message intact", func(t *testing.T) {
		in := "config failed (raw response: <entry><foo/></entry>)"
		if got := redactSecrets(in, nil, false); got != in {
			t.Fatalf("message altered for a non-secret family: %q", got)
		}
		if got := redactSecrets(in, []string{""}, false); got != in {
			t.Fatalf("empty secret should be skipped: %q", got)
		}
	})

	t.Run("scrubs every submitted secret", func(t *testing.T) {
		got := redactSecrets("a=TOP-SECRET-1 b=TOP-SECRET-2", []string{"TOP-SECRET-1", "TOP-SECRET-2"}, true)
		if strings.Contains(got, "SECRET-1") || strings.Contains(got, "SECRET-2") {
			t.Fatalf("a secret survived: %q", got)
		}
	})
}

// TestIsSecretBearing pins the signal that arms the collapse: the presence of a
// withSecrets extractor, not whether it produced a value on this call. Sabotage:
// make isSecretBearing return false unconditionally, or gate it on the extractor
// returning a non-empty slice, and the middle two subtests turn red.
func TestIsSecretBearing(t *testing.T) {
	type in struct{ Secret *string }
	none := func(*in) []string { return nil }

	t.Run("no options", func(t *testing.T) {
		if isSecretBearing[in](nil) {
			t.Fatal("a family with no options is not secret-bearing")
		}
	})

	t.Run("an extractor that yields nothing still counts", func(t *testing.T) {
		if !isSecretBearing([]writeOption[in]{withSecrets(none)}) {
			t.Fatal("presence of the extractor is the signal, not its output")
		}
	})

	t.Run("an extractor among several counts", func(t *testing.T) {
		if !isSecretBearing([]writeOption[in]{{}, withSecrets(none)}) {
			t.Fatal("a later option carrying an extractor must arm the collapse")
		}
	})

	t.Run("options carrying no extractor do not count", func(t *testing.T) {
		if isSecretBearing([]writeOption[in]{{}, {}}) {
			t.Fatal("an option with a nil extractor must not arm the collapse")
		}
	})
}

// TestRedactWriteErrorArmsOnFamilyNotSubmission is the wrapper-level statement of
// issue #99: two calls to the same secret-bearing family, one submitting a secret
// and one omitting it, must both collapse the raw response. Sabotage: change
// redactWriteError to pass len(gatherSecrets(...)) > 0 as collapseRaw and the
// second subtest turns red.
func TestRedactWriteErrorArmsOnFamilyNotSubmission(t *testing.T) {
	type in struct{ Secret *string }
	extract := func(i *in) []string { return secretVals(i.Secret) }
	opts := []writeOption[in]{withSecrets(extract)}
	const msg = "config failed (raw response: <entry><phash>STORED-HASH</phash></entry>)"

	t.Run("caller submitted a secret", func(t *testing.T) {
		got := redactWriteError(msg, &in{Secret: new("SUBMITTED")}, opts)
		if !strings.Contains(got, "(raw response: [redacted])") {
			t.Fatalf("raw response not collapsed: %q", got)
		}
	})

	t.Run("caller omitted the secret", func(t *testing.T) {
		got := redactWriteError(msg, &in{}, opts)
		if strings.Contains(got, "STORED-HASH") {
			t.Fatalf("stored secret leaked when none was submitted: %q", got)
		}
		if !strings.Contains(got, "(raw response: [redacted])") {
			t.Fatalf("raw response not collapsed: %q", got)
		}
	})

	t.Run("a family with no extractor keeps its raw response", func(t *testing.T) {
		if got := redactWriteError(msg, &in{}, nil); got != msg {
			t.Fatalf("message altered for a non-secret family: %q", got)
		}
	})
}

// TestServerProfileCreateRedactsSecretOnError drives the tacacs create tool
// through the registered handler and the fake API: the device rejects the write
// with an error that echoes the submitted shared secret, and the tool result and
// logs must not carry it. This proves the withSecrets extractor is actually
// wired into deviceCreateHandler (issue #92), not just that redactSecrets works.
func TestServerProfileCreateRedactsSecretOnError(t *testing.T) {
	const secret = "SUPERSECRET-abc123"
	d, _ := newTestDeps(t, "PA-VM",
		fakeRoute{Match: configAction("set"), Body: `<response status="error"><msg><line>validation error for secret ` + secret + `</line></msg></response>`},
	)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	RegisterTacacsProfileTools(srv, d)
	cs := connectInMemory(t, srv)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "panos_tacacs_profile_create", Arguments: map[string]any{
		"name":    "tac",
		"servers": []any{map[string]any{"name": "s1", "address": "10.0.0.1", "secret": secret}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatalf("expected the device error to surface as a tool error")
	}
	out := textContent(t, res)
	if strings.Contains(out, secret) {
		t.Fatalf("submitted secret leaked into the tool error: %q", out)
	}
	if !strings.Contains(out, redactedPlaceholder) {
		t.Fatalf("expected the redaction placeholder in the error: %q", out)
	}
}

// TestRedactSecretsMarkerOverlap pins that a submitted "secret" overlapping
// pango's raw-response marker cannot disarm the collapse. The needles are
// caller-supplied tool arguments, so this is reachable rather than hypothetical:
// before the fix, ReplaceAll ran first and a caller who submitted the marker text
// itself destroyed every marker occurrence, after which the truncation silently
// found nothing and the rest of the body flowed through (issue #106).
//
// Sabotage: move the marker lookup in redactSecrets back below the replacement
// loop. This turns red while every subtest in TestRedactSecrets stays green,
// which is the point: the whole existing suite missed this ordering.
func TestRedactSecretsMarkerOverlap(t *testing.T) {
	const stored = "$1$storedsalt$STOREDHASHTHECALLERNEVERSENT"
	msg := "config failed " + rawResponseMarker + " <entry><phash>" + stored + "</phash></entry>)"

	got := redactSecrets(msg, []string{rawResponseMarker}, true)
	if strings.Contains(got, stored) {
		t.Fatalf("a secret overlapping the marker suppressed the collapse: %q", got)
	}
	if !strings.Contains(got, "(raw response: [redacted])") {
		t.Fatalf("raw response not collapsed: %q", got)
	}
}

// assertRedactsSecret is the shared tail of the per-family redaction tests: the
// device rejected the write with a message echoing a secret, and neither the
// secret nor a missing placeholder may reach the tool result.
//
// It asserts on LITERAL secret values written in the calling test, never on
// anything a production function computed. Handing it a family's own extractor
// output, assertRedactsSecret(t, res, err, ldapProfileSecrets(&in)...), would be
// the symmetric-bug trap: if that extractor regressed to returning nil the
// assertion would have nothing to look for and would pass, while the very leak it
// exists to catch went through. The len(needles) == 0 guard makes that fail
// closed rather than silently vacuous, the same way nonEmptyNeedles guards
// assertNoSecretLeak.
//
// Only the assertion tail moves here. Each test keeps its own setup and its own
// sabotage-target doc comment, because those are what tie a test to the specific
// withSecrets(...) registration it pins.
func assertRedactsSecret(t *testing.T, res *mcp.CallToolResult, err error, secrets ...string) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	needles := nonEmptyNeedles(secrets)
	if len(needles) == 0 {
		t.Fatal("assertRedactsSecret needs at least one non-empty literal secret")
	}
	if !res.IsError {
		t.Fatal("expected the device error to surface as a tool error")
	}
	out := textContent(t, res)
	for _, s := range needles {
		if strings.Contains(out, s) {
			t.Fatalf("secret leaked into the tool error: %q", out)
		}
	}
	if !strings.Contains(out, redactedPlaceholder) {
		t.Fatalf("expected the redaction placeholder in the error: %q", out)
	}
}

// TestAssertRedactsSecretRejectsVacuousCall proves the helper's guard fires, so
// a caller who passes only empty needles is told rather than silently passing.
// Mirrors TestAssertNoSecretLeakSkipsEmptyNeedle.
//
// Sabotage: delete the len(needles) == 0 guard from assertRedactsSecret and this
// turns red.
func TestAssertRedactsSecretRejectsVacuousCall(t *testing.T) {
	fake := &testing.T{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		// The helper calls t.Fatal, which runs runtime.Goexit; a dedicated
		// goroutine contains that, matching TestAssertNoSecretLeakSkipsEmptyNeedle.
		assertRedactsSecret(fake, &mcp.CallToolResult{}, nil, "", "")
	}()
	<-done
	if !fake.Failed() {
		t.Fatal("assertRedactsSecret must reject a call with no non-empty needle")
	}
}

// TestPangoNestedLineErrorTakesRawFallback pins the pango behaviour this
// server's whole redaction posture rests on, and it is not the behaviour the
// rest of the suite's fixtures assume.
//
// MEASURED against a live PA-VM on PAN-OS 11.2.6: a write validation failure
// comes back DOUBLE-nested, <msg><line><line>...</line></line></msg>, and the
// text echoes the offending value verbatim. pango models <line> as a leaf, so
// the outer line's text is empty, the parsed message is empty, and Parse
// substitutes the entire raw body. That is why the COLLAPSE, not the literal
// replacement, is what defends the shape a real device actually produces.
//
// Deleting a production line does not sabotage this test, the same way it does
// not for the tests that pin an absent pango location: the load-bearing thing is
// a dependency's behaviour. It is an upgrade tripwire. If a pango bump teaches
// its line type to recurse, this goes red and tells the reader exactly what
// changed: the collapse would stop firing for the real device shape, and line
// text that echoes submitted values would reach the sinks with only the literal
// replacement in front of it.
func TestPangoNestedLineErrorTakesRawFallback(t *testing.T) {
	t.Run("double-nested lines fall back to the raw body", func(t *testing.T) {
		body := `<response status="error" code="12"><msg><line><line><![CDATA[ p -> server -> s1 -> port value=99999 should be equal to or between 1 and 65535]]></line></line></msg></response>`
		err := panoserr.Parse([]byte(body))
		if err == nil {
			t.Fatal("a status=error response must parse as an error")
		}
		if !strings.HasPrefix(err.Error(), rawResponseMarker) {
			t.Fatalf("the measured device shape must take the raw-response fallback, got %q", err.Error())
		}
	})

	// The other branch, and the shape every other redaction fixture in this suite
	// uses: pango parses it cleanly, so no marker appears and the collapse never
	// fires for it. Those fixtures therefore exercise the literal-replacement path
	// only, which is worth knowing when reading them.
	t.Run("single-nested lines parse to a clean message", func(t *testing.T) {
		body := `<response status="error" code="12"><msg><line><![CDATA[ p -> server -> s1 -> port is invalid]]></line></msg></response>`
		err := panoserr.Parse([]byte(body))
		if err == nil {
			t.Fatal("a status=error response must parse as an error")
		}
		if strings.Contains(err.Error(), rawResponseMarker) {
			t.Fatalf("a parseable message must not take the raw-response fallback, got %q", err.Error())
		}
		if !strings.Contains(err.Error(), "port is invalid") {
			t.Fatalf("the parsed message must carry the device text, got %q", err.Error())
		}
	})
}

// rawEchoBody is a device error whose <msg> is present but empty, which is one of
// the two shapes that make pango fall back to embedding the whole raw body
// (verified by parsing it in TestGetCollapsesRawResponse's sibling above). The
// entry element stands in for content a failed read could echo.
const rawEchoBody = `<response status="error" code="12"><result><msg></msg>` +
	`<entry name="leaky-entry"><ip-netmask>10.0.0.1/32</ip-netmask></entry></result></response>`

// The three tests below pin that the read, list and delete paths collapse pango's
// raw-response fallback. They deliberately use address, a family carrying NO
// secret, because the point is that the arming is unconditional: the write path's
// per-family signal is typed to the write input and cannot reach these three.
//
// Each pins the MECHANISM, not a reproduced leak. Whether PAN-OS ever answers a
// failed get, list or delete with a body carrying the entry is NOT PROVEN: probed
// against one PA-VM on 11.2.6, every read and delete failure came back with a
// non-empty parsed message and so skipped the fallback entirely. The fixture here
// is constructed, and is labelled as such. See redactDeviceError.
//
// They are three tests rather than one table so that deleting the redaction from
// any single core turns exactly one of them red.

// Sabotage: delete the redactDeviceError call from getCore.
func TestGetCollapsesRawResponse(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: rawEchoBody})
	h := getHandler[address.Location, address.Entry](d, "panos_address_get",
		newAddressService(d), addressResolve(d), addressSummary)

	res, _, err := h(t.Context(), nil, NameInput{Name: "nope"})
	assertCollapsedRawResponse(t, res, err)
}

// Sabotage: delete the redactDeviceError call from listCore.
func TestListCollapsesRawResponse(t *testing.T) {
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{Match: configAction("get"), Body: rawEchoBody})
	h := listHandler[address.Location, address.Entry](d, "panos_address_list",
		newAddressService(d), addressResolve(d),
		func(e *address.Entry) string { return e.Name }, addressSummary)

	res, _, err := h(t.Context(), nil, ListInput{})
	assertCollapsedRawResponse(t, res, err)
}

// Sabotage: delete the redactDeviceError call from deleteCore.
func TestDeleteCollapsesRawResponse(t *testing.T) {
	// Any config request, not just action=delete: pango's Delete resolves the
	// entry before removing it, so the failure can surface on either leg. Either
	// way the error reaches deleteCore, which is what this pins.
	d, _ := newTestDeps(t, "PA-VM", fakeRoute{
		Match: func(v url.Values) bool { return v.Get("type") == "config" },
		Body:  rawEchoBody,
	})
	h := deleteHandler[address.Location, address.Entry](d, "panos_address_delete",
		newAddressService(d), addressResolve(d))

	res, _, err := h(t.Context(), nil, NameInput{Name: "nope"})
	assertCollapsedRawResponse(t, res, err)
}

// assertCollapsedRawResponse checks a device error reached the tool result with
// the raw body collapsed rather than echoed.
func assertCollapsedRawResponse(t *testing.T, res *mcp.CallToolResult, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("a device error must surface as a tool error")
	}
	out := textContent(t, res)
	if strings.Contains(out, "leaky-entry") || strings.Contains(out, "10.0.0.1/32") {
		t.Fatalf("the raw response body reached the tool result: %q", out)
	}
	if !strings.Contains(out, "(raw response: [redacted])") {
		t.Fatalf("expected the collapsed raw response: %q", out)
	}
}
