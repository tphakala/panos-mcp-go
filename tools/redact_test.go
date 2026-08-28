package tools

import (
	"strings"
	"testing"

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
