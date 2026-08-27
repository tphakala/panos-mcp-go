package tools

import (
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestRedactSecrets(t *testing.T) {
	t.Run("replaces a submitted secret", func(t *testing.T) {
		got := redactSecrets("set failed: value 'hunter2' rejected by schema", []string{"hunter2"})
		if strings.Contains(got, "hunter2") {
			t.Fatalf("secret not scrubbed: %q", got)
		}
		if !strings.Contains(got, redactedPlaceholder) {
			t.Fatalf("expected the placeholder: %q", got)
		}
	})

	t.Run("collapses the raw-response fallback when a secret was submitted", func(t *testing.T) {
		got := redactSecrets("config failed (raw response: <entry><secret>hunter2</secret></entry>)", []string{"hunter2"})
		if strings.Contains(got, "hunter2") {
			t.Fatalf("secret survived in raw response: %q", got)
		}
		if !strings.Contains(got, "(raw response: [redacted])") {
			t.Fatalf("raw response not collapsed: %q", got)
		}
	})

	t.Run("leaves a message intact when no secret was submitted", func(t *testing.T) {
		in := "config failed (raw response: <entry><foo/></entry>)"
		if got := redactSecrets(in, nil); got != in {
			t.Fatalf("message altered with no secrets: %q", got)
		}
		if got := redactSecrets(in, []string{""}); got != in {
			t.Fatalf("empty secret should be skipped: %q", got)
		}
	})

	t.Run("scrubs every submitted secret", func(t *testing.T) {
		got := redactSecrets("a=TOP-SECRET-1 b=TOP-SECRET-2", []string{"TOP-SECRET-1", "TOP-SECRET-2"})
		if strings.Contains(got, "SECRET-1") || strings.Contains(got, "SECRET-2") {
			t.Fatalf("a secret survived: %q", got)
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
