package tools

import (
	"errors"
	"fmt"
	"strings"

	panoserr "github.com/PaloAltoNetworks/pango/errors"
	"github.com/PaloAltoNetworks/pango/xmlapi"
)

const redactedPlaceholder = "[REDACTED]"

// rawResponseMarker is the prefix pango's errors.Parse writes when it finds no
// structured <msg> in a device response and falls back to embedding the entire
// raw response body (pango errors package: fmt.Sprintf("(raw response: %s)",
// body)). That raw body can echo a submitted element verbatim, so the redactor
// collapses everything from this marker onward for a secret-bearing request.
const rawResponseMarker = "(raw response:"

// redactSecrets scrubs a device error message before it reaches a log sink or a
// tool result. It literally replaces every known secret value with a placeholder
// and, when collapseRaw is set, truncates pango's raw-response fallback. This is
// defense in depth for the write-only secret guarantee (issue #92): it can only
// scrub the exact values it is given, so a value the device transforms before
// echoing would not match a literal replace; the raw-response collapse is the
// backstop for that case. secrets may contain empty strings (an unset optional
// secret); those are skipped so an empty needle never matches.
//
// collapseRaw is deliberately independent of whether secrets is non-empty. A
// read-modify-write update resends the stored secret whenever the caller omits
// it, which is the documented way to keep that value, so the handler holds no
// plaintext to replace even though the device can still echo one (issue #99).
// Callers therefore arm the collapse on whether the tool family is
// secret-bearing at all, not on what this call submitted; see redactWriteError.
// A family that carries no secret passes false and keeps its full raw response,
// where the non-secret context (error code, xpath, schema message) is the whole
// value of the message.
//
// When the collapse DOES fire it discards everything, not just a tail. pango
// formats the fallback as exactly "(raw response: %s)", so the marker sits at
// offset 0 and no error code, xpath or device explanation precedes it; all of it
// lives inside the body. MEASURED on pango v0.10.3-0.20260731153743 by parsing a
// PAN-OS 11.2.6 validation failure: the result was
// `(raw response: <response status="error" code="12">...`, prefix empty. That
// total loss of diagnostics is the accepted cost of the guarantee, not an
// oversight; reducing the body to its <msg> lines instead is tracked separately.
//
// The marker is located BEFORE any replacement runs. The needles are caller-
// supplied tool arguments, so a caller who submits the marker text itself as a
// secret value would otherwise have ReplaceAll destroy every marker occurrence
// and silently disarm the collapse for the whole message (issue #106).
func redactSecrets(msg string, secrets []string, collapseRaw bool) string {
	// Split first, then replace, because replacement invalidates a saved index:
	// the needles and the placeholder differ in length. A secret occurrence that
	// straddled the marker would be missed, which cannot arise for a real pango
	// message: the fallback message BEGINS at the marker, so the prefix is empty
	// whenever the collapse fires.
	tail := ""
	if collapseRaw {
		if i := strings.Index(msg, rawResponseMarker); i >= 0 {
			msg, tail = msg[:i], rawResponseMarker+" [redacted])"
		}
	}
	for _, s := range secrets {
		if s != "" {
			msg = strings.ReplaceAll(msg, s, redactedPlaceholder)
		}
	}
	return msg + tail
}

// redactWriteError is the seam every write handler uses. It replaces the secret
// values this particular call submitted and collapses the raw-response fallback
// for any secret-bearing family, whether or not this call carried a value.
// Keeping this wrapper separate from redactSecrets keeps a bare boolean out of
// the handler call sites while leaving the primitive directly unit-testable.
func redactWriteError[In any](msg string, in *In, opts []writeOption[In]) string {
	return redactSecrets(msg, gatherSecrets(in, opts), isSecretBearing(opts))
}

// redactDeviceError is the seam getCore, listCore and deleteCore use. Those paths
// hold no submitted value to replace, so the raw-response collapse is the whole of
// it, and it runs for every family routed through those three cores rather than
// only secret-bearing ones (issue #105). Families with hand-written handlers that
// bypass the cores are NOT covered: the zone list, get, delete and update-seed-read
// paths in device_tools.go and the seed read in policy_tools.go's moveHandler are
// the current examples. No secret-bearing family has a bespoke handler, so nothing
// with a withSecrets extractor sits outside this seam.
//
// Unconditional rather than opted into per family because a per-family flag fails
// open: a family that forgot to pass it would silently lose the collapse, which is
// the failure mode issue #99 was.
//
// Whether a failed get, list or delete can even return a body carrying the entry
// is NOT PROVEN. Probed against one PA-VM on PAN-OS 11.2.6: a get of a missing
// entry, container or vsys came back status="success" code="7" (which pango still
// reports as an error, but resolves to a non-empty "Object not found", so no
// echo); a delete of a missing entry came back status="success" code="7" with a
// non-empty msg; and outright rejections came back code="16" with a structured
// single-line msg. Every one of those has a non-empty parsed message, which is
// the condition that skips the raw-response fallback, so the collapse never fired
// on any shape that box produced. That bounds the risk on that version; it does
// not eliminate it. Panorama, other PAN-OS versions and unenumerated failure
// modes were NOT MEASURED. This closes one shape of the leak, not the leak.
//
// secrets is empty for the three cores, which hold no submitted value. The seed
// read of a read-modify-write update passes the values that call submitted, since
// it is a read that happens to have them in hand.
//
// It takes the error rather than its string so that the device's numeric code
// survives the collapse. pango puts the fallback marker at offset 0, so a
// collapsed message would otherwise carry no code, no xpath and no device text at
// all, for every family including the ones with no secret. pango parses the code
// off the response attribute and keeps it on the error VALUE (errors.Parse builds
// Panos{Msg, Code} and fills Code on the fallback branch too), so it is still in
// hand after the body is discarded. Surfacing it cannot leak what the body held:
// the field is an int, and a non-numeric attribute unmarshals to 0 rather than to
// any of the body's text.
func redactDeviceError(err error, secrets ...string) string {
	if err == nil {
		return ""
	}
	msg := redactSecrets(err.Error(), secrets, true)
	if !strings.HasPrefix(msg, rawResponseMarker) {
		return msg
	}
	if pe, ok := errors.AsType[panoserr.Panos](err); ok {
		return withDeviceCode(pe.Code, msg)
	}
	// A failed delete reports through a different type: pango batches deletes into
	// a MultiConfig, and the client returns the *xmlapi.MultiConfigResponse itself
	// as the error (client.go:694). Its Error() falls back to errors.Parse over the
	// raw body only when the response carries no per-operation results
	// (xmlapi/multiconfig.go:110), which is when the marker can appear; with
	// results it returns the last result's own message and no marker. Checking both
	// types is what keeps the read paths behaving alike; without it delete alone
	// lost its code.
	if mc, ok := errors.AsType[*xmlapi.MultiConfigResponse](err); ok {
		return withDeviceCode(mc.Code, msg)
	}
	return msg
}

// withDeviceCode prefixes a collapsed message with the device's response code.
//
// Code 0 is omitted because it is what a response with no code attribute
// unmarshals to, so printing it would invent a code the device never sent. The
// wording is "response code" rather than "error code" because the value is just
// the response's code attribute, and the collapse fires whenever pango's parsed
// message comes out empty, which is reachable at codes that are not error codes.
func withDeviceCode(code int, msg string) string {
	if code == 0 {
		return msg
	}
	return fmt.Sprintf("device response code %d: %s", code, msg)
}

// isSecretBearing reports whether any option declares a secret extractor, which
// is how a tool family states that its entries carry write-only key material.
// Presence of the extractor is what matters, not whether it yielded a value on
// this call: that distinction is exactly the hole issue #99 describes.
func isSecretBearing[In any](opts []writeOption[In]) bool {
	for _, o := range opts {
		if o.secrets != nil {
			return true
		}
	}
	return false
}

// writeOption configures a create or update handler. It carries two things that
// look like one: the extractor that supplies the secret values a tool submitted,
// and, through its mere PRESENCE, the family's declaration that its entries carry
// write-only key material at all. isSecretBearing reads only the presence and
// ignores the values, and that is what arms the raw-response collapse for a
// read-modify-write that resends a stored secret the caller never sent (issue
// #99). Handlers for families that carry no secret take no options, and the
// variadic parameter keeps every existing call site unchanged.
type writeOption[In any] struct {
	secrets func(*In) []string
}

// withSecrets returns a writeOption that extracts the secret values an input
// carries, for redaction at the write-error sinks. A secret-bearing tool family
// passes withSecrets(...) when it registers its create and update handlers.
func withSecrets[In any](extract func(*In) []string) writeOption[In] {
	return writeOption[In]{secrets: extract}
}

// gatherSecrets collects the secret values to redact from in across every
// option, returning nil when no option supplies any.
func gatherSecrets[In any](in *In, opts []writeOption[In]) []string {
	var out []string
	for _, o := range opts {
		if o.secrets != nil {
			out = append(out, o.secrets(in)...)
		}
	}
	return out
}

// secretVals collects the non-nil, non-empty values pointed to by ptrs. It
// builds a withSecrets extractor from a family's optional *string secret fields.
func secretVals(ptrs ...*string) []string {
	out := make([]string, 0, len(ptrs))
	for _, p := range ptrs {
		if p != nil && *p != "" {
			out = append(out, *p)
		}
	}
	return out
}

// collectSecrets gathers the non-nil, non-empty secret from each item of a
// per-server input list, for families whose secrets live on a repeated element
// (server secrets, SNMP passwords).
func collectSecrets[T any](items []T, get func(T) *string) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		if p := get(it); p != nil && *p != "" {
			out = append(out, *p)
		}
	}
	return out
}

// --- per-family secret extractors -------------------------------------------
// Each secret-bearing tool family registers its create and update handlers with
// withSecrets(<one of these>) so a failed write redacts the value it submitted.
// Collecting them here keeps the set of values treated as secret auditable in
// one place (issue #92). A new secret-bearing family adds its extractor here and
// passes it via withSecrets at registration.

func ldapProfileSecrets(in *LdapProfileInput) []string { return secretVals(in.BindPassword) }

func tacacsProfileSecrets(in *TacacsProfileInput) []string {
	return collectSecrets(in.Servers, func(s TacacsServerInput) *string { return s.Secret })
}

func radiusProfileSecrets(in *RadiusProfileInput) []string {
	return collectSecrets(in.Servers, func(s RadiusServerInput) *string { return s.Secret })
}

func emailProfileSecrets(in *EmailProfileInput) []string {
	return collectSecrets(in.Servers, func(s EmailServerInput) *string { return s.Password })
}

func snmpTrapProfileSecrets(in *SnmpTrapProfileInput) []string {
	out := collectSecrets(in.V2cServers, func(s SnmpV2cServerInput) *string { return s.Community })
	out = append(out, collectSecrets(in.V3Servers, func(s SnmpV3ServerInput) *string { return s.AuthPassword })...)
	out = append(out, collectSecrets(in.V3Servers, func(s SnmpV3ServerInput) *string { return s.PrivPassword })...)
	return out
}

func ikeGatewaySecrets(in *IkeGatewayInput) []string { return secretVals(in.PreSharedKey) }

func localUserSecrets(in *LocalUserInput) []string { return secretVals(in.PasswordHash) }

func administratorSecrets(in *AdministratorInput) []string { return secretVals(in.PasswordHash) }

func authProfileSecrets(in *AuthProfileInput) []string {
	return secretVals(in.SsoKerberosKeytab)
}

func mfaProfileSecrets(in *MfaProfileInput) []string {
	return collectSecrets(in.Config, func(c MfaVendorConfigInput) *string { return c.Value })
}
