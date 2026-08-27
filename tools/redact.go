package tools

import "strings"

const redactedPlaceholder = "[REDACTED]"

// rawResponseMarker is the prefix pango's errors.Parse writes when it finds no
// structured <msg> in a device response and falls back to embedding the entire
// raw response body (pango errors package: fmt.Sprintf("(raw response: %s)",
// body)). That raw body can echo a submitted element verbatim, so the redactor
// collapses everything from this marker onward for a secret-bearing request.
const rawResponseMarker = "(raw response:"

// redactSecrets scrubs a device error message before it reaches a log sink or a
// tool result. It literally replaces every known secret value with a placeholder
// and, for a request that actually submitted a secret, collapses pango's
// raw-response fallback. This is defense in depth for the write-only secret
// guarantee (issue #92): it can only scrub the exact values it is given, so a
// value the device transforms before echoing would not match a literal replace;
// the raw-response collapse is the backstop for that case. secrets may contain
// empty strings (an unset optional secret); those are skipped so an empty needle
// never matches. A request that submitted no secret leaves the message intact so
// its non-secret context (error code, xpath, schema message, even the raw
// response) stays available for debugging.
func redactSecrets(msg string, secrets []string) string {
	submitted := false
	for _, s := range secrets {
		if s != "" {
			msg = strings.ReplaceAll(msg, s, redactedPlaceholder)
			submitted = true
		}
	}
	if submitted {
		if i := strings.Index(msg, rawResponseMarker); i >= 0 {
			msg = msg[:i] + rawResponseMarker + " [redacted])"
		}
	}
	return msg
}

// writeOption configures a create or update handler. Its only current use is
// supplying the secret values a tool submitted so the write-error sinks can
// redact them (see redactSecrets). Handlers for families that carry no secret
// take no options, and the variadic parameter keeps every existing call site
// unchanged.
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
