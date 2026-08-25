package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"maps"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// configEnvVars lists every variable LoadConfig reads, plus LOG_LEVEL which is
// only scrubbed, not read (see below). Keep in sync with config.go: a read
// variable missing here is not cleared, so the developer's real environment
// leaks into the tests and they pass or fail depending on the machine.
// PANOS_READ_ONLY is removed as a functional setting but stays here: LoadConfig
// still reads it for the migration guard, so it must be scrubbed like the rest.
// LOG_LEVEL is likewise no longer read (issue #4 renamed it to PANOS_LOG_LEVEL),
// but it stays so a developer's exported LOG_LEVEL cannot mask a regression that
// reintroduces the read; TestLoadConfigIgnoresBareLogLevel is the dedicated guard
// that reddens if a bare LOG_LEVEL read is added back.
var configEnvVars = []string{
	"PANOS_HOST", "PANOS_HOSTNAME", "PANOS_PORT", "PANOS_API_KEY", "PANOS_USERNAME", "PANOS_PASSWORD",
	"PANOS_SKIP_VERIFY", "PANOS_SKIP_VERIFY_CERTIFICATE", "PANOS_CA_CERT",
	"PANOS_ALLOW_WRITES", "PANOS_READ_ONLY", "PANOS_JOB_WAIT",
	"MCP_TRANSPORT", "MCP_HTTP_HOST", "MCP_HTTP_PORT", "MCP_HTTP_TOKEN", "PANOS_LOG_LEVEL", "LOG_LEVEL",
}

// setEnv unsets every configuration variable, then applies kv. The variables are
// genuinely removed rather than set to empty, because that is the state an MCP
// client launches this server in. t.Setenv captures the original value and
// registers the restoring cleanup before os.Unsetenv removes it. Tests using
// this helper must not call t.Parallel: t.Setenv panics in a parallel test.
func setEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	for _, k := range configEnvVars {
		t.Setenv(k, "")
		if err := os.Unsetenv(k); err != nil {
			t.Fatalf("unset %s: %v", k, err)
		}
	}
	for k, v := range kv {
		t.Setenv(k, v)
	}
}

func TestLoadConfigRequiresHost(t *testing.T) {
	setEnv(t, map[string]string{"PANOS_API_KEY": "k"})
	_, err := LoadConfig()
	if err == nil {
		t.Fatal("expected error for missing PANOS_HOST")
	}
	// Assert the composite phrase, not just "PANOS_HOST": that substring also
	// occurs inside "PANOS_HOSTNAME", so a message naming only the alias would
	// pass a bare Contains("PANOS_HOST") check vacuously.
	if !strings.Contains(err.Error(), "PANOS_HOST (or PANOS_HOSTNAME)") {
		t.Fatalf("error should name both PANOS_HOST and PANOS_HOSTNAME, got %v", err)
	}
}

// TestLoadConfigHostAlias pins that PANOS_HOSTNAME (the name pango itself reads)
// is accepted as a fallback for PANOS_HOST, that the primary wins when both are
// set, and that a whitespace-only primary falls through to the alias (issue #4).
func TestLoadConfigHostAlias(t *testing.T) {
	t.Run("fallback used when primary unset", func(t *testing.T) {
		setEnv(t, map[string]string{"PANOS_HOSTNAME": "  fw2  ", "PANOS_API_KEY": "k"})
		cfg, err := LoadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Host != "fw2" {
			t.Errorf("Host = %q, want fw2 from the PANOS_HOSTNAME fallback (trimmed)", cfg.Host)
		}
	})
	t.Run("primary wins when both set", func(t *testing.T) {
		setEnv(t, map[string]string{"PANOS_HOST": "primary", "PANOS_HOSTNAME": "alias", "PANOS_API_KEY": "k"})
		cfg, err := LoadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Host != "primary" {
			t.Errorf("Host = %q, want primary: PANOS_HOST must win over PANOS_HOSTNAME", cfg.Host)
		}
	})
	t.Run("blank primary falls through to alias", func(t *testing.T) {
		setEnv(t, map[string]string{"PANOS_HOST": "   ", "PANOS_HOSTNAME": "fw2", "PANOS_API_KEY": "k"})
		cfg, err := LoadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Host != "fw2" {
			t.Errorf("Host = %q, want fw2: a whitespace-only PANOS_HOST is treated as unset", cfg.Host)
		}
	})
}

// TestLoadConfigSkipVerifyAlias pins that PANOS_SKIP_VERIFY_CERTIFICATE (pango's
// name) is accepted as a fallback for PANOS_SKIP_VERIFY, and that the primary
// wins when both are set (issue #4).
func TestLoadConfigSkipVerifyAlias(t *testing.T) {
	t.Run("fallback used when primary unset", func(t *testing.T) {
		setEnv(t, map[string]string{
			"PANOS_HOST": "fw", "PANOS_API_KEY": "k",
			"PANOS_SKIP_VERIFY_CERTIFICATE": "true",
		})
		cfg, err := LoadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.SkipVerify {
			t.Error("SkipVerify = false, want true from the PANOS_SKIP_VERIFY_CERTIFICATE fallback")
		}
		// The startup warning names the source, so a skip-verify supplied by the
		// alias must be attributed to the alias.
		if cfg.SkipVerifySource != "PANOS_SKIP_VERIFY_CERTIFICATE" {
			t.Errorf("SkipVerifySource = %q, want PANOS_SKIP_VERIFY_CERTIFICATE", cfg.SkipVerifySource)
		}
	})
	t.Run("primary wins when both set", func(t *testing.T) {
		setEnv(t, map[string]string{
			"PANOS_HOST": "fw", "PANOS_API_KEY": "k",
			"PANOS_SKIP_VERIFY": "false", "PANOS_SKIP_VERIFY_CERTIFICATE": "true",
		})
		cfg, err := LoadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.SkipVerify {
			t.Error("SkipVerify = true, want false: PANOS_SKIP_VERIFY must win over the alias")
		}
		if cfg.SkipVerifySource != "PANOS_SKIP_VERIFY" {
			t.Errorf("SkipVerifySource = %q, want PANOS_SKIP_VERIFY (the primary supplied the value)", cfg.SkipVerifySource)
		}
	})
	t.Run("no source when neither set", func(t *testing.T) {
		setEnv(t, map[string]string{"PANOS_HOST": "fw", "PANOS_API_KEY": "k"})
		cfg, err := LoadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.SkipVerify {
			t.Error("SkipVerify = true, want false when neither variable is set")
		}
		// Empty means unset: the field must not name a variable that supplied
		// nothing, or a reader that treats empty as "unset" is misled.
		if cfg.SkipVerifySource != "" {
			t.Errorf("SkipVerifySource = %q, want empty when neither variable is set", cfg.SkipVerifySource)
		}
	})
}

// TestLoadConfigRejectsBlankHost pins that a whitespace-only host is rejected at
// startup rather than reaching pango and failing later as a URL error.
func TestLoadConfigRejectsBlankHost(t *testing.T) {
	setEnv(t, map[string]string{"PANOS_HOST": "   ", "PANOS_API_KEY": "k"})
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected error for whitespace-only PANOS_HOST")
	}
}

func TestLoadConfigRequiresAuth(t *testing.T) {
	for _, tc := range []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{"no credentials", map[string]string{"PANOS_HOST": "fw"}, "PANOS_USERNAME"},
		{"username without password", map[string]string{"PANOS_HOST": "fw", "PANOS_USERNAME": "admin"}, "PANOS_PASSWORD"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setEnv(t, tc.env)
			_, err := LoadConfig()
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error should name %s, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestLoadConfigAcceptsAPIKeyAlone pins that an API key alone satisfies auth,
// the counterpart to the two rejection cases above.
func TestLoadConfigAcceptsAPIKeyAlone(t *testing.T) {
	setEnv(t, map[string]string{"PANOS_HOST": "fw", "PANOS_API_KEY": "secret-key"})
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APIKey != "secret-key" {
		t.Fatalf("APIKey = %q, want %q", cfg.APIKey, "secret-key")
	}
}

// The expected values below are written as literals on purpose. Referencing the
// production constants would make this test a tautology that cannot catch an
// accidental change to a default.
func TestLoadConfigDefaults(t *testing.T) {
	setEnv(t, map[string]string{"PANOS_HOST": "fw", "PANOS_API_KEY": "k"})
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Transport != "stdio" {
		t.Errorf("Transport = %q, want stdio", cfg.Transport)
	}
	if cfg.JobWait != 120*time.Second {
		t.Errorf("JobWait = %v, want 2m0s", cfg.JobWait)
	}
	if cfg.HTTPPort != 8080 {
		t.Errorf("HTTPPort = %d, want 8080", cfg.HTTPPort)
	}
	if cfg.HTTPHost != "127.0.0.1" {
		t.Errorf("HTTPHost = %q, want 127.0.0.1", cfg.HTTPHost)
	}
	if cfg.LogLevel != slog.LevelInfo {
		t.Errorf("LogLevel = %v, want INFO", cfg.LogLevel)
	}
	// Port 0 is the contract that makes pango omit the port from the URL.
	if cfg.Port != 0 {
		t.Errorf("Port = %d, want 0 so the scheme default applies", cfg.Port)
	}
	// Writes are opt-in (issue #3): with PANOS_ALLOW_WRITES unset the server is
	// read-only, the safe default. Dropping the negation in readOnlyFromEnv, so an
	// absent variable yields read-write, turns this red.
	if !cfg.ReadOnly {
		t.Error("ReadOnly = false, want true: writes must be opt-in via PANOS_ALLOW_WRITES")
	}
	if cfg.SkipVerify {
		t.Errorf("SkipVerify = %v, want false", cfg.SkipVerify)
	}
}

func TestLoadConfigParsesValues(t *testing.T) {
	setEnv(t, map[string]string{
		"PANOS_HOST": "fw.example.net", "PANOS_PORT": "8443",
		"PANOS_USERNAME": "admin", "PANOS_PASSWORD": "pw",
		"PANOS_SKIP_VERIFY": "true", "PANOS_ALLOW_WRITES": "true",
		"PANOS_JOB_WAIT": "30",
		"MCP_TRANSPORT":  "http", "MCP_HTTP_HOST": "0.0.0.0", "MCP_HTTP_PORT": "9090",
		"MCP_HTTP_TOKEN":  "tok",
		"PANOS_LOG_LEVEL": "debug",
	})
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	// Every string field is asserted. Checking only the numeric and boolean
	// fields would let a swap of the Username and Password sources ship green.
	for _, c := range []struct{ name, got, want string }{
		{"Host", cfg.Host, "fw.example.net"},
		{"Username", cfg.Username, "admin"},
		{"Password", cfg.Password, "pw"},
		{"Transport", cfg.Transport, "http"},
		{"HTTPHost", cfg.HTTPHost, "0.0.0.0"},
		{"HTTPToken", cfg.HTTPToken, "tok"},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
	if cfg.Port != 8443 {
		t.Errorf("Port = %d, want 8443", cfg.Port)
	}
	if cfg.HTTPPort != 9090 {
		t.Errorf("HTTPPort = %d, want 9090", cfg.HTTPPort)
	}
	if !cfg.SkipVerify {
		t.Errorf("SkipVerify = %v, want true", cfg.SkipVerify)
	}
	// PANOS_ALLOW_WRITES=true is the one input that flips ReadOnly off; dropping
	// the negation (cfg.ReadOnly stays true) turns this red.
	if cfg.ReadOnly {
		t.Errorf("ReadOnly = %v, want false when PANOS_ALLOW_WRITES=true", cfg.ReadOnly)
	}
	if cfg.JobWait != 30*time.Second {
		t.Errorf("JobWait = %v, want 30s", cfg.JobWait)
	}
	if cfg.LogLevel != slog.LevelDebug {
		t.Errorf("LogLevel = %v, want DEBUG", cfg.LogLevel)
	}
}

// TestLoadConfigParsesExplicitFalse pins that an explicit "false" is read as
// false. Without it, a parseBoolEnv that ignored its parsed value and always
// returned true would survive the suite, silently disabling TLS verification or
// enabling writes for an operator who asked for neither. PANOS_ALLOW_WRITES=false
// must behave exactly like the absent default: read-only.
func TestLoadConfigParsesExplicitFalse(t *testing.T) {
	setEnv(t, map[string]string{
		"PANOS_HOST": "fw", "PANOS_API_KEY": "k",
		"PANOS_SKIP_VERIFY": "false", "PANOS_ALLOW_WRITES": "false",
	})
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SkipVerify {
		t.Error("SkipVerify = true, want false for an explicit false")
	}
	if !cfg.ReadOnly {
		t.Error("ReadOnly = false, want true: PANOS_ALLOW_WRITES=false means read-only")
	}
}

// TestLoadConfigRejectsRemovedReadOnlyVar pins the migration guard. A lingering
// PANOS_READ_ONLY with any non-empty value must abort startup and name both the
// old and the new variable, so an operator who still sets the old variable is
// forced to migrate consciously instead of having a prior write-intent silently
// dropped. Both "true" and "false" must trip it: the guard keys on a non-empty
// value, not on the parsed boolean. Deleting the guard block turns this red.
func TestLoadConfigRejectsRemovedReadOnlyVar(t *testing.T) {
	for _, val := range []string{"true", "false"} {
		t.Run(val, func(t *testing.T) {
			setEnv(t, map[string]string{
				"PANOS_HOST": "fw", "PANOS_API_KEY": "k", "PANOS_READ_ONLY": val,
			})
			_, err := LoadConfig()
			if err == nil {
				t.Fatal("expected an error when the removed PANOS_READ_ONLY is set")
			}
			for _, want := range []string{"PANOS_READ_ONLY", "PANOS_ALLOW_WRITES"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error should name %s, got %v", want, err)
				}
			}
		})
	}
}

// TestLoadConfigIgnoresBlankRemovedVar pins that an empty or whitespace-only
// PANOS_READ_ONLY does not trip the migration guard, matching how the rest of
// LoadConfig treats empty as unset. The server boots read-only. Replacing the
// TrimSpace guard condition with a bare LookupEnv presence check turns this red.
func TestLoadConfigIgnoresBlankRemovedVar(t *testing.T) {
	setEnv(t, map[string]string{
		"PANOS_HOST": "fw", "PANOS_API_KEY": "k", "PANOS_READ_ONLY": "   ",
	})
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("a blank PANOS_READ_ONLY must not abort startup: %v", err)
	}
	if !cfg.ReadOnly {
		t.Error("ReadOnly = false, want true: a blank PANOS_READ_ONLY leaves the safe default")
	}
}

// TestLoadConfigGuardPrecedesAllowWrites pins that the migration guard is checked
// before PANOS_ALLOW_WRITES, so an operator who adds the new variable but forgets
// to delete the old one is stopped rather than silently booting writable.
func TestLoadConfigGuardPrecedesAllowWrites(t *testing.T) {
	setEnv(t, map[string]string{
		"PANOS_HOST": "fw", "PANOS_API_KEY": "k",
		"PANOS_READ_ONLY": "true", "PANOS_ALLOW_WRITES": "true",
	})
	_, err := LoadConfig()
	if err == nil {
		t.Fatal("expected the guard to abort when PANOS_READ_ONLY is set alongside PANOS_ALLOW_WRITES")
	}
	if !strings.Contains(err.Error(), "PANOS_READ_ONLY") {
		t.Errorf("error should name PANOS_READ_ONLY, got %v", err)
	}
}

// TestLoadConfigLogLevelIsCaseInsensitive pins that the spelling most operators
// type actually works, rather than silently resolving to the default.
func TestLoadConfigLogLevelIsCaseInsensitive(t *testing.T) {
	setEnv(t, map[string]string{"PANOS_HOST": "fw", "PANOS_API_KEY": "k", "PANOS_LOG_LEVEL": "DEBUG"})
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogLevel != slog.LevelDebug {
		t.Fatalf("PANOS_LOG_LEVEL=DEBUG gave %v, want DEBUG", cfg.LogLevel)
	}
}

// TestLoadConfigIgnoresBareLogLevel pins the deliberate asymmetry of issue #4:
// unlike PANOS_HOST and PANOS_SKIP_VERIFY, the log level has NO fallback. The
// server reads only PANOS_LOG_LEVEL, so a bare LOG_LEVEL inherited from whatever
// environment the MCP client passes down is ignored and the default holds.
func TestLoadConfigIgnoresBareLogLevel(t *testing.T) {
	setEnv(t, map[string]string{"PANOS_HOST": "fw", "PANOS_API_KEY": "k", "LOG_LEVEL": "debug"})
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogLevel != slog.LevelInfo {
		t.Errorf("LogLevel = %v, want INFO: a bare LOG_LEVEL must not be read", cfg.LogLevel)
	}
}

func TestLoadConfigAcceptsPortBoundaries(t *testing.T) {
	for _, port := range []string{"1", "65535"} {
		t.Run(port, func(t *testing.T) {
			setEnv(t, map[string]string{"PANOS_HOST": "fw", "PANOS_API_KEY": "k", "PANOS_PORT": port})
			cfg, err := LoadConfig()
			if err != nil {
				t.Fatalf("port %s should be accepted: %v", port, err)
			}
			if got := strconv.Itoa(cfg.Port); got != port {
				t.Fatalf("Port = %s, want %s", got, port)
			}
		})
	}
}

func TestLoadConfigAcceptsMaxJobWait(t *testing.T) {
	setEnv(t, map[string]string{"PANOS_HOST": "fw", "PANOS_API_KEY": "k", "PANOS_JOB_WAIT": "86400"})
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("86400 is the documented maximum and must be accepted: %v", err)
	}
	if cfg.JobWait != 86400*time.Second {
		t.Fatalf("JobWait = %v, want 24h0m0s", cfg.JobWait)
	}
}

func TestLoadConfigRejectsBadValues(t *testing.T) {
	base := func(extra map[string]string) map[string]string {
		env := map[string]string{"PANOS_HOST": "fw", "PANOS_API_KEY": "k"}
		maps.Copy(env, extra)
		return env
	}
	// wantErr binds each case to the variable it is meant to exercise, so a case
	// cannot pass by failing on some unrelated rule.
	for _, tc := range []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{"bad transport", map[string]string{"MCP_TRANSPORT": "grpc"}, "MCP_TRANSPORT"},
		{"port not a number", map[string]string{"PANOS_PORT": "nope"}, "PANOS_PORT"},
		{"port too large", map[string]string{"PANOS_PORT": "65536"}, "PANOS_PORT"},
		{"port zero", map[string]string{"PANOS_PORT": "0"}, "PANOS_PORT"},
		{"port negative", map[string]string{"PANOS_PORT": "-1"}, "PANOS_PORT"},
		{"http port zero", map[string]string{"MCP_HTTP_PORT": "0"}, "MCP_HTTP_PORT"},
		{"job wait not a number", map[string]string{"PANOS_JOB_WAIT": "abc"}, "PANOS_JOB_WAIT"},
		{"job wait zero", map[string]string{"PANOS_JOB_WAIT": "0"}, "PANOS_JOB_WAIT"},
		{"job wait negative", map[string]string{"PANOS_JOB_WAIT": "-5"}, "PANOS_JOB_WAIT"},
		{"job wait above cap", map[string]string{"PANOS_JOB_WAIT": "86401"}, "PANOS_JOB_WAIT"},
		// Above the point where waitSec * time.Second wraps int64 negative. It
		// is rejected by the same cap as the case above rather than by any
		// overflow-specific branch; the cap is what keeps the multiplication in
		// range, so this case pins that the cap sits below the wrap point.
		{"job wait past duration wrap", map[string]string{"PANOS_JOB_WAIT": "9223372037"}, "PANOS_JOB_WAIT"},
		{"job wait beyond int64", map[string]string{"PANOS_JOB_WAIT": "9223372036854775808"}, "PANOS_JOB_WAIT"},
		// Match the stable phrase "PANOS_SKIP_VERIFY value" to pin attribution to
		// the primary: it cannot occur in the alias error, whose text is
		// "invalid PANOS_SKIP_VERIFY_CERTIFICATE value".
		{"bad skip verify", map[string]string{"PANOS_SKIP_VERIFY": "yes"}, "PANOS_SKIP_VERIFY value"},
		// The alias is set and invalid; the error must name the variable that
		// carried the value, so the full _CERTIFICATE name (not the primary that
		// is a prefix of it) is required.
		{"bad skip verify certificate alias", map[string]string{"PANOS_SKIP_VERIFY_CERTIFICATE": "yes"}, "PANOS_SKIP_VERIFY_CERTIFICATE"},
		{"bad allow writes", map[string]string{"PANOS_ALLOW_WRITES": "maybe"}, "PANOS_ALLOW_WRITES"},
		{"bad log level", map[string]string{"PANOS_LOG_LEVEL": "verbose"}, "PANOS_LOG_LEVEL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setEnv(t, base(tc.env))
			_, err := LoadConfig()
			if err == nil {
				t.Fatalf("expected an error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error should name %s, got %v", tc.wantErr, err)
			}
		})
	}
}

// Redaction depends on Config satisfying these interfaces as a VALUE, not as a
// pointer. With pointer receivers the whole suite and the linter still pass
// while logging a Config prints the credentials in full, so the property is
// pinned here at compile time rather than left to a comment.
var (
	_ slog.LogValuer = Config{}
	_ fmt.Stringer   = Config{}
)

// TestConfigRedactsSecrets pins that the real logging and formatting paths do
// not print the API key or the password. Config is logged during startup, and
// CI publishes test logs.
func TestConfigRedactsSecrets(t *testing.T) {
	//nolint:gosec // G101: these are fixture values, not real credentials. The
	// test exists precisely to prove they never reach a rendered Config.
	cfg := Config{
		Host:      "fw",
		APIKey:    "LUFRPT1TUPERSECRETKEY",
		Username:  "admin",
		Password:  "hunter2",
		HTTPToken: "TOKENSUPERSECRET1234",
	}
	// A real JSON handler, which is what main.go installs, plus the fmt verbs a
	// caller might reach for. %#v is deliberately absent: it prints struct
	// fields verbatim and no Stringer can intercept it.
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("startup", "config", cfg)

	// Nested inside another struct, the JSON handler falls through to
	// encoding/json, which consults neither LogValuer nor Stringer. The json:"-"
	// tags are what close this path.
	var nested bytes.Buffer
	slog.New(slog.NewJSONHandler(&nested, nil)).
		Info("nested", "ctx", struct{ Cfg Config }{cfg})

	//nolint:musttag // Config is not a JSON API type. It is marshalled here only to prove the json:"-" tags keep the credentials out.
	marshalled, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Each verb is rendered separately rather than calling String(), because the
	// property under test is that these paths route through String() at all.
	viaV := fmt.Sprintf("%v", cfg)    //nolint:gocritic // redundantSprint: exercising the %v path is the point.
	viaS := fmt.Sprintf("%s", cfg)    //nolint:gocritic,staticcheck // redundantSprint/S1025: exercising the %s path is the point.
	viaPtr := fmt.Sprintf("%v", &cfg) //nolint:gocritic // redundantSprint: exercising a *Config is the point.

	for name, rendered := range map[string]string{
		"String()":           cfg.String(),
		"%v":                 viaV,
		"%+v":                fmt.Sprintf("%+v", cfg),
		"%s":                 viaS,
		"pointer %v":         viaPtr,
		"slog JSON handler":  buf.String(),
		"slog nested struct": nested.String(),
		"json.Marshal":       string(marshalled),
	} {
		if strings.Contains(rendered, "LUFRPT1TUPERSECRETKEY") {
			t.Errorf("%s leaked the API key: %s", name, rendered)
		}
		if strings.Contains(rendered, "hunter2") {
			t.Errorf("%s leaked the password: %s", name, rendered)
		}
		if strings.Contains(rendered, "TOKENSUPERSECRET1234") {
			t.Errorf("%s leaked the http token: %s", name, rendered)
		}
	}
	// The presence-only signal must still be reported, so an operator can confirm
	// a token is configured without the value ever appearing.
	if s := cfg.String(); !strings.Contains(s, "http_token_set=true") {
		t.Errorf("String() should report http_token_set=true: %s", s)
	}
}

// TestLoadConfigTrimsStringInputs pins the trimming on every field that gets it,
// not just the host. Dropping TrimSpace from any single field otherwise passes.
func TestLoadConfigTrimsStringInputs(t *testing.T) {
	setEnv(t, map[string]string{
		"PANOS_HOST": "  fw  ", "PANOS_API_KEY": "  k  ",
		"PANOS_USERNAME": "  admin  ",
		"MCP_TRANSPORT":  "  http  ", "MCP_HTTP_HOST": "  0.0.0.0  ",
		"MCP_HTTP_PORT": "  9090  ", "MCP_HTTP_TOKEN": "  tok  ",
		"PANOS_JOB_WAIT":    "  30  ",
		"PANOS_SKIP_VERIFY": "  true  ", "PANOS_ALLOW_WRITES": "  true  ",
		"PANOS_LOG_LEVEL": "  debug  ",
	})
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, got, want string }{
		{"Host", cfg.Host, "fw"},
		{"APIKey", cfg.APIKey, "k"},
		{"Username", cfg.Username, "admin"},
		{"Transport", cfg.Transport, "http"},
		{"HTTPHost", cfg.HTTPHost, "0.0.0.0"},
		{"HTTPToken", cfg.HTTPToken, "tok"},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
	if cfg.HTTPPort != 9090 {
		t.Errorf("HTTPPort = %d, want 9090", cfg.HTTPPort)
	}
	if cfg.JobWait != 30*time.Second {
		t.Errorf("JobWait = %v, want 30s", cfg.JobWait)
	}
	if !cfg.SkipVerify {
		t.Error("SkipVerify = false, want true")
	}
	// The whitespace an operator pastes around a value must still enable writes
	// rather than error. Removing TrimSpace from parseBoolEnv makes ParseBool fail
	// on "  true  ", which surfaces here as an unexpected LoadConfig error.
	if cfg.ReadOnly {
		t.Error(`ReadOnly = true, want false: PANOS_ALLOW_WRITES="  true  " enables writes after trimming`)
	}
	if cfg.LogLevel != slog.LevelDebug {
		t.Errorf("LogLevel = %v, want DEBUG", cfg.LogLevel)
	}
}

// writeTestCA generates a throwaway self-signed CA, PEM-encodes it into a temp
// file, and returns the path. Used by config and server tests that need a CA
// file loadCACertPool will accept.
func writeTestCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "panos-mcp-go test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	return path
}

// TestIsLoopback pins the loopback classification that the MCP_HTTP_TOKEN guard
// relies on. Anything not provably loopback (a hostname, 0.0.0.0, empty, or an
// IPv6 literal carrying a zone id that net.ParseIP rejects) must read as false so
// the guard fails closed.
func TestIsLoopback(t *testing.T) {
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"127.0.0.1", true},
		{"127.0.0.2", true}, // the whole 127.0.0.0/8 range is loopback
		{"::1", true},
		{"[::1]", true},
		{"localhost", true},
		{"LocalHost", true},
		{"0.0.0.0", false},
		{"192.168.1.5", false},
		{"example.com", false},
		{"", false},
		{"::1%lo0", false},   // a zone id is not parsed as an IP: fail closed
		{"[::1%lo0]", false}, // same, bracketed
	} {
		if got := isLoopback(tc.host); got != tc.want {
			t.Errorf("isLoopback(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

// TestLoadConfigHTTPTokenRequiredWhenNonLoopback pins the fail-closed rule: an
// http transport bound to a non-loopback interface must not start without
// MCP_HTTP_TOKEN, while loopback and stdio are exempt (issue #5).
func TestLoadConfigHTTPTokenRequiredWhenNonLoopback(t *testing.T) {
	for _, tc := range []struct {
		name    string
		env     map[string]string
		wantErr string // substring; "" means expect success
	}{
		{"non-loopback http without token", map[string]string{
			"MCP_TRANSPORT": "http", "MCP_HTTP_HOST": "0.0.0.0",
		}, "MCP_HTTP_TOKEN"},
		{"non-loopback http with token", map[string]string{
			"MCP_TRANSPORT": "http", "MCP_HTTP_HOST": "0.0.0.0", "MCP_HTTP_TOKEN": "tok",
		}, ""},
		{"loopback http without token", map[string]string{
			"MCP_TRANSPORT": "http", "MCP_HTTP_HOST": "127.0.0.1",
		}, ""},
		{"stdio ignores non-loopback host", map[string]string{
			"MCP_TRANSPORT": "stdio", "MCP_HTTP_HOST": "0.0.0.0",
		}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{"PANOS_HOST": "fw", "PANOS_API_KEY": "k"}
			maps.Copy(env, tc.env)
			setEnv(t, env)
			_, err := LoadConfig()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("LoadConfig: unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("LoadConfig error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

// TestLoadConfigRejectsSkipVerifyWithCACert pins that the two contradictory TLS
// inputs are rejected rather than silently resolved (issue #8).
func TestLoadConfigRejectsSkipVerifyWithCACert(t *testing.T) {
	ca := writeTestCA(t)
	setEnv(t, map[string]string{
		"PANOS_HOST": "fw", "PANOS_API_KEY": "k",
		"PANOS_SKIP_VERIFY": "true", "PANOS_CA_CERT": ca,
	})
	_, err := LoadConfig()
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("LoadConfig error = %v, want 'mutually exclusive'", err)
	}
}

// TestLoadConfigValidatesCACert pins that PANOS_CA_CERT is read and parsed at
// load time, so a bad path or a non-PEM file fails at startup, and that a valid
// path is stored trimmed (issue #8).
func TestLoadConfigValidatesCACert(t *testing.T) {
	t.Run("nonexistent path", func(t *testing.T) {
		setEnv(t, map[string]string{"PANOS_HOST": "fw", "PANOS_API_KEY": "k", "PANOS_CA_CERT": "/nonexistent/ca.pem"})
		if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), "PANOS_CA_CERT") {
			t.Fatalf("LoadConfig error = %v, want a PANOS_CA_CERT read error", err)
		}
	})
	t.Run("invalid pem", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "bad.pem")
		if err := os.WriteFile(bad, []byte("not a pem"), 0o600); err != nil {
			t.Fatal(err)
		}
		setEnv(t, map[string]string{"PANOS_HOST": "fw", "PANOS_API_KEY": "k", "PANOS_CA_CERT": bad})
		if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), "no certificates parsed") {
			t.Fatalf("LoadConfig error = %v, want a parse error", err)
		}
	})
	t.Run("valid pem is loaded and trimmed", func(t *testing.T) {
		ca := writeTestCA(t)
		setEnv(t, map[string]string{"PANOS_HOST": "fw", "PANOS_API_KEY": "k", "PANOS_CA_CERT": "  " + ca + "  "})
		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		if cfg.CACert != ca {
			t.Fatalf("CACert = %q, want trimmed %q", cfg.CACert, ca)
		}
	})
}
