package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
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
	"MCP_TRANSPORT", "MCP_HTTP_HOST", "MCP_HTTP_PORT", "PANOS_LOG_LEVEL", "LOG_LEVEL",
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
		"PANOS_CA_CERT": "/etc/ssl/ca.pem", "PANOS_JOB_WAIT": "30",
		"MCP_TRANSPORT": "http", "MCP_HTTP_HOST": "0.0.0.0", "MCP_HTTP_PORT": "9090",
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
		{"CACert", cfg.CACert, "/etc/ssl/ca.pem"},
		{"Transport", cfg.Transport, "http"},
		{"HTTPHost", cfg.HTTPHost, "0.0.0.0"},
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
		for k, v := range extra {
			env[k] = v
		}
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
		// Trailing space pins attribution to the primary: "PANOS_SKIP_VERIFY " does
		// not occur in the alias error "invalid PANOS_SKIP_VERIFY_CERTIFICATE value".
		{"bad skip verify", map[string]string{"PANOS_SKIP_VERIFY": "yes"}, "PANOS_SKIP_VERIFY "},
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
		Host:     "fw",
		APIKey:   "LUFRPT1TUPERSECRETKEY",
		Username: "admin",
		Password: "hunter2",
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
	}
}

// TestLoadConfigTrimsStringInputs pins the trimming on every field that gets it,
// not just the host. Dropping TrimSpace from any single field otherwise passes.
func TestLoadConfigTrimsStringInputs(t *testing.T) {
	setEnv(t, map[string]string{
		"PANOS_HOST": "  fw  ", "PANOS_API_KEY": "  k  ",
		"PANOS_USERNAME": "  admin  ", "PANOS_CA_CERT": "  /ca.pem  ",
		"MCP_TRANSPORT": "  http  ", "MCP_HTTP_HOST": "  0.0.0.0  ",
		"MCP_HTTP_PORT": "  9090  ", "PANOS_JOB_WAIT": "  30  ",
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
		{"CACert", cfg.CACert, "/ca.pem"},
		{"Transport", cfg.Transport, "http"},
		{"HTTPHost", cfg.HTTPHost, "0.0.0.0"},
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
