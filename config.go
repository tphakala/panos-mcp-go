package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultHTTPHost = "127.0.0.1"
	defaultHTTPPort = 8080
	defaultJobWait  = 120 * time.Second

	// maxJobWaitSec caps PANOS_JOB_WAIT at 24 hours. An upper bound is required,
	// not merely tidy: time.Duration is int64 nanoseconds, so waitSec * time.Second
	// overflows above math.MaxInt64/int64(time.Second) = 9223372036 and wraps to a
	// negative duration, which a positivity check placed before the multiplication
	// cannot see. A negative deadline expires immediately, and time.NewTicker panics
	// on a non-positive duration.
	maxJobWaitSec = 24 * 60 * 60

	minPort = 1
	maxPort = 65535

	transportStdio = "stdio"
	transportHTTP  = "http"
)

// Config holds the server configuration, loaded from environment variables. It
// carries an API key and a password, so it redacts them on the fmt and slog
// paths; see LogValue for what that does and does not cover.
type Config struct {
	Host     string
	Port     int
	APIKey   string `json:"-"`
	Username string
	// Password and APIKey are json:"-" because encoding/json consults neither
	// slog.LogValuer nor fmt.Stringer. Without the tag, a Config nested inside
	// another struct that is logged through a JSON handler prints both in full.
	Password   string `json:"-"`
	SkipVerify bool
	// SkipVerifySource names the variable that set SkipVerify (PANOS_SKIP_VERIFY
	// or the pango alias PANOS_SKIP_VERIFY_CERTIFICATE) so a startup warning can
	// report which variable disabled TLS verification. Empty when neither is set.
	SkipVerifySource string
	CACert           string
	ReadOnly         bool
	JobWait          time.Duration
	Transport        string
	HTTPHost         string
	HTTPPort         int
	LogLevel         slog.Level
}

// LogValue implements slog.LogValuer. It reports whether the API key and the
// password are present, never their values, which covers every fmt verb except
// %#v, and slog attributes. %#v still prints the struct fields verbatim.
//
// The receiver must be a value rather than a pointer: with a pointer receiver,
// logging a Config instead of a *Config silently bypasses redaction and prints
// the credentials. The copy happens only on a log call, never in a hot path.
//
//nolint:gocritic // hugeParam: value receiver is required for redaction, see above.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("host", c.Host),
		slog.Int("port", c.Port),
		slog.Bool("api_key_set", c.APIKey != ""),
		slog.String("username", c.Username),
		slog.Bool("password_set", c.Password != ""),
		slog.Bool("skip_verify", c.SkipVerify),
		slog.String("ca_cert", c.CACert),
		slog.Bool("read_only", c.ReadOnly),
		slog.Duration("job_wait", c.JobWait),
		slog.String("transport", c.Transport),
		slog.String("http_host", c.HTTPHost),
		slog.Int("http_port", c.HTTPPort),
		slog.String("log_level", c.LogLevel.String()),
	)
}

// String implements fmt.Stringer so that %v and %+v redact the credentials too.
// slog.LogValuer alone does not cover fmt verbs.
func (c Config) String() string { return c.LogValue().String() }

// LoadConfig reads configuration from environment variables. Authentication is
// an API key, or a username and password pair. When an API key and a username
// are both supplied the API key is what pango ends up using, so the pair is
// accepted rather than rejected. PANOS_HOSTNAME and PANOS_SKIP_VERIFY_CERTIFICATE
// are accepted as fallback aliases for PANOS_HOST and PANOS_SKIP_VERIFY, and the
// log level is read from PANOS_LOG_LEVEL only (issue #4); these are the names
// pango reads under Client.CheckEnvironment (pango
// v0.10.3-0.20260731153743-efa43570c367, client.go:161,269,1141, read 2026-08-11).
func LoadConfig() (Config, error) {
	// Trim the string inputs. A value like " " would otherwise satisfy a
	// non-empty check and fail much later, at connection time, with a URL error
	// instead of a configuration error. Password is deliberately not trimmed:
	// leading or trailing whitespace can be part of a real password.
	//
	// PANOS_HOST is primary; PANOS_HOSTNAME is accepted as a fallback alias
	// because it is the name pango itself reads (issue #4).
	host, _ := envFirst("PANOS_HOST", "PANOS_HOSTNAME")
	cfg := Config{
		Host:     host,
		APIKey:   strings.TrimSpace(os.Getenv("PANOS_API_KEY")),
		Username: strings.TrimSpace(os.Getenv("PANOS_USERNAME")),
		Password: os.Getenv("PANOS_PASSWORD"),
		CACert:   strings.TrimSpace(os.Getenv("PANOS_CA_CERT")),
		HTTPHost: envOr("MCP_HTTP_HOST", defaultHTTPHost),
		// ReadOnly defaults to true so writes are opt-in (issue #3). The assignment
		// below overwrites it in the normal path; keeping the safe value here means
		// that if that assignment is ever removed, the server fails closed
		// (read-only) rather than open.
		ReadOnly: true,
	}

	if cfg.Host == "" {
		return Config{}, errors.New("PANOS_HOST (or PANOS_HOSTNAME) environment variable is required")
	}
	if cfg.APIKey == "" {
		if cfg.Username == "" {
			return Config{}, errors.New("PANOS_USERNAME environment variable is required (or set PANOS_API_KEY)")
		}
		if cfg.Password == "" {
			return Config{}, errors.New("PANOS_PASSWORD environment variable is required (or set PANOS_API_KEY)")
		}
	}

	var err error
	// An unset port stays 0. pango builds the API URL without a port component
	// when Client.Port is 0, leaving net/http to apply the scheme default
	// (pango v0.10.3-0.20260731153743-efa43570c367, client.go:308-312, read
	// 2026-08-11). A value that IS set must be a usable port.
	if cfg.Port, err = portEnv("PANOS_PORT", 0); err != nil {
		return Config{}, err
	}
	if cfg.SkipVerify, cfg.SkipVerifySource, err = parseBoolEnvFirst("PANOS_SKIP_VERIFY", "PANOS_SKIP_VERIFY_CERTIFICATE"); err != nil {
		return Config{}, err
	}
	// Writes are opt-in (issue #3): readOnlyFromEnv returns read-only unless
	// PANOS_ALLOW_WRITES=true. The ReadOnly default set above explains why a lost
	// assignment fails closed.
	if cfg.ReadOnly, err = readOnlyFromEnv(); err != nil {
		return Config{}, err
	}

	waitSec, err := intEnv("PANOS_JOB_WAIT", int(defaultJobWait/time.Second))
	if err != nil {
		return Config{}, err
	}
	if waitSec < 1 || waitSec > maxJobWaitSec {
		return Config{}, fmt.Errorf("PANOS_JOB_WAIT must be between 1 and %d seconds, got %d", maxJobWaitSec, waitSec)
	}
	cfg.JobWait = time.Duration(waitSec) * time.Second

	cfg.Transport = envOr("MCP_TRANSPORT", transportStdio)
	switch cfg.Transport {
	case transportStdio, transportHTTP:
	default:
		return Config{}, fmt.Errorf("invalid MCP_TRANSPORT value %q: expected %s/%s",
			cfg.Transport, transportStdio, transportHTTP)
	}

	if cfg.HTTPPort, err = portEnv("MCP_HTTP_PORT", defaultHTTPPort); err != nil {
		return Config{}, err
	}
	// Read PANOS_LOG_LEVEL only, never a bare LOG_LEVEL (issue #4): MCP clients
	// pass their own environment down, so an unrelated LOG_LEVEL would otherwise
	// change this server's verbosity. Unlike the host and skip-verify aliases,
	// there is deliberately no fallback here; ignoring the inherited name is the
	// fix, and the namespaced name matches pango's own PANOS_LOG_LEVEL.
	if cfg.LogLevel, err = levelEnv("PANOS_LOG_LEVEL", slog.LevelInfo); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// envOr returns the trimmed value of the environment variable key, or fallback
// when the variable is unset, empty, or only whitespace.
func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// envFirst returns the trimmed value of the first non-empty variable, checking
// primary first and then each alias in order, together with the name it came
// from (so a caller can attribute a parse error to the variable that actually
// carried the value). When none is set it returns "" and the primary name.
// Aliases exist to honour pango's own environment contract (issue #4): the
// project's own name stays primary and wins, the pango name is a fallback. The
// primary parameter is separate from the variadic aliases so a zero-name call
// cannot compile.
func envFirst(primary string, aliases ...string) (value, from string) {
	if v := strings.TrimSpace(os.Getenv(primary)); v != "" {
		return v, primary
	}
	for _, n := range aliases {
		if v := strings.TrimSpace(os.Getenv(n)); v != "" {
			return v, n
		}
	}
	return "", primary
}

// parseBoolEnvFirst parses the first set variable among primary and aliases as a
// boolean, primary first. It resolves only the NAME through envFirst and then
// reuses parseBoolEnv, so trimming, the empty-means-false rule, and the error
// message format all stay single-sourced. It also returns that name (from), so a
// caller can report which variable supplied a security-relevant value. A parse
// failure is reported against the variable that actually carried the value, so
// an operator using only a pango alias is pointed at the alias, never at a
// primary they never set.
func parseBoolEnvFirst(primary string, aliases ...string) (value bool, from string, err error) {
	_, from = envFirst(primary, aliases...)
	value, err = parseBoolEnv(from)
	return value, from, err
}

// intEnv parses an integer environment variable, returning def when the
// variable is unset or empty.
func intEnv(key string, def int) (int, error) {
	s := strings.TrimSpace(os.Getenv(key))
	if s == "" {
		return def, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid %s value %q: expected an integer", key, s)
	}
	return n, nil
}

// portEnv parses a TCP port environment variable, returning def when the
// variable is unset or empty. A value that is present must be in the range 1 to
// 65535. def is returned unchecked, so a caller may pass 0 to leave the port
// unset and let the transport pick the scheme default.
func portEnv(key string, def int) (int, error) {
	if strings.TrimSpace(os.Getenv(key)) == "" {
		return def, nil
	}
	// Pass 0 rather than def: the variable is known to be set here, so intEnv's
	// fallback is unreachable, and passing def would send it through the range
	// check below, which def is documented to skip.
	n, err := intEnv(key, 0)
	if err != nil {
		return 0, err
	}
	if n < minPort || n > maxPort {
		return 0, fmt.Errorf("%s must be between %d and %d, got %d", key, minPort, maxPort, n)
	}
	return n, nil
}

// parseBoolEnv reads a boolean environment variable. An unset or empty value
// yields false with no error; any other value is parsed with strconv.ParseBool
// so that a typo fails loudly at startup instead of silently reading as false.
func parseBoolEnv(name string) (bool, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return false, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("invalid %s value %q: expected true/false", name, raw)
	}
	return v, nil
}

// readOnlyFromEnv resolves the read-only setting. Writes are opt-in via
// PANOS_ALLOW_WRITES (issue #3): absent or empty means read-only, so a typo in
// the variable NAME fails safe; a typo in the VALUE still fails loudly through
// parseBoolEnv. A lingering PANOS_READ_ONLY aborts startup rather than being
// silently ignored: it governed the same safety property under the old
// contract, so disregarding it could leave the server in a mode the operator
// did not intend. Forcing a conscious migration is the point of issue #3.
//
// Both error paths return true (read-only), so the helper fails safe in
// isolation: a caller that logged the error instead of aborting would still get
// read-only, not writes.
func readOnlyFromEnv() (bool, error) {
	if strings.TrimSpace(os.Getenv("PANOS_READ_ONLY")) != "" {
		return true, errors.New(
			"PANOS_READ_ONLY has been removed: writes are disabled unless PANOS_ALLOW_WRITES=true; unset PANOS_READ_ONLY")
	}
	allowWrites, err := parseBoolEnv("PANOS_ALLOW_WRITES")
	if err != nil {
		return true, err
	}
	return !allowWrites, nil
}

// levelEnv parses a slog level, returning def when the variable is unset or
// empty. slog.Level.UnmarshalText accepts debug/info/warn/error in any case,
// plus offsets such as ERROR+2, and rejects everything else, so a typo fails at
// startup rather than silently resolving to the default level.
func levelEnv(key string, def slog.Level) (slog.Level, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def, nil
	}
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(raw)); err != nil {
		return 0, fmt.Errorf("invalid %s value %q: expected debug/info/warn/error, optionally with an offset such as ERROR+2", key, raw)
	}
	return lvl, nil
}
