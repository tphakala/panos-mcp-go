package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

// version is overwritten at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := runMain(); err != nil {
		os.Exit(1)
	}
}

func runMain() error {
	// Install a JSON handler before anything can log, so a configuration error
	// has the same shape as every later line, and set it as the slog default so
	// that libraries logging through the package-level functions are covered
	// too. The level is raised or lowered once the config is known.
	levelVar := &slog.LevelVar{}
	levelVar.Set(slog.LevelInfo)
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: levelVar}))
	slog.SetDefault(logger)

	cfg, err := LoadConfig()
	if err != nil {
		logger.Error("configuration error", "error", err)
		return err
	}
	// A disabled TLS check is a security-relevant state, and PANOS_SKIP_VERIFY has
	// a pango-alias fallback (PANOS_SKIP_VERIFY_CERTIFICATE) that could be inherited
	// from the environment, so make it loud and name the variable that set it
	// rather than letting it pass silently (issue #4 review). Emit it BEFORE the
	// configured level is applied, so a low-verbosity PANOS_LOG_LEVEL (error, for
	// example) cannot suppress this security warning; the handler is still at the
	// default info level here, so a WARN is guaranteed to be written.
	if cfg.SkipVerify {
		logger.Warn("TLS certificate verification is disabled; the firewall session can be intercepted",
			"source", cfg.SkipVerifySource)
	}
	levelVar.Set(cfg.LogLevel)
	// Log the redacted group explicitly. slog already resolves Config through its
	// LogValue method, so cfg.LogValue() produces byte-identical output to passing
	// cfg; the difference is visible only to static analysis. The go/clear-text-logging
	// scanner cannot model the slog.LogValuer redaction, so it reads a bare cfg as the
	// APIKey and Password fields flowing into a log call. Passing the resolved group
	// reduces those secret fields to the api_key_set/password_set/http_token_set
	// presence booleans (the non-secret fields such as host and username are logged as
	// before), keeping the raw secrets out of the call while the runtime output is
	// unchanged (see Config.LogValue and TestConfigRedactsSecrets).
	logger.Debug("configuration loaded", "version", version, "config", cfg.LogValue())

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx, &cfg, logger); err != nil {
		logger.Error("server error", "error", err)
		return err
	}
	return nil
}
