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
	levelVar.Set(cfg.LogLevel)
	// A disabled TLS check is a security-relevant state, and PANOS_SKIP_VERIFY has
	// a pango-alias fallback (PANOS_SKIP_VERIFY_CERTIFICATE) that could be inherited
	// from the environment, so make it loud and name the variable that set it
	// rather than letting it pass silently (issue #4 review).
	if cfg.SkipVerify {
		logger.Warn("TLS certificate verification is disabled; the firewall session can be intercepted",
			"source", cfg.SkipVerifySource)
	}
	logger.Debug("configuration loaded", "version", version, "config", cfg)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx, &cfg, logger); err != nil {
		logger.Error("server error", "error", err)
		return err
	}
	return nil
}
