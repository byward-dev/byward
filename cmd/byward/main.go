// Command byward is an auth-only proxy that puts an MCP server behind OAuth 2.1 / OIDC.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/server"
	"github.com/byward-dev/byward/internal/tracing"
)

// getenv looks names up in environ, the same environment the configuration was read from.
func getenv(environ []string) func(string) string {
	return func(name string) string {
		for _, kv := range environ {
			if k, v, ok := strings.Cut(kv, "="); ok && k == name {
				return v
			}
		}
		return ""
	}
}

// Exit codes: configuration errors are distinct from runtime failures (ADR-0020 §5).
const (
	exitOK      = 0
	exitRuntime = 1
	exitConfig  = 2
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Environ(), os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args, environ []string, stdout, stderr io.Writer) int {
	cfg, act, err := config.Load(args, environ, os.ReadFile)
	switch {
	case config.IsHelp(err):
		_, _ = io.WriteString(stdout, config.Usage())
		return exitOK
	case err != nil:
		_, _ = fmt.Fprintf(stderr, "byward: configuration error: %v\n", err)
		return exitConfig
	case act.Version:
		printVersion(stdout, act.JSON)
		return exitOK
	case act.PrintConfig:
		for _, v := range cfg.Values.Effective() {
			_, _ = fmt.Fprintf(stdout, "%s=%s (%s)\n", v.Setting.Env(), v.Display(), v.Source)
		}
		return exitOK
	}

	log := logging.New(stderr, cfg.LogFormat)
	log.Info("starting", "version", buildInfo().Version)
	for _, v := range cfg.Values.Effective() {
		log.Info("config", "setting", v.Setting.Env(), "value", v.Display(), "source", string(v.Source))
	}
	for _, r := range cfg.Relaxations {
		log.Warn("development mode relaxation", "relaxation", r)
	}
	if cfg.NoAuth {
		log.Warn("to require sign-in, remove BYWARD_INSECURE_NO_AUTH and configure an IdP; see docs/reference/settings.md", "relaxation", "next step")
	}
	// Traces only when the operator sets OTEL_TRACES_EXPORTER (ADR-0021 §9).
	tracingOn, stopTracing, err := tracing.Setup(ctx, getenv(environ), buildInfo().Version)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "byward: configuration error: OTEL_* tracing settings: %v\n", err)
		return exitConfig
	}
	defer func() {
		flushCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = stopTracing(flushCtx)
	}()
	if tracingOn {
		log.Info("tracing on", "reason", "OTEL_TRACES_EXPORTER is set")
	}
	srv, err := server.New(cfg, log)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "byward: configuration error: %v\n", err)
		return exitConfig
	}
	if err := server.Run(ctx, srv, log); err != nil {
		log.Error("stopped", "error", err)
		return exitRuntime
	}
	return exitOK
}

type version struct {
	Version   string `json:"version"`
	Revision  string `json:"revision,omitempty"`
	Time      string `json:"time,omitempty"`
	Modified  bool   `json:"modified,omitempty"`
	GoVersion string `json:"go_version"`
}

func buildInfo() version {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return version{Version: "unknown"}
	}
	v := version{Version: bi.Main.Version, GoVersion: bi.GoVersion}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			v.Revision = s.Value
		case "vcs.time":
			v.Time = s.Value
		case "vcs.modified":
			v.Modified = s.Value == "true"
		}
	}
	return v
}

func printVersion(w io.Writer, asJSON bool) {
	v := buildInfo()
	if asJSON {
		_ = json.NewEncoder(w).Encode(v)
		return
	}
	_, _ = fmt.Fprintf(w, "byward %s (%s, %s)\n", v.Version, v.Revision, v.GoVersion)
}
