// Command mcp-authproxy is an auth-only proxy that puts an MCP server behind OAuth 2.1 / OIDC.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/corker/mcp-authproxy/internal/config"
	"github.com/corker/mcp-authproxy/internal/logging"
	"github.com/corker/mcp-authproxy/internal/server"
)

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
		_, _ = fmt.Fprintf(stderr, "mcp-authproxy: configuration error: %v\n", err)
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
	if err := server.Run(ctx, server.New(cfg, log), log); err != nil {
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
	_, _ = fmt.Fprintf(w, "mcp-authproxy %s (%s, %s)\n", v.Version, v.Revision, v.GoVersion)
}
