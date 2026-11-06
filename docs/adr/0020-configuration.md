# ADR-0020: Configuration — flags and env, secrets from files, one registry

- Status: Accepted
- Date: 2026-11-06
- Issue: #19 (F18)

## Context

The proxy runs from a container image, under Kubernetes, compose or systemd (ADR-0019). It fronts
exactly one upstream (ADR-0001: no aggregation), and the access gate takes plain allowlists (ADR-0015).

Standards (fetched 2026-11-05/06): clig.dev, "Apply configuration parameters in order of
precedence" (flags, then environment) and "**Do not read secrets from environment variables.** …
Secrets should only be accepted via credential files"; Twelve-Factor §III, "stores config in
*environment variables*"; Docker Compose, "Secrets are mounted as a file in `/run/secrets/<secret_name>`",
and the `_FILE` convention of Docker Official Images; Kubernetes Secrets "can be mounted as data
volumes"; systemd credentials, a file per credential in `$CREDENTIALS_DIRECTORY`, "not propagated
down the process tree", and systemd.exec, "environment variables are not suitable for passing secrets".

Competitors (source): babs reads env only, needs 6 keys, logs a redacted `startup_config`; oauth2-proxy
rejects unknown keys and has `--config-test` but prints converted config unredacted; Pomerium turns
removed keys into hard errors with a docs URL; agentgateway generates its config docs and serves a
redacted config dump. None suggests a correction for a misspelt key or rejects unknown environment
variables.

## Decision

1. **Sources: flags > `MCP_AUTHPROXY_*` env > defaults.** Every setting has both a flag and an env
   name. No general config file; lists are comma-separated.
2. **Secrets only from files:** `*_FILE` env or `--*-file` flags. An inline secret is accepted only
   with `--dev` and logs a warning.
3. **Structured settings come from files:**
   - signing and sealing keys from a directory, the file name being the key ID (ADR-0007); rotation
     adds a file and restarts;
   - static clients from one JSON file, `--static-clients-file` (client ID, authentication method,
     redirect URIs, secret file; ADR-0008).
4. **One registry in code** holds every setting: name, env, flag, default, secret or not, version
   introduced, deprecation. It generates the docs reference, `--help` and `--help-config <KEY>`, and
   drives validation and redaction.
5. **Strict startup:**
   - an unknown `MCP_AUTHPROXY_*` variable is an error with a "did you mean" suggestion;
   - a removed key is an error with a docs link;
   - a deprecated key works with a warning for at least one minor release;
   - configuration errors exit with their own code, distinct from runtime failures.
6. **Effective configuration** is logged at startup with each value's source
   (`default|env|flag|file`), secrets as `<redacted>`; `--print-config` prints it and exits.
7. **`check --offline`** validates the configuration without network access; `doctor` adds the network
   checks (F20).
8. **IdP presets by name** (`MCP_AUTHPROXY_IDP=entra`). A test keeps the Entra quickstart at five or
   fewer required keys. `init entra` prints the `az` commands and a minimal env file; it never runs
   `az` (ADR-0012).
9. **No hot reload;** a restart applies changes.

## Consequences

- Setting names and the static-clients file format are public interface, versioned through the
  registry's `since` and deprecation fields.
- Kubernetes secret rotation needs a rollout; that is the supported path.
- Later: a JSON Schema if a config file is ever added; reloading TLS certificate files if the proxy
  terminates TLS.

## Considered options

- A YAML or TOML config file (dex, Pomerium, oauth2-proxy): rejected; it adds a parser, a schema and a
  third precedence layer, and every target already handles env plus files.
- Secrets in plain env (babs): rejected; env leaks into child processes and diagnostics, against
  clig.dev and systemd guidance.
- Hot reload (Pomerium): rejected; swapping keys or IdPs mid-flight risks partial application.
