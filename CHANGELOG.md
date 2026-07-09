# Changelog

All notable changes to `phoenix-firewall` are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

---

## [0.4.1] — 2026-07-09

### Fixed

- **Enrollment sends the full v4 payload on the `--api-key` path**
  (`cmd/enroll.go`, `internal/client/`): `phoenix-firewall enroll --api-key <key>`
  previously called a legacy client method that sent only `device_id` + `metadata`,
  so the backend rejected it with `422` (missing `bootstrap_token`, `hostname`,
  `platform`, `agent_version`). Both enrollment paths now build the complete
  `EnrollRequest` (hostname, platform, agent_version) via `EnrollDevice`;
  `bootstrap_token` is omitted from the body when empty so the API-key path is
  authorized by the key alone. Removed the stripped legacy `Enroll` method.

---

## [0.4.0] — 2026-07-09

### Added

- **Proxy identity/health endpoint** (`internal/proxy/health.go`): proxy now serves
  `GET /__phoenix/health` via `goproxy.NonproxyHandler`, returning a JSON body with
  the identity marker `"service":"phoenix-firewall"`, version, port, fail_mode, and
  backend reachability status. Shims use this to confirm (via identity marker) they are
  talking to a genuine Phoenix proxy, not an arbitrary process on the port.

- **HTTP identity handshake in shims** (`internal/shim/generator.go`): replaces the
  blind TCP probe that caused npm/pip/cargo hangs and false-positive proxy routing when
  any Docker container or dev server occupied port 8080. Shims now send
  `GET /__phoenix/health` and check for the `"service":"phoenix-firewall"` marker
  before routing traffic. A foreign listener produces a clear warning to stderr;
  fail-closed mode blocks the package manager with an actionable message.

- **`fail_mode` config wiring** (`internal/config/config.go`, `cmd/root.go`):
  `initConfig()` now calls `viper.ReadInConfig()` so `agent.toml` is actually parsed.
  `Config.FailMode` is populated from `fail_mode.mode`; env var `PHOENIX_FAIL_MODE`
  overrides at runtime. Only `"closed"` is accepted; anything else normalises to
  `"open"`.

- **Fail-closed policy enforcement in proxy handler** (`internal/proxy/handler.go`):
  when the Phoenix backend API is unreachable, fail-closed mode returns a 403 CONNECT
  block with an actionable error message instead of silently passing traffic through.

- **Backend reachability reporting** (`internal/telemetry/heartbeat.go`, `cmd/proxy.go`):
  `HeartbeatSender` gains an `OnResult func(ok bool)` callback and sends one immediate
  heartbeat at startup. The callback updates `HealthState.backendOK`, which the health
  endpoint reflects. On unreachability the proxy logs:
  `[phoenix-firewall] WARNING: cannot reach Phoenix backend at <url> — operating in fail_mode=<mode>`.

- **Backend enrollment in `enroll` command** (`cmd/enroll.go`,
  `internal/client/firewall.go`): `enroll` now POSTs to
  `/api/v1/firewall/agent/enroll` with device ID and host metadata (hostname, OS,
  arch). The backend-issued `api_key` is persisted to `agent.toml`. Enrollment is
  best-effort: comms failures produce a warning and write local config anyway.
  New `--bootstrap-token` flag accepted as an alternative to `--api-key`.

- **`rules list` subcommand** (`cmd/rules.go`): retrieve and display firewall rules
  attached to the authenticated API key from `GET /api/v1/firewall/rules`. Supports
  `--limit`, `--offset`, and `--json` flags.

- **Installation and proxy alias docs** (`docs/INSTALL.md`,
  `docs/LOCAL_PROXY_ALIAS_GUIDE.md`): step-by-step guides for unsigned-binary
  installation on macOS/Windows/Linux and setting up local proxy aliases.

- **Tenant ID propagation** (`internal/client`, `cmd/heartbeat.go`): `tenant_id` from
  enrollment now threads through to the `/evaluate` payload and heartbeat, scoping
  policy to the correct Phoenix organization end-to-end.

- **Configurable local proxy port** (`cmd/init_cmd.go`, `internal/shim/generator.go`,
  `internal/config`): `--proxy-port` flag / `proxy_port` in `agent.toml` lets users
  avoid conflicts with services (e.g. Docker) that also bind 8080. Precedence:
  CLI flag / `PHOENIX_PORT` env var > `agent.toml` > 8080 default.

- **`--test-mode` for `init`** (`internal/shim/generator.go`, all 3 platforms): bakes
  an unconditional `npm_config_ignore_scripts=true` into every generated npm/pnpm
  shim — before the bypass-token check, independent of firewall verdict or proxy
  reachability. For hosts used to test the firewall against known-malicious
  packages, so a lifecycle script can't execute even if the package is let through.

- **Direct-host-install (proxy-bypass) detection** (`internal/telemetry/bypass.go`):
  shims now always record unscanned installs (proxy unreachable, `fail_mode=open`)
  to a local log, independent of `PHOENIX_FIREWALL_VERBOSE`. The endpoint daemon's
  heartbeat drains and reports `direct_install_bypass_events` on every cycle.

- **Safe canary test fixture** (`internal/proxy/testdata/canary-packages/`):
  local-only npm package mimicking a postinstall network-beacon TTP (DNS lookup +
  outbound HTTPS call) with zero real risk — no filesystem/credential access, no
  data exfiltration, always exits 0 — for exercising this detection path safely.
  Not wired into any build/CI path and not published.

### Fixed

- **Bash `exec` permanent stderr redirection bug**: the bare
  `exec 3<>/dev/tcp/... 2>/dev/null` form permanently redirected the shell's fd 2,
  silencing all subsequent `echo ... >&2` messages. Fixed to
  `{ exec 3<>...; } 2>/dev/null` (block-scoped redirect).

- **`fileHash` hashed path string, not file contents**: the heartbeat integrity stub
  computed `sha256(path_string)`. Replaced with a real `os.Open` / `io.Copy` /
  `sha256.New` implementation with a path-string fallback on open error.

- **Heartbeat 4xx/5xx treated as success**: `http.DefaultClient.Do` returns
  `err == nil` for non-2xx responses. Added explicit status-code check; any
  400–599 response now triggers `OnResult(false)`.

- **`version.Agent` constant used in heartbeat payload**: was hardcoded to `"0.1.0"`.

- **Windows shim now bakes fail_mode default**: `InstallPATH(failMode string)` was
  discarding the `failMode` argument (`_ = failMode`). The batch shim template now
  includes `if not defined PHOENIX_FAIL_MODE set "PHOENIX_FAIL_MODE=<mode>"`.

- **`agent.toml` file permissions enforced on re-enroll**: `os.WriteFile` only applies
  permissions on `O_CREATE`; a pre-existing file retains its old mode.
  `os.Chmod(tomlPath, 0600)` is now called explicitly after every write.

- **npm registry matcher missed the default HTTPS port** (`internal/proxy/handler.go`):
  goproxy's MITM CONNECT tunnels present the host as `registry.npmjs.org:443`, which
  failed the matchers' exact-host comparison and silently passed npm tarball
  requests through unchecked. `stripDefaultPort` now normalizes the URL before
  matching — also handles schemeless URLs and preserves bracketed IPv6 literals.

- **`proxy_port` TOML override ignored env-var precedence** (`cmd/config_helpers.go`):
  the override only checked the CLI flag's `Changed("port")`, missing
  `PHOENIX_PORT` env var values sourced via `viper.AutomaticEnv()` — so `agent.toml`
  could silently clobber a port set via env var. Now checks `viper.IsSet("port")`,
  matching the precedence pattern already used for `strict_mode`/`enforce_policy_freshness`.

- **`init --proxy-port`/`agent.toml` `proxy_port` accepted out-of-range values**:
  now validated against 1–65535 instead of writing an unusable port to config.

- **Heartbeat/tenant-wire tests didn't exercise the paths they claimed to**: three
  heartbeat tests passed an empty API key, hitting the no-op early return instead of
  the real `sync.Once` stop / interval-clamp logic; a tenant-wire test discarded a
  `Check()` error, letting its `omitempty` assertion pass vacuously. Rewritten
  against real code paths.

- **`Makefile` `build`/`build-all` stamped `dev (commit: unknown, built: unknown)`**
  regardless of `VERSION`/`GIT_COMMIT`/`BUILD_DATE`: ldflags targeted nonexistent
  `cmd.Version`/`cmd.GitCommit`/`cmd.BuildDate` symbols instead of the actual
  lowercase `cmd.version`/`cmd.commit`/`cmd.date` (`.goreleaser.yml` already had
  this right; only the plain Makefile was stale).

### Security

- Bumped `golang.org/x/net` 0.43.0 → 0.55.0 (medium-severity HTML-parser
  denial-of-service advisory, GHSA-5cv4-jp36-h3mw).

### Known gaps (tracked for follow-up)

- Windows shim still uses a bare PowerShell TCP probe — no HTTP identity handshake.
  Full handshake requires PowerShell 5+ `WebClient`; tracked for a follow-up PR.
- `PUB-firewall/phoenix-firewall/` nested duplicate directory is stale; safe to remove
  but requires explicit authorisation for destructive deletion.
- `--test-mode` disables lifecycle scripts for npm and pnpm only; Yarn Classic does
  not reliably honor `npm_config_ignore_scripts` via env var and needs a CLI flag
  the shim can't safely inject for every subcommand — tracked as a follow-up.
- Open low-severity Rust `lru` crate advisory (GHSA-rhfx-m35p-ff5j) on
  `Cargo.toml`/`phoenix-firewall/Cargo.toml`, not addressed by this release.

---

## [0.3.0] — 2026-05-xx

### Security hardening release

- **Fail-closed on API error in strict mode**: handler, scan path, and system path all
  block on backend unreachability when `strict_mode = true`.
- **System/service mode wires strict-mode and policy gate**: previously inert in the
  LaunchAgent/systemd deployed path.
- **Bypass requires server-authenticated API call**: `phoenix-firewall bypass verify`
  — deleted local ED25519 keygen; private key was readable by same-user malware.
- **`trust.go` resolves privileged helpers from trusted dirs only** (CWE-426 fix).
- **Bounded API/feed reads**: 16 MiB response cap, 32 MiB fallback feed cap.
- **HTTP client timeouts** on policy syncer and telemetry heartbeat.
- **Report file permissions**: `0644 → 0600`.
- +15 tests (71 total): strict fail-closed, bypass auth, feed parse safety, wiring
  test guards system-mode regression.

---

## [0.2.0] — 2026-04-xx

Initial public release. Userland shims (`~/.local/bin`), `init` subcommand,
agent-bridge home-dir discovery, LaunchAgent/systemd-user/schtasks persistence,
local ED25519 bypass tokens, GoReleaser pipeline (cross-platform unsigned release,
checksums, SBOM), comprehensive README.

---

## [0.1.0] — 2026-04-xx

Bootstrap: module path `github.com/Security-Phoenix-demo/phoenix-firewall`,
MITM proxy wiring, userland proxy and shim interception foundation.
