<p align="center">
  <img src="assets/phoenix-firewall-banner.jpeg" alt="Phoenix Supply Chain Firewall" width="600">
</p>

<h1 align="center">Phoenix Supply Chain Firewall</h1>

<p align="center">
  <strong>Detection without enforcement is noise.</strong><br>
  Intelligence-driven package firewall — proxy mode for CI, endpoint mode for developer workstations.
</p>

<p align="center">
  <a href="https://github.com/Security-Phoenix-demo/phoenix-firewall/actions"><img src="https://img.shields.io/github/actions/workflow/status/Security-Phoenix-demo/phoenix-firewall/release.yml?label=build" alt="Build Status"></a>
  <a href="https://github.com/Security-Phoenix-demo/phoenix-firewall/releases"><img src="https://img.shields.io/github/v/release/Security-Phoenix-demo/phoenix-firewall" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License"></a>
  <a href="https://phxintel.security"><img src="https://img.shields.io/badge/powered%20by-Phoenix%20Security-orange" alt="Phoenix Security"></a>
</p>

---

## Two modes, one binary

This binary ships two independent interception modes. They are **complementary layers**, not duplicates — each catches installs the other might miss.

| | Proxy mode (v2) | Endpoint / shim mode (v4) |
|---|---|---|
| **How it works** | MITM proxy on port :8443; `HTTPS_PROXY` redirects traffic | PATH shims intercept the command before the process starts |
| **Where it runs** | CI/CD runner (ephemeral) or dev machine | Developer workstation (persistent, user-level) |
| **Setup** | Set `HTTPS_PROXY`, add CA cert | `phoenix-firewall init` once |
| **Root / admin required?** | No (ephemeral CA in `~/.phoenix-firewall/`) | No (userland) |
| **When it blocks** | After the package manager process starts, at the TLS layer | Before the package manager process starts |
| **Persistent across reboots?** | No — proxy must be (re)started each session | Yes — shims stay in `~/.local/bin/` |
| **Works with coding agent hooks?** | No | Yes — via `agent-bridge` |
| **Command** | `phoenix-firewall proxy` | `phoenix-firewall init` + shims |

**Recommended combination:**

- CI/CD pipelines → proxy mode (`phoenix-firewall proxy` or GitHub Action)
- Developer workstations → endpoint/shim mode (`phoenix-firewall init`)
- Both modes on a workstation → deepest defence; shim blocks at invocation, proxy is a network-layer backstop

When both fire for the same install, the agent-bridge deduplication (R-FUNC-091) ensures the verdict is counted only once.

---

## Proxy mode — how it works

```
Developer runs: npm ci
       │
       ▼ HTTPS_PROXY=https://localhost:8443
       npm → CONNECT registry.npmjs.org:443 → phoenix-firewall proxy
                │
                ├─ goproxy MITM intercepts TLS tunnel
                ├─ Generates leaf cert signed by ephemeral CA
                ├─ npm trusts it via NODE_EXTRA_CA_CERTS
                │
                ├─ Decrypts request: GET /@scope/pkg/-/pkg-1.0.0.tgz
                ├─ Registry matcher extracts ecosystem=npm, package=pkg, version=1.0.0
                ├─ LRU cache check (10K entries) — if hit: skip API call
                ├─ POST /api/v1/firewall/evaluate → Phoenix backend
                │   └─ 30-condition rules engine + MPI signals (52 heuristics + LLM)
                │
                ├─ allow → proxies request to real registry.npmjs.org
                ├─ warn  → proxies request + prints stderr warning
                └─ block → returns HTTP 403 to npm; npm fails with exit 1
```

### What the MITM proxy does (step by step)

1. **CA generation** — on first run, `proxy.EnsureCA()` generates an ephemeral root CA in `~/.phoenix-firewall/ca/` (Ed25519, 24h validity). The CA is regenerated each session by default.

2. **Proxy startup** — listens on `:8443` (configurable via `--port`). In CI mode (`--ci`), prints `export HTTPS_PROXY=... NODE_EXTRA_CA_CERTS=...` for the shell to `eval`.

3. **CONNECT interception** — when a package manager opens a TLS tunnel (HTTPS), goproxy intercepts the `CONNECT` handshake and uses the ephemeral CA to generate a fresh leaf certificate for that host, signed on-the-fly.

4. **URL matching** — `internal/registry/` contains per-ecosystem matchers. Each matcher knows the URL pattern for that registry:
   - npm/yarn/pnpm: `registry.npmjs.org/@scope/pkg/-/pkg-ver.tgz`
   - PyPI: `pypi.org/simple/pkg/`, `files.pythonhosted.org/packages/.../file.tar.gz`
   - Cargo: `crates.io/api/v1/crates/pkg/ver/download`
   - Maven: `repo1.maven.org/maven2/group/artifact/ver/file.jar`
   - RubyGems: `rubygems.org/gems/pkg-ver.gem`
   - GitLab Package Registry: configurable host + path

5. **Evaluation** — extracted `(ecosystem, package, version)` is sent to `POST /api/v1/firewall/evaluate`. The backend runs the 30-condition rules engine (your configured rules) plus MPI intelligence (52 heuristic signals, dual-LLM verification).

6. **Enforcement** — verdict determines response:
   - `allow` → proxy forwards the original request to the real registry
   - `warn` → forwards, writes warning to stderr
   - `block` → returns HTTP 403 with JSON `{"blocked":true,"reason":"..."}` — the package manager never fetches the tarball
   - `require_approval` → 403, exit code 78, Slack notification dispatched

7. **Caching** — results are held in a per-session LRU cache (10,000 entries). Transitive dependencies that repeat a package skip the API call.

8. **Fail mode** — if the API is unreachable, default is fail-open (install proceeds). Add `--strict` for fail-closed.

### Proxy mode: registry coverage

| Ecosystem | Registry host | Trigger URL pattern |
|-----------|--------------|---------------------|
| npm / yarn / pnpm | registry.npmjs.org, registry.yarnpkg.com | `/-/pkg-ver.tgz` |
| pip / uv / poetry | pypi.org, files.pythonhosted.org | `/simple/`, `/packages/.../` |
| Cargo | crates.io | `/api/v1/crates/*/download` |
| Maven | repo1.maven.org | `/maven2/**/*.jar` |
| RubyGems | rubygems.org | `/gems/*.gem` |
| GitLab packages | configurable via `--gitlab-hosts` | Any GitLab package API path |
| Custom registries | via `--extra-registries` | `ecosystem:host` |

---

## Endpoint / shim mode — how it works

```
Developer runs: npm install lodash
       │
       ▼ PATH: ~/.local/bin/npm  (shim, installed by phoenix-firewall init)
       shim script:
         ├─ reads PHOENIX_BYPASS_TOKEN (if set, skip evaluation)
         ├─ calls: phoenix-firewall agent-bridge --ecosystem npm --command "npm install lodash"
         │             │
         │             ├─ reads ~/.config/phoenix-firewall/agent-bridge.json
         │             ├─ (future: routes to local worker over Unix socket)
         │             └─ fallback: POST /api/v1/firewall/agent/evaluate → Phoenix backend
         │
         ├─ verdict = allow/warn → exec real npm (shimDir/npm.real or PATH remainder)
         └─ verdict = block → exit 2; real npm never runs
```

Shims are plain bash scripts (`.cmd` on Windows) installed in `~/.local/bin/`. Because `~/.local/bin` is prepended to PATH by `phoenix-firewall init`, every shell (terminal, IDE, CI job running as your user) uses the shim automatically.

The shim calls `phoenix-firewall agent-bridge`, which:
1. Looks for `~/.config/phoenix-firewall/agent-bridge.json` (userland) or `/etc/phoenix-firewall/agent-bridge.json` (system)
2. If a local worker is running (v4 full mode): routes over the Unix socket — zero extra network latency
3. If no local worker: falls back to `POST /api/v1/firewall/agent/evaluate` directly

### Shim mode: package manager coverage (13 PMs)

npm, yarn, pnpm, pip, pip3, uv, poetry, cargo, gem, bundler, go, dotnet, conda

---

## Quick start

### Proxy mode (CI/CD or dev machine, one-shot)

```bash
# 1. Download binary
curl -sSfL "https://github.com/Security-Phoenix-demo/phoenix-firewall/releases/latest/download/phoenix-firewall_$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/').tar.gz" \
  | tar -xz && mv phoenix-firewall ~/.local/bin/

# 2. Start proxy + inject env vars into current shell
eval $(phoenix-firewall proxy --api-key $PHOENIX_API_KEY --ci)

# 3. Use package managers as normal — they're protected
npm ci
pip install -r requirements.txt
```

### Endpoint / shim mode (developer workstation, persistent)

```bash
# 1. Download binary (same as above)

# 2. One-time setup — installs shims to ~/.local/bin, writes config
phoenix-firewall init

# 3. Activate with your API key (get one at phxintel.security)
phoenix-firewall enroll --api-key $PHOENIX_API_KEY

# 4. Restart your shell (or source ~/.zprofile / ~/.profile)
# Done — every npm/pip/cargo call is now evaluated
```

### GitHub Action (CI/CD)

```yaml
- uses: Security-Phoenix-demo/firewall-action@v1
  with:
    api-key: ${{ secrets.PHOENIX_API_KEY }}
    mode: enforce
    fail-on: block
```

---

## Installation

### Download pre-built binary

```bash
# Detect OS + arch automatically
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')

curl -sSfL "https://github.com/Security-Phoenix-demo/phoenix-firewall/releases/latest/download/phoenix-firewall_${OS}_${ARCH}.tar.gz" \
  | tar -xz
mv phoenix-firewall ~/.local/bin/
chmod +x ~/.local/bin/phoenix-firewall

# Verify
phoenix-firewall version
```

### Windows

```powershell
# Download and extract zip
$url = "https://github.com/Security-Phoenix-demo/phoenix-firewall/releases/latest/download/phoenix-firewall_windows_amd64.zip"
Invoke-WebRequest $url -OutFile phoenix-firewall.zip
Expand-Archive phoenix-firewall.zip -DestinationPath "$env:APPDATA\PhoenixFirewall"
# Add to PATH via System Properties > Environment Variables
```

### Build from source

```bash
git clone https://github.com/Security-Phoenix-demo/phoenix-firewall
cd phoenix-firewall
go build -o phoenix-firewall .
```

---

## Endpoint mode: detailed setup

### Step 1 — init

```bash
phoenix-firewall init [--api-key <key>] [--api-url <url>]
```

Creates:
- `~/.config/phoenix-firewall/agent.toml` — agent configuration (mode 0600)
- `~/.config/phoenix-firewall/agent-bridge.json` — local worker discovery file for coding agent hooks
- Shims in `~/.local/bin/` for all 13 package managers
- PATH entry appended to `~/.zprofile`, `~/.profile`, `~/.bash_profile` (whichever exist)

### Step 2 — enroll

```bash
phoenix-firewall enroll --api-key <your-phoenix-api-key>
```

Writes (or updates) `api_key` in `~/.config/phoenix-firewall/agent.toml`. Supports optional `--tenant-id` and `--device-id` for enterprise multi-tenant setups.

### Step 3 — install as background service (optional)

```bash
# Installs and starts the agent as a user-level background service
phoenix-firewall system install
phoenix-firewall system start
phoenix-firewall system status
```

| OS | Mechanism | Location |
|----|-----------|----------|
| macOS | LaunchAgent (no sudo) | `~/Library/LaunchAgents/io.phoenix.security.firewall.plist` |
| Linux | systemd --user (no sudo) | `~/.config/systemd/user/phoenix-firewall.service` |
| Windows | Task Scheduler /RL LIMITED (no admin) | `PhoenixFirewall\Agent` scheduled task |

### Step 4 — verify

```bash
# Shim should intercept — you'll see a phoenix-firewall evaluation log
npm install lodash
```

### Configuration file: `~/.config/phoenix-firewall/agent.toml`

```toml
api_url = "https://api.phxintel.security"
api_key = "phx_fwagent_..."

[policy]
poll_interval_s = 300       # how often to sync policy from backend
stale_threshold_s = 86400   # 24h — after this, fail per fail_mode.mode

[telemetry]
heartbeat_interval_s = 300  # how often to send device health beacon
depth = "metadata"          # "metadata" | "debug"

[fail_mode]
# "open"  = allow installs when backend unreachable (default for userland)
# "closed" = block installs when backend unreachable (enterprise)
mode = "open"
```

### Bypass tokens (for IT-approved one-off installs)

When a package is blocked but an engineer has a legitimate reason, an admin can issue a single-use bypass token:

```bash
# Admin issues a token (via Phoenix dashboard or API)
# Engineer sets the token in their env for that one install:
PHOENIX_BYPASS_TOKEN=<jwt> npm install some-internal-package
# Token is consumed on first use (JTI replay prevention)
```

Bypass tokens are signed with an ED25519 keypair generated on first run at `~/.config/phoenix-firewall/bypass-signing-key.pem`.

---

## Proxy mode: detailed setup

### Direct proxy (dev machine)

```bash
# Start proxy — generates CA, starts listener on :8443
phoenix-firewall proxy --api-key $PHOENIX_API_KEY

# In another terminal, configure your package manager:
export HTTPS_PROXY=https://localhost:8443
export NODE_EXTRA_CA_CERTS=~/.phoenix-firewall/ca/phoenix-ca.crt  # npm/node
export SSL_CERT_FILE=~/.phoenix-firewall/ca/phoenix-ca.crt        # Python
npm ci   # intercepted
```

### CI mode (one-line setup)

```bash
# Starts proxy + emits eval-able env vars for the current shell
eval $(phoenix-firewall proxy --api-key $PHOENIX_API_KEY --ci)

# All subsequent package manager calls are intercepted
npm ci
pip install -r requirements.txt
cargo build
```

### With auto trust injection (requires sudo once)

```bash
# Injects CA into system trust store permanently
phoenix-firewall proxy --api-key $PHOENIX_API_KEY --trust
# Now all package managers trust the CA without NODE_EXTRA_CA_CERTS
```

### Offline / air-gapped mode

```bash
# Download feed snapshot
curl -sf https://api.phxintel.security/api/v1/firewall/feed/npm.json -o npm-feed.json

# Use local feed as fallback when API unreachable
phoenix-firewall proxy --api-key $PHOENIX_API_KEY --fallback-feed npm-feed.json --ci
```

### Strict mode (fail-closed)

```bash
# Block all installs if Phoenix API is unreachable
phoenix-firewall proxy --api-key $PHOENIX_API_KEY --strict --ci
```

---

## CLI reference

```
phoenix-firewall <subcommand> [flags]

Subcommands:
  init          Set up endpoint mode for the current user (no root required)
  enroll        Activate with your Phoenix API key
  proxy         Start the MITM proxy server (CI/CD or dev machine)
  scan          One-shot lockfile scan
  system        Manage the background service (install/start/stop/status)
  agent-bridge  Route a package evaluation to local worker or backend (used by shims)
  version       Print version information

Global flags:
  --api-url string    Phoenix API base URL (default: https://api.phxintel.security)
  --api-key string    Phoenix API key [env: PHOENIX_API_KEY]
  --verbose           Verbose logging

proxy flags:
  --port int          Proxy listen port (default: 8443)
  --ca-dir string     CA directory (default: ~/.phoenix-firewall/ca/)
  --trust             Inject CA into system trust store (requires sudo)
  --ci                CI mode: print eval-able env var exports
  --strict            Fail-closed when API unreachable
  --fallback-feed     Path to local JSON feed for offline operation
  --report-path       Write JSON scan report to path

init flags:
  --api-key string    Pre-populate API key in agent.toml
  --api-url string    Phoenix API URL

enroll flags:
  --api-key string    Your Phoenix API key (required)
  --api-url string    Phoenix API URL
  --tenant-id string  Tenant ID (optional, auto-detected from key)
  --device-id string  Device ID (optional, auto-generated)

system subcommands:
  install     Install user-level OS service
  uninstall   Remove OS service
  start       Start the service
  stop        Stop the service
  status      Show service status

agent-bridge flags:
  --ecosystem string  Package ecosystem (npm, pip, cargo…)
  --package string    Package name
  --command string    Full install command string
```

---

## Intelligence: what the backend checks

Every evaluation calls the Phoenix backend which runs:

| Signal source | What it checks |
|---|---|
| MPI heuristic engine | 52 rules across 7 categories: code execution, network callbacks, persistence, reconnaissance, metadata anomalies, CI/CD abuse, runtime behaviour |
| MPI dual-LLM verification | Gemini 2.5 Flash (analyst) + Claude Sonnet 4 (adversarial judge) — each votes independently |
| 15+ ecosystem feeds | OSSF, OSM, SafeChain — covering npm, PyPI, Maven, NuGet, Cargo, Go, RubyGems |
| Your firewall rules | Up to 30 conditions: package pattern, CVSS, EPSS, MPI confidence, threat type, package age, license, maintainer age, KEV, ransomware associations |
| Vulnerability data | CVSS, EPSS, CISA KEV, PoC availability, patch lag |

**Action precedence when multiple rules match**: block > require_approval > warn > audit > allow

---

## Security properties

| Property | Proxy mode | Endpoint mode |
|---|---|---|
| Ephemeral CA | Yes — 24h, `~/.phoenix-firewall/ca/` | N/A |
| Root / admin required | No | No |
| Fail mode | Fail-open (configurable) | Fail-open (configurable) |
| API key storage | Env var / CLI flag | `~/.config/phoenix-firewall/agent.toml` (0600) |
| Bypass mechanism | `PHOENIX_STRICT=false` + API unreachable | `PHOENIX_BYPASS_TOKEN=<jwt>` (single-use JWT) |
| Signed binary | Checksums published per release (code signing pending Apple Dev cert) | Same |

---

## CI/CD integrations

| Platform | Method | Setup |
|---|---|---|
| GitHub Actions | [firewall-action@v1](integrations/github-action/) | `uses: Security-Phoenix-demo/firewall-action@v1` |
| GitLab CI | Proxy mode in before_script | See [integrations/gitlab-ci/](integrations/gitlab-ci/) |
| Jenkins | Shared library | See [integrations/jenkins/](integrations/jenkins/) |
| Azure DevOps | Pipeline template | See [integrations/azure-devops/](integrations/azure-devops/) |
| Bitbucket | Pipe | See [integrations/bitbucket/](integrations/bitbucket/) |
| Any CI | `curl \| eval` | `eval $(phoenix-firewall proxy --api-key $KEY --ci)` |

---

## Relationship to PUB-firewall-agents-hub

[PUB-firewall-agents-hub](../PUB-firewall-agents-hub/) provides the **intent-time interception layer** for coding agents (Claude Code, Cursor, Copilot, Gemini Antigravity, and 4 others). It wraps the `phoenix_check_package` MCP tool.

This repo provides the **OS-level backstop**: shims catch any install that bypasses or predates the agent hook, whether triggered from a terminal, a script, or a CI job.

The two layers are designed to coexist. When both fire for the same package:
- The agent hook fires at *intent time* (when the LLM proposes the install command)
- The shim fires at *execution time* (when the shell actually runs it)
- The `agent-bridge` discovery file (`agent-bridge.json`) deduplicates verdicts so the same install isn't double-counted in telemetry

---

## License

Apache License 2.0 — Copyright 2026 Phoenix Security Ltd.

---

<p align="center">
  <a href="https://phoenix.security">Phoenix Security</a> · <a href="https://phxintel.security">CVE Intelligence</a> · <a href="https://github.com/Security-Phoenix-demo/phoenix-firewall/issues">Report Bug</a>
</p>
