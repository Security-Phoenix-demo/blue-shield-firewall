<p align="center">
  <img src="assets/phoenix-firewall-banner.jpeg" alt="Phoenix Security Blue Shield - Firewall" width="600">
</p>

<h1 align="center">Phoenix Security Blue Shield - Firewall</h1>

<p align="center">
  <strong>Detection without enforcement is noise.</strong><br>
  Intelligence-driven package firewall — proxy mode for CI, endpoint mode for developer workstations.
</p>

<p align="center">
  <a href="https://github.com/Security-Phoenix-demo/blue-shield-firewall/actions"><img src="https://img.shields.io/github/actions/workflow/status/Security-Phoenix-demo/blue-shield-firewall/release.yml?label=build" alt="Build Status"></a>
  <a href="https://github.com/Security-Phoenix-demo/blue-shield-firewall/releases"><img src="https://img.shields.io/github/v/release/Security-Phoenix-demo/blue-shield-firewall" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License"></a>
  <a href="https://phxintel.security"><img src="https://img.shields.io/badge/powered%20by-Phoenix%20Security-orange" alt="Phoenix Security"></a>
</p>

---

## Two modes, one binary

This binary ships two independent interception modes. They are **complementary layers**, not duplicates — each catches installs the other might miss.

| | Proxy mode (v2) | Endpoint / shim mode (v4) |
|---|---|---|
| **How it works** | MITM proxy on port :8080 by default; `HTTPS_PROXY` redirects traffic | PATH shims intercept the command before the process starts |
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

## Quick start

### macOS / Linux — one-line install

```bash
curl -sSfL https://raw.githubusercontent.com/Security-Phoenix-demo/blue-shield-firewall/main/scripts/install.sh | bash
```

### Windows — PowerShell

```powershell
irm https://raw.githubusercontent.com/Security-Phoenix-demo/blue-shield-firewall/main/scripts/install.ps1 | iex
```

### Proxy mode (CI/CD or dev machine, one-shot)

```bash
# Start proxy + inject env vars into current shell
eval $(phoenix-firewall proxy --api-key $PHOENIX_API_KEY --ci)

# Use package managers as normal — they're protected
npm ci
pip install -r requirements.txt
```

### Endpoint / shim mode (developer workstation, persistent)

```bash
# One-time setup — installs shims to ~/.local/bin, writes config
phoenix-firewall init

# Activate with your API key (get one at phxintel.security)
phoenix-firewall enroll --api-key $PHOENIX_API_KEY

# Restart your shell — every npm/pip/cargo call is now evaluated
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

### Download pre-built binary (v0.2.0)

| Platform | Asset |
|----------|-------|
| macOS (Apple Silicon) | `phoenix-firewall_0.2.0_darwin_arm64.tar.gz` |
| macOS (Intel) | `phoenix-firewall_0.2.0_darwin_amd64.tar.gz` |
| Linux x86_64 | `phoenix-firewall_0.2.0_linux_amd64.tar.gz` |
| Linux ARM64 | `phoenix-firewall_0.2.0_linux_arm64.tar.gz` |
| Windows x86_64 | `phoenix-firewall_0.2.0_windows_amd64.zip` |

Download from **[github.com/Security-Phoenix-demo/blue-shield-firewall/releases/tag/v0.2.0](https://github.com/Security-Phoenix-demo/blue-shield-firewall/releases/tag/v0.2.0)**

```bash
# macOS / Linux — auto-detect arch
VER=0.2.0
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
curl -sSfL "https://github.com/Security-Phoenix-demo/blue-shield-firewall/releases/download/v${VER}/phoenix-firewall_${VER}_${OS}_${ARCH}.tar.gz" \
  | tar -xz
mv phoenix-firewall ~/.local/bin/
chmod +x ~/.local/bin/phoenix-firewall
phoenix-firewall version
```

```powershell
# Windows PowerShell
$ver = "0.2.0"
$url = "https://github.com/Security-Phoenix-demo/blue-shield-firewall/releases/download/v$ver/phoenix-firewall_${ver}_windows_amd64.zip"
Invoke-WebRequest $url -OutFile phoenix-firewall.zip
Expand-Archive phoenix-firewall.zip -DestinationPath "$env:LOCALAPPDATA\Programs\phoenix-firewall" -Force
Unblock-File "$env:LOCALAPPDATA\Programs\phoenix-firewall\phoenix-firewall.exe"
```

### Build from source

```bash
git clone https://github.com/Security-Phoenix-demo/blue-shield-firewall
cd blue-shield-firewall
go build -o phoenix-firewall .
```

Requires Go 1.23+.

> **Note on code signing**: binaries are unsigned in this release. See [docs/INSTALL.md §5](docs/INSTALL.md#5-running-an-unsigned-binary) for the per-OS workaround (two commands on macOS, one click on Windows).

---

## Proxy mode — how it works

```
Developer runs: npm ci
       │
       ▼ HTTPS_PROXY=http://127.0.0.1:8080
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

### Registry coverage

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
         ├─ if PHOENIX_FIREWALL_BYPASS_TOKEN set: runs `phoenix-firewall bypass verify`
         │     (server-authenticated, fails closed — an unauthorized token does
         │      NOT skip the firewall; it routes through evaluation as normal)
         ├─ calls: phoenix-firewall agent-bridge --ecosystem npm --command "npm install lodash"
         │             │
         │             ├─ reads ~/.config/phoenix-firewall/agent-bridge.json
         │             └─ fallback: POST /api/v1/firewall/agent/evaluate → Phoenix backend
         │
         ├─ verdict = allow/warn → exec real npm
         └─ verdict = block → exit 2; real npm never runs
```

**Package manager coverage (13 PMs):** npm, yarn, pnpm, pip, pip3, uv, poetry, cargo, gem, bundler, go, dotnet, conda

---

## Endpoint mode: detailed setup

### Step 1 — init

```bash
phoenix-firewall init [--api-key <key>] [--api-url <url>]
```

Creates:
- `~/.config/phoenix-firewall/agent.toml` — agent configuration (mode 0600)
- `~/.config/phoenix-firewall/agent-bridge.json` — local worker discovery file
- Shims in `~/.local/bin/` for all 13 package managers
- PATH entry in `~/.zprofile`, `~/.profile`, `~/.bash_profile`

### Step 2 — enroll

```bash
phoenix-firewall enroll --api-key <your-phoenix-api-key>
```

### Step 3 — install as background service (optional)

```bash
phoenix-firewall system install
phoenix-firewall system start
phoenix-firewall system status
```

| OS | Mechanism | Location |
|----|-----------|----------|
| macOS | LaunchAgent (no sudo) | `~/Library/LaunchAgents/io.phoenix.security.firewall.plist` |
| Linux | systemd --user (no sudo) | `~/.config/systemd/user/phoenix-firewall.service` |
| Windows | Task Scheduler /RL LIMITED (no admin) | `PhoenixFirewall\Agent` scheduled task |

### Configuration: `~/.config/phoenix-firewall/agent.toml`

```toml
api_url = "https://phxintel.security"
api_key = "phx_fwagent_..."

[policy]
poll_interval_s = 300
stale_threshold_s = 86400

[telemetry]
heartbeat_interval_s = 300
depth = "metadata"

[fail_mode]
mode = "open"   # "open" = fail-open (default) | "closed" = fail-closed
```

---

## Proxy mode: detailed setup

### Direct proxy

```bash
phoenix-firewall proxy --api-key $PHOENIX_API_KEY

# In another terminal:
export HTTPS_PROXY=http://127.0.0.1:8080
export NODE_EXTRA_CA_CERTS=~/.config/phoenix-firewall/phoenix-ca.crt
export SSL_CERT_FILE=~/.config/phoenix-firewall/phoenix-ca.crt
npm ci
```

### CI mode (one-line)

```bash
eval $(phoenix-firewall proxy --api-key $PHOENIX_API_KEY --ci)
npm ci
pip install -r requirements.txt
cargo build
```

### Offline / air-gapped mode

```bash
curl -sf https://phxintel.security/api/v1/firewall/feed/npm.json -o npm-feed.json
phoenix-firewall proxy --api-key $PHOENIX_API_KEY --fallback-feed npm-feed.json --ci
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
  agent-bridge  Route a package evaluation to local worker or backend
  version       Print version information

Global flags:
  --api-url string    Phoenix API base URL (default: https://phxintel.security)
  --api-key string    Phoenix API key [env: PHOENIX_API_KEY]
  --verbose           Verbose logging

proxy flags:
  --port int          Proxy listen port (default: 8080)
  --ca-dir string     CA directory (default: ~/.config/phoenix-firewall/)
  --trust             Inject CA into system trust store (requires sudo)
  --ci                CI mode: print eval-able env var exports
  --strict            Fail-closed when API unreachable
  --fallback-feed     Path to local JSON feed for offline operation
  --report-path       Write JSON scan report to path
```

---

## Intelligence: what the backend checks

| Signal source | What it checks |
|---|---|
| MPI heuristic engine | 52 rules across 7 categories: code execution, network callbacks, persistence, reconnaissance, metadata anomalies, CI/CD abuse, runtime behaviour |
| MPI dual-LLM verification | Gemini 2.5 Flash (analyst) + Claude Sonnet 4 (adversarial judge) |
| 15+ ecosystem feeds | OSSF, OSM, SafeChain — npm, PyPI, Maven, NuGet, Cargo, Go, RubyGems |
| Your firewall rules | Up to 30 conditions: package pattern, MPI confidence, threat type, package age, license, maintainer age, KEV status |
| Vulnerability data | CVSS, EPSS, CISA KEV, PoC availability |

**Action precedence when multiple rules match**: block > require_approval > warn > audit > allow

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

## Verify integrity

Every release ships SHA-256 checksums and a Sigstore keyless signature.

```bash
# Verify checksum
sha256sum -c checksums.txt

# Verify Sigstore signature
cosign verify-blob checksums.txt \
  --certificate-identity-regexp 'https://github.com/Security-Phoenix-demo/blue-shield-firewall/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature checksums.txt.sig \
  --certificate checksums.txt.pem
```

---

## License

Apache License 2.0 — Copyright 2026 Phoenix Security Ltd.

---

<p align="center">
  <a href="https://phoenix.security">Phoenix Security</a> · <a href="https://phxintel.security">CVE Intelligence</a> · <a href="https://github.com/Security-Phoenix-demo/blue-shield-firewall/issues">Report Bug</a>
</p>
