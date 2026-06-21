# Installing Phoenix Security Blue Shield - Firewall

> Version: v0.4.0
> Audience: end users on macOS / Windows / Linux installing `phoenix-firewall` from a public GitHub release.
> Status: **binaries are not yet code-signed** — see §5 for what that means and how to work around the OS gatekeepers.

---

## 1. TL;DR — one-line installers

### macOS / Linux

```bash
curl -sSfL https://raw.githubusercontent.com/Security-Phoenix-demo/blue-shield-firewall/main/scripts/install.sh | bash
```

Pin a specific version:
```bash
curl -sSfL https://raw.githubusercontent.com/Security-Phoenix-demo/blue-shield-firewall/main/scripts/install.sh \
  | bash -s -- --version v0.4.0 --prefix ~/.local/bin
```

### Windows (PowerShell)

```powershell
irm https://raw.githubusercontent.com/Security-Phoenix-demo/blue-shield-firewall/main/scripts/install.ps1 | iex
```

Pin a specific version:
```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/Security-Phoenix-demo/blue-shield-firewall/main/scripts/install.ps1))) -Version v0.4.0
```

Both scripts:
- Resolve the correct OS/arch asset from the GitHub release
- Verify the SHA-256 against `checksums.txt`
- Extract to a user-writable prefix (no `sudo` / no Administrator)
- Apply the per-OS unsigned-binary workaround automatically (see §5)

---

## 2. Supported platforms

| OS | Arch | Asset |
|---|---|---|
| macOS 11+ | Apple Silicon (M1/M2/M3) | `phoenix-firewall_0.4.0_darwin_arm64.tar.gz` |
| macOS 11+ | Intel | `phoenix-firewall_0.4.0_darwin_amd64.tar.gz` |
| Linux | x86_64 | `phoenix-firewall_0.4.0_linux_amd64.tar.gz` |
| Linux | ARM64 | `phoenix-firewall_0.4.0_linux_arm64.tar.gz` |
| Windows 10 / 11 | x86_64 | `phoenix-firewall_0.4.0_windows_amd64.zip` |

Every asset is paired with a SHA-256 in `checksums.txt` and a Syft SBOM in `*.sbom.json`.

All assets are available at:
**[github.com/Security-Phoenix-demo/blue-shield-firewall/releases/tag/v0.4.0](https://github.com/Security-Phoenix-demo/blue-shield-firewall/releases/tag/v0.4.0)**

---

## 3. Manual install (no script)

### macOS / Linux

```bash
VER=0.4.0
OS=$(uname -s | tr '[:upper:]' '[:lower:]')                  # darwin | linux
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')    # amd64 | arm64

# Download
curl -sSfL -o phoenix-firewall.tgz \
  "https://github.com/Security-Phoenix-demo/blue-shield-firewall/releases/download/v${VER}/phoenix-firewall_${VER}_${OS}_${ARCH}.tar.gz"

# Verify checksum
curl -sSfL -o checksums.txt \
  "https://github.com/Security-Phoenix-demo/blue-shield-firewall/releases/download/v${VER}/checksums.txt"
grep "_${OS}_${ARCH}.tar.gz" checksums.txt | sha256sum -c

# Extract and install
tar -xzf phoenix-firewall.tgz
install -m 0755 phoenix-firewall ~/.local/bin/phoenix-firewall

# Verify
phoenix-firewall version
```

### Windows (PowerShell, no admin)

```powershell
$ver = "0.4.0"
$asset = "phoenix-firewall_${ver}_windows_amd64.zip"
$url = "https://github.com/Security-Phoenix-demo/blue-shield-firewall/releases/download/v$ver/$asset"

# Download
Invoke-WebRequest $url -OutFile $asset

# Verify checksum
$checksumUrl = "https://github.com/Security-Phoenix-demo/blue-shield-firewall/releases/download/v$ver/checksums.txt"
$checksums = (Invoke-WebRequest $checksumUrl).Content
$expected = ($checksums -split "`n" | Where-Object { $_ -match "windows_amd64.zip" }) -split "\s+" | Select-Object -First 1
$actual = (Get-FileHash $asset -Algorithm SHA256).Hash.ToLower()
if ($actual -ne $expected) { throw "Checksum mismatch — aborting" }

# Extract
$dest = "$env:LOCALAPPDATA\Programs\phoenix-firewall"
Expand-Archive -Path $asset -DestinationPath $dest -Force
Unblock-File "$dest\phoenix-firewall.exe"

# Add to PATH (current user, permanent)
$currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($currentPath -notlike "*$dest*") {
    [Environment]::SetEnvironmentVariable("PATH", "$currentPath;$dest", "User")
}

Write-Host "Installed to $dest — restart your terminal, then run: phoenix-firewall version"
```

---

## 4. Build from source

Requires Go 1.23+. No CGO — binaries are statically linked.

```bash
git clone https://github.com/Security-Phoenix-demo/blue-shield-firewall.git
cd blue-shield-firewall
go build -o ~/.local/bin/phoenix-firewall .
phoenix-firewall version
```

Cross-compile for a specific platform:
```bash
GOOS=windows GOARCH=amd64 go build -o phoenix-firewall.exe .
GOOS=darwin  GOARCH=arm64 go build -o phoenix-firewall-mac-arm64 .
```

---

## 5. Running an unsigned binary

Binaries in v0.4.0 are unsigned. Apple notarization and Windows Authenticode signing are in progress. Here is what each OS does on first run and how to unblock it.

### 5.1 macOS

**Symptom**: _"phoenix-firewall cannot be opened because the developer cannot be verified"_ or _"phoenix-firewall is damaged and cannot be opened"_.

**Why**: macOS requires executables to be signed. Downloaded files also get a `com.apple.quarantine` attribute that triggers Gatekeeper.

**Fix** (the install script applies this automatically):

```bash
# Remove quarantine attribute
xattr -d com.apple.quarantine $(which phoenix-firewall)

# Ad-hoc sign — no Apple Developer ID required
codesign --force --sign - $(which phoenix-firewall)
```

If you opened the binary via Finder before clearing quarantine, also go to:
**System Settings → Privacy & Security → scroll down → "Open Anyway"**

> Apple notarization is the proper long-term fix. Until the team has an Apple Developer ID + notary submission flow, all macOS users will need these two commands.

### 5.2 Windows

**Symptom**: SmartScreen popup — _"Windows protected your PC — Microsoft Defender SmartScreen prevented an unrecognized app from starting"_.

**Why**: SmartScreen flags unsigned executables. An EV Authenticode cert removes the warning immediately; a standard cert builds reputation over time.

**Fix** (the install script applies `Unblock-File` automatically):

```powershell
Unblock-File "$env:LOCALAPPDATA\Programs\phoenix-firewall\phoenix-firewall.exe"
```

On the SmartScreen popup: click **More info → Run anyway**. Subsequent launches will not prompt.

For unattended scenarios (e.g. CI runners, MDM rollouts) you can exempt the binary path from SmartScreen via Group Policy or registry, but that's an admin-side action — see `PUB-Shield-Endpoint/docs/` for the MDM recipe.

### 5.3 Linux

No gatekeeper. `chmod +x` is all that is needed — the installer handles this.

---

## 6. First run: enroll your API key

Get your API key at **[phxintel.security](https://phxintel.security/)**.

```bash
# Set for the current session
export PHOENIX_API_KEY=phx_...

# Or persist it permanently via the enroll subcommand
phoenix-firewall enroll --api-key phx_...
```

`enroll` writes the key to `~/.config/phoenix-firewall/agent.toml` (mode 0600). The key is never logged.

---

## 7. Choose your mode

### Proxy mode — CI/CD or one-shot dev machine use

```bash
# Start proxy and inject env vars into the current shell
eval $(phoenix-firewall proxy --api-key $PHOENIX_API_KEY --ci)

# All subsequent package manager calls are intercepted
npm ci
pip install -r requirements.txt
cargo build
```

### Endpoint / shim mode — persistent developer workstation protection

```bash
# Install shims and write config (one-time)
phoenix-firewall init

# Enroll your API key
phoenix-firewall enroll --api-key $PHOENIX_API_KEY

# Restart your shell — done
# Every npm/pip/cargo/uv/poetry/go/dotnet/gem call is now evaluated
```

### Optional: run as a background service

```bash
phoenix-firewall system install
phoenix-firewall system start
phoenix-firewall system status
```

| OS | Service mechanism | No admin required |
|---|---|---|
| macOS | LaunchAgent | `~/Library/LaunchAgents/io.phoenix.security.firewall.plist` |
| Linux | systemd --user | `~/.config/systemd/user/phoenix-firewall.service` |
| Windows | Task Scheduler /RL LIMITED | `PhoenixFirewall\Agent` |

---

## 8. Verify release integrity

Every release ships:
- `checksums.txt` — SHA-256 of every archive
- `checksums.txt.sig` + `checksums.txt.pem` — Sigstore keyless signature
- `phoenix-firewall_*_<os>_<arch>.sbom.json` — CycloneDX SBOM
- `phoenix-firewall.intoto.jsonl` — SLSA Level 3 provenance

### Verify checksum

```bash
sha256sum -c checksums.txt
```

### Verify Sigstore signature

Install [cosign](https://docs.sigstore.dev/cosign/installation) (`brew install cosign` on macOS), then:

```bash
cosign verify-blob checksums.txt \
  --certificate-identity-regexp 'https://github.com/Security-Phoenix-demo/blue-shield-firewall/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature checksums.txt.sig \
  --certificate checksums.txt.pem
# Expected: Verified OK
```

### Verify SLSA L3 provenance

```bash
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest

slsa-verifier verify-artifact \
  --provenance-path phoenix-firewall.intoto.jsonl \
  --source-uri github.com/Security-Phoenix-demo/blue-shield-firewall \
  --source-tag v0.4.0 \
  phoenix-firewall_0.4.0_linux_amd64.tar.gz
# Expected: PASSED: SLSA verification passed
```

### SBOM inspection

```bash
jq '.components[] | {name, version, purl}' phoenix-firewall_*_$(uname -s | tr '[:upper:]' '[:lower:]')_amd64.sbom.json | head
```

---

## 9. Signing status

| Layer | Status |
|---|---|
| SHA-256 checksums | ✅ Shipping |
| Sigstore keyless (cosign) | ✅ Shipping |
| SLSA Level 3 provenance | ✅ Shipping |
| CycloneDX SBOM | ✅ Shipping |
| Apple Developer ID + notarization | ⏳ Pending — Apple Developer Program enrollment ($99/yr) |
| Windows Authenticode (Azure Trusted Signing) | ✅ Account provisioned — wired into release workflow |

When Apple and Windows certs are in place, the §5 workarounds become unnecessary.

---

## 10. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `phoenix-firewall: command not found` | `~/.local/bin` not in PATH | `export PATH="$HOME/.local/bin:$PATH"` |
| `killed: 9` on macOS | Gatekeeper rejected unsigned binary | `xattr -d com.apple.quarantine` + `codesign --force --sign -` (§5.1) |
| `Windows protected your PC` | SmartScreen on unsigned binary | More info → Run anyway (§5.2) |
| `SHA-256 mismatch` | Wrong asset or arch | Confirm `uname -m`, re-download pinning `--version v0.4.0` |
| `401 Unauthorized` | Missing or invalid API key | `phoenix-firewall enroll --api-key phx_...` |
| `connect: connection refused` | Proxy not running | `eval $(phoenix-firewall proxy --api-key $KEY --ci)` |

---

## 11. Related

- [README.md](../README.md) — overview and quick start
- [scripts/install.sh](../scripts/install.sh) — POSIX installer
- [scripts/install.ps1](../scripts/install.ps1) — Windows PowerShell installer
- [docs/LOCAL_PROXY_ALIAS_GUIDE.md](LOCAL_PROXY_ALIAS_GUIDE.md) — shell aliases for proxy mode
- [.goreleaser.yml](../.goreleaser.yml) — release build configuration
- [Phoenix platform](https://phxintel.security/) — API keys, firewall rules, dashboards
