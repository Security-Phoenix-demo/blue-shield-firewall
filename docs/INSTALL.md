# Installing Phoenix Security Blue Shield - Firewall (without code-signing certs)

> Audience: end users on macOS / Windows / Linux installing `phoenix-firewall` from a public GitHub release.
> Status: **binaries are not yet code-signed** — see §5 for what that means and how to work around the OS gatekeepers.

---

## 1. TL;DR — one-line installers

### macOS / Linux

```bash
curl -sSfL https://raw.githubusercontent.com/Security-Phoenix-demo/phoenix-firewall/main/scripts/install.sh | bash
```

Pins a version: `... | bash -s -- --version v0.1.0 --prefix /usr/local/bin`

### Windows (PowerShell)

```powershell
irm https://raw.githubusercontent.com/Security-Phoenix-demo/phoenix-firewall/main/scripts/install.ps1 | iex
```

Pins a version: `& ([scriptblock]::Create((irm https://...install.ps1))) -Version v0.1.0`

Both scripts:

- resolve the latest GitHub release of `Security-Phoenix-demo/phoenix-firewall`,
- download the OS/arch-specific tarball or zip,
- **verify the SHA-256** against the release's `checksums.txt`,
- extract to a user-writable prefix (no `sudo` / no Administrator),
- apply the per-OS unsigned-binary workaround (see §5).

---

## 2. Supported platforms

| OS | Arch | Asset |
|---|---|---|
| macOS 11+ | x86_64 (Intel) | `phoenix-firewall_X.Y.Z_darwin_amd64.tar.gz` |
| macOS 11+ | arm64 (Apple Silicon) | `phoenix-firewall_X.Y.Z_darwin_arm64.tar.gz` |
| Linux | x86_64 | `phoenix-firewall_X.Y.Z_linux_amd64.tar.gz` |
| Linux | arm64 | `phoenix-firewall_X.Y.Z_linux_arm64.tar.gz` |
| Windows 10 / 11 | x86_64 | `phoenix-firewall_X.Y.Z_windows_amd64.zip` |

Every asset is paired with a SHA-256 in `checksums.txt` and a Syft SBOM in `*.sbom.json`.

---

## 3. Manual install (no script)

### macOS / Linux

```bash
VER=v0.1.0
OS=$(uname -s | tr '[:upper:]' '[:lower:]')                  # darwin | linux
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')    # amd64 | arm64

curl -sSfL -o phoenix-firewall.tgz \
  "https://github.com/Security-Phoenix-demo/phoenix-firewall/releases/download/${VER}/phoenix-firewall_${VER#v}_${OS}_${ARCH}.tar.gz"

# Verify
curl -sSfL -o checksums.txt \
  "https://github.com/Security-Phoenix-demo/phoenix-firewall/releases/download/${VER}/checksums.txt"
shasum -a 256 -c <(grep "_${OS}_${ARCH}.tar.gz" checksums.txt)

tar -xzf phoenix-firewall.tgz
install -m 0755 phoenix-firewall ~/.local/bin/phoenix-firewall
```

### Windows (PowerShell, no admin)

```powershell
$ver = 'v0.1.0'
$asset = "phoenix-firewall_$($ver.TrimStart('v'))_windows_amd64.zip"
Invoke-WebRequest "https://github.com/Security-Phoenix-demo/phoenix-firewall/releases/download/$ver/$asset" -OutFile $asset
Expand-Archive -Path $asset -DestinationPath "$env:LOCALAPPDATA\Programs\phoenix-firewall" -Force
Unblock-File "$env:LOCALAPPDATA\Programs\phoenix-firewall\phoenix-firewall.exe"
```

---

## 4. Build from source (if no release tag is published yet)

Until the first `v*` tag is pushed, releases won't exist. Build it locally:

```bash
git clone https://github.com/Security-Phoenix-demo/phoenix-firewall.git
cd phoenix-firewall
go build -o ~/.local/bin/phoenix-firewall .
phoenix-firewall version
```

Requires Go 1.23+. CGO is disabled in the release builds, so the resulting binary is statically linked and portable.

---

## 5. Running an unsigned binary

Code signing (Apple Developer ID + notarization, Windows Authenticode) is **deferred** while procurement of the certs is in flight. Here is what every supported OS does on first run and how to unblock it.

### 5.1 macOS

**Symptom**: First launch shows _"phoenix-firewall cannot be opened because the developer cannot be verified"_ or _"phoenix-firewall is damaged and cannot be opened"_.

**Why**: macOS 11+ requires every executable to be at least *ad-hoc* signed. Downloaded files also pick up the `com.apple.quarantine` extended attribute, which triggers Gatekeeper on first launch.

**Fix** (already applied by `scripts/install.sh`):

```bash
# Drop quarantine
xattr -d com.apple.quarantine $(which phoenix-firewall)

# Ad-hoc sign — does NOT require Apple Developer ID
codesign --force --sign - $(which phoenix-firewall)
```

If you ran the binary via the GUI before clearing quarantine, you'll also need to approve it once under **System Settings → Privacy & Security → "Open Anyway"**.

> Apple notarization is the proper long-term fix. Until the team has an Apple Developer ID + notary submission flow, all macOS users will need these two commands.

### 5.2 Windows

**Symptom**: SmartScreen popup _"Windows protected your PC — Microsoft Defender SmartScreen prevented an unrecognized app from starting"_.

**Why**: SmartScreen rates unsigned executables as untrusted until enough installations build "reputation". An EV Authenticode cert removes the warning instantly; a regular Authenticode cert builds reputation over a few weeks.

**Fix** (already applied by `scripts/install.ps1` for the download mark; the SmartScreen popup must be dismissed manually):

```powershell
# Clear the "Mark of the Web" (zone identifier)
Unblock-File "$env:LOCALAPPDATA\Programs\phoenix-firewall\phoenix-firewall.exe"
```

On the SmartScreen popup itself, click **More info → Run anyway**. Subsequent launches will not prompt.

For unattended scenarios (e.g. CI runners, MDM rollouts) you can exempt the binary path from SmartScreen via Group Policy or registry, but that's an admin-side action — see `PUB-Shield-Endpoint/docs/` for the MDM recipe.

### 5.3 Linux

**Symptom**: none. Linux has no equivalent gatekeeper for plain ELF binaries; `chmod +x` is all that's needed.

If you're on a hardened distro with IMA / AppArmor / SELinux: the binary may need a label. The installer prints a hint if it detects that.

---

## 6. Verifying the binary

Every release ships:

- `phoenix-firewall_X.Y.Z_<os>_<arch>.tar.gz` (or `.zip` on Windows) — binary + README + LICENSE
- `checksums.txt` — SHA-256 of every archive
- `checksums.txt.sig` + `checksums.txt.pem` — **Sigstore keyless signature** of `checksums.txt`
- `phoenix-firewall_X.Y.Z_<os>_<arch>.sbom.json` — Syft-generated CycloneDX SBOM
- `phoenix-firewall.intoto.jsonl` — **SLSA Level 3 provenance** attestation

You don't need any pre-shared keys or tokens to verify. Both signatures are tied to this repo + the release workflow via short-lived OIDC certificates anchored in Sigstore's public transparency log (Rekor).

### 6.1 Cosign signature on `checksums.txt`

Install [cosign](https://docs.sigstore.dev/cosign/installation):

```bash
brew install cosign           # macOS
go install github.com/sigstore/cosign/v2/cmd/cosign@latest   # any platform
```

Verify:

```bash
VER=v0.1.0
gh release download "$VER" -R Security-Phoenix-demo/phoenix-firewall \
    --pattern 'checksums.txt*' \
    --pattern '*.tar.gz' \
    --pattern '*.zip'

cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/Security-Phoenix-demo/phoenix-firewall/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature checksums.txt.sig \
  --certificate checksums.txt.pem \
  checksums.txt
# expected output: "Verified OK"
```

Then verify your binary's SHA-256 matches the signed `checksums.txt`:

```bash
shasum -a 256 -c <(grep -E '(linux|darwin|windows)_(amd64|arm64)\.(tar\.gz|zip)' checksums.txt)
```

If cosign fails → the release is not authentic; abort.
If the hash check fails → a single artifact was tampered with; abort.

### 6.2 SLSA Level 3 provenance

Install [slsa-verifier](https://github.com/slsa-framework/slsa-verifier):

```bash
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest
```

Verify:

```bash
gh release download "$VER" -R Security-Phoenix-demo/phoenix-firewall \
    --pattern 'phoenix-firewall.intoto.jsonl'

slsa-verifier verify-artifact \
  --provenance-path phoenix-firewall.intoto.jsonl \
  --source-uri github.com/Security-Phoenix-demo/phoenix-firewall \
  --source-tag "$VER" \
  phoenix-firewall_0.1.0_linux_amd64.tar.gz
# expected output: "PASSED: SLSA verification passed"
```

This proves the artifact was built by the canonical reusable workflow (`slsa-framework/slsa-github-generator`) on this repo at the tag's commit — not by an attacker with a stolen GH token.

### 6.3 SBOM inspection

```bash
jq '.components[] | {name, version, purl}' phoenix-firewall_*_$(uname -s | tr '[:upper:]' '[:lower:]')_amd64.sbom.json | head
```

---

## 7. Publishing a release (for maintainers)

The release workflow at `.github/workflows/release.yml` runs `goreleaser` on every `v*` tag. To cut a release:

```bash
# Make sure the working tree is clean and on main
git checkout main && git pull

# Tag and push
git tag -a v0.1.0 -m "phoenix-firewall v0.1.0 — first userland release"
git push origin v0.1.0
```

What happens:

1. GitHub Actions builds for the 5 OS/arch targets defined in `.goreleaser.yml`.
2. Syft generates an SBOM per archive.
3. `goreleaser` uploads tarballs + `.zip` + `checksums.txt` + SBOMs to the `v0.1.0` release page.
4. The release notes (auto-generated from commits) include the unsigned-binary disclaimer block defined in `.goreleaser.yml` `release.header`.

Dry-run a snapshot (no tag, no publish) via **Actions → Release phoenix-firewall → Run workflow**. Artifacts will appear under the workflow run as `phoenix-firewall-snapshot` for 7 days.

---

## 8. Signing status

| Layer | What it proves | Status | Tracking |
|---|---|---|---|
| **SHA-256 checksums** | Bit-for-bit integrity of each archive | ✅ Shipping | — |
| **Cosign keyless (Sigstore)** | Artifact was built by this repo's release workflow, anchored in Rekor transparency log | ✅ Shipping (§6.1) | — |
| **SLSA Level 3 provenance** | Hermetic, non-falsifiable build attestation | ✅ Shipping (§6.2) | — |
| **CycloneDX SBOM** | Component inventory for vuln-scan tooling | ✅ Shipping | — |
| **GPG-signed tarballs** | Approved by a holder of the Phoenix release-signing GPG key | ⏳ Deferred — needs key ceremony | `docs/plans/2026-05-18-phoenix-firewall-signing-plan.md` §5 |
| **Apple Developer ID + notarization** | macOS Gatekeeper accepts silently | ⏳ Pending Apple Developer Program enrollment ($99/yr, 24–48 h) | PRD-SCF-001-v4 B6 |
| **Windows Authenticode (EV preferred)** | Windows SmartScreen accepts silently | ⏳ Pending; recommended path = **Azure Trusted Signing** (~$10–40/mo, no hardware token, signs from Linux runners) | PRD-SCF-001-v4 B6 |
| **`.deb` / `.rpm` repo signing** | `apt` / `dnf` trust the Phoenix repo | Lives in `PUB-Shield-Endpoint/`, separate from this binary | — |

When Apple + Windows certs land, `.goreleaser.yml` gains a `notarize:` stanza and an Authenticode signing step; §5 of this doc (the unsigned-binary workarounds) collapses to "just run it, the OS won't complain".

---

## 9. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `phoenix-firewall: command not found` | `~/.local/bin` not in `PATH` | `export PATH="$HOME/.local/bin:$PATH"` |
| `killed: 9` on macOS first run | Gatekeeper rejected unsigned binary | Run the `xattr -d com.apple.quarantine` + `codesign --force --sign -` pair from §5.1 |
| `Windows protected your PC` popup | SmartScreen on unsigned binary | More info → Run anyway (§5.2) |
| `SHA-256 mismatch` from installer | Asset name shifted (typo, wrong arch) | Confirm `uname -m`, re-run with `--version` pinned |
| Installer says "could not resolve latest release" | No tags published yet | Use §4 (build from source) or pass `--version v0.x.y` |

---

## 10. Related

- [scripts/install.sh](../scripts/install.sh) — POSIX installer
- [scripts/install.ps1](../scripts/install.ps1) — Windows installer
- [.goreleaser.yml](../.goreleaser.yml) — release build config
- [.github/workflows/release.yml](../.github/workflows/release.yml) — release CI
- [Phoenix Platform docs — USING_API_KEYS_IN_THE_WILD.md](https://github.com/Security-Phoenix-demo/vulnerability-db/blob/main/docs/API/USING_API_KEYS_IN_THE_WILD.md) — how to use the installed binary
