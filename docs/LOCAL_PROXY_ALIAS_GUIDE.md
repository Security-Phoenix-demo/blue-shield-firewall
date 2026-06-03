# Local Proxy Alias Guide

> How to force local package manager commands through `phoenix-firewall proxy` with shell aliases or functions.
> Use this when you want proxy-mode protection without installing persistent PATH shims.

## When To Use This

Use proxy aliases when:

- You want a reversible local setup for demos or testing.
- You do not want to run `phoenix-firewall init`.
- You want only selected package manager commands to use the firewall.
- You want a network-layer backstop while testing endpoint mode.

Use endpoint/shim mode instead when:

- You need persistent workstation enforcement.
- You need protection for every shell, IDE, and agent session.
- You want package manager interception before the process starts.

## Start The Proxy

In one terminal, start the proxy and keep it running:

```bash
export PHOENIX_API_KEY="phx_your_key_here"
phoenix-firewall proxy --api-key "$PHOENIX_API_KEY" --port 8080
```

Strict mode treats warnings as blocks:

```bash
phoenix-firewall proxy --api-key "$PHOENIX_API_KEY" --port 8080 --strict
```

The current binary default is port `8080`. If you change `--port`, update the alias configuration below.

The proxy generates its CA certificate at:

```bash
~/.phoenix-firewall/ca/phoenix-ca.crt
```

Package managers need both:

- proxy environment variables, so traffic goes through Phoenix;
- CA environment variables, so TLS connections trust the Phoenix MITM certificate.

## One-Session Setup

Paste this into the shell where you will run installs:

```bash
export PHOENIX_FIREWALL_PROXY_URL="http://127.0.0.1:8080"
export PHOENIX_FIREWALL_CA="$HOME/.phoenix-firewall/ca/phoenix-ca.crt"
```

Then define the package manager functions you need.

## npm, yarn, and pnpm

```bash
pf-npm() {
  env \
    HTTPS_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
    HTTP_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
    NODE_EXTRA_CA_CERTS="$PHOENIX_FIREWALL_CA" \
    npm "$@"
}

pf-yarn() {
  env \
    HTTPS_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
    HTTP_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
    NODE_EXTRA_CA_CERTS="$PHOENIX_FIREWALL_CA" \
    yarn "$@"
}

pf-pnpm() {
  env \
    HTTPS_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
    HTTP_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
    NODE_EXTRA_CA_CERTS="$PHOENIX_FIREWALL_CA" \
    pnpm "$@"
}
```

Usage:

```bash
pf-npm install lodash
pf-yarn add react
pf-pnpm install
```

## Force Default npm Commands Through The Firewall

If you want `npm` to mean `firewalled npm` in the current shell, use functions:

```bash
npm() {
  HTTPS_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
  HTTP_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
  NODE_EXTRA_CA_CERTS="$PHOENIX_FIREWALL_CA" \
  command npm "$@"
}

yarn() {
  HTTPS_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
  HTTP_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
  NODE_EXTRA_CA_CERTS="$PHOENIX_FIREWALL_CA" \
  command yarn "$@"
}

pnpm() {
  HTTPS_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
  HTTP_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
  NODE_EXTRA_CA_CERTS="$PHOENIX_FIREWALL_CA" \
  command pnpm "$@"
}
```

Remove the function for the current shell:

```bash
unset -f npm yarn pnpm
```

## pip and PyPI

Use these functions for Python package installs:

```bash
pf-pip() {
  env \
    HTTPS_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
    HTTP_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
    PIP_CERT="$PHOENIX_FIREWALL_CA" \
    REQUESTS_CA_BUNDLE="$PHOENIX_FIREWALL_CA" \
    pip "$@"
}

pf-pip3() {
  env \
    HTTPS_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
    HTTP_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
    PIP_CERT="$PHOENIX_FIREWALL_CA" \
    REQUESTS_CA_BUNDLE="$PHOENIX_FIREWALL_CA" \
    pip3 "$@"
}

pf-python-pip() {
  env \
    HTTPS_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
    HTTP_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
    PIP_CERT="$PHOENIX_FIREWALL_CA" \
    REQUESTS_CA_BUNDLE="$PHOENIX_FIREWALL_CA" \
    python -m pip "$@"
}
```

Usage:

```bash
pf-pip install requests
pf-pip3 install -r requirements.txt
pf-python-pip install flask
```

To make `pip` and `pip3` firewalled by default:

```bash
pip() {
  HTTPS_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
  HTTP_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
  PIP_CERT="$PHOENIX_FIREWALL_CA" \
  REQUESTS_CA_BUNDLE="$PHOENIX_FIREWALL_CA" \
  command pip "$@"
}

pip3() {
  HTTPS_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
  HTTP_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
  PIP_CERT="$PHOENIX_FIREWALL_CA" \
  REQUESTS_CA_BUNDLE="$PHOENIX_FIREWALL_CA" \
  command pip3 "$@"
}
```

Remove them:

```bash
unset -f pip pip3
```

## uv and poetry

```bash
pf-uv() {
  env \
    HTTPS_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
    HTTP_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
    SSL_CERT_FILE="$PHOENIX_FIREWALL_CA" \
    uv "$@"
}

pf-poetry() {
  env \
    HTTPS_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
    HTTP_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
    REQUESTS_CA_BUNDLE="$PHOENIX_FIREWALL_CA" \
    poetry "$@"
}
```

Usage:

```bash
pf-uv pip install requests
pf-poetry add requests
```

## Cargo, RubyGems, Bundler, dotnet, and conda

```bash
pf-cargo() {
  env \
    HTTPS_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
    HTTP_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
    CARGO_HTTP_CAINFO="$PHOENIX_FIREWALL_CA" \
    cargo "$@"
}

pf-gem() {
  env \
    HTTPS_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
    HTTP_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
    SSL_CERT_FILE="$PHOENIX_FIREWALL_CA" \
    gem "$@"
}

pf-bundle() {
  env \
    HTTPS_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
    HTTP_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
    BUNDLE_SSL_CA_CERT="$PHOENIX_FIREWALL_CA" \
    bundle "$@"
}

pf-dotnet() {
  env \
    HTTPS_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
    HTTP_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
    SSL_CERT_FILE="$PHOENIX_FIREWALL_CA" \
    dotnet "$@"
}

pf-conda() {
  env \
    HTTPS_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
    HTTP_PROXY="$PHOENIX_FIREWALL_PROXY_URL" \
    SSL_CERT_FILE="$PHOENIX_FIREWALL_CA" \
    conda "$@"
}
```

Go modules rely on the OS trust store. For `go get` and `go mod download`, run the proxy with `--trust` or install the Phoenix CA into the system trust store.

## Persistent Shell Setup

Add this block to `~/.zshrc` or `~/.bashrc` when you want persistent aliases:

```bash
# Phoenix Security Blue Shield - Firewall proxy aliases
export PHOENIX_FIREWALL_PROXY_URL="${PHOENIX_FIREWALL_PROXY_URL:-http://127.0.0.1:8080}"
export PHOENIX_FIREWALL_CA="${PHOENIX_FIREWALL_CA:-$HOME/.phoenix-firewall/ca/phoenix-ca.crt}"

pf-npm() {
  env HTTPS_PROXY="$PHOENIX_FIREWALL_PROXY_URL" HTTP_PROXY="$PHOENIX_FIREWALL_PROXY_URL" NODE_EXTRA_CA_CERTS="$PHOENIX_FIREWALL_CA" npm "$@"
}

pf-pip() {
  env HTTPS_PROXY="$PHOENIX_FIREWALL_PROXY_URL" HTTP_PROXY="$PHOENIX_FIREWALL_PROXY_URL" PIP_CERT="$PHOENIX_FIREWALL_CA" REQUESTS_CA_BUNDLE="$PHOENIX_FIREWALL_CA" pip "$@"
}
```

Reload:

```bash
source ~/.zshrc
# or
source ~/.bashrc
```

## Verify Traffic Is Going Through The Firewall

1. Start the proxy:

   ```bash
   phoenix-firewall proxy --api-key "$PHOENIX_API_KEY" --port 8080
   ```

2. In a second terminal, run a firewalled command:

   ```bash
   pf-npm view lodash version
   pf-pip index versions requests
   ```

3. Confirm the proxy terminal prints registry traffic or package evaluations.

If the package manager reports certificate errors:

- confirm `~/.phoenix-firewall/ca/phoenix-ca.crt` exists;
- confirm the relevant CA env var is set;
- restart the proxy if the CA was regenerated;
- use `--trust` for tools that only use the system trust store.

## Safety Notes

- These aliases only affect the shell where they are defined.
- They do not protect package managers launched from other terminals, IDEs, cron jobs, or CI runners.
- They do not replace endpoint/shim mode for managed developer workstations.
- Do not put `PHOENIX_API_KEY` directly into shared shell profiles. Export it from a local secret manager or a private user profile.
