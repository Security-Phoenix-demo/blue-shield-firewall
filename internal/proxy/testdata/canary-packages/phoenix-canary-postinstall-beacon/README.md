# Canary test fixture: postinstall network beacon

**This is not malware. It is a firewall detection test fixture.** It exists
so we can verify the firewall actually catches this exact TTP (a package
lifecycle script that does a DNS lookup then an outbound HTTPS call) without
running anything that resembles the real incident it's modeled on.

## What it does, precisely

`scripts/postinstall.js` does exactly this and nothing else:

1. Resolves `PHOENIX_CANARY_ENDPOINT` (default `canary.phxintel.security`) via DNS.
2. Opens one HTTPS connection to it and POSTs a fixed, non-identifying JSON body.
3. Exits 0 no matter what happens — success, DNS failure, connection refused,
   timeout, blocked by the firewall — the install must never fail or hang.

## What it deliberately does NOT do

- No filesystem access (the `fs` module isn't even imported).
- No reads of SSH keys, `.gitconfig`, credentials, or environment variables
  beyond the one endpoint-override var — and that var's value is never sent
  anywhere, it only chooses the destination.
- No data collection/exfiltration — the request body is a static string with
  no host, user, or path information in it.
- No persistence, no child processes, no self-modification.

Read the top-of-file comment in `scripts/postinstall.js` before changing
anything — every "does NOT do" item above is enforced by an explicit code
comment at the point it matters, so a future edit can't silently reintroduce
one of these without someone having to consciously remove that comment too.

## Do not publish this to public npm

This directory is a local fixture, kept out of the module's dependency graph
(this is a Go repo — nothing here ever runs `npm install` against it
automatically). If you want to exercise the *real* npm-install-through-proxy
path rather than just unit-testing the matcher/handler logic:

1. `npm pack` this directory to produce a real `.tgz`.
2. Install it only inside a disposable, network-isolated container/VM you
   control — never on a real workstation, never from a shared/public registry.
3. Point `PHOENIX_CANARY_ENDPOINT` at infrastructure you own that just logs
   the hit (a bare `POST /canary -> 200` handler is enough). Do not point it
   at any third party's infrastructure, "known C2" or otherwise — connecting
   to real attacker infrastructure, even to send nothing, is not something to
   do casually for a test.

## Why the package name won't collide with anything real

`phoenix-firewall-canary-postinstall-beacon` is not a real published package
and is not intended to ever be published. It also deliberately does *not*
reuse the real incident's package name (`anthropic-toolkit`), so it can never
be confused with, or accidentally shadow, that package or any other real one.
