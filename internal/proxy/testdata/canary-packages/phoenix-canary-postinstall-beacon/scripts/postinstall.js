#!/usr/bin/env node
'use strict';

/**
 * PHOENIX SECURITY — FIREWALL DETECTION TEST FIXTURE. NOT MALWARE. DO NOT PUBLISH.
 *
 * This script exists to give the firewall's postinstall-network-behavior
 * detection something real to detect, without any of the actual harm a real
 * attack of this shape would do. It reproduces only the *shape* of the
 * incident TTP (lifecycle script -> DNS lookup -> outbound HTTPS call), and
 * nothing else:
 *
 *   - No filesystem access of any kind (no `fs` module is even imported).
 *   - No reads of SSH keys, git config, credentials, env vars, or any other
 *     host data. The only env var touched is PHOENIX_CANARY_ENDPOINT, and
 *     its value is never sent anywhere — it only selects where THIS script
 *     connects to.
 *   - No data is collected or exfiltrated. The outbound request body is
 *     always the fixed string below; nothing from this host is included.
 *   - No persistence: no files written, no cron/registry/startup entries,
 *     no child processes spawned.
 *   - Fails silently and always exits 0. A blocked/unreachable network call
 *     must never fail `npm install` for whoever runs this fixture.
 *
 * Usage: see README.md in this directory. Default endpoint points at
 * Phoenix-controlled infrastructure that does nothing but log the hit for
 * verification — replace PHOENIX_CANARY_ENDPOINT if you stand up your own.
 */

const dns = require('dns');
const https = require('https');

const ENDPOINT = process.env.PHOENIX_CANARY_ENDPOINT || 'canary.phxintel.security';
const REQUEST_TIMEOUT_MS = 3000;
const FIXED_BODY = JSON.stringify({ source: 'phoenix-firewall-canary-postinstall-beacon' });

function done() {
  // Always succeed. This fixture must never block or slow down a real
  // `npm install` beyond the timeout below, and must never surface as an
  // install failure regardless of network conditions.
  process.exit(0);
}

dns.lookup(ENDPOINT, (dnsErr, address) => {
  if (dnsErr) {
    done();
    return;
  }

  const req = https.request(
    {
      host: address,
      servername: ENDPOINT, // SNI, so TLS cert validation matches the hostname, not the raw IP
      port: 443,
      path: '/canary',
      method: 'POST',
      timeout: REQUEST_TIMEOUT_MS,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(FIXED_BODY),
        'User-Agent': 'phoenix-firewall-canary-postinstall-beacon/0.0.1',
      },
    },
    (res) => {
      res.resume(); // drain and discard; we don't care about the response
      done();
    },
  );

  req.on('error', done);
  req.on('timeout', () => {
    req.destroy();
    done();
  });

  req.write(FIXED_BODY);
  req.end();
});

// Belt-and-suspenders: never let this script hang the install indefinitely
// even if something above doesn't behave as expected.
setTimeout(done, REQUEST_TIMEOUT_MS + 1000);
