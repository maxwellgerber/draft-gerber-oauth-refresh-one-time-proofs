# Reference implementations

Small authorization servers and clients used to test the two drafts in this
repository under network faults, client crashes and attacks. Not production
code.

- `one-time-proofs/`: draft-gerber-oauth-refresh-one-time-proofs (signed
  counter and nonce; ES256 and Ed25519).
- `rolling-refresh-verifiers/`: draft-gerber-oauth-rolling-refresh-verifiers
  (counted hash chain; SHA-256 only).

Each directory has the same layout: `server.mjs`, `client.mjs` (runs in Node
and in a browser), `test.mjs`, and `browser.html`, `browser_test.py` and
`serve.mjs` for the Chromium checks.

## Running

Requires Node 22 or later. In either directory:

    node --test test.mjs

The browser checks additionally require Python with Playwright and Chromium:

    python3 browser_test.py
