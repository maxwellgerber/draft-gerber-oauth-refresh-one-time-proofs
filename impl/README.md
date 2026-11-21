# Reference implementation

A small authorization server and client for
draft-gerber-oauth-refresh-one-time-proofs, used to test the design under
network faults and client crashes. Not production code.

- `server.mjs`: in-memory authorization server (`refresh_jwk`, counter and
  nonce processing, metadata). ES256 and Ed25519.
- `client.mjs`: client that runs unchanged in Node and in a browser
  (WebCrypto, non-extractable keys by default).
- `test.mjs`: fault injection, crash recovery, soak and attack tests.
- `browser.html`, `browser_test.py`, `serve.mjs`: the same client in
  Chromium, with IndexedDB storage and a Web Lock across tabs.

## Running

Requires Node 22 or later.

    node --test test.mjs

The browser checks additionally require Python with Playwright and Chromium:

    python3 browser_test.py
