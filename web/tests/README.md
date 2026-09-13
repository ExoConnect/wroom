# Browser media regression

`reconnect.mjs` uses Node's built-in CDP WebSocket client (Node 22+) and real
Chromium media, not mocked PeerConnections. No extra npm dependencies.

Start Vite and a **test-only, fake-media** Chromium instance in separate terminals:

```sh
pnpm --filter web dev
chromium --headless=new --remote-debugging-port=9333 \
  --user-data-dir="$(mktemp -d)" \
  --use-fake-device-for-media-stream --use-fake-ui-for-media-stream \
  --autoplay-policy=no-user-gesture-required --mute-audio --no-first-run
```

Then, from the repository root:

```sh
cargo test -p wroomd --release browser_reconnect_churn -- --ignored --nocapture
```

The Rust harness starts a separate signaling server and four media shards on
OS-assigned ports; it does not restart or use the deployed server. The script
creates its own isolated browser contexts, a unique room, and cleans up afterward.
It checks three alternating leave/rejoin cycles (including an empty receive set),
unchanged receiving DTLS transports, advancing decoded audio/video, and 20 seconds
without a cascading reconnect. A metadata-only SDP test cannot catch this bug:
Chromium replaces the BUNDLE transport when its anchor is rejected.

Optional environment variables:

- `WROOM_TEST_WEB_URL`: Vite origin (default `http://localhost:5173`).
- `WROOM_TEST_CDP_URL`: fake-media Chromium debugging endpoint (default
  `http://127.0.0.1:9333`). Never expose this endpoint publicly.

To check an already running server instead, run `node web/tests/reconnect.mjs`.
It uses the web app's normal signaling URL unless `WROOM_TEST_SIGNALING_URL` is set.
