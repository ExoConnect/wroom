// Client configuration.
//
// Server URL resolution:
//   - Set VITE_WROOMD_URL to point the client at a wroomd instance, e.g.
//       VITE_WROOMD_URL=ws://localhost:8080 pnpm dev
//     (scheme ws:// or wss://; the /ws path is appended automatically).
//   - When unset, the client uses a same-origin "/ws" URL. In `vite dev` that
//     path is proxied to http://localhost:8080 — wroomd's default bind — see
//     vite.config.ts. In production it assumes the signaling socket is served
//     by the same origin that serves the app.
export function signalingUrl(): string {
  const base = (import.meta.env.VITE_WROOMD_URL as string | undefined)?.replace(/\/+$/, "")
  if (base) return `${base}/ws`
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:"
  return `${proto}//${window.location.host}/ws`
}

// Signaling debug mode (decision 15 requires human-readable inspection
// tooling). When enabled, every ClientMessage/ServerMessage is logged to the
// console as JSON. Enable with either:
//   - VITE_WROOM_SIGNALING_DEBUG=1 in the environment, or
//   - localStorage.setItem("wroom:debug", "1") in the browser console.
export function signalingDebug(): boolean {
  if (import.meta.env.VITE_WROOM_SIGNALING_DEBUG) return true
  try {
    return window.localStorage.getItem("wroom:debug") === "1"
  } catch {
    return false
  }
}

// ClientInfo reported in JoinRequest.
export const CLIENT_NAME = "web"
export const CLIENT_VERSION = "0.0.0-m0"
