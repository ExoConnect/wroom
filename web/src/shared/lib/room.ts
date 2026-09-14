// Room identity helpers — centralized so lobby, header, and control bar
// agree on one ephemeral-links model (decision 16: a URL is a room).
//
// "/r/<room>" is canonical; "#<room>" is a legacy fallback read only.

import { toast } from "sonner"

/** Room slug from the current location, or "" on the landing state. */
export function roomFromLocation(): string {
  const m = window.location.pathname.match(/^\/r\/([^/]+)\/?$/)
  if (m) return decodeURIComponent(m[1])
  if (window.location.hash.length > 1)
    return decodeURIComponent(window.location.hash.slice(1))
  return ""
}

/** Canonical in-app path for a room slug. */
export function roomPath(room: string): string {
  return `/r/${encodeURIComponent(room)}`
}

const SLUG_ADJECTIVES = [
  "swift",
  "quiet",
  "bright",
  "cosy",
  "rapid",
  "mellow",
  "vivid",
  "nimble",
  "calm",
  "bold",
  "amber",
  "cedar",
]

const SLUG_NOUNS = [
  "falcon",
  "otter",
  "willow",
  "comet",
  "harbor",
  "meadow",
  "raven",
  "tiger",
  "maple",
  "reef",
  "sparrow",
  "canyon",
]

/** Random human-friendly room slug ("swift-falcon-42") for one-click create. */
export function randomRoomSlug(): string {
  const pick = <T>(xs: T[]): T => xs[Math.floor(Math.random() * xs.length)]
  return `${pick(SLUG_ADJECTIVES)}-${pick(SLUG_NOUNS)}-${Math.floor(Math.random() * 90 + 10)}`
}

/**
 * Copy the current room URL (invite link) to the clipboard.
 * Uses the Clipboard API with a textarea/execCommand fallback for insecure
 * contexts or denied permissions. With `silent`, success toasts are skipped
 * (for inline morph confirmations); failures still toast since the user
 * must fall back to the address bar. Returns true on success.
 */
export async function copyRoomLink(opts?: { silent?: boolean }): Promise<boolean> {
  const silent = opts?.silent ?? false
  const url = window.location.href
  try {
    await navigator.clipboard.writeText(url)
    if (!silent) toast.success("Link copied")
    return true
  } catch {
    // Clipboard API unavailable — legacy fallback below.
  }
  const ta = document.createElement("textarea")
  ta.value = url
  ta.style.position = "fixed"
  ta.style.opacity = "0"
  document.body.appendChild(ta)
  ta.select()
  try {
    document.execCommand("copy")
    if (!silent) toast.success("Link copied")
    return true
  } catch {
    toast.error("Couldn't copy the link — copy it from the address bar")
    return false
  } finally {
    ta.remove()
  }
}
