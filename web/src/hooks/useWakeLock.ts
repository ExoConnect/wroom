import { useEffect } from "react"
import { useCallStore } from "@/store/call"

/** Structural type — WakeLock is not in every DOM lib version we compile
 *  against, and the API is small enough to describe inline. */
interface WakeLockSentinelLike {
  onrelease: ((this: unknown, ev: Event) => unknown) | null
  release(): Promise<void>
}
interface WakeLockLike {
  request(type: "screen"): Promise<WakeLockSentinelLike>
}

/**
 * Hold a screen wake lock while in a call. The browser auto-releases the
 * sentinel when the tab hides, so it is re-requested on `visibilitychange`
 * back to visible. Released when the call ends (phase leaves "joined").
 * Best-effort: unsupported platforms and denied requests are ignored.
 */
export function useWakeLock(): void {
  const phase = useCallStore((s) => s.phase)

  useEffect(() => {
    if (phase !== "joined") return
    const nav = navigator as Navigator & { wakeLock?: WakeLockLike }
    if (!nav.wakeLock) return

    let sentinel: WakeLockSentinelLike | null = null
    let disposed = false

    const acquire = () => {
      if (sentinel || document.visibilityState !== "visible") return
      nav.wakeLock!.request("screen").then(
        (s) => {
          if (disposed) {
            void s.release()
            return
          }
          // The system can release the lock without the tab hiding (e.g.
          // battery saver) — clear the ref so the next visibilitychange or
          // a later effect re-acquires.
          s.onrelease = () => {
            if (sentinel === s) sentinel = null
          }
          sentinel = s
        },
        () => {}, // NotAllowedError / NotSupportedError — best-effort only
      )
    }

    const onVisibility = () => {
      if (document.visibilityState === "visible") {
        // Hiding auto-released the old sentinel — drop the stale ref and
        // request a fresh one.
        sentinel = null
        acquire()
      }
    }

    acquire()
    document.addEventListener("visibilitychange", onVisibility)
    return () => {
      disposed = true
      document.removeEventListener("visibilitychange", onVisibility)
      if (sentinel) {
        sentinel.onrelease = null
        void sentinel.release()
        sentinel = null
      }
    }
  }, [phase])
}
