// Local media capture helpers.
//
// getUserMedia is wrapped in a module-level promise so React StrictMode's
// double-invoked effects (and the join screen → call transition) share one
// capture instead of opening the camera twice.

export interface LocalMedia {
  stream: MediaStream
  /** False when permission was denied or no devices exist — join proceeds audio/video-less. */
  ok: boolean
  error?: string
}

let pending: Promise<LocalMedia> | null = null

/** Capture cam + mic once; subsequent calls return the same promise. */
export function getLocalMedia(): Promise<LocalMedia> {
  if (pending) return pending
  pending = (async (): Promise<LocalMedia> => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: {
          echoCancellation: true,
          noiseSuppression: true,
          autoGainControl: true,
          channelCount: 1,
        },
        video: {
          width: { ideal: 1280 },
          height: { ideal: 720 },
          frameRate: { ideal: 30, max: 30 },
        },
      })
      return { stream, ok: true }
    } catch (err) {
      // Retry once with audio only — a missing camera shouldn't block joining.
      try {
        const stream = await navigator.mediaDevices.getUserMedia({ audio: true })
        return { stream, ok: true, error: "Camera unavailable — joined with mic only." }
      } catch {
        return {
          stream: new MediaStream(),
          ok: false,
          error:
            err instanceof DOMException && err.name === "NotAllowedError"
              ? "Camera/mic permission denied — joining without media."
              : "No camera/mic available — joining without media.",
        }
      }
    }
  })()
  // A fully failed capture shouldn't poison future attempts forever — allow
  // one retry per page load by clearing on denial is deliberately NOT done so
  // the permission state stays stable within a session.
  return pending
}

/** Stop all local tracks and reset so a future join re-captures. */
export function releaseLocalMedia(stream: MediaStream | null | undefined): void {
  stream?.getTracks().forEach((t) => t.stop())
  pending = null
}

// Stable per-participant track ids for M0's fixed cam+mic set. Track ids are
// unique per participant (see TrackRef); readable ids keep debug logs legible.
export const LOCAL_TRACK_IDS = { mic: "mic", cam: "cam", screen: "screen" } as const
