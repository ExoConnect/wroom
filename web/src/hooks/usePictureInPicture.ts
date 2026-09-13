// Picture-in-picture for the "main" video tile.
//
// `enter()` PiPs the pinned tile's <video>, falling back to the first remote
// tile (tiles carry `data-tile-id`; the self tile is marked
// `data-tile-local`). With `auto: true` the hook tries to enter PiP when the
// tab is hidden — Chrome allows this from a media-playing page, guarded with
// try/catch — and exits again when the tab becomes visible (only if *we*
// entered it, so a user-requested PiP isn't killed on return).

import { useCallback, useEffect, useRef } from "react"
import { useCallStore } from "@/store/call"

const pipSupported = (): boolean =>
  typeof document !== "undefined" &&
  "pictureInPictureEnabled" in document &&
  document.pictureInPictureEnabled

/** Pinned tile's <video>, else the first remote tile's <video>. */
function findPipVideo(): HTMLVideoElement | null {
  const { pinnedId } = useCallStore.getState()
  if (pinnedId) {
    const v = document.querySelector<HTMLVideoElement>(
      `[data-tile-id="${CSS.escape(pinnedId)}"] video`,
    )
    if (v?.srcObject) return v
  }
  const candidates = [
    ...document.querySelectorAll<HTMLVideoElement>(
      "[data-tile-id]:not([data-tile-local]) video",
    ),
  ]
  return (
    candidates.find(
      (v) =>
        v.srcObject instanceof MediaStream &&
        v.srcObject.getVideoTracks().length > 0,
    ) ?? null
  )
}

export function usePictureInPicture(opts?: { auto?: boolean }) {
  const autoEntered = useRef(false)

  const enter = useCallback(async (): Promise<boolean> => {
    if (!pipSupported() || document.pictureInPictureElement) return false
    const video = findPipVideo()
    if (!video || video.disablePictureInPicture) return false
    try {
      await video.requestPictureInPicture()
      return true
    } catch {
      return false
    }
  }, [])

  useEffect(() => {
    if (!opts?.auto) return
    const onVis = () => {
      if (document.visibilityState === "hidden") {
        void enter().then((ok) => {
          autoEntered.current = ok
        })
      } else if (autoEntered.current) {
        autoEntered.current = false
        if (document.pictureInPictureElement) {
          void document.exitPictureInPicture().catch(() => {})
        }
      }
    }
    document.addEventListener("visibilitychange", onVis)
    return () => document.removeEventListener("visibilitychange", onVis)
  }, [opts?.auto, enter])

  return { enter, supported: pipSupported() }
}
