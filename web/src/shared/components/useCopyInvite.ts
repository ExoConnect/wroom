// Silent copy-invite state: `copied` is true for 2s after a successful
// copy so the invoking control can morph instead of toasting.

import { useCallback, useEffect, useRef, useState } from "react"
import { copyRoomLink } from "@/shared/lib/room"

/** Runs a silent copy; `copied` is true for 2s after success. */
export function useCopyInvite(timeoutMs = 2000) {
  const [copied, setCopied] = useState(false)
  const timer = useRef(0)
  useEffect(() => () => window.clearTimeout(timer.current), [])
  const copy = useCallback(async () => {
    const ok = await copyRoomLink({ silent: true })
    if (!ok) return false
    setCopied(true)
    window.clearTimeout(timer.current)
    timer.current = window.setTimeout(() => setCopied(false), timeoutMs)
    return true
  }, [timeoutMs])
  return { copied, copy }
}
