import { useEffect, useRef, useState } from "react"

/** True while the user is active; flips false `ms` after the last
 *  pointer/touch/key event. Used to auto-hide the floating control bar. */
export function useAutoHide(ms = 3000): boolean {
  const [visible, setVisible] = useState(true)
  const timer = useRef<number>(0)
  useEffect(() => {
    const poke = () => {
      setVisible(true)
      window.clearTimeout(timer.current)
      timer.current = window.setTimeout(() => setVisible(false), ms)
    }
    const events = ["pointermove", "pointerdown", "touchstart", "keydown"] as const
    for (const e of events) window.addEventListener(e, poke, { passive: true })
    poke()
    return () => {
      for (const e of events) window.removeEventListener(e, poke)
      window.clearTimeout(timer.current)
    }
  }, [ms])
  return visible
}
