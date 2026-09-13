import { useEffect, useState } from "react"

/** Tracks an element's content-box size via ResizeObserver. Returns a
 *  callback ref, so it also works on conditionally mounted elements.
 *  A window resize/orientationchange listener re-syncs as a fallback for
 *  mobile rotations where RO timing can lag. */
export function useElementSize<T extends HTMLElement>() {
  const [el, setEl] = useState<T | null>(null)
  const [size, setSize] = useState({ width: 0, height: 0 })
  useEffect(() => {
    if (!el) return
    const ro = new ResizeObserver(([entry]) => {
      const { width, height } = entry.contentRect
      setSize((s) =>
        s.width === width && s.height === height ? s : { width, height },
      )
    })
    ro.observe(el)
    const sync = () => {
      // These elements are padding-free; client* == content box here.
      const { clientWidth: width, clientHeight: height } = el
      setSize((s) =>
        s.width === width && s.height === height ? s : { width, height },
      )
    }
    window.addEventListener("resize", sync)
    window.addEventListener("orientationchange", sync)
    return () => {
      ro.disconnect()
      window.removeEventListener("resize", sync)
      window.removeEventListener("orientationchange", sync)
    }
  }, [el])
  return [setEl, size] as const
}
