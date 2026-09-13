import { useEffect, useState } from "react"

/** Tracks an element's content-box size via ResizeObserver. Returns a
 *  callback ref, so it also works on conditionally mounted elements. */
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
    return () => ro.disconnect()
  }, [el])
  return [setEl, size] as const
}
