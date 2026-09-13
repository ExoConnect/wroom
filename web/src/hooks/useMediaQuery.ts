import { useEffect, useState } from "react"

/** Live `matchMedia(query).matches` — re-renders on change (incl. rotation,
 *  window resizes crossing the breakpoint, pointer-class changes). */
export function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(() => window.matchMedia(query).matches)
  useEffect(() => {
    const mq = window.matchMedia(query)
    const onChange = () => setMatches(mq.matches)
    onChange()
    mq.addEventListener("change", onChange)
    return () => mq.removeEventListener("change", onChange)
  }, [query])
  return matches
}
