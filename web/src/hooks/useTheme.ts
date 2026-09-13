// Theme preference: "system" | "light" | "dark".
//
// The store's `theme` field is the source of truth for components; this
// module persists the choice to localStorage ("wroom:theme"), applies the
// `.dark` class to <html>, and follows `prefers-color-scheme` while in
// "system" mode. Initialization runs once at module evaluation (the app
// bundle is a single chunk, so this also covers the join screen), and a
// store subscription keeps the class in sync with later changes.

import { useCallback } from "react"
import { useMediaQuery } from "@/hooks/useMediaQuery"
import { useCallStore, type Theme } from "@/store/call"

const STORAGE_KEY = "wroom:theme"
const DARK_MQ = "(prefers-color-scheme: dark)"

const isTheme = (v: unknown): v is Theme =>
  v === "system" || v === "light" || v === "dark"

let initialized = false

function initTheme(): void {
  if (initialized || typeof window === "undefined" || !window.document) return
  initialized = true

  let stored: string | null = null
  try {
    stored = window.localStorage.getItem(STORAGE_KEY)
  } catch {
    // Storage blocked (private mode etc.) — fall back to the default theme.
  }
  if (isTheme(stored) && stored !== useCallStore.getState().theme) {
    useCallStore.setState({ theme: stored })
  }

  const mq = window.matchMedia(DARK_MQ)
  const apply = () => {
    const t = useCallStore.getState().theme
    const dark = t === "dark" || (t === "system" && mq.matches)
    document.documentElement.classList.toggle("dark", dark)
  }
  mq.addEventListener("change", apply)
  useCallStore.subscribe((s, prev) => {
    if (s.theme !== prev.theme) apply()
  })
  apply()
}

initTheme()

/** Current theme + setter; the `.dark` class is applied automatically. */
export function useTheme() {
  const theme = useCallStore((s) => s.theme)
  const systemDark = useMediaQuery(DARK_MQ)
  const resolvedTheme: "light" | "dark" =
    theme === "system" ? (systemDark ? "dark" : "light") : theme

  const setTheme = useCallback((t: Theme) => {
    try {
      window.localStorage.setItem(STORAGE_KEY, t)
    } catch {
      // Storage blocked — apply for this session only.
    }
    useCallStore.getState().set({ theme: t })
  }, [])

  return { theme, resolvedTheme, setTheme }
}
