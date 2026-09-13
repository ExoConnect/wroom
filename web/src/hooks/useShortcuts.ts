// Global call keyboard shortcuts.
//
//   m        toggle microphone
//   v        toggle camera
//   p        pin/unpin the hovered tile (or the first remote tile)
//   Space    hold = push-to-talk while muted (re-mutes on keyup)
//   s        toggle per-tile stats
//   c        toggle chat panel
//   f        fullscreen the pinned (or first remote) tile
//   Esc      close dialog → close panels → unpin
//   ?        keyboard-shortcuts dialog
//
// Keys are ignored while typing in editable fields or while a modifier
// (Ctrl/Meta/Alt) is held. Tiles expose `data-tile-id` (+ `data-tile-local`
// on the self tile) so "hovered or first remote" resolution is DOM-based —
// no extra wiring in the tile components beyond the attribute.

import { useEffect } from "react"
import { toast } from "sonner"
import { LOCAL_TRACK_IDS } from "@/lib/media"
import { session } from "@/lib/session"
import { playSound } from "@/lib/sounds"
import { useCallStore } from "@/store/call"

/** Focused element swallows Space as "activate" — don't hijack it for PTT. */
function activatesSpace(el: Element | null): boolean {
  if (!(el instanceof HTMLElement) || el === document.body) return false
  if (el.tagName === "BUTTON" || el.tagName === "A" || el.tagName === "SELECT")
    return true
  const role = el.getAttribute("role")
  return (
    role === "button" ||
    role === "link" ||
    role === "menuitem" ||
    role === "option" ||
    role === "switch" ||
    role === "tab" ||
    role === "checkbox" ||
    el.isContentEditable
  )
}

function isEditable(t: EventTarget | null): boolean {
  return (
    t instanceof HTMLElement &&
    (t.tagName === "INPUT" ||
      t.tagName === "TEXTAREA" ||
      t.tagName === "SELECT" ||
      t.isContentEditable)
  )
}

/** Hovered tile id, else the first remote tile's id. */
function targetTileId(): string | null {
  const hovered = document.querySelector<HTMLElement>("[data-tile-id]:hover")
  if (hovered?.dataset.tileId) return hovered.dataset.tileId
  const firstRemote = [
    ...document.querySelectorAll<HTMLElement>("[data-tile-id]"),
  ].find((el) => el.dataset.tileLocal == null)
  return firstRemote?.dataset.tileId ?? null
}

export function useShortcuts(): void {
  useEffect(() => {
    let ptt = false
    const endPtt = () => {
      if (!ptt) return
      ptt = false
      session.setTrackEnabled(LOCAL_TRACK_IDS.mic, false)
    }

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.defaultPrevented || isEditable(e.target)) return
      const s = useCallStore.getState()

      // "?" — Shift+/ on most layouts produces "?" directly.
      if (e.key === "?" || (e.key === "/" && e.shiftKey)) {
        e.preventDefault()
        s.set({ shortcutsOpen: !s.shortcutsOpen })
        return
      }

      if (e.key === "Escape") {
        // Innermost thing first; Radix dialogs/menus close themselves on Esc
        // (their handlers run before this window listener in the bubble).
        if (s.shortcutsOpen) s.set({ shortcutsOpen: false })
        else if (s.chatOpen) s.set({ chatOpen: false })
        else if (s.participantsOpen) s.set({ participantsOpen: false })
        else if (s.pinnedId) s.setPinned(null)
        return
      }

      if (e.metaKey || e.ctrlKey || e.altKey) return

      if (e.key === " ") {
        // Push-to-talk: only while muted, and not while an activatable
        // element (button, link, menu item, tile) holds focus — their Space
        // is "click". Tiles also preventDefault on Space, caught above.
        if (e.repeat || s.micEnabled || activatesSpace(document.activeElement))
          return
        e.preventDefault()
        ptt = true
        session.setTrackEnabled(LOCAL_TRACK_IDS.mic, true)
        return
      }

      switch (e.key.toLowerCase()) {
        case "m": {
          e.preventDefault()
          playSound(s.micEnabled ? "mute" : "unmute")
          session.setTrackEnabled(LOCAL_TRACK_IDS.mic, !s.micEnabled)
          break
        }
        case "v": {
          e.preventDefault()
          playSound("click")
          session.setTrackEnabled(LOCAL_TRACK_IDS.cam, !s.camEnabled)
          break
        }
        case "p": {
          const id = targetTileId()
          if (!id) return
          e.preventDefault()
          playSound("pin")
          s.setPinned(s.pinnedId === id ? null : id)
          break
        }
        case "s": {
          e.preventDefault()
          s.set({ showStats: !s.showStats })
          break
        }
        case "c": {
          e.preventDefault()
          s.set(
            s.chatOpen
              ? { chatOpen: false }
              : { chatOpen: true, chatUnread: 0, participantsOpen: false },
          )
          break
        }
        case "f": {
          const id = s.pinnedId ?? targetTileId()
          if (!id) return
          e.preventDefault()
          const el = document.querySelector<HTMLElement>(
            `[data-tile-id="${CSS.escape(id)}"]`,
          )
          if (document.fullscreenElement) {
            void document.exitFullscreen().catch(() => {})
          } else if (el) {
            void el.requestFullscreen().catch(() => {
              toast.error("Fullscreen isn't available right now")
            })
          }
          break
        }
      }
    }

    const onKeyUp = (e: KeyboardEvent) => {
      if (e.key === " ") endPtt()
    }

    window.addEventListener("keydown", onKeyDown)
    window.addEventListener("keyup", onKeyUp)
    window.addEventListener("blur", endPtt)
    return () => {
      window.removeEventListener("keydown", onKeyDown)
      window.removeEventListener("keyup", onKeyUp)
      window.removeEventListener("blur", endPtt)
      endPtt()
    }
  }, [])
}
