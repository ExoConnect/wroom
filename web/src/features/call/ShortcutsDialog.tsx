import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Kbd } from "@/components/ui/kbd"
import { useCallStore } from "@/store/call"

const SHORTCUTS: { keys: string[]; label: string }[] = [
  { keys: ["M"], label: "Toggle microphone" },
  { keys: ["V"], label: "Toggle camera" },
  { keys: ["P"], label: "Pin / unpin the hovered tile" },
  { keys: ["Space"], label: "Hold to talk while muted (push-to-talk)" },
  { keys: ["S"], label: "Toggle per-tile stats" },
  { keys: ["C"], label: "Toggle chat" },
  { keys: ["F"], label: "Fullscreen the pinned tile" },
  { keys: ["Esc"], label: "Close panels / unpin" },
  { keys: ["?"], label: "Show this dialog" },
]

/** "?" — list of in-call keyboard shortcuts. Controlled by store
 *  `shortcutsOpen` so the header button, the more-menu item and the "?"
 *  key all drive the same dialog. */
export function ShortcutsDialog() {
  const open = useCallStore((s) => s.shortcutsOpen)
  const set = useCallStore((s) => s.set)
  return (
    <Dialog open={open} onOpenChange={(o) => set({ shortcutsOpen: o })}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Keyboard shortcuts</DialogTitle>
          <DialogDescription>
            Shortcuts are ignored while typing.
          </DialogDescription>
        </DialogHeader>
        <ul className="flex flex-col">
          {SHORTCUTS.map((s) => (
            <li
              key={s.label}
              className="flex items-center justify-between gap-4 border-b border-border/60 py-2 last:border-0"
            >
              <span className="text-sm">{s.label}</span>
              <span className="flex shrink-0 items-center gap-1">
                {s.keys.map((k) => (
                  <Kbd key={k}>{k === "Space" ? "Space" : k}</Kbd>
                ))}
              </span>
            </li>
          ))}
        </ul>
      </DialogContent>
    </Dialog>
  )
}
