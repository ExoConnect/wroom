import { useEffect, useRef, useState } from "react"
import { MessageSquare, Send, X } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet"
import { useMediaQuery } from "@/hooks/useMediaQuery"
import { session } from "@/lib/session"
import { cn } from "@/lib/utils"
import { useCallStore, type ChatMessage } from "@/store/call"

/** Server limit is 2000 UTF-8 bytes (see proto SendChat) — count bytes,
 *  not chars, so multibyte text can't push a message over. */
const CHAT_MAX_BYTES = 2000
const utf8 = new TextEncoder()

const fmtTime = (ms: number) =>
  new Date(ms).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })

/** Message list + composer — shared by the mobile sheet and desktop panel. */
function ChatBody() {
  const chat = useCallStore((s) => s.chat)
  const connected = useCallStore((s) => s.reconnect.kind === "connected")
  const [draft, setDraft] = useState("")
  const listRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)
  /** Whether the view is pinned to the newest message — cleared when the
   *  user scrolls up so incoming messages don't yank the list. */
  const pinned = useRef(true)

  useEffect(() => {
    const el = listRef.current
    if (el && pinned.current) el.scrollTop = el.scrollHeight
  }, [chat])

  const onScroll = () => {
    const el = listRef.current
    if (el) pinned.current = el.scrollHeight - el.scrollTop - el.clientHeight < 48
  }

  const bytes = utf8.encode(draft).length
  const canSend = draft.trim().length > 0 && bytes <= CHAT_MAX_BYTES && connected

  const send = () => {
    if (!canSend) return
    session.sendChat(draft)
    setDraft("")
    pinned.current = true
    const el = inputRef.current
    if (el) el.style.height = "auto"
    requestAnimationFrame(() => {
      const list = listRef.current
      if (list) list.scrollTop = list.scrollHeight
    })
  }

  const grow = (el: HTMLTextAreaElement) => {
    el.style.height = "auto"
    el.style.height = `${Math.min(el.scrollHeight, 96)}px`
  }

  return (
    <>
      <div
        ref={listRef}
        onScroll={onScroll}
        className="min-h-0 flex-1 overflow-y-auto"
      >
        {chat.length === 0 ? (
          <p className="px-4 py-8 text-center text-sm text-muted-foreground">
            No messages yet — say hi.
          </p>
        ) : (
          <ul className="flex flex-col gap-2.5 p-3">
            {chat.map((m: ChatMessage) => (
              <li
                key={m.id}
                className={cn(
                  "flex flex-col",
                  m.self ? "items-end" : "items-start",
                )}
              >
                <span className="mb-0.5 px-1 text-[11px] text-muted-foreground">
                  {m.self ? fmtTime(m.sentAt) : `${m.displayName || "Unknown"} · ${fmtTime(m.sentAt)}`}
                </span>
                <span
                  className={cn(
                    "max-w-[85%] rounded-2xl px-3 py-1.5 text-sm break-words whitespace-pre-wrap",
                    m.self
                      ? "rounded-br-md bg-primary text-primary-foreground"
                      : "rounded-bl-md bg-muted",
                  )}
                >
                  {m.text}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div
        className="border-t p-2"
        style={{
          paddingBottom: "calc(0.5rem + env(safe-area-inset-bottom, 0px))",
        }}
      >
        <div className="flex items-end gap-2">
          <textarea
            ref={inputRef}
            value={draft}
            rows={1}
            placeholder={connected ? "Message…" : "Reconnecting…"}
            aria-label="Chat message"
            className="max-h-24 min-h-8 flex-1 resize-none rounded-lg border border-input bg-transparent px-2.5 py-1.5 text-sm transition-colors outline-none placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30"
            onChange={(e) => {
              setDraft(e.target.value)
              grow(e.target)
            }}
            onKeyDown={(e) => {
              // Enter sends; Shift+Enter inserts a newline.
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault()
                send()
              }
            }}
          />
          <Button
            size="icon"
            className="size-8 shrink-0"
            disabled={!canSend}
            title="Send"
            aria-label="Send message"
            onClick={send}
          >
            <Send />
          </Button>
        </div>
        {draft.length > 0 && (
          <p
            className={cn(
              "px-1 pt-1 text-right text-[11px] tabular-nums",
              bytes > CHAT_MAX_BYTES ? "text-destructive" : "text-muted-foreground",
            )}
          >
            {bytes}/{CHAT_MAX_BYTES}
          </p>
        )}
      </div>
    </>
  )
}

/**
 * Room chat. On desktop a collapsible side panel next to the grid (same
 * pattern as ParticipantList); on mobile (<768px) a shadcn Sheet slides in
 * over the call. Opening the panel clears `chatUnread`.
 */
export function ChatPanel() {
  const open = useCallStore((s) => s.chatOpen)
  const count = useCallStore((s) => s.chat.length)
  const mobile = useMediaQuery("(width < 768px)")

  useEffect(() => {
    if (open) useCallStore.getState().set({ chatUnread: 0 })
  }, [open])

  const close = () => useCallStore.getState().set({ chatOpen: false })

  const header = (
    <div className="flex items-center gap-1 px-3 py-2.5 text-sm font-medium">
      <MessageSquare className="size-4 shrink-0" />
      <span className="mr-1">Chat</span>
      <span className="text-xs text-muted-foreground">{count}</span>
      <span className="ml-auto" />
      <Button variant="ghost" size="icon" className="size-8" title="Close" onClick={close}>
        <X />
      </Button>
    </div>
  )

  if (mobile) {
    return (
      <Sheet
        open={open}
        onOpenChange={(o) => useCallStore.getState().set({ chatOpen: o })}
      >
        <SheetContent side="right" className="w-[85vw] gap-0 p-0" showCloseButton={false}>
          <SheetHeader className="p-0">
            <SheetTitle className="sr-only">Chat</SheetTitle>
            <SheetDescription className="sr-only">
              Room text chat
            </SheetDescription>
            {header}
          </SheetHeader>
          <Separator />
          <ChatBody />
        </SheetContent>
      </Sheet>
    )
  }

  return (
    <aside
      aria-hidden={!open}
      className={cn(
        "z-20 shrink-0 overflow-hidden transition-[width,opacity] duration-200 ease-out",
        open ? "w-80 opacity-100" : "w-0 opacity-0 pointer-events-none",
      )}
    >
      <div className="flex h-full w-80 flex-col rounded-xl border bg-card">
        {header}
        <Separator />
        <ChatBody />
      </div>
    </aside>
  )
}

export default ChatPanel
