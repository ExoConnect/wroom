import { CircleAlert, PhoneOff } from "lucide-react"
import { Button } from "@/components/ui/button"
import { session } from "@/lib/session"
import { playSound } from "@/lib/sounds"
import { useCallStore } from "@/store/call"
import { LobbyShell } from "./LobbyShell"

/**
 * Post-call screen — shown when phase is "closed" and a room identity is
 * still around. `endedReason` is null when the user left on purpose and the
 * detail string when the connection dropped or the server ended the call.
 */
export function CallEnded() {
  const roomName = useCallStore((s) => s.roomName)
  const selfName = useCallStore((s) => s.selfName)
  const endedReason = useCallStore((s) => s.endedReason)

  const rejoin = () => {
    playSound("click")
    void session.join(roomName, selfName)
  }
  const backToLobby = () => {
    playSound("click")
    useCallStore.getState().set({ phase: "idle" })
  }

  return (
    <LobbyShell>
      <div className="flex flex-col gap-4 py-10">
        <div className="flex size-12 items-center justify-center rounded-full bg-muted">
          <PhoneOff className="size-5 text-muted-foreground" />
        </div>
        <div className="flex flex-col gap-1.5">
          <h1 className="text-3xl font-semibold tracking-tight">You left the call</h1>
          <p className="truncate font-mono text-sm text-muted-foreground">
            /r/{roomName}
          </p>
        </div>
        {endedReason && (
          <div className="flex items-start gap-2 rounded-xl border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
            <CircleAlert className="mt-0.5 size-4 shrink-0" />
            <span>{endedReason}</span>
          </div>
        )}
        <div className="flex flex-col gap-2 pt-1">
          <Button
            size="lg"
            className="h-12 w-full bg-brand text-[15px] font-semibold text-brand-foreground hover:bg-brand/90"
            disabled={!roomName || !selfName}
            onClick={rejoin}
          >
            Rejoin
          </Button>
          <Button
            size="lg"
            variant="secondary"
            className="h-12 w-full"
            onClick={backToLobby}
          >
            Back to lobby
          </Button>
        </div>
      </div>
    </LobbyShell>
  )
}
