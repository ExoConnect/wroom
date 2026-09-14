import { CircleAlert, PhoneOff } from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { session } from "@/lib/session"
import { playSound } from "@/lib/sounds"
import { useCallStore } from "@/store/call"

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
    <div className="flex min-h-svh items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader>
          <div className="flex size-10 items-center justify-center rounded-full bg-muted">
            <PhoneOff className="size-5 text-muted-foreground" />
          </div>
          <CardTitle className="text-2xl tracking-tight">You left the call</CardTitle>
          <CardDescription>/r/{roomName}</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {endedReason && (
            <div className="flex items-start gap-2 rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
              <CircleAlert className="mt-0.5 size-4 shrink-0" />
              <span>{endedReason}</span>
            </div>
          )}
          <Button
            size="lg"
            className="w-full"
            disabled={!roomName || !selfName}
            onClick={rejoin}
          >
            Rejoin
          </Button>
          <Button size="lg" variant="secondary" className="w-full" onClick={backToLobby}>
            Back to lobby
          </Button>
        </CardContent>
      </Card>
    </div>
  )
}
