import { MicOff, Users, VideoOff } from "lucide-react"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Separator } from "@/components/ui/separator"
import { TrackKind, TrackSource } from "@/gen/signaling/v1/signaling_pb"
import { useCallStore } from "@/store/call"
import { cn } from "@/lib/utils"

export function ParticipantList() {
  const participants = useCallStore((s) => s.participants)
  const selfId = useCallStore((s) => s.selfId)
  const activeSpeakers = useCallStore((s) => s.activeSpeakers)
  const list = Object.values(participants)

  return (
    <aside className="flex w-64 shrink-0 flex-col rounded-xl border bg-card">
      <div className="flex items-center gap-2 px-4 py-3 text-sm font-medium">
        <Users className="size-4" />
        Participants
        <span className="ml-auto text-xs text-muted-foreground">{list.length}</span>
      </div>
      <Separator />
      <ScrollArea className="flex-1">
        <ul className="p-2">
          {list.map((p) => {
            const mic = p.tracks.find((t) => t.source === TrackSource.MICROPHONE)
            const cam = p.tracks.find(
              (t) => t.kind === TrackKind.VIDEO && t.source === TrackSource.CAMERA,
            )
            const speaking = activeSpeakers.includes(p.id)
            return (
              <li
                key={p.id}
                className={cn(
                  "flex items-center gap-2 rounded-lg px-2 py-2 text-sm",
                  speaking && "bg-emerald-500/10",
                )}
              >
                <span
                  className={cn(
                    "truncate",
                    speaking && "font-medium text-emerald-400",
                  )}
                >
                  {p.name || p.id}
                  {p.id === selfId && (
                    <span className="text-muted-foreground"> (you)</span>
                  )}
                </span>
                <span className="ml-auto flex items-center gap-1.5 text-muted-foreground">
                  {mic?.muted && <MicOff className="size-3.5 text-destructive" />}
                  {cam?.muted && <VideoOff className="size-3.5 text-destructive" />}
                </span>
              </li>
            )
          })}
        </ul>
      </ScrollArea>
    </aside>
  )
}
