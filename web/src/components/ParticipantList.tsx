import { Activity, MicOff, Pin, Users, VideoOff, Volume2, VolumeX, X } from "lucide-react"
import { Button } from "@/components/ui/button"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Separator } from "@/components/ui/separator"
import { TrackKind, TrackSource } from "@/gen/signaling/v1/signaling_pb"
import { playSound } from "@/lib/sounds"
import { useCallStore } from "@/store/call"
import { cn } from "@/lib/utils"

export function ParticipantList() {
  const participants = useCallStore((s) => s.participants)
  const selfId = useCallStore((s) => s.selfId)
  const activeSpeakers = useCallStore((s) => s.activeSpeakers)
  const open = useCallStore((s) => s.participantsOpen)
  const soundsEnabled = useCallStore((s) => s.soundsEnabled)
  const showStats = useCallStore((s) => s.showStats)
  const pinnedId = useCallStore((s) => s.pinnedId)
  const set = useCallStore((s) => s.set)
  const setPinned = useCallStore((s) => s.setPinned)
  const list = Object.values(participants)
  const close = () => set({ participantsOpen: false })

  return (
    <>
      {/* Backdrop — narrow screens only, where the panel overlays the grid. */}
      {open && (
        <div
          className="absolute inset-0 z-10 bg-black/40 animate-in fade-in duration-200 md:hidden"
          onClick={close}
        />
      )}
      <aside
        aria-hidden={!open}
        className={cn(
          "z-20 shrink-0 overflow-hidden transition-[width,opacity,transform] duration-200 ease-out",
          // <768px the panel floats over the grid instead of squeezing it.
          "max-md:absolute max-md:inset-y-3 max-md:right-3",
          open
            ? "w-72 opacity-100 max-md:translate-x-0"
            : "w-0 opacity-0 pointer-events-none max-md:w-72 max-md:translate-x-[115%]",
        )}
      >
        <div className="flex h-full w-72 flex-col rounded-xl border bg-card max-md:shadow-xl">
          <div className="flex items-center gap-1 px-3 py-2.5 text-sm font-medium">
            <Users className="size-4 shrink-0" />
            <span className="mr-1">Participants</span>
            <span className="text-xs text-muted-foreground">{list.length}</span>
            <span className="ml-auto" />
            <Button
              variant={showStats ? "secondary" : "ghost"}
              size="icon"
              className="size-8"
              title="Toggle per-tile stats (s)"
              aria-pressed={showStats}
              onClick={() => {
                playSound("click")
                set({ showStats: !showStats })
              }}
            >
              <Activity />
            </Button>
            <Button
              variant={soundsEnabled ? "secondary" : "ghost"}
              size="icon"
              className="size-8"
              title={soundsEnabled ? "Mute UI sounds" : "Unmute UI sounds"}
              aria-pressed={soundsEnabled}
              onClick={() => {
                set({ soundsEnabled: !soundsEnabled })
                playSound("click") // plays only when re-enabling
              }}
            >
              {soundsEnabled ? <Volume2 /> : <VolumeX />}
            </Button>
            <Button
              variant="ghost"
              size="icon"
              className="size-8"
              title="Close"
              onClick={close}
            >
              <X />
            </Button>
          </div>
          <Separator />
          <ScrollArea className="min-h-0 flex-1">
            <ul className="p-2">
              {list.map((p) => {
                const mic = p.tracks.find((t) => t.source === TrackSource.MICROPHONE)
                const cam = p.tracks.find(
                  (t) => t.kind === TrackKind.VIDEO && t.source === TrackSource.CAMERA,
                )
                const speaking = activeSpeakers.includes(p.id)
                const pinned = pinnedId === p.id
                return (
                  <li
                    key={p.id}
                    className={cn(
                      "group flex items-center gap-2 rounded-lg px-2 py-2 text-sm",
                      speaking && "bg-emerald-500/10",
                    )}
                  >
                    <button
                      type="button"
                      title={pinned ? "Unpin" : "Pin to stage"}
                      onClick={() => {
                        playSound("pin")
                        setPinned(pinned ? null : p.id)
                      }}
                      className={cn(
                        "flex min-w-0 flex-1 cursor-pointer items-center gap-2 text-left",
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
                    </button>
                    <span className="ml-auto flex items-center gap-1.5 text-muted-foreground">
                      {mic?.muted && <MicOff className="size-3.5 text-destructive" />}
                      {cam?.muted && <VideoOff className="size-3.5 text-destructive" />}
                      <Pin
                        className={cn(
                          "size-3.5",
                          pinned
                            ? "text-foreground"
                            : "opacity-0 group-hover:opacity-60",
                        )}
                      />
                    </span>
                  </li>
                )
              })}
            </ul>
          </ScrollArea>
        </div>
      </aside>
    </>
  )
}
