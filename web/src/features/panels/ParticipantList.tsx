import {
  Activity,
  HeadphoneOff,
  MicOff,
  Pin,
  ScreenShare,
  Users,
  VideoOff,
  Volume2,
  VolumeX,
  X,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Separator } from "@/components/ui/separator"
import { Switch } from "@/components/ui/switch"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { TrackKind, TrackSource } from "@/gen/wroom/signaling/v1/signaling_pb"
import { playSound } from "@/lib/sounds"
import { useCallStore, type UplinkQuality } from "@/store/call"
import { cn } from "@/lib/utils"

const QUALITY_DOT: Record<UplinkQuality, string> = {
  good: "bg-emerald-400",
  fair: "bg-amber-400",
  poor: "bg-red-400",
  unknown: "bg-muted-foreground/40",
}

const QUALITY_LABEL: Record<UplinkQuality, string> = {
  good: "good connection",
  fair: "fair connection",
  poor: "poor connection",
  unknown: "connection unknown",
}

export function ParticipantList() {
  const participants = useCallStore((s) => s.participants)
  const selfId = useCallStore((s) => s.selfId)
  const activeSpeakers = useCallStore((s) => s.activeSpeakers)
  const remoteQuality = useCallStore((s) => s.remoteQuality)
  const uplinkQuality = useCallStore((s) => s.uplinkQuality)
  const remoteMuted = useCallStore((s) => s.remoteAudioMuted)
  const open = useCallStore((s) => s.participantsOpen)
  const soundsEnabled = useCallStore((s) => s.soundsEnabled)
  const showStats = useCallStore((s) => s.showStats)
  const pinnedId = useCallStore((s) => s.pinnedId)
  const set = useCallStore((s) => s.set)
  const setPinned = useCallStore((s) => s.setPinned)
  const list = Object.values(participants)
  const close = () => set({ participantsOpen: false })

  // "Deafen" lives in the store (CallScreen applies it) — component-local
  // state would stick muted=true on the sinks if the mobile sheet unmounted.
  const setRemoteMuted = (v: boolean) => set({ remoteAudioMuted: v })

  return (
    <>
      {/* Backdrop — the panel overlays the grid below lg. */}
      {open && (
        <div
          className="absolute inset-0 z-10 bg-black/40 animate-in fade-in duration-200 motion-reduce:animate-none lg:hidden"
          onClick={close}
          aria-hidden
        />
      )}
      <aside
        id="participants-panel"
        aria-hidden={!open}
        aria-label="Participants"
        className={cn(
          "z-20 shrink-0 overflow-hidden transition-[width,opacity,transform] duration-200 ease-out motion-reduce:transition-none",
          // Below lg the panel floats over the grid instead of squeezing it;
          // on phones it becomes a full-height sheet flush with the edge.
          "max-lg:absolute max-lg:inset-y-3 max-lg:right-3 max-sm:inset-y-0 max-sm:right-0",
          open
            ? "w-80 max-w-[85vw] opacity-100 max-lg:translate-x-0"
            : "w-0 opacity-0 pointer-events-none max-lg:w-80 max-lg:translate-x-[115%]",
        )}
      >
        <div className="flex h-full w-80 max-w-[85vw] flex-col rounded-xl border bg-card max-lg:shadow-xl max-sm:rounded-none max-sm:border-y-0 max-sm:border-r-0">
          <div className="flex items-center gap-1 px-4 py-3 text-sm font-medium">
            <Users className="size-4 shrink-0" />
            <span className="mr-1">Participants</span>
            <span className="text-xs text-muted-foreground">{list.length}</span>
            <span className="ml-auto" />
            <Button
              variant={showStats ? "secondary" : "ghost"}
              size="icon"
              className="size-8"
              title="Toggle per-tile stats (s)"
              aria-label="Toggle per-tile stats"
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
              aria-label={soundsEnabled ? "Mute UI sounds" : "Unmute UI sounds"}
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
              aria-label="Close participants"
              onClick={close}
            >
              <X />
            </Button>
          </div>
          <Separator />
          <ScrollArea className="min-h-0 flex-1">
            <ul className="p-3">
              {list.map((p) => {
                const mic = p.tracks.find((t) => t.source === TrackSource.MICROPHONE)
                const cam = p.tracks.find(
                  (t) => t.kind === TrackKind.VIDEO && t.source === TrackSource.CAMERA,
                )
                const sharing = p.tracks.some(
                  (t) =>
                    (t.source === TrackSource.SCREENSHARE ||
                      t.source === TrackSource.SCREENSHARE_AUDIO) &&
                    !t.muted,
                )
                const speaking = activeSpeakers.includes(p.id)
                const pinned = pinnedId === p.id
                const isSelf = p.id === selfId
                const quality = isSelf
                  ? uplinkQuality
                  : (remoteQuality[p.id] ?? "unknown")
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
                      aria-label={
                        pinned ? `Unpin ${p.name || p.id}` : `Pin ${p.name || p.id}`
                      }
                      aria-pressed={pinned}
                      onClick={() => {
                        playSound("pin")
                        setPinned(pinned ? null : p.id)
                      }}
                      className={cn(
                        "flex min-w-0 flex-1 cursor-pointer items-center gap-2 text-left",
                      )}
                    >
                      {/* Quality dot — own row shows uplink, others remote. */}
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span
                            role="img"
                            aria-label={`${p.name || p.id}: ${QUALITY_LABEL[quality]}`}
                            className={cn(
                              "size-2 shrink-0 rounded-full",
                              QUALITY_DOT[quality],
                              speaking && "animate-pulse motion-reduce:animate-none",
                            )}
                          />
                        </TooltipTrigger>
                        <TooltipContent side="left">
                          {QUALITY_LABEL[quality]}
                        </TooltipContent>
                      </Tooltip>
                      <span
                        className={cn(
                          "truncate",
                          speaking && "font-medium text-emerald-400",
                        )}
                      >
                        {p.name || p.id}
                        {isSelf && (
                          <span className="text-muted-foreground"> (you)</span>
                        )}
                      </span>
                      {sharing && (
                        <span className="flex shrink-0 items-center gap-1 rounded-full bg-secondary px-1.5 py-0.5 text-[10px] leading-none text-muted-foreground">
                          <ScreenShare className="size-2.5" aria-hidden />
                          sharing screen
                        </span>
                      )}
                    </button>
                    <span className="ml-auto flex items-center gap-1.5 text-muted-foreground">
                      {mic?.muted && (
                        <MicOff
                          className="size-3.5 text-destructive"
                          aria-label="Muted"
                        />
                      )}
                      {cam?.muted && (
                        <VideoOff
                          className="size-3.5 text-destructive"
                          aria-label="Camera off"
                        />
                      )}
                      <Pin
                        className={cn(
                          "size-3.5",
                          pinned
                            ? "text-foreground"
                            : "opacity-0 group-hover:opacity-60",
                        )}
                        aria-hidden
                      />
                    </span>
                  </li>
                )
              })}
            </ul>
          </ScrollArea>
          <Separator />
          {/* Mute all remote audio for yourself (other participants still
              hear everyone — this only flips .muted on our <audio> sinks). */}
          <label
            className="flex h-12 cursor-pointer items-center gap-3 px-4 text-sm hover:bg-muted/50 focus-within:ring-2 focus-within:ring-inset focus-within:ring-ring"
            style={{
              marginBottom: "calc(0.5rem + env(safe-area-inset-bottom, 0px))",
            }}
          >
            <HeadphoneOff className="size-4 shrink-0 text-muted-foreground" />
            <span className="flex-1">Mute remote audio</span>
            <Switch
              checked={remoteMuted}
              onCheckedChange={setRemoteMuted}
              aria-label="Mute all remote audio"
            />
          </label>
        </div>
      </aside>
    </>
  )
}
