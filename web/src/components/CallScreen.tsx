import { useEffect, useMemo, useRef, useState, type CSSProperties } from "react"
import { Badge } from "@/components/ui/badge"
import { TrackKind } from "@/gen/signaling/v1/signaling_pb"
import { useAutoHide } from "@/hooks/useAutoHide"
import { useElementSize } from "@/hooks/useElementSize"
import { useParticipantSounds } from "@/hooks/useParticipantSounds"
import { session } from "@/lib/session"
import { playSound } from "@/lib/sounds"
import { cn } from "@/lib/utils"
import { useCallStore } from "@/store/call"
import { useStatsStore, type TrackStats } from "@/store/stats"
import { ControlBar } from "./ControlBar"
import { ParticipantList } from "./ParticipantList"
import { VideoTile } from "./VideoTile"

const GAP = 12 // px — matches gap-3

interface TileData {
  /** Participant id, or `mid:<mid>` for grant-less orphan video. */
  id: string
  stream: MediaStream | null
  label: string
  micMuted: boolean
  videoOff: boolean
  mirror: boolean
  speaking: boolean
  /** Remote video mid — stats lookup key. */
  mid: string | null
  local: boolean
}

/** Widest 16:9 tile that fits `count` tiles into a w×h box (col count search). */
function fitTileWidth(count: number, w: number, h: number): number {
  let best = 0
  for (let cols = 1; cols <= count; cols++) {
    const rows = Math.ceil(count / cols)
    const cellW = (w - GAP * (cols - 1)) / cols
    const cellH = (h - GAP * (rows - 1)) / rows
    best = Math.max(best, Math.min(cellW, (cellH * 16) / 9))
  }
  return Math.floor(best)
}

const fmtStats = (s: TrackStats) =>
  `${s.width}×${s.height} · ${Math.round(s.fps)}fps · ${Math.round(s.kbps)}kbps`

/** Hidden <audio> sink for a remote audio track. */
function RemoteAudio({ stream }: { stream: MediaStream }) {
  const ref = useRef<HTMLAudioElement>(null)
  useEffect(() => {
    const el = ref.current
    if (el && el.srcObject !== stream) el.srcObject = stream
    return () => {
      if (el) el.srcObject = null
    }
  }, [stream])
  return <audio ref={ref} autoPlay data-remote-audio="" />
}

function connBadge(state: RTCPeerConnectionState | null) {
  if (!state || state === "new" || state === "connecting") return null
  if (state === "connected") return null
  return (
    <Badge variant={state === "failed" ? "destructive" : "secondary"}>{state}</Badge>
  )
}

export function CallScreen() {
  const roomName = useCallStore((s) => s.roomName)
  const selfName = useCallStore((s) => s.selfName)
  const selfId = useCallStore((s) => s.selfId)
  const participants = useCallStore((s) => s.participants)
  const remoteMedia = useCallStore((s) => s.remoteMedia)
  const midToTrackRef = useCallStore((s) => s.midToTrackRef)
  const localStream = useCallStore((s) => s.localStream)
  const micEnabled = useCallStore((s) => s.micEnabled)
  const camEnabled = useCallStore((s) => s.camEnabled)
  const activeSpeakers = useCallStore((s) => s.activeSpeakers)
  const pubConnState = useCallStore((s) => s.pubConnState)
  const subConnState = useCallStore((s) => s.subConnState)
  const pinnedId = useCallStore((s) => s.pinnedId)
  const setPinned = useCallStore((s) => s.setPinned)
  const showStats = useCallStore((s) => s.showStats)
  const statsByMid = useStatsStore((s) => s.byMid)
  const localStats = useStatsStore((s) => s.local)

  const controlsVisible = useAutoHide(3000)
  useParticipantSounds()
  const [gridRef, gridSize] = useElementSize<HTMLDivElement>()
  const [stageRef, stageSize] = useElementSize<HTMLDivElement>()

  // Best-effort LeaveRequest on tab close / reload.
  useEffect(() => {
    const onUnload = () => session.leave()
    window.addEventListener("beforeunload", onUnload)
    return () => window.removeEventListener("beforeunload", onUnload)
  }, [])

  // Keyboard: Escape unpins, "s" toggles per-tile stats.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement | null
      if (
        el &&
        (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.isContentEditable)
      )
        return
      if (e.key === "Escape") {
        useCallStore.getState().setPinned(null)
      } else if (e.key === "s" || e.key === "S") {
        const s = useCallStore.getState()
        s.set({ showStats: !s.showStats })
      }
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [])

  // Mobile autoplay policy can pause the hidden audio sinks until the first
  // user gesture — resume any paused ones on interaction.
  useEffect(() => {
    const resume = () => {
      for (const el of document.querySelectorAll<HTMLAudioElement>(
        "audio[data-remote-audio]",
      )) {
        if (el.paused) void el.play().catch(() => {})
      }
    }
    window.addEventListener("pointerdown", resume)
    window.addEventListener("touchend", resume)
    return () => {
      window.removeEventListener("pointerdown", resume)
      window.removeEventListener("touchend", resume)
    }
  }, [])

  const remoteAudio = Object.values(remoteMedia).filter((m) => m.track.kind === "audio")

  // Flat tile list: local first, then remotes, then orphan video media.
  const tiles = useMemo<TileData[]>(() => {
    // First video mid per participant → tile stream (a participant may have
    // zero video media — they still get an avatar tile so audio-only callers
    // show up).
    const videoByPid = new Map<string, string>()
    const orphans: string[] = [] // video media whose mid isn't grant-mapped yet
    for (const m of Object.values(remoteMedia)) {
      if (m.track.kind !== "video") continue
      const ref = midToTrackRef[m.mid]
      if (ref && !videoByPid.has(ref.participantId)) videoByPid.set(ref.participantId, m.mid)
      else if (!ref) orphans.push(m.mid)
    }

    const list: TileData[] = [
      {
        id: selfId || "__local",
        stream: localStream,
        label: `${selfName || "You"} (you)`,
        micMuted: !micEnabled,
        videoOff: !camEnabled,
        mirror: true,
        speaking: activeSpeakers.includes(selfId),
        mid: null,
        local: true,
      },
    ]
    for (const p of Object.values(participants)) {
      if (p.id === selfId) continue
      const mid = videoByPid.get(p.id) ?? null
      const ref = mid ? midToTrackRef[mid] : undefined
      const videoTrack = ref ? p.tracks.find((t) => t.id === ref.trackId) : undefined
      list.push({
        id: p.id,
        stream: mid ? remoteMedia[mid].stream : null,
        label: p.name || p.id,
        micMuted: p.tracks.some((t) => t.kind === TrackKind.AUDIO && t.muted),
        videoOff: videoTrack?.muted ?? true,
        mirror: false,
        speaking: activeSpeakers.includes(p.id),
        mid,
        local: false,
      })
    }
    for (const mid of orphans) {
      list.push({
        id: `mid:${mid}`,
        stream: remoteMedia[mid].stream,
        label: "…",
        micMuted: false,
        videoOff: false,
        mirror: false,
        speaking: false,
        mid,
        local: false,
      })
    }
    return list
  }, [
    remoteMedia,
    midToTrackRef,
    participants,
    selfId,
    selfName,
    localStream,
    micEnabled,
    camEnabled,
    activeSpeakers,
  ])

  // Unpin when the pinned participant leaves (or the orphan media drops).
  useEffect(() => {
    if (pinnedId && !tiles.some((t) => t.id === pinnedId)) setPinned(null)
  }, [tiles, pinnedId, setPinned])

  // Keep departed tiles mounted ~200 ms for a fade/zoom-out animation.
  const [exiting, setExiting] = useState<TileData[]>([])
  const prevTiles = useRef<TileData[]>([])
  useEffect(() => {
    const prev = prevTiles.current
    prevTiles.current = tiles
    const live = new Set(tiles.map((t) => t.id))
    const gone = prev.filter((t) => !live.has(t.id))
    if (gone.length === 0) return
    setExiting((e) => [...e, ...gone.filter((g) => !e.some((x) => x.id === g.id))])
    const leaving = new Set(gone.map((g) => g.id))
    const timer = window.setTimeout(
      () => setExiting((e) => e.filter((x) => !leaving.has(x.id))),
      220,
    )
    return () => window.clearTimeout(timer)
  }, [tiles])

  const togglePin = (id: string) => {
    playSound("pin")
    setPinned(pinnedId === id ? null : id)
  }
  const pin = (id: string) => {
    playSound("pin")
    setPinned(id)
  }

  const renderTile = (
    t: TileData,
    opts: { className?: string; style?: CSSProperties; ghost?: boolean } = {},
  ) => (
    <VideoTile
      key={`${opts.ghost ? "x-" : ""}${t.id}`}
      stream={t.stream}
      label={t.label}
      micMuted={t.micMuted}
      videoOff={t.videoOff}
      mirror={t.mirror}
      speaking={t.speaking}
      pinned={!opts.ghost && pinnedId === t.id}
      stats={
        !opts.ghost && showStats
          ? (() => {
              const s = t.local ? localStats : t.mid ? statsByMid[t.mid] : undefined
              return s ? fmtStats(s) : undefined
            })()
          : undefined
      }
      onTogglePin={opts.ghost ? undefined : () => togglePin(t.id)}
      onPin={opts.ghost ? undefined : () => pin(t.id)}
      className={cn(
        opts.ghost
          ? "pointer-events-none animate-out fade-out zoom-out-95 duration-200 fill-mode-forwards"
          : "animate-in fade-in zoom-in-95 duration-200",
        opts.className,
      )}
      style={opts.style}
    />
  )

  const pinnedTile = pinnedId ? tiles.find((t) => t.id === pinnedId) : undefined
  const filmstrip = pinnedTile ? tiles.filter((t) => t.id !== pinnedTile.id) : []

  // Grid layout: pick the column count that maximizes 16:9 tile area so the
  // grid fills the viewport at any count. Exiting ghosts keep their slot so
  // the grid doesn't jump mid-animation.
  const gridCount = tiles.length + exiting.length
  const tileW =
    !pinnedTile && gridCount > 0 && gridSize.width > 0 && gridSize.height > 0
      ? fitTileWidth(gridCount, gridSize.width, gridSize.height)
      : 0
  const tileStyle: CSSProperties = tileW ? { width: tileW } : { width: "100%" }

  // Pinned layout: stage tile is the largest 16:9 box inside the stage area.
  const stageW =
    stageSize.width > 0
      ? Math.floor(Math.min(stageSize.width, (stageSize.height * 16) / 9))
      : 0
  const stageStyle: CSSProperties | undefined = stageW ? { width: stageW } : undefined

  return (
    <div className="flex h-svh flex-col">
      <header className="flex items-center gap-3 border-b px-4 py-2.5">
        <span className="text-sm font-semibold tracking-tight">wroom</span>
        <span className="truncate text-sm text-muted-foreground">/r/{roomName}</span>
        <div className="ml-auto flex items-center gap-2">
          {connBadge(pubConnState)}
          {connBadge(subConnState)}
          <Badge variant="secondary">{Object.keys(participants).length} in call</Badge>
        </div>
      </header>

      <div className="relative flex min-h-0 flex-1 overflow-hidden">
        {/* pb-20 reserves room for the floating control bar. */}
        <main className="relative min-w-0 flex-1 overflow-hidden p-3 pb-20">
          {pinnedTile ? (
            <div className="flex size-full flex-col gap-3 md:flex-row">
              <div
                ref={stageRef}
                className="flex min-h-0 min-w-0 flex-1 items-center justify-center"
              >
                {renderTile(pinnedTile, {
                  className: "w-full",
                  style: stageStyle,
                })}
              </div>
              {filmstrip.length > 0 && (
                <div className="flex shrink-0 gap-3 overflow-x-auto pb-1 md:w-52 md:flex-col md:overflow-x-visible md:overflow-y-auto md:pb-0 lg:w-64">
                  {filmstrip.map((t) =>
                    renderTile(t, { className: "w-40 shrink-0 md:w-full" }),
                  )}
                </div>
              )}
            </div>
          ) : (
            <div
              ref={gridRef}
              className={cn(
                "flex size-full flex-wrap items-center justify-center gap-3 overflow-y-auto",
                // content-center clips scrolled overflow; only safe once the
                // fit is computed to not overflow.
                tileW ? "content-center" : "content-start",
              )}
            >
              {tiles.map((t) =>
                renderTile(t, {
                  className: "transition-[width] duration-200",
                  style: tileStyle,
                }),
              )}
              {exiting.map((t) => renderTile(t, { ghost: true, style: tileStyle }))}
            </div>
          )}
          {tiles.length === 1 && exiting.length === 0 && (
            <p className="pointer-events-none absolute inset-x-0 bottom-24 animate-in fade-in text-center text-sm text-muted-foreground duration-300">
              No one else is here yet — share the link to this room.
            </p>
          )}
        </main>

        <ParticipantList />

        <div
          className={cn(
            "absolute inset-x-0 bottom-4 z-30 flex justify-center transition-all duration-300",
            controlsVisible
              ? "translate-y-0 opacity-100"
              : "pointer-events-none translate-y-3 opacity-0",
          )}
        >
          <ControlBar />
        </div>
      </div>

      {remoteAudio.map((m) => (
        <RemoteAudio key={m.mid} stream={m.stream} />
      ))}
    </div>
  )
}
