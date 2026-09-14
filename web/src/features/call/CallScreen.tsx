import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type ReactNode,
} from "react"
import { toast } from "sonner"
import { TooltipProvider } from "@/components/ui/tooltip"
import {
  TrackKind,
  TrackSource,
  type Participant,
} from "@/gen/wroom/signaling/v1/signaling_pb"
import { useAutoHide } from "@/hooks/useAutoHide"
import { useElementSize } from "@/hooks/useElementSize"
import { useMediaQuery } from "@/hooks/useMediaQuery"
import { useParticipantSounds } from "@/hooks/useParticipantSounds"
import { usePictureInPicture } from "@/hooks/usePictureInPicture"
import { useShortcuts } from "@/hooks/useShortcuts"
import { useWakeLock } from "@/hooks/useWakeLock"
import { DEFAULT_ASPECT, packTiles } from "@/lib/layout"
import { applySinkTo, LOCAL_TRACK_IDS } from "@/lib/media"
import { session } from "@/lib/session"
import { playSound } from "@/lib/sounds"
import { cn } from "@/lib/utils"
import { useCallStore, type UplinkQuality } from "@/store/call"
import { useStatsStore, type AudioTrackStats } from "@/store/stats"
import {
  formatTrackStats as fmtStats,
  statsQualityDetail as qualityDetail,
} from "@/shared/lib/quality"
import { ChatPanel, ParticipantList } from "@/features/panels"
import { ControlBar } from "./ControlBar"
import { ReconnectBanner } from "./ReconnectBanner"
import { RoomHeader } from "./RoomHeader"
import { CopyInviteButton } from "@/shared/components/CopyInvite"
import { ShortcutsDialog } from "./ShortcutsDialog"
import { VideoTile } from "./VideoTile"

const GAP = 12 // px — matches gap-3
const PIP_MARGIN = 12 // px — PiP distance to screen edges
/** PiP bottom-corner offset: clears the control bar's reserved strip. */
const PIP_BOTTOM = 92 // pb-20 (80) + margin
const SAFE_BOTTOM = "env(safe-area-inset-bottom, 0px)"
/** Our own screen-share tile id (not a participant id). */
const SELF_SCREEN_ID = "__screen"

interface TileData {
  /** Participant id, `mid:<mid>` for orphan/screen video, `__screen` for ours. */
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
  /** Screen-share tile → object-contain, never cropped. */
  screen?: boolean
  /** Connection quality shown on the tile. */
  quality?: UplinkQuality
}

/** Hidden <audio> sink for a remote audio track. */
function RemoteAudio({ stream }: { stream: MediaStream }) {
  const ref = useRef<HTMLAudioElement>(null)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    if (el.srcObject !== stream) el.srcObject = stream
    el.muted = useCallStore.getState().remoteAudioMuted
    applySinkTo(el)
    return () => {
      if (el) el.srcObject = null
    }
  }, [stream])
  return <audio ref={ref} autoPlay data-remote-audio="" />
}

type PipCorner = "tl" | "tr" | "bl" | "br"

const PIP_CORNER_STYLE: Record<PipCorner, CSSProperties> = {
  tl: { left: PIP_MARGIN, top: PIP_MARGIN },
  tr: { right: PIP_MARGIN, top: PIP_MARGIN },
  bl: { left: PIP_MARGIN, bottom: `calc(${PIP_BOTTOM}px + ${SAFE_BOTTOM})` },
  br: { right: PIP_MARGIN, bottom: `calc(${PIP_BOTTOM}px + ${SAFE_BOTTOM})` },
}

/**
 * Floating self-view for the mobile 1:1 layout. Draggable with pointer
 * capture; snaps to the nearest corner on release. A pointer-up without
 * movement is a tap → `onTap` (swap cameras). Positions are relative to the
 * nearest positioned ancestor (the <main> element).
 */
function PipView({ onTap, children }: { onTap: () => void; children: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null)
  const [corner, setCorner] = useState<PipCorner>("br")
  const [drag, setDrag] = useState<{ x: number; y: number } | null>(null)
  const gesture = useRef<{
    id: number
    dx: number
    dy: number
    sx: number
    sy: number
    moved: boolean
  } | null>(null)

  const parentRect = () =>
    (ref.current?.offsetParent as HTMLElement | null)?.getBoundingClientRect()

  const onPointerDown = (e: React.PointerEvent<HTMLDivElement>) => {
    const el = ref.current
    if (!el || (e.pointerType === "mouse" && e.button !== 0)) return
    const r = el.getBoundingClientRect()
    gesture.current = {
      id: e.pointerId,
      dx: e.clientX - r.left,
      dy: e.clientY - r.top,
      sx: e.clientX,
      sy: e.clientY,
      moved: false,
    }
    el.setPointerCapture(e.pointerId)
  }

  const onPointerMove = (e: React.PointerEvent<HTMLDivElement>) => {
    const g = gesture.current
    const el = ref.current
    const pr = parentRect()
    if (!g || !el || !pr || g.id !== e.pointerId) return
    if (!g.moved && Math.abs(e.clientX - g.sx) + Math.abs(e.clientY - g.sy) > 6) {
      g.moved = true
    }
    if (!g.moved) return
    setDrag({
      x: Math.min(
        Math.max(e.clientX - pr.left - g.dx, PIP_MARGIN),
        Math.max(PIP_MARGIN, pr.width - el.offsetWidth - PIP_MARGIN),
      ),
      y: Math.min(
        Math.max(e.clientY - pr.top - g.dy, PIP_MARGIN),
        Math.max(PIP_MARGIN, pr.height - el.offsetHeight - PIP_BOTTOM),
      ),
    })
  }

  const endGesture = (e: React.PointerEvent<HTMLDivElement>, tap: boolean) => {
    const g = gesture.current
    if (!g || g.id !== e.pointerId) return
    gesture.current = null
    const el = ref.current
    const pr = parentRect()
    if (g.moved && el && pr) {
      // Snap to whichever corner the PiP center is closest to.
      const r = el.getBoundingClientRect()
      const cx = r.left - pr.left + r.width / 2
      const cy = r.top - pr.top + r.height / 2
      setCorner(
        `${cy > pr.height / 2 ? "b" : "t"}${cx > pr.width / 2 ? "r" : "l"}` as PipCorner,
      )
    } else if (tap && !g.moved) {
      onTap()
    }
    setDrag(null)
  }

  return (
    <div
      ref={ref}
      role="button"
      tabIndex={0}
      aria-label="Swap cameras"
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault()
          onTap()
        }
      }}
      className={cn(
        "absolute z-20 w-[30vw] touch-none select-none",
        drag
          ? "cursor-grabbing"
          : "cursor-grab transition-[left,top] duration-200 ease-out motion-reduce:transition-none",
      )}
      style={drag ? { left: drag.x, top: drag.y } : PIP_CORNER_STYLE[corner]}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={(e) => endGesture(e, true)}
      onPointerCancel={(e) => endGesture(e, false)}
    >
      {children}
    </div>
  )
}

export function CallScreen() {
  const selfName = useCallStore((s) => s.selfName)
  const selfId = useCallStore((s) => s.selfId)
  const participants = useCallStore((s) => s.participants)
  const remoteMedia = useCallStore((s) => s.remoteMedia)
  const midToTrackRef = useCallStore((s) => s.midToTrackRef)
  const localStream = useCallStore((s) => s.localStream)
  const micEnabled = useCallStore((s) => s.micEnabled)
  const camEnabled = useCallStore((s) => s.camEnabled)
  const activeSpeakers = useCallStore((s) => s.activeSpeakers)
  const pinnedId = useCallStore((s) => s.pinnedId)
  const setPinned = useCallStore((s) => s.setPinned)
  const showStats = useCallStore((s) => s.showStats)
  const screenStream = useCallStore((s) => s.screenStream)
  const screenShareMids = useCallStore((s) => s.screenShareMids)
  const remoteQuality = useCallStore((s) => s.remoteQuality)
  const uplinkQuality = useCallStore((s) => s.uplinkQuality)
  const talkingWhileMuted = useCallStore((s) => s.talkingWhileMuted)
  const speakerView = useCallStore((s) => s.speakerView)
  const chatOpen = useCallStore((s) => s.chatOpen)
  const participantsOpen = useCallStore((s) => s.participantsOpen)
  const set = useCallStore((s) => s.set)
  const statsByMid = useStatsStore((s) => s.byMid)
  const audioByMid = useStatsStore((s) => s.audioByMid)
  const localStats = useStatsStore((s) => s.local)

  const mobile = useMediaQuery("(width < 768px)")
  const coarsePointer = useMediaQuery("(pointer: coarse)")
  // Touch devices keep the control bar on screen — there's no hover to
  // rediscover it, and pointer taps shouldn't be required to unhide it.
  const controlsVisible = useAutoHide(3000) || coarsePointer
  useParticipantSounds()
  useShortcuts()
  useWakeLock()
  usePictureInPicture({ auto: true })
  const [gridRef, gridSize] = useElementSize<HTMLDivElement>()
  const [stageRef, stageSize] = useElementSize<HTMLDivElement>()

  // Real per-tile video aspects (w/h), reported by each VideoTile once its
  // <video> knows its dimensions. Missing entries default to 16:9.
  const [aspects, setAspects] = useState<Record<string, number>>({})
  const reportAspect = useCallback((id: string, ratio: number) => {
    if (!(ratio > 0) || !Number.isFinite(ratio)) return
    setAspects((prev) =>
      Math.abs((prev[id] ?? DEFAULT_ASPECT) - ratio) < 0.005
        ? prev
        : { ...prev, [id]: ratio },
    )
  }, [])

  // Best-effort LeaveRequest on tab close / reload.
  useEffect(() => {
    const onUnload = () => session.leave()
    window.addEventListener("beforeunload", onUnload)
    return () => window.removeEventListener("beforeunload", onUnload)
  }, [])

  // "You're muted" toast with an Unmute action — once per mute episode (the
  // flag flips false→true once; a fixed toast id dedupes repeats anyway).
  useEffect(() => {
    if (!talkingWhileMuted) return
    toast("You're muted", {
      id: "talking-while-muted",
      duration: 4000,
      action: {
        label: "Unmute",
        onClick: () => session.setTrackEnabled(LOCAL_TRACK_IDS.mic, true),
      },
    })
  }, [talkingWhileMuted])

  // Sustained poor uplink → warning that clears itself; re-fires only on a
  // fresh poor episode (the effect keys on the quality value).
  useEffect(() => {
    if (uplinkQuality !== "poor") {
      toast.dismiss("uplink-poor")
      return
    }
    const t = window.setTimeout(() => {
      toast.warning("Your connection is weak — video quality reduced", {
        id: "uplink-poor",
        duration: 5000,
      })
    }, 5000)
    return () => window.clearTimeout(t)
  }, [uplinkQuality])
  // Don't leave the warning up after leaving the call.
  useEffect(
    () => () => {
      toast.dismiss("uplink-poor")
    },
    [],
  )

  // Join/leave toasts with names + a polite live-region announcement.
  // The join snapshot is the baseline — no toasts for people already here.
  const [announcement, setAnnouncement] = useState("")
  const prevParticipants = useRef<Record<string, Participant> | null>(null)
  useEffect(() => {
    const prev = prevParticipants.current
    prevParticipants.current = participants
    if (prev === null) return
    for (const [id, p] of Object.entries(participants)) {
      if (!(id in prev) && id !== selfId) {
        const name = p.name || "Someone"
        toast(`${name} joined`)
        setAnnouncement(`${name} joined the call`)
      }
    }
    for (const [id, p] of Object.entries(prev)) {
      if (!(id in participants) && id !== selfId) {
        const name = p.name || "Someone"
        toast(`${name} left`)
        setAnnouncement(`${name} left the call`)
      }
    }
  }, [participants, selfId])

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

  // Deafen: store flag → every remote <audio> sink. Applied here (the
  // always-mounted screen), not inside a panel that can unmount and leave
  // elements stuck muted.
  const remoteAudioMuted = useCallStore((s) => s.remoteAudioMuted)
  useEffect(() => {
    for (const el of document.querySelectorAll<HTMLAudioElement>(
      "audio[data-remote-audio]",
    )) {
      el.muted = remoteAudioMuted
    }
  }, [remoteAudioMuted, remoteMedia])

  // Flat tile list: local first (+ our own screen share), then remotes, then
  // remote screen shares, then orphan video media.
  const tiles = useMemo<TileData[]>(() => {
    const screenMidSet = new Set(screenShareMids)
    const isScreenMid = (mid: string): boolean => {
      if (screenMidSet.has(mid)) return true
      const ref = midToTrackRef[mid]
      const track =
        ref &&
        participants[ref.participantId]?.tracks.find((t) => t.id === ref.trackId)
      return track?.source === TrackSource.SCREENSHARE
    }

    // First *camera* video mid per participant → tile stream (screen mids are
    // handled as their own tiles; a participant may have zero video media —
    // they still get an avatar tile so audio-only callers show up).
    const videoByPid = new Map<string, string>()
    const screenMids: string[] = []
    const orphans: string[] = [] // video media whose mid isn't grant-mapped yet
    for (const m of Object.values(remoteMedia)) {
      if (m.track.kind !== "video") continue
      if (isScreenMid(m.mid)) {
        screenMids.push(m.mid)
        continue
      }
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
    if (screenStream) {
      list.push({
        id: SELF_SCREEN_ID,
        stream: screenStream,
        label: "Your screen",
        micMuted: false,
        videoOff: false,
        mirror: false,
        speaking: false,
        mid: null,
        local: true,
        screen: true,
      })
    }
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
        quality: remoteQuality[p.id],
      })
    }
    for (const mid of screenMids) {
      const ref = midToTrackRef[mid]
      const name = ref ? participants[ref.participantId]?.name : undefined
      list.push({
        id: `mid:${mid}`,
        stream: remoteMedia[mid].stream,
        label: name ? `${name}'s screen` : "Screen share",
        micMuted: false,
        videoOff: false,
        mirror: false,
        speaking: false,
        mid,
        local: false,
        screen: true,
        quality: ref ? remoteQuality[ref.participantId] : undefined,
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
    screenStream,
    screenShareMids,
    remoteQuality,
  ])

  // Unpin when the pinned participant leaves (or the orphan/screen media drops).
  useEffect(() => {
    if (pinnedId && !tiles.some((t) => t.id === pinnedId)) setPinned(null)
  }, [tiles, pinnedId, setPinned])

  // Only one side panel at a time — opening one closes the other. (The
  // control-bar toggles already do this; this is the safety net for any
  // other writer, e.g. ChatPanel's own open path.)
  useEffect(() => {
    if (chatOpen && participantsOpen) set({ participantsOpen: false })
  }, [chatOpen, participantsOpen, set])

  // Keep departed tiles mounted ~200 ms for a fade/zoom-out animation.
  // Removal timers live in a ref: a `tiles` change within the window must not
  // cancel a pending removal (the cleanup would clear it and, with prevTiles
  // already updated, the departure would never be re-detected — the ghost
  // would keep its grid slot forever).
  const [exiting, setExiting] = useState<TileData[]>([])
  const prevTiles = useRef<TileData[]>([])
  const exitTimers = useRef<number[]>([])
  // Tile ids that have already rendered once — used to gate the enter
  // animation (see newTileIds below). A useState-held Set rather than a ref:
  // deliberately non-reactive bookkeeping, and it keeps the react/refs
  // render-access rule quiet. Entries are dropped on leave so a rejoiner
  // still animates in.
  const [seenTiles] = useState(() => new Set<string>())
  useEffect(
    () => () => {
      for (const t of exitTimers.current) window.clearTimeout(t)
      exitTimers.current = []
    },
    [],
  )
  useEffect(() => {
    const prev = prevTiles.current
    prevTiles.current = tiles
    const live = new Set(tiles.map((t) => t.id))
    const gone = prev.filter((t) => !live.has(t.id))
    if (gone.length === 0) return
    setExiting((e) => [...e, ...gone.filter((g) => !e.some((x) => x.id === g.id))])
    const leaving = new Set(gone.map((g) => g.id))
    exitTimers.current.push(
      window.setTimeout(
        () => setExiting((e) => e.filter((x) => !leaving.has(x.id))),
        220,
      ),
    )
    for (const id of leaving) seenTiles.delete(id)
  }, [tiles, seenTiles])

  // Tile ids allowed to play the enter animation: those appearing for the
  // FIRST time. Pinning remounts a tile under a different container — a real
  // unmount+remount — and without this gate every remount replays
  // animate-in, which reads as a blink on each pin click.
  const newTileIds = useMemo(() => {
    const fresh = new Set<string>()
    for (const t of tiles) {
      if (!seenTiles.has(t.id)) fresh.add(t.id)
      seenTiles.add(t.id)
    }
    return fresh
  }, [tiles, seenTiles])

  // Drop aspect entries for tiles that no longer exist — bounded map.
  // (Render-phase adjustment: setState during render is React's sanctioned
  // pattern for derived state — avoids an extra effect pass.)
  const liveTileIds = useMemo(
    () => new Set([...tiles, ...exiting].map((t) => t.id)),
    [tiles, exiting],
  )
  const [aspectTileIds, setAspectTileIds] = useState(liveTileIds)
  if (aspectTileIds !== liveTileIds) {
    setAspectTileIds(liveTileIds)
    setAspects((prev) => {
      const keys = Object.keys(prev)
      if (keys.every((k) => liveTileIds.has(k))) return prev
      const next: Record<string, number> = {}
      for (const k of keys) if (liveTileIds.has(k)) next[k] = prev[k]
      return next
    })
  }

  const togglePin = (id: string) => {
    playSound("pin")
    setPinned(pinnedId === id ? null : id)
  }
  const pin = (id: string) => {
    playSound("pin")
    setPinned(id)
  }
  const stopShare = () => void session.stopScreenShare()

  // ── auto-pinning ────────────────────────────────────────────────────────
  // A remote screen share takes the stage when the user hasn't pinned
  // anything. Unpinning it by hand suppresses re-pinning until every share
  // ends; speaker view (below) yields to shares entirely.
  const firstShareId = useMemo(() => {
    const mid = screenShareMids.find((m) => remoteMedia[m])
    return mid ? `mid:${mid}` : null
  }, [screenShareMids, remoteMedia])
  const screenAutoPin = useRef<string | null>(null)
  const screenPinSuppressed = useRef(false)
  useEffect(() => {
    const auto = screenAutoPin.current
    if (auto != null && pinnedId !== auto) {
      // The pin moved off our auto-pin. If the share tile is still around
      // this was a manual unpin — respect it for the rest of the share.
      if (pinnedId == null && liveTileIds.has(auto))
        screenPinSuppressed.current = true
      screenAutoPin.current = null
    }
    if (!firstShareId) {
      screenPinSuppressed.current = false
      if (auto != null && pinnedId === auto) setPinned(null)
      screenAutoPin.current = null
      return
    }
    if (screenPinSuppressed.current || pinnedId != null) return
    screenAutoPin.current = firstShareId
    setPinned(firstShareId)
  }, [firstShareId, pinnedId, liveTileIds, setPinned])

  // Speaker view: the stage follows the loudest remote speaker. A manual pin
  // (or unpin of the current top speaker) wins until the top speaker changes.
  // Switching an existing auto-pin is rate-limited so rapid turn-taking
  // doesn't bounce the stage.
  const speakerAutoPin = useRef<string | null>(null)
  const lastTopSpeaker = useRef<string | null>(null)
  const lastSpeakerPinAt = useRef(0)
  useEffect(() => {
    if (!speakerView) {
      const cur = speakerAutoPin.current
      speakerAutoPin.current = null
      lastTopSpeaker.current = null
      if (cur != null && pinnedId === cur) setPinned(null)
      return
    }
    if (firstShareId) return
    const top =
      activeSpeakers.find((id) => id !== selfId && liveTileIds.has(id)) ?? null
    const topChanged = top !== lastTopSpeaker.current
    lastTopSpeaker.current = top
    if (!top) return
    const cur = speakerAutoPin.current
    if (pinnedId != null && pinnedId !== cur) {
      speakerAutoPin.current = null
      return
    }
    if (pinnedId === cur && cur === top) return
    if (pinnedId == null && cur == null && !topChanged) return
    if (cur != null && performance.now() - lastSpeakerPinAt.current < 1500) return
    lastSpeakerPinAt.current = performance.now()
    speakerAutoPin.current = top
    setPinned(top)
  }, [speakerView, firstShareId, activeSpeakers, selfId, pinnedId, liveTileIds, setPinned])

  // pid → audio jitter-buffer stats (for the per-tile stats badge).
  const audioStatsByPid = useMemo(() => {
    const m = new Map<string, AudioTrackStats>()
    for (const [mid, ref] of Object.entries(midToTrackRef)) {
      if (remoteMedia[mid]?.track.kind !== "audio") continue
      const a = audioByMid[mid]
      if (a && !m.has(ref.participantId)) m.set(ref.participantId, a)
    }
    return m
  }, [midToTrackRef, remoteMedia, audioByMid])

  const pinnedTile = pinnedId ? tiles.find((t) => t.id === pinnedId) : undefined
  const filmstrip = pinnedTile ? tiles.filter((t) => t.id !== pinnedTile.id) : []

  // Mobile 1:1: one remote tile → full-bleed remote + draggable self PiP.
  // Sharing my own screen breaks 1:1 — "Your screen" must stay visible, so
  // fall back to the grid (remote shares already force remoteTiles ≥ 2).
  const remoteTiles = tiles.filter((t) => !t.local)
  const mobileOneToOne =
    mobile && !pinnedTile && remoteTiles.length === 1 && !screenStream
  const [pipIsSelf, setPipIsSelf] = useState(true)
  // Render-phase reset: leaving 1:1 mode restores the default arrangement
  // (remote big, self in the PiP).
  if (!mobileOneToOne && !pipIsSelf) setPipIsSelf(true)
  const localTile = tiles.find((t) => t.local && !t.screen)
  const bigTile = mobileOneToOne ? (pipIsSelf ? remoteTiles[0] : localTile) : undefined
  const pipTile = mobileOneToOne ? (pipIsSelf ? localTile : remoteTiles[0]) : undefined

  // Grid layout: column count maximizing total tile area with each tile's own
  // aspect (per-row uniform cell height — see lib/layout.ts). Exiting ghosts
  // keep their slot so the grid doesn't jump mid-animation.
  const packAspects = useMemo(
    () => [...tiles, ...exiting].map((t) => aspects[t.id] ?? DEFAULT_ASPECT),
    [tiles, exiting, aspects],
  )
  const packed = useMemo(
    () =>
      !mobileOneToOne &&
      !pinnedTile &&
      packAspects.length > 0 &&
      gridSize.width > 0 &&
      gridSize.height > 0
        ? packTiles(packAspects, gridSize.width, gridSize.height, GAP)
        : null,
    [packAspects, gridSize.width, gridSize.height, mobileOneToOne, pinnedTile],
  )
  const boxStyle = (i: number): CSSProperties =>
    packed?.tiles[i]
      ? { width: packed.tiles[i].w, height: packed.tiles[i].h }
      : { width: "100%" }

  // Pinned stage: largest box of the pinned tile's own aspect (desktop);
  // mobile pinned is full-bleed like the 1:1 layout.
  const stageAspect = pinnedTile ? (aspects[pinnedTile.id] ?? DEFAULT_ASPECT) : DEFAULT_ASPECT
  const stageW =
    stageSize.width > 0
      ? Math.floor(Math.min(stageSize.width, stageSize.height * stageAspect))
      : 0
  const stageStyle: CSSProperties | undefined = mobile
    ? { width: "100%", height: "100%" }
    : stageW
      ? { width: stageW }
      : undefined

  const renderTile = (
    t: TileData,
    opts: {
      className?: string
      style?: CSSProperties
      ghost?: boolean
      /** pin = click toggles pin (default); none = non-interactive. */
      action?: "pin" | "none"
      /** Lift the name pill above the floating control bar. */
      labelLifted?: boolean
    } = {},
  ) => {
    const action = opts.action ?? (opts.ghost ? "none" : "pin")
    const firstRender = !opts.ghost && newTileIds.has(t.id)
    return (
      <VideoTile
        key={`${opts.ghost ? "x-" : ""}${t.id}`}
        stream={t.stream}
        label={t.label}
        micMuted={t.micMuted}
        videoOff={t.videoOff}
        mirror={t.mirror}
        speaking={t.speaking}
        pinned={action === "pin" && pinnedId === t.id}
        quality={t.quality}
        qualityDetail={
          t.local ? qualityDetail(localStats) : qualityDetail(t.mid ? statsByMid[t.mid] : undefined)
        }
        screenShare={t.screen}
        onStopShare={t.id === SELF_SCREEN_ID ? stopShare : undefined}
        labelLifted={opts.labelLifted}
        tileId={opts.ghost ? undefined : t.id}
        self={t.local}
        aspect={aspects[t.id] ?? DEFAULT_ASPECT}
        onAspect={opts.ghost ? undefined : (r) => reportAspect(t.id, r)}
        stats={
          !opts.ghost && showStats
            ? (() => {
                const s = t.local ? localStats : t.mid ? statsByMid[t.mid] : undefined
                return s
                  ? fmtStats(s, t.local ? undefined : audioStatsByPid.get(t.id))
                  : undefined
              })()
            : undefined
        }
        onTogglePin={action === "pin" ? () => togglePin(t.id) : undefined}
        onPin={action === "pin" ? () => pin(t.id) : undefined}
        className={cn(
          opts.ghost
            ? "pointer-events-none animate-out fade-out zoom-out-95 duration-200 fill-mode-forwards motion-reduce:animate-none"
            : firstRender
              ? "animate-in fade-in zoom-in-95 duration-200 motion-reduce:animate-none"
              : null,
          opts.className,
        )}
        style={opts.style}
      />
    )
  }

  return (
    <TooltipProvider delayDuration={400}>
      <div className="flex h-svh animate-in flex-col fade-in duration-300 motion-reduce:animate-none">
        <ReconnectBanner />
        <RoomHeader />

        <div
          className={cn(
            "relative flex min-h-0 flex-1 overflow-hidden",
            !mobileOneToOne && "gap-3 p-3",
          )}
        >
          {/* paddingBottom reserves room for the floating control bar. */}
          <main
            className={cn(
              "relative min-w-0 flex-1 overflow-hidden",
              !mobileOneToOne &&
                "rounded-2xl border bg-background p-4",
            )}
            style={{
              paddingBottom: mobileOneToOne
                ? 0
                : `calc(6rem + ${SAFE_BOTTOM})`,
            }}
          >
            {mobileOneToOne && bigTile && pipTile ? (
              <>
                {renderTile(bigTile, {
                  action: "none",
                  className: "size-full rounded-none border-0",
                  style: { width: "100%", height: "100%" },
                  labelLifted: true,
                })}
                <PipView onTap={() => setPipIsSelf((v) => !v)}>
                  {renderTile(pipTile, {
                    action: "none",
                    className: "w-full shadow-xl shadow-black/50",
                  })}
                </PipView>
              </>
            ) : pinnedTile ? (
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
                      renderTile(t, { className: "h-28 w-auto shrink-0 md:h-auto md:w-full" }),
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
                  packed && !packed.overflow ? "content-center" : "content-start",
                )}
              >
                {tiles.map((t, i) =>
                  renderTile(t, {
                    className: "transition-[width,height] duration-200 motion-reduce:transition-none",
                    style: boxStyle(i),
                  }),
                )}
                {exiting.map((t, j) =>
                  renderTile(t, { ghost: true, style: boxStyle(tiles.length + j) }),
                )}
              </div>
            )}
            {tiles.length === 1 && exiting.length === 0 && (
              <div className="pointer-events-none absolute inset-0 flex items-center justify-center p-6">
                <div className="pointer-events-auto flex max-w-[16rem] animate-in fade-in zoom-in-95 flex-col items-center gap-2 rounded-2xl border bg-card/90 px-5 py-4 text-center shadow-2xl backdrop-blur-md duration-300 motion-reduce:animate-none">
                  <p className="text-sm font-semibold">You&apos;re the first here</p>
                  <p className="text-xs leading-relaxed text-muted-foreground">
                    Share the link — guests land straight in the call.
                  </p>
                  <CopyInviteButton className="mt-1" />
                </div>
              </div>
            )}
          </main>

          <ParticipantList />
          <ChatPanel />

          <div
            className={cn(
              "absolute inset-x-0 z-30 flex justify-center px-3 transition-all duration-200 ease-out motion-reduce:transition-none",
              controlsVisible
                ? "translate-y-0 opacity-100"
                : "pointer-events-none translate-y-2 opacity-0",
            )}
            style={{ bottom: `calc(1.25rem + ${SAFE_BOTTOM})` }}
          >
            <ControlBar />
          </div>
        </div>

        {remoteAudio.map((m) => (
          <RemoteAudio key={m.mid} stream={m.stream} />
        ))}

        <ShortcutsDialog />

        {/* Polite live region: join/leave announcements for screen readers. */}
        <div aria-live="polite" className="sr-only">
          {announcement}
        </div>
      </div>
    </TooltipProvider>
  )
}
