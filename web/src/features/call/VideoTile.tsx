import { useEffect, useRef, type CSSProperties } from "react"
import { MicOff, Pin, PinOff, VideoOff, X } from "lucide-react"
import { DEFAULT_ASPECT } from "@/lib/layout"
import { cn } from "@/lib/utils"
import { initialsFor } from "@/shared/lib/avatar"
import { QualityIndicator } from "@/shared/components/QualityIndicator"
import type { UplinkQuality } from "@/store/call"

interface VideoTileProps {
  /** MediaStream to render; null renders the avatar placeholder. */
  stream: MediaStream | null
  label: string
  /** Mic muted indicator. */
  micMuted?: boolean
  /** True when there is no live video to show (camera off / audio only). */
  videoOff?: boolean
  /** Mirror the video (local preview). */
  mirror?: boolean
  /** Active-speaker highlight ring. */
  speaking?: boolean
  /** Currently pinned to the stage. */
  pinned?: boolean
  /** Preformatted stats badge text (top-left overlay). */
  stats?: string
  /** Connection quality shown as signal bars next to the label. */
  quality?: UplinkQuality
  /** Extra tooltip text for the quality indicator. */
  qualityDetail?: string
  /** Screen-share tile: fit the whole frame (never crop a screen). */
  screenShare?: boolean
  /** Our own share: render a "Stop sharing" button. */
  onStopShare?: () => void
  /** Tile identity for DOM lookups (shortcuts, PiP) → `data-tile-id`. */
  tileId?: string
  /** Marks the tile as the local self-view → `data-tile-local`. */
  self?: boolean
  /** Source aspect (w/h) — sets the tile box's aspect-ratio unless the
   *  parent pins both dimensions via `style`. Defaults to 16:9. */
  aspect?: number
  /** Called with the video element's real pixel aspect (videoWidth /
   *  videoHeight) whenever it becomes known or changes. */
  onAspect?: (ratio: number) => void
  /** Single click / pin button → toggle pin. */
  onTogglePin?: () => void
  /** Double click → pin (never unpins). */
  onPin?: () => void
  /** Lift the name pill above the floating control bar (mobile full-bleed). */
  labelLifted?: boolean
  className?: string
  style?: CSSProperties
}

export function VideoTile({
  stream,
  label,
  micMuted = false,
  videoOff = false,
  mirror = false,
  speaking = false,
  pinned = false,
  stats,
  quality,
  qualityDetail,
  screenShare = false,
  onStopShare,
  tileId,
  self = false,
  aspect = DEFAULT_ASPECT,
  onAspect,
  onTogglePin,
  onPin,
  labelLifted = false,
  className,
  style,
}: VideoTileProps) {
  const videoRef = useRef<HTMLVideoElement>(null)
  const hasVideo = !!stream && !videoOff && stream.getVideoTracks().length > 0

  useEffect(() => {
    const el = videoRef.current
    if (el && el.srcObject !== stream) el.srcObject = stream
    return () => {
      if (el) el.srcObject = null
    }
  }, [stream])

  // Report the stream's real pixel aspect on metadata load and whenever the
  // <video> fires `resize` (encoder/layer switches change dimensions). The
  // callback lives in a ref so the listeners don't re-subscribe per render.
  const onAspectRef = useRef(onAspect)
  useEffect(() => {
    onAspectRef.current = onAspect
  })
  useEffect(() => {
    const el = videoRef.current
    if (!el) return
    const report = () => {
      const { videoWidth: w, videoHeight: h } = el
      if (w > 0 && h > 0) onAspectRef.current?.(w / h)
    }
    report()
    el.addEventListener("loadedmetadata", report)
    el.addEventListener("resize", report)
    return () => {
      el.removeEventListener("loadedmetadata", report)
      el.removeEventListener("resize", report)
    }
  }, [stream])

  const initials = initialsFor(label)

  return (
    <div
      role={onTogglePin ? "button" : undefined}
      tabIndex={onTogglePin ? 0 : undefined}
      aria-pressed={onTogglePin ? pinned : undefined}
      aria-label={
        onTogglePin ? (pinned ? `Unpin ${label}` : `Pin ${label}`) : undefined
      }
      title={onTogglePin ? (pinned ? `Unpin ${label}` : `Pin ${label}`) : undefined}
      data-tile-id={tileId}
      data-tile-local={self || undefined}
      onClick={onTogglePin}
      onDoubleClick={onPin}
      onKeyDown={
        onTogglePin
          ? (e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault()
                onTogglePin()
              }
            }
          : undefined
      }
      style={{ aspectRatio: aspect, ...style }}
      className={cn(
        "group relative overflow-hidden rounded-2xl border bg-black ring-2 ring-transparent transition-shadow duration-200 motion-reduce:transition-none",
        onTogglePin &&
          "cursor-pointer focus-visible:outline-none focus-visible:ring-ring",
        speaking ? "ring-brand" : "hover:ring-border",
        className,
      )}
    >
      <video
        ref={videoRef}
        autoPlay
        playsInline
        muted // remote audio plays through dedicated <audio> elements
        className={cn(
          "size-full",
          screenShare ? "object-contain" : "object-cover",
          mirror && "-scale-x-100",
          !hasVideo && "hidden",
        )}
      />
      {!hasVideo && (
        <div
          className="flex size-full items-center justify-center bg-gradient-to-br from-zinc-700 to-zinc-900"
        >
          <div className="flex size-16 items-center justify-center rounded-full bg-black/45 text-lg font-semibold text-white backdrop-blur-sm">
            {initials || <VideoOff className="size-6" />}
          </div>
        </div>
      )}

      {stats && (
        <span className="absolute left-2 top-2 rounded-md bg-black/60 px-1.5 py-1 font-mono text-[10px] leading-none text-white/90">
          {stats}
        </span>
      )}

      {onStopShare && (
        <button
          type="button"
          aria-label="Stop sharing your screen"
          onClick={(e) => {
            e.stopPropagation()
            onStopShare()
          }}
          className="absolute left-1/2 top-2 flex h-8 -translate-x-1/2 items-center gap-1.5 rounded-full bg-black/70 px-3 text-xs font-medium text-white transition-opacity hover:bg-black/85 focus-visible:opacity-100 focus-visible:ring-2 focus-visible:ring-white/60 focus-visible:outline-none motion-reduce:transition-none sm:opacity-0 sm:group-hover:opacity-100"
        >
          <X className="size-3.5" /> Stop sharing
        </button>
      )}

      {onTogglePin && (
        <button
          type="button"
          title={pinned ? "Unpin" : "Pin"}
          aria-label={pinned ? `Unpin ${label}` : `Pin ${label}`}
          onClick={(e) => {
            e.stopPropagation()
            onTogglePin()
          }}
          className={cn(
            "absolute right-2 top-2 flex size-8 items-center justify-center rounded-full bg-black/60 text-white transition-opacity hover:bg-black/80 focus-visible:opacity-100 focus-visible:ring-2 focus-visible:ring-white/60 focus-visible:outline-none motion-reduce:transition-none",
            pinned ? "opacity-100" : "opacity-0 group-hover:opacity-100",
          )}
        >
          {pinned ? <PinOff className="size-3.5" /> : <Pin className="size-3.5" />}
        </button>
      )}

      <div
        className={cn(
          "absolute left-2 flex max-w-[calc(100%-1rem)] items-center gap-1.5 rounded-full bg-black/60 py-1 pl-2.5 pr-2 text-white backdrop-blur-sm",
          labelLifted ? "bottom-24" : "bottom-2",
        )}
      >
        <span className="truncate text-xs font-medium">{label}</span>
        {quality && (
          <QualityIndicator quality={quality} detail={qualityDetail} />
        )}
        {micMuted && <MicOff className="size-3 shrink-0" aria-label="Muted" />}
      </div>
    </div>
  )
}
