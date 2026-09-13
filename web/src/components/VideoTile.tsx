import { useEffect, useRef, type CSSProperties } from "react"
import { MicOff, Pin, PinOff, VideoOff } from "lucide-react"
import { DEFAULT_ASPECT } from "@/lib/layout"
import { cn } from "@/lib/utils"

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
  aspect = DEFAULT_ASPECT,
  onAspect,
  onTogglePin,
  onPin,
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

  const initials = label
    .split(/\s+/)
    .map((w) => w[0])
    .filter(Boolean)
    .slice(0, 2)
    .join("")
    .toUpperCase()

  return (
    <div
      role={onTogglePin ? "button" : undefined}
      tabIndex={onTogglePin ? 0 : undefined}
      title={onTogglePin ? (pinned ? `Unpin ${label}` : `Pin ${label}`) : undefined}
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
        "group relative overflow-hidden rounded-xl border bg-card ring-2 ring-transparent transition-shadow duration-200",
        onTogglePin && "cursor-pointer",
        speaking ? "ring-emerald-500/80" : "hover:ring-border",
        className,
      )}
    >
      <video
        ref={videoRef}
        autoPlay
        playsInline
        muted // remote audio plays through dedicated <audio> elements
        className={cn(
          "size-full object-cover",
          mirror && "-scale-x-100",
          !hasVideo && "hidden",
        )}
      />
      {!hasVideo && (
        <div className="flex size-full items-center justify-center bg-muted/40">
          <div className="flex size-16 items-center justify-center rounded-full bg-secondary text-lg font-semibold text-secondary-foreground">
            {initials || <VideoOff className="size-6" />}
          </div>
        </div>
      )}

      {stats && (
        <span className="absolute left-2 top-2 rounded-md bg-black/60 px-1.5 py-1 font-mono text-[10px] leading-none text-white/90">
          {stats}
        </span>
      )}

      {onTogglePin && (
        <button
          type="button"
          title={pinned ? "Unpin" : "Pin"}
          onClick={(e) => {
            e.stopPropagation()
            onTogglePin()
          }}
          className={cn(
            "absolute right-2 top-2 flex size-8 items-center justify-center rounded-full bg-black/60 text-white transition-opacity hover:bg-black/80 focus-visible:opacity-100 focus-visible:ring-2 focus-visible:ring-white/60",
            pinned ? "opacity-100" : "opacity-0 group-hover:opacity-100",
          )}
        >
          {pinned ? <PinOff className="size-3.5" /> : <Pin className="size-3.5" />}
        </button>
      )}

      <div className="absolute inset-x-0 bottom-0 flex items-center justify-between gap-2 bg-gradient-to-t from-black/60 to-transparent px-3 py-2">
        <span className="truncate text-xs font-medium text-white">{label}</span>
        {micMuted && (
          <span className="rounded-full bg-black/50 p-1 text-white">
            <MicOff className="size-3" />
          </span>
        )}
      </div>
    </div>
  )
}
