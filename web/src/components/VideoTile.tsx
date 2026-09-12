import { useEffect, useRef } from "react"
import { MicOff, VideoOff } from "lucide-react"
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
  className?: string
}

export function VideoTile({
  stream,
  label,
  micMuted = false,
  videoOff = false,
  mirror = false,
  speaking = false,
  className,
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

  const initials = label
    .split(/\s+/)
    .map((w) => w[0])
    .filter(Boolean)
    .slice(0, 2)
    .join("")
    .toUpperCase()

  return (
    <div
      className={cn(
        "relative aspect-video overflow-hidden rounded-xl border bg-card ring-2 ring-transparent transition-shadow",
        speaking && "ring-2 ring-emerald-500/70",
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
