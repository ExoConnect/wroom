import { useCallStore } from "@/store/call"
import { cn } from "@/lib/utils"

/** Bar heights (px) — ascending like a conventional level meter. */
const BAR_HEIGHTS = [4, 6, 9, 12, 15] as const
/** micLevel at which each bar lights. */
const BAR_THRESHOLD = [0.04, 0.22, 0.42, 0.62, 0.82] as const
/** Lit colors: green body, amber warning, red clipping. */
const BAR_LIT = [
  "bg-emerald-500",
  "bg-emerald-500",
  "bg-emerald-500",
  "bg-amber-500",
  "bg-red-500",
] as const

/**
 * Five-bar live mic level driven by store `micLevel` (written ~20 Hz by
 * startMicMeter in lib/media). Compact enough to sit on the join screen or
 * beside the control-bar mic button.
 */
export function MicMeter({ className }: { className?: string }) {
  const level = useCallStore((s) => s.micLevel)
  return (
    <div
      className={cn("flex h-4 items-end gap-[3px]", className)}
      role="meter"
      aria-label="Microphone level"
      aria-valuemin={0}
      aria-valuemax={1}
      aria-valuenow={Math.round(level * 100) / 100}
    >
      {BAR_HEIGHTS.map((h, i) => (
        <span
          key={i}
          className={cn(
            "w-[3px] rounded-full transition-colors duration-75",
            level >= BAR_THRESHOLD[i] ? BAR_LIT[i] : "bg-muted-foreground/25",
          )}
          style={{ height: h }}
        />
      ))}
    </div>
  )
}
