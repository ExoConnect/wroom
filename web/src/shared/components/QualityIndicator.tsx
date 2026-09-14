import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { cn } from "@/lib/utils"
import {
  QUALITY_BARS as BARS,
  QUALITY_COLOR as COLOR,
  QUALITY_LABEL as LABEL,
} from "@/shared/lib/quality"
import type { UplinkQuality } from "@/store/call"

interface QualityIndicatorProps {
  quality: UplinkQuality
  /** Extra context for the tooltip, e.g. "packet loss 6%". */
  detail?: string
  className?: string
}

/**
 * Three signal bars colored by connection quality, with a tooltip on
 * hover/focus ("Poor connection — packet loss 6%"). Keyboard-focusable so
 * the tooltip is reachable without a pointer.
 */
export function QualityIndicator({ quality, detail, className }: QualityIndicatorProps) {
  const text = detail ? `${LABEL[quality]} — ${detail}` : LABEL[quality]
  const lit = BARS[quality]
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          tabIndex={0}
          role="img"
          aria-label={text}
          className={cn(
            "inline-flex items-end gap-[2px] rounded-sm outline-none focus-visible:ring-2 focus-visible:ring-white/60",
            COLOR[quality],
            className,
          )}
        >
          {[4, 7, 10].map((h, i) => (
            <span
              key={h}
              aria-hidden
              className={cn("w-[3px] rounded-[1px] bg-current", i >= lit && "opacity-25")}
              style={{ height: h }}
            />
          ))}
        </span>
      </TooltipTrigger>
      <TooltipContent side="top" sideOffset={4}>
        {text}
      </TooltipContent>
    </Tooltip>
  )
}
