import { useEffect, useState } from "react"
import { Check, Link2, Users } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useTheme } from "@/hooks/useTheme"
import { cn } from "@/lib/utils"
import { QualityIndicator } from "@/shared/components/QualityIndicator"
import { ThemeIcon, ThemeMenuItems } from "@/shared/components/ThemeToggle"
import { useCopyInvite } from "@/shared/components/useCopyInvite"
import { uplinkQualityDetail } from "@/shared/lib/quality"
import { useCallStore } from "@/store/call"
import { useStatsStore } from "@/store/stats"

function connBadge(state: RTCPeerConnectionState | null) {
  if (!state || state === "new" || state === "connecting") return null
  if (state === "connected") return null
  return (
    <Badge variant={state === "failed" ? "destructive" : "secondary"}>
      {state}
    </Badge>
  )
}

/** Elapsed call time: "4:37", "1:02:11" past the hour. */
function formatElapsed(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000))
  const h = Math.floor(total / 3600)
  const m = Math.floor((total % 3600) / 60)
  const s = total % 60
  const mm = h > 0 ? String(m).padStart(2, "0") : String(m)
  return `${h > 0 ? `${h}:` : ""}${mm}:${String(s).padStart(2, "0")}`
}

/** Call top bar: room identity + link copy, uplink quality, theme, help.
 *  Collapses to icon-only controls under `sm`. */
export function RoomHeader() {
  const roomName = useCallStore((s) => s.roomName)
  const joinedAt = useCallStore((s) => s.joinedAt)
  const participantCount = useCallStore((s) => Object.keys(s.participants).length)
  const uplinkQuality = useCallStore((s) => s.uplinkQuality)
  const pubConnState = useCallStore((s) => s.pubConnState)
  const subConnState = useCallStore((s) => s.subConnState)
  const localStats = useStatsStore((s) => s.local)
  const { theme } = useTheme()
  const { copied, copy } = useCopyInvite()

  // Tick the call timer once a second (header-only re-render).
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (joinedAt == null) return
    const t = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(t)
  }, [joinedAt])

  const uplinkDetail = uplinkQualityDetail(localStats)
  const elapsed = joinedAt != null ? formatElapsed(now - joinedAt) : null

  return (
    <header className="flex items-center gap-1.5 border-b px-3 py-1.5 sm:gap-2 md:gap-3 md:px-4 md:py-2.5">
      <span className="text-xs font-semibold tracking-tight md:text-sm">
        wroom
      </span>
      <span className="min-w-0 max-w-[38vw] truncate rounded-full bg-muted px-2 py-0.5 font-mono text-xs tabular-nums text-muted-foreground sm:max-w-none md:text-xs">
        /r/{roomName}
        {elapsed ? ` · ${elapsed}` : null}
      </span>

      <div className="ml-auto flex items-center gap-1 sm:gap-1.5 md:gap-2">
        {connBadge(pubConnState)}
        {connBadge(subConnState)}
        <Badge variant="secondary" className="gap-1">
          <Users className="size-3" aria-hidden />
          {participantCount}
          <span className="hidden sm:inline"> in call</span>
        </Badge>

        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              className="size-8"
              aria-label={copied ? "Copied!" : "Copy room link"}
              onClick={() => void copy()}
            >
              {copied ? <Check className="text-emerald-500" /> : <Link2 />}
            </Button>
          </TooltipTrigger>
          <TooltipContent>{copied ? "Copied!" : "Copy room link"}</TooltipContent>
        </Tooltip>

        <QualityIndicator
          quality={uplinkQuality}
          detail={uplinkDetail}
          className="px-1"
        />

        <DropdownMenu>
          <Tooltip>
            <TooltipTrigger asChild>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  className="size-8"
                  aria-label={`Theme: ${theme}`}
                >
                  <ThemeIcon theme={theme} />
                </Button>
              </DropdownMenuTrigger>
            </TooltipTrigger>
            <TooltipContent>Theme</TooltipContent>
          </Tooltip>
          <DropdownMenuContent align="end" className="w-40">
            <ThemeMenuItems />
          </DropdownMenuContent>
        </DropdownMenu>

        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              className={cn("hidden size-8 font-semibold sm:inline-flex")}
              aria-label="Keyboard shortcuts"
              onClick={() => useCallStore.getState().set({ shortcutsOpen: true })}
            >
              ?
            </Button>
          </TooltipTrigger>
          <TooltipContent>Keyboard shortcuts</TooltipContent>
        </Tooltip>
      </div>
    </header>
  )
}
