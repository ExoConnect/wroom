import { Link2, Users } from "lucide-react"
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
import { copyRoomLink } from "@/shared/lib/room"
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

/** Call top bar: room identity + link copy, uplink quality, theme, help.
 *  Collapses to icon-only controls under `sm`. */
export function RoomHeader() {
  const roomName = useCallStore((s) => s.roomName)
  const participantCount = useCallStore((s) => Object.keys(s.participants).length)
  const uplinkQuality = useCallStore((s) => s.uplinkQuality)
  const pubConnState = useCallStore((s) => s.pubConnState)
  const subConnState = useCallStore((s) => s.subConnState)
  const localStats = useStatsStore((s) => s.local)
  const { theme } = useTheme()

  const uplinkDetail = uplinkQualityDetail(localStats)

  return (
    <header className="flex items-center gap-1.5 border-b px-3 py-1.5 sm:gap-2 md:gap-3 md:px-4 md:py-2.5 dark:border-white/10">
      <span className="text-xs font-semibold tracking-tight md:text-sm">
        wroom
      </span>
      <span className="min-w-0 truncate rounded-full bg-muted px-2 py-0.5 font-mono text-xs text-muted-foreground md:text-xs">
        /r/{roomName}
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
              aria-label="Copy room link"
              onClick={() => void copyRoomLink()}
            >
              <Link2 />
            </Button>
          </TooltipTrigger>
          <TooltipContent>Copy room link</TooltipContent>
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
              className={cn("size-8 font-semibold")}
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
