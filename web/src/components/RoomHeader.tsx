import { Link2, MonitorSmartphone, Moon, Sun, Users } from "lucide-react"
import { toast } from "sonner"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useTheme } from "@/hooks/useTheme"
import { cn } from "@/lib/utils"
import { useCallStore, type Theme } from "@/store/call"
import { useStatsStore } from "@/store/stats"
import { QualityIndicator } from "./QualityIndicator"

function connBadge(state: RTCPeerConnectionState | null) {
  if (!state || state === "new" || state === "connecting") return null
  if (state === "connected") return null
  return (
    <Badge variant={state === "failed" ? "destructive" : "secondary"}>
      {state}
    </Badge>
  )
}

const THEME_ICON: Record<Theme, typeof Sun> = {
  system: MonitorSmartphone,
  light: Sun,
  dark: Moon,
}

async function copyRoomLink(): Promise<void> {
  const url = window.location.href
  try {
    await navigator.clipboard.writeText(url)
    toast.success("Link copied")
    return
  } catch {
    // Clipboard API unavailable (insecure context, denied) — legacy fallback.
  }
  const ta = document.createElement("textarea")
  ta.value = url
  ta.style.position = "fixed"
  ta.style.opacity = "0"
  document.body.appendChild(ta)
  ta.select()
  try {
    document.execCommand("copy")
    toast.success("Link copied")
  } catch {
    toast.error("Couldn't copy the link — copy it from the address bar")
  }
  ta.remove()
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
  const { theme, setTheme } = useTheme()
  const ThemeIcon = THEME_ICON[theme]

  const uplinkDetail =
    localStats && (localStats.rttMs != null || localStats.packetsLost != null)
      ? [
          localStats.rttMs != null ? `RTT ${Math.round(localStats.rttMs)}ms` : null,
          localStats.packetsLost != null
            ? `${localStats.packetsLost} packets lost`
            : null,
        ]
          .filter(Boolean)
          .join(" · ")
      : undefined

  return (
    <header className="flex items-center gap-1.5 border-b px-3 py-1.5 sm:gap-2 md:gap-3 md:px-4 md:py-2.5">
      <span className="text-xs font-semibold tracking-tight md:text-sm">
        wroom
      </span>
      <span className="min-w-0 truncate text-xs text-muted-foreground md:text-sm">
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
                  <ThemeIcon />
                </Button>
              </DropdownMenuTrigger>
            </TooltipTrigger>
            <TooltipContent>Theme</TooltipContent>
          </Tooltip>
          <DropdownMenuContent align="end" className="w-40">
            <DropdownMenuRadioGroup
              value={theme}
              onValueChange={(v) => setTheme(v as Theme)}
            >
              <DropdownMenuRadioItem value="system">
                <MonitorSmartphone /> System
              </DropdownMenuRadioItem>
              <DropdownMenuRadioItem value="light">
                <Sun /> Light
              </DropdownMenuRadioItem>
              <DropdownMenuRadioItem value="dark">
                <Moon /> Dark
              </DropdownMenuRadioItem>
            </DropdownMenuRadioGroup>
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
