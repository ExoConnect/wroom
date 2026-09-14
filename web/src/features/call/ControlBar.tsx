import { useState, type ReactElement, type ReactNode } from "react"
import {
  Activity,
  Check,
  ChevronDown,
  Copy,
  Keyboard,
  MessageSquare,
  Mic,
  MicOff,
  MonitorSmartphone,
  MoreVertical,
  PhoneOff,
  PictureInPicture2,
  Presentation,
  ScreenShare,
  ScreenShareOff,
  Users,
  Video,
  VideoOff,
  Volume2,
  VolumeX,
} from "lucide-react"
import { toast } from "sonner"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Separator } from "@/components/ui/separator"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet"
import { Switch } from "@/components/ui/switch"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { DevicePicker } from "@/shared/components/DevicePicker"
import { ThemeIcon, ThemeMenuItems } from "@/shared/components/ThemeToggle"
import { useCopyInvite } from "@/shared/components/useCopyInvite"
import { useMediaQuery } from "@/hooks/useMediaQuery"
import { usePictureInPicture } from "@/hooks/usePictureInPicture"
import { useTheme } from "@/hooks/useTheme"
import { LOCAL_TRACK_IDS } from "@/lib/media"
import { session } from "@/lib/session"
import { playSound } from "@/lib/sounds"
import { cn } from "@/lib/utils"
import { useCallStore } from "@/store/call"

const canScreenShare = (): boolean =>
  typeof navigator !== "undefined" &&
  !!navigator.mediaDevices &&
  "getDisplayMedia" in navigator.mediaDevices

/** Live mic level rendered as a fill rising inside the mic glyph itself.
 *  Two stacked copies of the icon: the base in button color, and a
 *  bottom-anchored emerald copy clipped to `level` height — a liquid
 *  fill that never distorts the glyph. Same `micLevel` signal (~20 Hz) the
 *  old bar meter used, isolated here so only the icon re-renders. */
function MicLevelIcon() {
  const level = useCallStore((s) => s.micLevel)
  // Perceptual display curve: linear RMS hugs the bottom of a 20px glyph
  // until shouting, so show sqrt — silence still reads exactly empty and
  // full-scale still pegs. Signal itself is untouched.
  const pct = Math.min(100, Math.max(0, Math.sqrt(Math.max(0, level)) * 100))
  return (
    <span aria-hidden className="relative inline-flex size-5">
      <Mic className="size-5" />
      <span
        className="absolute inset-x-0 bottom-0 overflow-hidden transition-[height] duration-100 ease-linear motion-reduce:hidden"
        style={{ height: `${pct}%` }}
      >
        <Mic className="absolute bottom-0 left-0 size-5 text-emerald-500" />
      </span>
    </span>
  )
}

/** session.startScreenShare/stopScreenShare are part of the call session's
 *  public surface (lib/session.ts). */

/** Tooltip on hover-capable pointers only; pass-through on touch. */
function Tip({
  content,
  coarse,
  children,
}: {
  content: ReactNode
  coarse: boolean
  children: ReactElement
}) {
  if (coarse) return children
  return (
    <Tooltip>
      <TooltipTrigger asChild>{children}</TooltipTrigger>
      <TooltipContent side="top">{content}</TooltipContent>
    </Tooltip>
  )
}

export function ControlBar() {
  const micEnabled = useCallStore((s) => s.micEnabled)
  const camEnabled = useCallStore((s) => s.camEnabled)
  const participantsOpen = useCallStore((s) => s.participantsOpen)
  const chatOpen = useCallStore((s) => s.chatOpen)
  const chatUnread = useCallStore((s) => s.chatUnread)
  const participantCount = useCallStore((s) => Object.keys(s.participants).length)
  // "Has device" ≠ "has a live track": setCameraEnabled(false) stops and
  // removes the video track (honest mute — LED off), so the store's device
  // list is what keeps the button usable for re-enabling.
  const devices = useCallStore((s) => s.devices)
  const micTrack = !!useCallStore((s) => s.localStream?.getAudioTracks().length)
  const camTrack = !!useCallStore((s) => s.localStream?.getVideoTracks().length)
  const hasMic = micEnabled || micTrack || devices.mics.length > 0
  const hasCam = camEnabled || camTrack || devices.cams.length > 0
  const screenStream = useCallStore((s) => s.screenStream)
  const roomName = useCallStore((s) => s.roomName)
  const speakerView = useCallStore((s) => s.speakerView)
  const showStats = useCallStore((s) => s.showStats)
  const soundsEnabled = useCallStore((s) => s.soundsEnabled)
  const { theme, setTheme } = useTheme()
  const { copied: sheetCopied, copy } = useCopyInvite()
  const { enter: enterPip, supported: pipSupported } = usePictureInPicture()

  // <640px the bar is a full-width strip and "more" is a bottom Sheet.
  const compact = useMediaQuery("(width < 640px)")
  const coarse = useMediaQuery("(pointer: coarse)")
  const [moreOpen, setMoreOpen] = useState(false)
  const [confirmLeave, setConfirmLeave] = useState(false)

  const set = useCallStore.getState().set

  const toggleMic = () => {
    playSound(micEnabled ? "mute" : "unmute")
    session.setTrackEnabled(LOCAL_TRACK_IDS.mic, !micEnabled)
  }
  const toggleCam = () => {
    playSound("click")
    session.setTrackEnabled(LOCAL_TRACK_IDS.cam, !camEnabled)
  }
  const toggleShare = () => {
    playSound("click")
    if (screenStream) void session.stopScreenShare()
    else void session.startScreenShare()
  }
  const toggleChat = () => {
    playSound("click")
    const s = useCallStore.getState()
    s.set(
      s.chatOpen
        ? { chatOpen: false }
        : { chatOpen: true, chatUnread: 0, participantsOpen: false },
    )
  }
  const toggleParticipants = () => {
    playSound("click")
    const s = useCallStore.getState()
    s.set(
      s.participantsOpen
        ? { participantsOpen: false }
        : { participantsOpen: true, chatOpen: false },
    )
  }
  const doLeave = () => {
    playSound("leave")
    session.leave()
  }
  const onLeaveClick = () => {
    // Touch/small screens: leave immediately, no confirm dialog.
    if (compact || coarse) doLeave()
    else setConfirmLeave(true)
  }
  const openShortcuts = () => set({ shortcutsOpen: true })
  const onEnterPip = () =>
    void enterPip().then((ok) => {
      if (!ok) toast.info("Picture-in-picture isn't available for this tile")
    })

  const moreMenuItems = (
    <>
      <DropdownMenuCheckboxItem
        checked={speakerView}
        onCheckedChange={(v) => set({ speakerView: v })}
      >
        <Presentation /> Speaker view
      </DropdownMenuCheckboxItem>
      <DropdownMenuCheckboxItem
        checked={showStats}
        onCheckedChange={(v) => set({ showStats: v })}
      >
        <Activity /> Show stats
      </DropdownMenuCheckboxItem>
      <DropdownMenuCheckboxItem
        checked={soundsEnabled}
        onCheckedChange={(v) => {
          set({ soundsEnabled: v })
          if (v) playSound("click")
        }}
      >
        {soundsEnabled ? <Volume2 /> : <VolumeX />} Sounds
      </DropdownMenuCheckboxItem>
      <DropdownMenuSub>
        <DropdownMenuSubTrigger>
          <ThemeIcon theme={theme} />
          Theme
        </DropdownMenuSubTrigger>
        <DropdownMenuSubContent className="w-40">
          <ThemeMenuItems />
        </DropdownMenuSubContent>
      </DropdownMenuSub>
      <DropdownMenuSeparator />
      <DropdownMenuItem onClick={openShortcuts}>
        <Keyboard /> Keyboard shortcuts
      </DropdownMenuItem>
      <DropdownMenuItem disabled={!pipSupported} onClick={onEnterPip}>
        <PictureInPicture2 /> Enter picture-in-picture
      </DropdownMenuItem>
    </>
  )

  const micVariant = micEnabled ? "secondary" : "destructive"
  const camVariant = camEnabled ? "secondary" : "destructive"

  return (
    <>
      <div
        role="toolbar"
        aria-label="Call controls"
        className={cn(
          "flex items-center gap-2 border bg-card/80 shadow-lg backdrop-blur sm:gap-2.5",
          compact
            ? "w-full justify-between rounded-2xl px-3 py-2.5"
            : "justify-center rounded-2xl px-4 py-3",
        )}
      >
        {/* Mic + device chevron */}
        <div className="flex items-center">
          <Tip coarse={coarse} content={micEnabled ? "Mute microphone (M)" : "Unmute microphone (M)"}>
            <Button
              variant={micVariant}
              size="icon-lg"
              className={cn("h-11 w-11 rounded-full", "sm:rounded-r-none")}
              disabled={!hasMic}
              aria-label={micEnabled ? "Mute microphone" : "Unmute microphone"}
              aria-pressed={!micEnabled}
              onClick={toggleMic}
            >
              {micEnabled ? <MicLevelIcon /> : <MicOff />}
            </Button>
          </Tip>
          <DevicePicker
            kind="mic"
            trigger={
              <Button
                variant={micVariant}
                size="icon-lg"
                className="h-11 w-8 rounded-l-none rounded-r-full border-l border-l-black/10 px-0 max-sm:hidden dark:border-l-white/10"
                aria-label="Choose microphone"
                disabled={!hasMic}
              >
                <ChevronDown className="size-3.5" />
              </Button>
            }
          />
        </div>

        {/* Camera + device chevron */}
        <div className="flex items-center">
          <Tip coarse={coarse} content={camEnabled ? "Turn camera off (V)" : "Turn camera on (V)"}>
            <Button
              variant={camVariant}
              size="icon-lg"
              className="h-11 w-11 rounded-full sm:rounded-r-none"
              disabled={!hasCam}
              aria-label={camEnabled ? "Turn camera off" : "Turn camera on"}
              aria-pressed={!camEnabled}
              onClick={toggleCam}
            >
              {camEnabled ? <Video /> : <VideoOff />}
            </Button>
          </Tip>
          <DevicePicker
            kind="cam"
            trigger={
              <Button
                variant={camVariant}
                size="icon-lg"
                className="h-11 w-8 rounded-l-none rounded-r-full border-l border-l-black/10 px-0 max-sm:hidden dark:border-l-white/10"
                aria-label="Choose camera"
                disabled={!hasCam}
              >
                <ChevronDown className="size-3.5" />
              </Button>
            }
          />
        </div>

        {/* Screen share — hidden where getDisplayMedia doesn't exist. */}
        {canScreenShare() && (
          <Tip coarse={coarse} content={screenStream ? "Stop sharing" : "Share screen"}>
            <Button
              variant={screenStream ? "default" : "secondary"}
              size="icon-lg"
              className="size-11 rounded-full max-sm:hidden"
              aria-label={screenStream ? "Stop sharing screen" : "Share screen"}
              aria-pressed={!!screenStream}
              onClick={toggleShare}
            >
              {screenStream ? <ScreenShareOff /> : <ScreenShare />}
            </Button>
          </Tip>
        )}

        {/* Chat */}
        <Tip coarse={coarse} content="Chat (C)">
          <div className="relative">
            <Button
              variant={chatOpen ? "default" : "secondary"}
              size="icon-lg"
              className="size-11 rounded-full"
              aria-label={chatOpen ? "Close chat" : "Open chat"}
              aria-expanded={chatOpen}
              aria-controls="chat-panel"
              onClick={toggleChat}
            >
              <MessageSquare />
            </Button>
            {chatUnread > 0 && (
              <Badge
                variant="destructive"
                className="pointer-events-none absolute -right-1 -top-1 h-5 min-w-5 justify-center px-1"
              >
                {chatUnread > 9 ? "9+" : chatUnread}
              </Badge>
            )}
          </div>
        </Tip>

        {/* Participants — hidden on compact; reachable via the more sheet. */}
        <Tip coarse={coarse} content="Participants">
          <div className="relative max-sm:hidden">
            <Button
              variant={participantsOpen ? "default" : "secondary"}
              size="icon-lg"
              className="size-11 rounded-full"
              aria-label="Participants"
              aria-expanded={participantsOpen}
              aria-controls="participants-panel"
              onClick={toggleParticipants}
            >
              <Users />
            </Button>
            <Badge
              variant={participantsOpen ? "secondary" : "default"}
              className="pointer-events-none absolute -right-1 -top-1 h-5 min-w-5 justify-center px-1"
            >
              {participantCount}
            </Badge>
          </div>
        </Tip>

        {/* More — DropdownMenu on ≥sm, bottom Sheet on phones. */}
        {compact ? (
          <Tip coarse={coarse} content="More options">
            <Button
              variant="secondary"
              size="icon-lg"
              className="size-11 rounded-full"
              aria-label="More options"
              aria-expanded={moreOpen}
              onClick={() => setMoreOpen(true)}
            >
              <MoreVertical />
            </Button>
          </Tip>
        ) : (
          <DropdownMenu>
            <Tip coarse={coarse} content="More options">
              <DropdownMenuTrigger asChild>
                <Button
                  variant="secondary"
                  size="icon-lg"
                  className="size-11 rounded-full"
                  aria-label="More options"
                >
                  <MoreVertical />
                </Button>
              </DropdownMenuTrigger>
            </Tip>
            <DropdownMenuContent side="top" align="center" className="w-56">
              {moreMenuItems}
            </DropdownMenuContent>
          </DropdownMenu>
        )}

        {/* Leave */}
        <Tip coarse={coarse} content="Leave call">
          <Button
            variant="destructive"
            size="icon-lg"
            className="size-11 rounded-full bg-destructive text-white hover:bg-destructive/80"
            aria-label="Leave call"
            onClick={onLeaveClick}
          >
            <PhoneOff />
          </Button>
        </Tip>
      </div>

      {/* Leave confirmation — desktop only (mobile/coarse leaves directly). */}
      <Dialog open={confirmLeave} onOpenChange={setConfirmLeave}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Leave the call?</DialogTitle>
            <DialogDescription>
              You'll disconnect from /r/{roomName}.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmLeave(false)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={doLeave}>
              Leave call
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Compact "more" — bottom sheet with the same options plus
          participants/devices that don't fit the phone bar. */}
      <Sheet open={moreOpen} onOpenChange={setMoreOpen}>
        <SheetContent side="bottom" className="gap-0 rounded-t-2xl p-0">
          <SheetHeader className="p-4 pb-2">
            <SheetTitle>Options</SheetTitle>
            <SheetDescription className="sr-only">
              Call options and preferences
            </SheetDescription>
          </SheetHeader>
          <div className="flex flex-col px-2 pb-6">
            <button
              type="button"
              className="flex h-11 items-center gap-3 rounded-lg px-3 text-left text-sm hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              onClick={() => {
                setMoreOpen(false)
                toggleParticipants()
              }}
            >
              <Users className="size-4" />
              <span className="flex-1">Participants</span>
              <span className="text-xs text-muted-foreground">
                {participantCount}
              </span>
            </button>

            <SheetToggle
              icon={<Presentation className="size-4" />}
              label="Speaker view"
              checked={speakerView}
              onChange={(v) => set({ speakerView: v })}
            />
            <SheetToggle
              icon={<Activity className="size-4" />}
              label="Show stats"
              checked={showStats}
              onChange={(v) => set({ showStats: v })}
            />
            <SheetToggle
              icon={
                soundsEnabled ? (
                  <Volume2 className="size-4" />
                ) : (
                  <VolumeX className="size-4" />
                )
              }
              label="Sounds"
              checked={soundsEnabled}
              onChange={(v) => {
                set({ soundsEnabled: v })
                if (v) playSound("click")
              }}
            />

            <Separator className="my-2" />
            <div className="flex items-center gap-3 px-3 py-2">
              <MonitorSmartphone className="size-4 shrink-0" />
              <span className="flex-1 text-sm">Theme</span>
              <div className="flex rounded-lg border p-0.5">
                {(
                  [
                    ["system", "System"],
                    ["light", "Light"],
                    ["dark", "Dark"],
                  ] as const
                ).map(([v, label]) => (
                  <button
                    key={v}
                    type="button"
                    aria-pressed={theme === v}
                    className={cn(
                      "h-8 rounded-md px-2.5 text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                      theme === v
                        ? "bg-secondary font-medium"
                        : "text-muted-foreground",
                    )}
                    onClick={() => setTheme(v)}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>

            <Separator className="my-2" />
            <div className="flex items-center gap-3 px-3 py-1.5">
              <Mic className="size-4 shrink-0" />
              <span className="flex-1 text-sm">Microphone</span>
              <DevicePicker
                kind="mic"
                trigger={
                  <Button variant="outline" size="sm" aria-label="Choose microphone">
                    Choose
                  </Button>
                }
              />
            </div>
            <div className="flex items-center gap-3 px-3 py-1.5">
              <Video className="size-4 shrink-0" />
              <span className="flex-1 text-sm">Camera</span>
              <DevicePicker
                kind="cam"
                trigger={
                  <Button variant="outline" size="sm" aria-label="Choose camera">
                    Choose
                  </Button>
                }
              />
            </div>

            <Separator className="my-2" />
            <button
              type="button"
              className="flex h-11 items-center gap-3 rounded-lg px-3 text-left text-sm hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              onClick={() => {
                // Let the "Copied" morph flash before the sheet dismisses.
                void copy().then(() =>
                  window.setTimeout(() => setMoreOpen(false), 450),
                )
              }}
            >
              {sheetCopied ? (
                <Check className="size-4 text-emerald-500" />
              ) : (
                <Copy className="size-4" />
              )}
              <span className="flex-1">
                {sheetCopied ? "Copied!" : "Copy room link"}
              </span>
            </button>
            <button
              type="button"
              className="flex h-11 items-center gap-3 rounded-lg px-3 text-left text-sm hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              onClick={() => {
                setMoreOpen(false)
                openShortcuts()
              }}
            >
              <Keyboard className="size-4" />
              <span className="flex-1">Keyboard shortcuts</span>
            </button>
            <button
              type="button"
              disabled={!pipSupported}
              className="flex h-11 items-center gap-3 rounded-lg px-3 text-left text-sm hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50"
              onClick={() => {
                setMoreOpen(false)
                onEnterPip()
              }}
            >
              <PictureInPicture2 className="size-4" />
              <span className="flex-1">Picture-in-picture</span>
            </button>
            <button
              type="button"
              className="flex h-11 items-center gap-3 rounded-lg px-3 text-left text-sm text-destructive hover:bg-destructive/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              onClick={() => {
                setMoreOpen(false)
                doLeave()
              }}
            >
              <PhoneOff className="size-4" />
              <span className="flex-1">Leave call</span>
            </button>
          </div>
        </SheetContent>
      </Sheet>
    </>
  )
}

/** Label + Switch row for the compact options sheet. */
function SheetToggle({
  icon,
  label,
  checked,
  onChange,
}: {
  icon: ReactNode
  label: string
  checked: boolean
  onChange: (v: boolean) => void
}) {
  return (
    <label className="flex h-11 cursor-pointer items-center gap-3 rounded-lg px-3 text-sm hover:bg-muted focus-within:ring-2 focus-within:ring-ring">
      {icon}
      <span className="flex-1">{label}</span>
      <Switch
        checked={checked}
        onCheckedChange={onChange}
        aria-label={label}
      />
    </label>
  )
}
