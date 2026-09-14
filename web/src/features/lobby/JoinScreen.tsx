import { useCallback, useEffect, useRef, useState } from "react"
import {
  ChevronDown,
  CircleAlert,
  Dices,
  Loader2,
  Mic,
  MicOff,
  Video,
  VideoOff,
  Volume2,
} from "lucide-react"
import { Alert, AlertAction, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { DevicePicker } from "@/shared/components/DevicePicker"
import { MicMeter } from "@/shared/components/MicMeter"
import { initialsFor } from "@/shared/lib/avatar"
import { randomRoomSlug, roomFromLocation, roomPath } from "@/shared/lib/room"
import { enumerate, loadSelection, setSelectedDevices, watchDevices } from "@/lib/devices"
import {
  getLocalMedia,
  releaseLocalMedia,
  setCameraEnabled,
  setMicEnabled,
  startMicMeter,
  supportsSinkSelection,
  testSpeaker,
  type LocalMedia,
} from "@/lib/media"
import { session } from "@/lib/session"
import { playSound } from "@/lib/sounds"
import { useCallStore } from "@/store/call"
import { cn } from "@/lib/utils"
import { LobbyShell } from "./LobbyShell"

export function JoinScreen() {
  const [room, setRoom] = useState(roomFromLocation)
  const [name, setName] = useState(() => localStorage.getItem("wroom:name") ?? "")
  const phase = useCallStore((s) => s.phase)
  const notice = useCallStore((s) => s.notice)
  const localStream = useCallStore((s) => s.localStream)
  const micEnabled = useCallStore((s) => s.micEnabled)
  const camEnabled = useCallStore((s) => s.camEnabled)
  const videoRef = useRef<HTMLVideoElement>(null)
  const [denied, setDenied] = useState(false)
  const busy = phase === "media" || phase === "connecting" || phase === "joining"
  const canPickSpeaker = supportsSinkSelection()

  // Apply a finished capture to the store + start the mic meter on it.
  const applyCapture = useCallback((m: LocalMedia) => {
    const s = useCallStore.getState()
    if (s.phase !== "idle" && s.phase !== "closed") return
    s.set({
      localStream: m.stream,
      notice: m.ok ? s.notice : (m.error ?? s.notice),
      micEnabled: m.stream.getAudioTracks()[0]?.enabled ?? false,
      camEnabled: m.stream.getVideoTracks()[0]?.enabled ?? false,
    })
    setDenied(!!m.denied)
    const mic = m.stream.getAudioTracks()[0]
    if (mic) startMicMeter(mic)
  }, [])

  // Pre-flight capture: prompt for devices while the user is still on the
  // join screen so joining itself is fast. Device labels only populate after
  // the permission grant, so enumerate() runs post-capture; watchDevices()
  // keeps the lists fresh on hotplug.
  useEffect(() => {
    setSelectedDevices(loadSelection())
    const unwatch = watchDevices()
    let alive = true
    void getLocalMedia().then((m) => {
      void enumerate().catch(() => {})
      if (alive) applyCapture(m)
    })
    return () => {
      alive = false
      unwatch()
    }
  }, [applyCapture])

  useEffect(() => {
    const el = videoRef.current
    if (el) el.srcObject = camEnabled ? localStream : null
  }, [localStream, camEnabled])

  const toggleMic = () => {
    playSound(micEnabled ? "mute" : "unmute")
    setMicEnabled(!micEnabled)
  }
  const toggleCam = () => {
    playSound("click")
    void setCameraEnabled(!camEnabled).catch(() => {})
  }

  // Permission was denied: drop the dead capture so getLocalMedia re-requests.
  const retryMedia = () => {
    releaseLocalMedia(localStream)
    setDenied(false)
    useCallStore.getState().set({ notice: null })
    void getLocalMedia().then((m) => {
      void enumerate().catch(() => {})
      applyCapture(m)
    })
  }

  const surprise = () => {
    playSound("click")
    setRoom(randomRoomSlug())
  }

  const canJoin = room.trim().length > 0 && name.trim().length > 0 && !busy

  const onJoin = () => {
    const r = room.trim()
    localStorage.setItem("wroom:name", name.trim())
    window.history.pushState(null, "", roomPath(r))
    void session.join(r, name.trim())
  }

  const statusText =
    phase === "media"
      ? "Requesting camera & mic…"
      : phase === "connecting"
        ? "Connecting…"
        : phase === "joining"
          ? "Joining room…"
          : null

  const slug = room.trim() || "your-room"
  const hasVideo =
    camEnabled && (localStream?.getVideoTracks().length ?? 0) > 0
  const identity = name.trim() || "You"

  return (
    <LobbyShell>
      <div className="flex flex-col gap-5 py-6">
        <div className="flex flex-col gap-2">
          <h1 className="text-3xl font-semibold tracking-tight">
            Start a room in seconds.
          </h1>
          <p className="text-sm leading-relaxed text-muted-foreground">
            Pick a room name, share the link. No accounts, nothing to
            install — the link <span className="font-medium text-foreground">is</span> the
            room.
          </p>
        </div>

        {/* Preview — the hero, not a thumbnail. */}
        <div className="relative aspect-video overflow-hidden rounded-2xl border bg-black">
          <video
            ref={videoRef}
            autoPlay
            playsInline
            muted
            className={cn("size-full -scale-x-100 object-cover", !hasVideo && "hidden")}
          />
          {!hasVideo && (
            <div className="flex size-full items-center justify-center bg-gradient-to-br from-zinc-700 to-zinc-900">
              <div className="flex size-16 items-center justify-center rounded-full bg-black/45 text-xl font-semibold text-white backdrop-blur-sm">
                {initialsFor(identity) || <VideoOff className="size-6" />}
              </div>
            </div>
          )}
          <div className="absolute bottom-3 left-3 flex gap-2">
            <Button
              variant={micEnabled ? "secondary" : "destructive"}
              size="icon-sm"
              className="rounded-full shadow-lg"
              onClick={toggleMic}
              title={micEnabled ? "Mute microphone" : "Unmute microphone"}
              aria-label={micEnabled ? "Mute microphone" : "Unmute microphone"}
            >
              {micEnabled ? <Mic /> : <MicOff />}
            </Button>
            <Button
              variant={camEnabled ? "secondary" : "destructive"}
              size="icon-sm"
              className="rounded-full shadow-lg"
              onClick={toggleCam}
              title={camEnabled ? "Turn camera off" : "Turn camera on"}
              aria-label={camEnabled ? "Turn camera off" : "Turn camera on"}
            >
              {camEnabled ? <Video /> : <VideoOff />}
            </Button>
          </div>
          <span className="absolute bottom-3 right-3 rounded-full bg-black/60 px-2.5 py-1 text-[11px] text-white/80">
            Preview — only you can see this
          </span>
        </div>

        {denied && (
          <Alert variant="destructive">
            <CircleAlert />
            <AlertTitle>Camera & mic are blocked</AlertTitle>
            <AlertDescription>
              Allow access in the browser's site permissions (the lock or
              tune icon left of the address bar), then retry.
            </AlertDescription>
            <AlertAction>
              <Button variant="outline" size="sm" onClick={retryMedia}>
                Retry
              </Button>
            </AlertAction>
          </Alert>
        )}

        {/* Room name + one-click create. */}
        <div className="flex flex-col gap-1.5">
          <label htmlFor="wroom-room" className="text-xs font-medium text-muted-foreground">
            Room
          </label>
          <div className="flex gap-2">
            <Input
              id="wroom-room"
              placeholder="sunday-jam"
              value={room}
              onChange={(e) => setRoom(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && canJoin && onJoin()}
              autoFocus={!room}
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              className="h-11"
            />
            <Button
              variant="outline"
              size="icon"
              className="h-11 w-11 shrink-0"
              title="Generate a random room name"
              aria-label="Generate a random room name"
              onClick={surprise}
            >
              <Dices />
            </Button>
          </div>
          <p className="truncate text-xs text-muted-foreground">
            <span className="font-mono">/r/{slug}</span>
            <span> · anyone with the link can join</span>
          </p>
        </div>

        <div className="flex flex-col gap-1.5">
          <label htmlFor="wroom-name" className="text-xs font-medium text-muted-foreground">
            Your name
          </label>
          <Input
            id="wroom-name"
            placeholder="Ada"
            value={name}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && canJoin && onJoin()}
            autoFocus={!!room}
            autoComplete="name"
            className="h-11"
          />
        </div>

        {notice && !denied && (
          <div className="flex items-start gap-2 rounded-xl border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
            <CircleAlert className="mt-0.5 size-4 shrink-0" />
            <span>{notice}</span>
          </div>
        )}
        {statusText && (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Loader2 className="size-4 animate-spin" />
            <span>{statusText}</span>
          </div>
        )}

        <Button
          size="lg"
          className="h-12 w-full bg-brand text-[15px] font-semibold text-brand-foreground hover:bg-brand/90"
          disabled={!canJoin}
          onClick={onJoin}
        >
          {busy ? <Loader2 className="animate-spin" /> : null}
          Join room
        </Button>

        <details className="group rounded-2xl border">
          <summary className="flex cursor-pointer list-none items-center gap-2 px-4 py-3 text-sm font-medium [&::-webkit-details-marker]:hidden">
            <span className="flex-1">Devices & sound</span>
            <ChevronDown className="size-4 text-muted-foreground transition-transform group-open:rotate-180" />
          </summary>
          <div className="flex flex-col gap-2 px-4 pb-4">
            <div className="flex items-center gap-2">
              <div className="min-w-0 flex-1">
                <DevicePicker kind="mic" />
              </div>
              <MicMeter className="shrink-0" />
            </div>
            <DevicePicker kind="cam" />
            {canPickSpeaker && (
              <div className="flex items-center gap-2">
                <div className="min-w-0 flex-1">
                  <DevicePicker kind="speaker" />
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  className="shrink-0"
                  onClick={() => testSpeaker()}
                >
                  <Volume2 />
                  Test
                </Button>
              </div>
            )}
          </div>
        </details>
      </div>
    </LobbyShell>
  )
}
