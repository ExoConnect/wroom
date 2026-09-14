import { useCallback, useEffect, useRef, useState } from "react"
import { CircleAlert, Loader2, Mic, MicOff, Video, VideoOff, Volume2 } from "lucide-react"
import { Alert, AlertAction, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { DevicePicker } from "@/components/DevicePicker"
import { MicMeter } from "@/components/MicMeter"
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

/** Ephemeral links: a URL is a room (decision 16). "/r/<room>" or #<room>. */
function roomFromLocation(): string {
  const m = window.location.pathname.match(/^\/r\/([^/]+)\/?$/)
  if (m) return decodeURIComponent(m[1])
  if (window.location.hash.length > 1) return decodeURIComponent(window.location.hash.slice(1))
  return ""
}

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

  const canJoin = room.trim().length > 0 && name.trim().length > 0 && !busy

  const onJoin = () => {
    const r = room.trim()
    localStorage.setItem("wroom:name", name.trim())
    window.history.pushState(null, "", `/r/${encodeURIComponent(r)}`)
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

  return (
    <div className="flex min-h-svh items-center justify-center p-4">
      <Card className="w-full max-w-md sm:max-w-2xl">
        <CardHeader>
          <CardTitle className="text-2xl tracking-tight">wroom</CardTitle>
          <CardDescription>
            Fast, open video calls. Pick a room name, share the link.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 sm:grid-cols-2">
            {/* Preview + device controls — above the form on narrow screens. */}
            <div className="flex min-w-0 flex-col gap-3">
              <div className="relative aspect-video overflow-hidden rounded-lg border bg-muted/40">
                <video
                  ref={videoRef}
                  autoPlay
                  playsInline
                  muted
                  className={cn("size-full -scale-x-100 object-cover", !camEnabled && "hidden")}
                />
                {!camEnabled && (
                  <div className="flex size-full items-center justify-center text-muted-foreground">
                    <VideoOff className="size-8" />
                  </div>
                )}
                <div className="absolute bottom-2 left-2 flex gap-2">
                  <Button
                    variant={micEnabled ? "secondary" : "destructive"}
                    size="icon-sm"
                    className="rounded-full"
                    onClick={toggleMic}
                    title={micEnabled ? "Mute microphone" : "Unmute microphone"}
                  >
                    {micEnabled ? <Mic /> : <MicOff />}
                  </Button>
                  <Button
                    variant={camEnabled ? "secondary" : "destructive"}
                    size="icon-sm"
                    className="rounded-full"
                    onClick={toggleCam}
                    title={camEnabled ? "Turn camera off" : "Turn camera on"}
                  >
                    {camEnabled ? <Video /> : <VideoOff />}
                  </Button>
                </div>
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

              <div className="flex flex-col gap-2">
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
            </div>

            {/* Room / name / join. */}
            <div className="flex min-w-0 flex-col gap-3">
              <Input
                placeholder="Room name"
                value={room}
                onChange={(e) => setRoom(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && canJoin && onJoin()}
                autoFocus={!room}
              />
              <Input
                placeholder="Your name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && canJoin && onJoin()}
                autoFocus={!!room}
              />

              {notice && !denied && (
                <div className="flex items-start gap-2 rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
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
                className="mt-auto w-full"
                disabled={!canJoin}
                onClick={onJoin}
              >
                {busy ? <Loader2 className="animate-spin" /> : null}
                Join room
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
