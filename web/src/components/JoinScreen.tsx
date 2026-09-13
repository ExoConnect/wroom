import { useEffect, useRef, useState } from "react"
import { CircleAlert, Loader2, Mic, MicOff, Video, VideoOff } from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { getLocalMedia } from "@/lib/media"
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
  const videoRef = useRef<HTMLVideoElement>(null)
  const [micOn, setMicOn] = useState(true)
  const [camOn, setCamOn] = useState(true)
  const busy = phase === "media" || phase === "connecting" || phase === "joining"

  // Pre-flight capture: prompt for devices while the user is still on the
  // join screen so joining itself is fast.
  useEffect(() => {
    void getLocalMedia().then((m) => {
      const s = useCallStore.getState()
      if (s.phase === "idle" || s.phase === "closed") {
        s.set({
          localStream: m.stream,
          notice: m.ok ? s.notice : (m.error ?? s.notice),
        })
        const mic = m.stream.getAudioTracks()[0]
        const cam = m.stream.getVideoTracks()[0]
        setMicOn(mic?.enabled ?? false)
        setCamOn(cam?.enabled ?? false)
      }
    })
  }, [])

  useEffect(() => {
    const el = videoRef.current
    if (el) el.srcObject = camOn ? localStream : null
  }, [localStream, camOn])

  const toggleMic = () => {
    const t = localStream?.getAudioTracks()[0]
    if (t) {
      t.enabled = !t.enabled
      setMicOn(t.enabled)
      playSound(t.enabled ? "unmute" : "mute")
    }
  }
  const toggleCam = () => {
    const t = localStream?.getVideoTracks()[0]
    if (t) {
      t.enabled = !t.enabled
      setCamOn(t.enabled)
      playSound("click")
    }
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
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="text-2xl tracking-tight">wroom</CardTitle>
          <CardDescription>
            Fast, open video calls. Pick a room name, share the link.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div className="relative aspect-video overflow-hidden rounded-lg border bg-muted/40">
            <video
              ref={videoRef}
              autoPlay
              playsInline
              muted
              className={cn("size-full -scale-x-100 object-cover", !camOn && "hidden")}
            />
            {!camOn && (
              <div className="flex size-full items-center justify-center text-muted-foreground">
                <VideoOff className="size-8" />
              </div>
            )}
            <div className="absolute bottom-2 left-2 flex gap-2">
              <Button
                variant={micOn ? "secondary" : "destructive"}
                size="icon-sm"
                className="rounded-full"
                onClick={toggleMic}
                title={micOn ? "Mute microphone" : "Unmute microphone"}
              >
                {micOn ? <Mic /> : <MicOff />}
              </Button>
              <Button
                variant={camOn ? "secondary" : "destructive"}
                size="icon-sm"
                className="rounded-full"
                onClick={toggleCam}
                title={camOn ? "Turn camera off" : "Turn camera on"}
              >
                {camOn ? <Video /> : <VideoOff />}
              </Button>
            </div>
          </div>

          <div className="flex flex-col gap-3">
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
          </div>

          {notice && (
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

          <Button size="lg" className="w-full" disabled={!canJoin} onClick={onJoin}>
            {busy ? <Loader2 className="animate-spin" /> : null}
            Join room
          </Button>
        </CardContent>
      </Card>
    </div>
  )
}
