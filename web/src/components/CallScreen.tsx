import { useEffect, useRef } from "react"
import { Badge } from "@/components/ui/badge"
import { TrackKind } from "@/gen/signaling/v1/signaling_pb"
import { session } from "@/lib/session"
import { useCallStore } from "@/store/call"
import { ControlBar } from "./ControlBar"
import { ParticipantList } from "./ParticipantList"
import { VideoTile } from "./VideoTile"

/** Hidden <audio> sink for a remote audio track. */
function RemoteAudio({ stream }: { stream: MediaStream }) {
  const ref = useRef<HTMLAudioElement>(null)
  useEffect(() => {
    const el = ref.current
    if (el && el.srcObject !== stream) el.srcObject = stream
    return () => {
      if (el) el.srcObject = null
    }
  }, [stream])
  return <audio ref={ref} autoPlay />
}

function connBadge(state: RTCPeerConnectionState | null) {
  if (!state || state === "new" || state === "connecting") return null
  if (state === "connected") return null
  return (
    <Badge variant={state === "failed" ? "destructive" : "secondary"}>{state}</Badge>
  )
}

export function CallScreen() {
  const roomName = useCallStore((s) => s.roomName)
  const selfName = useCallStore((s) => s.selfName)
  const selfId = useCallStore((s) => s.selfId)
  const participants = useCallStore((s) => s.participants)
  const remoteMedia = useCallStore((s) => s.remoteMedia)
  const midToTrackRef = useCallStore((s) => s.midToTrackRef)
  const localStream = useCallStore((s) => s.localStream)
  const micEnabled = useCallStore((s) => s.micEnabled)
  const camEnabled = useCallStore((s) => s.camEnabled)
  const activeSpeakers = useCallStore((s) => s.activeSpeakers)
  const pubConnState = useCallStore((s) => s.pubConnState)
  const subConnState = useCallStore((s) => s.subConnState)

  // Best-effort LeaveRequest on tab close / reload.
  useEffect(() => {
    const onUnload = () => session.leave()
    window.addEventListener("beforeunload", onUnload)
    return () => window.removeEventListener("beforeunload", onUnload)
  }, [])

  const remoteAudio = Object.values(remoteMedia).filter((m) => m.track.kind === "audio")
  // First video mid per participant → tile stream (a participant may have zero
  // video media — they still get an avatar tile so audio-only callers show up).
  const videoByPid = new Map<string, string>()
  const orphanVideo: string[] = [] // video media whose mid isn't grant-mapped yet
  for (const m of Object.values(remoteMedia)) {
    if (m.track.kind !== "video") continue
    const ref = midToTrackRef[m.mid]
    if (ref && !videoByPid.has(ref.participantId)) videoByPid.set(ref.participantId, m.mid)
    else if (!ref) orphanVideo.push(m.mid)
  }
  const remoteParticipants = Object.values(participants).filter((p) => p.id !== selfId)
  const micMuted = (p: (typeof remoteParticipants)[number]) =>
    p.tracks.some((t) => t.kind === TrackKind.AUDIO && t.muted)

  return (
    <div className="flex h-svh flex-col">
      <header className="flex items-center gap-3 border-b px-4 py-2.5">
        <span className="text-sm font-semibold tracking-tight">wroom</span>
        <span className="text-sm text-muted-foreground">/r/{roomName}</span>
        <div className="ml-auto flex items-center gap-2">
          {connBadge(pubConnState)}
          {connBadge(subConnState)}
          <Badge variant="secondary">{Object.keys(participants).length} in call</Badge>
        </div>
      </header>

      <div className="flex min-h-0 flex-1 gap-4 p-4">
        <main className="min-w-0 flex-1 overflow-y-auto">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
            <VideoTile
              stream={localStream}
              label={`${selfName || "You"} (you)`}
              micMuted={!micEnabled}
              videoOff={!camEnabled}
              mirror
              speaking={activeSpeakers.includes(selfId)}
            />
            {remoteParticipants.map((p) => {
              const mid = videoByPid.get(p.id)
              const ref = mid ? midToTrackRef[mid] : undefined
              const videoTrack = ref
                ? p.tracks.find((t) => t.id === ref.trackId)
                : undefined
              return (
                <VideoTile
                  key={p.id}
                  stream={mid ? remoteMedia[mid].stream : null}
                  label={p.name || p.id}
                  micMuted={micMuted(p)}
                  videoOff={videoTrack?.muted ?? true}
                  speaking={activeSpeakers.includes(p.id)}
                />
              )
            })}
            {orphanVideo.map((mid) => (
              <VideoTile key={mid} stream={remoteMedia[mid].stream} label="…" />
            ))}
          </div>
          {remoteParticipants.length === 0 && orphanVideo.length === 0 && (
            <p className="mt-6 text-center text-sm text-muted-foreground">
              No one else is here yet — share the link to this room.
            </p>
          )}
        </main>
        <ParticipantList />
      </div>

      <footer className="flex justify-center pb-5">
        <ControlBar />
      </footer>

      {remoteAudio.map((m) => (
        <RemoteAudio key={m.mid} stream={m.stream} />
      ))}
    </div>
  )
}
