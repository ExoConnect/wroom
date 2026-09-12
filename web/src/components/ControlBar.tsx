import { Mic, MicOff, PhoneOff, Video, VideoOff } from "lucide-react"
import { Button } from "@/components/ui/button"
import { session } from "@/lib/session"
import { LOCAL_TRACK_IDS } from "@/lib/media"
import { useCallStore } from "@/store/call"
import { cn } from "@/lib/utils"

export function ControlBar() {
  const micEnabled = useCallStore((s) => s.micEnabled)
  const camEnabled = useCallStore((s) => s.camEnabled)
  const hasMic = !!useCallStore((s) => s.localStream?.getAudioTracks().length)
  const hasCam = !!useCallStore((s) => s.localStream?.getVideoTracks().length)

  return (
    <div className="flex items-center justify-center gap-3 rounded-2xl border bg-card/80 px-4 py-3 backdrop-blur">
      <Button
        variant={micEnabled ? "secondary" : "destructive"}
        size="icon-lg"
        className="rounded-full"
        disabled={!hasMic}
        title={micEnabled ? "Mute microphone" : "Unmute microphone"}
        onClick={() => session.setTrackEnabled(LOCAL_TRACK_IDS.mic, !micEnabled)}
      >
        {micEnabled ? <Mic /> : <MicOff />}
      </Button>
      <Button
        variant={camEnabled ? "secondary" : "destructive"}
        size="icon-lg"
        className="rounded-full"
        disabled={!hasCam}
        title={camEnabled ? "Turn camera off" : "Turn camera on"}
        onClick={() => session.setTrackEnabled(LOCAL_TRACK_IDS.cam, !camEnabled)}
      >
        {camEnabled ? <Video /> : <VideoOff />}
      </Button>
      <Button
        variant="destructive"
        size="icon-lg"
        className={cn("rounded-full bg-destructive text-white hover:bg-destructive/80")}
        title="Leave call"
        onClick={() => session.leave()}
      >
        <PhoneOff />
      </Button>
    </div>
  )
}
