import { Mic, MicOff, PhoneOff, Users, Video, VideoOff } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { session } from "@/lib/session"
import { LOCAL_TRACK_IDS } from "@/lib/media"
import { playSound } from "@/lib/sounds"
import { useCallStore } from "@/store/call"
import { cn } from "@/lib/utils"

export function ControlBar() {
  const micEnabled = useCallStore((s) => s.micEnabled)
  const camEnabled = useCallStore((s) => s.camEnabled)
  const participantsOpen = useCallStore((s) => s.participantsOpen)
  const participantCount = useCallStore((s) => Object.keys(s.participants).length)
  const hasMic = !!useCallStore((s) => s.localStream?.getAudioTracks().length)
  const hasCam = !!useCallStore((s) => s.localStream?.getVideoTracks().length)

  const toggleMic = () => {
    playSound(micEnabled ? "mute" : "unmute")
    session.setTrackEnabled(LOCAL_TRACK_IDS.mic, !micEnabled)
  }
  const toggleCam = () => {
    playSound("click")
    session.setTrackEnabled(LOCAL_TRACK_IDS.cam, !camEnabled)
  }
  const toggleParticipants = () => {
    playSound("click")
    useCallStore.getState().set({ participantsOpen: !participantsOpen })
  }
  const leave = () => {
    playSound("leave")
    session.leave()
  }

  return (
    <div className="flex items-center justify-center gap-3 rounded-2xl border bg-card/80 px-4 py-3 shadow-lg backdrop-blur">
      <Button
        variant={micEnabled ? "secondary" : "destructive"}
        size="icon-lg"
        className="size-11 rounded-full"
        disabled={!hasMic}
        title={micEnabled ? "Mute microphone" : "Unmute microphone"}
        onClick={toggleMic}
      >
        {micEnabled ? <Mic /> : <MicOff />}
      </Button>
      <Button
        variant={camEnabled ? "secondary" : "destructive"}
        size="icon-lg"
        className="size-11 rounded-full"
        disabled={!hasCam}
        title={camEnabled ? "Turn camera off" : "Turn camera on"}
        onClick={toggleCam}
      >
        {camEnabled ? <Video /> : <VideoOff />}
      </Button>
      <div className="relative">
        <Button
          variant={participantsOpen ? "default" : "secondary"}
          size="icon-lg"
          className="size-11 rounded-full"
          title="Participants"
          aria-expanded={participantsOpen}
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
      <Button
        variant="destructive"
        size="icon-lg"
        className={cn("size-11 rounded-full bg-destructive text-white hover:bg-destructive/80")}
        title="Leave call"
        onClick={leave}
      >
        <PhoneOff />
      </Button>
    </div>
  )
}
