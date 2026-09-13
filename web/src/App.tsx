import { useCallStore } from "@/store/call"
import { CallEnded } from "@/components/CallEnded"
import { CallScreen } from "@/components/CallScreen"
import { JoinScreen } from "@/components/JoinScreen"

function App() {
  const phase = useCallStore((s) => s.phase)
  const roomName = useCallStore((s) => s.roomName)
  if (phase === "joined") return <CallScreen />
  // Call-ended screen needs the room identity for "Rejoin" — fall back to
  // the join form when there is nothing to rejoin.
  if (phase === "closed" && roomName) return <CallEnded />
  return <JoinScreen />
}

export default App
