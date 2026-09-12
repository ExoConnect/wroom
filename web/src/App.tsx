import { useCallStore } from "@/store/call"
import { CallScreen } from "@/components/CallScreen"
import { JoinScreen } from "@/components/JoinScreen"

function App() {
  const phase = useCallStore((s) => s.phase)
  return phase === "joined" ? <CallScreen /> : <JoinScreen />
}

export default App
