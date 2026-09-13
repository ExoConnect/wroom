import { useEffect, useRef } from "react"
import { playSound } from "@/lib/sounds"
import { useCallStore } from "@/store/call"

/** Plays join/leave blips when the participant count changes. The initial
 *  snapshot is the baseline — no sound for people already in the room. */
export function useParticipantSounds(): void {
  const count = useCallStore((s) => Object.keys(s.participants).length)
  const prev = useRef<number | null>(null)
  useEffect(() => {
    if (prev.current === null) {
      prev.current = count
      return
    }
    if (count > prev.current) playSound("join")
    else if (count < prev.current) playSound("leave")
    prev.current = count
  }, [count])
}
