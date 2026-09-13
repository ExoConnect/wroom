// Synthesized UI sounds — no audio assets. Each sound is one or two short
// oscillator tones (<=150 ms total, gain <= 0.15) through a shared
// AudioContext that is created lazily and resumed on the first user gesture
// (mobile autoplay policy blocks contexts created without a gesture).

import { useCallStore } from "@/store/call"

export type SoundKind = "mute" | "unmute" | "join" | "leave" | "click" | "pin"

let ctx: AudioContext | null = null

function audio(): AudioContext | null {
  if (typeof window === "undefined" || !("AudioContext" in window)) return null
  ctx ??= new AudioContext()
  if (ctx.state === "suspended") void ctx.resume()
  return ctx
}

// Unlock on the first gesture so event-driven sounds (join/leave) can play.
if (typeof window !== "undefined") {
  const unlock = () => audio()
  window.addEventListener("pointerdown", unlock, { once: true, capture: true })
  window.addEventListener("keydown", unlock, { once: true, capture: true })
}

interface Tone {
  /** Frequency in Hz. */
  f: number
  /** Start offset in seconds. */
  t: number
  /** Duration in seconds. */
  d: number
  type?: OscillatorType
  /** Peak gain (<= 0.15). */
  g?: number
}

const SOUNDS: Record<SoundKind, Tone[]> = {
  // Two descending tones.
  mute: [
    { f: 520, t: 0, d: 0.05 },
    { f: 330, t: 0.055, d: 0.07 },
  ],
  // Two ascending tones.
  unmute: [
    { f: 330, t: 0, d: 0.05 },
    { f: 520, t: 0.055, d: 0.07 },
  ],
  // Soft two-note chime.
  join: [
    { f: 660, t: 0, d: 0.06, g: 0.11 },
    { f: 990, t: 0.07, d: 0.08, g: 0.09 },
  ],
  // Single low blip.
  leave: [{ f: 220, t: 0, d: 0.12, g: 0.11 }],
  // Tiny tick.
  click: [{ f: 1800, t: 0, d: 0.02, type: "triangle", g: 0.07 }],
  // Quick double snap upward.
  pin: [
    { f: 880, t: 0, d: 0.04, type: "triangle", g: 0.1 },
    { f: 1320, t: 0.045, d: 0.05, type: "triangle", g: 0.09 },
  ],
}

export function playSound(kind: SoundKind): void {
  if (!useCallStore.getState().soundsEnabled) return
  const ac = audio()
  if (!ac) return
  const t0 = ac.currentTime
  for (const tone of SOUNDS[kind]) {
    const osc = ac.createOscillator()
    const gain = ac.createGain()
    osc.type = tone.type ?? "sine"
    osc.frequency.value = tone.f
    const start = t0 + tone.t
    // Fast attack + exponential decay — avoids audible clicks.
    gain.gain.setValueAtTime(0.0001, start)
    gain.gain.exponentialRampToValueAtTime(tone.g ?? 0.15, start + 0.008)
    gain.gain.exponentialRampToValueAtTime(0.0001, start + tone.d)
    osc.connect(gain)
    gain.connect(ac.destination)
    osc.start(start)
    osc.stop(start + tone.d + 0.02)
  }
}
