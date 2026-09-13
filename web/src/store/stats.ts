// Live per-track media stats store (zustand). The RtcManager stats poller
// (lib/webrtc.ts) is the only writer; components subscribe read-only —
// same pattern as store/call.ts.

import { create } from "zustand"

export interface TrackStats {
  fps: number
  width: number
  height: number
  kbps: number
  codec?: string
  packetsLost?: number
  jitterMs?: number
  rttMs?: number
}

export interface StatsState {
  /** remote inbound tracks keyed by transceiver mid */
  byMid: Record<string, TrackStats>
  /** local outbound video */
  local: TrackStats | null
  set: (patch: Partial<Omit<StatsState, "set">>) => void
}

export const useStatsStore = create<StatsState>((set) => ({
  byMid: {},
  local: null,
  set: (patch) => set(patch),
}))
