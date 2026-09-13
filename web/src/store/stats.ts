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
  /** Mean jitter-buffer delay (ms): 1000 × jitterBufferDelay /
   *  jitterBufferEmittedCount, inbound video. */
  jbMs?: number
}

export interface AudioTrackStats {
  /** Mean jitter-buffer delay (ms). */
  jbMs: number
  /** Mean jitter-buffer target delay (ms). */
  targetJbMs: number
  /** Cumulative packets lost. */
  lost: number
}

export interface StatsState {
  /** remote inbound video tracks keyed by transceiver mid */
  byMid: Record<string, TrackStats>
  /** remote inbound audio tracks keyed by transceiver mid */
  audioByMid: Record<string, AudioTrackStats>
  /** local outbound video */
  local: TrackStats | null
  set: (patch: Partial<Omit<StatsState, "set">>) => void
}

export const useStatsStore = create<StatsState>((set) => ({
  byMid: {},
  audioByMid: {},
  local: null,
  set: (patch) => set(patch),
}))
