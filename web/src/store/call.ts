// Call state store (zustand). The session layer (lib/session.ts) is the only
// writer; components subscribe read-only.

import { create } from "zustand"
import type {
  ConnectionQuality,
  Participant,
  TrackRef,
} from "@/gen/signaling/v1/signaling_pb"

export type CallPhase =
  | "idle" // join screen
  | "media" // requesting local capture
  | "connecting" // opening the signaling socket
  | "joining" // JoinRequest sent, awaiting JoinResponse
  | "joined" // in the call
  | "closed" // left / disconnected — back to join screen with a notice

export interface RemoteMedia {
  /** m-line on the subscriber PC that carries this track. */
  mid: string
  track: MediaStreamTrack
  stream: MediaStream
}

interface CallState {
  phase: CallPhase
  /** User-facing notice for the join screen (errors, disconnect reasons). */
  notice: string | null
  roomName: string
  selfId: string
  selfName: string
  /** All participants incl. self, keyed by id — snapshot + RoomDelta applied. */
  participants: Record<string, Participant>
  /** mid → {participantId, trackId} from SubscriptionGrant, for labeling. */
  midToTrackRef: Record<string, TrackRef>
  /** Live remote tracks keyed by subscriber-PC mid. */
  remoteMedia: Record<string, RemoteMedia>
  localStream: MediaStream | null
  micEnabled: boolean
  camEnabled: boolean
  /** Ids of local tracks the server has paused via TrackDemand. */
  pausedLocalTracks: Record<string, boolean>
  /** Ordered loudest-first participant ids. */
  activeSpeakers: string[]
  connectionQuality: Record<string, ConnectionQuality>
  pubConnState: RTCPeerConnectionState | null
  subConnState: RTCPeerConnectionState | null
  /** Participant (or `mid:<mid>` orphan tile) shown on the big stage. */
  pinnedId: string | null
  /** Participants side panel — collapsed by default. */
  participantsOpen: boolean
  /** UI blips (pref — survives reset()). */
  soundsEnabled: boolean
  /** Per-tile stats badge (pref — survives reset()). */
  showStats: boolean

  set(partial: Partial<CallState>): void
  setPinned(id: string | null): void
  reset(): void
}

const initial = {
  phase: "idle" as CallPhase,
  notice: null,
  roomName: "",
  selfId: "",
  selfName: "",
  participants: {},
  midToTrackRef: {},
  remoteMedia: {},
  localStream: null,
  micEnabled: true,
  camEnabled: true,
  pausedLocalTracks: {},
  activeSpeakers: [],
  connectionQuality: {},
  pubConnState: null,
  subConnState: null,
  pinnedId: null,
  participantsOpen: false,
}

export const useCallStore = create<CallState>((set) => ({
  ...initial,
  soundsEnabled: true,
  showStats: false,
  set: (partial) => set(partial),
  setPinned: (id) => set({ pinnedId: id }),
  reset: () => set({ ...initial }),
}))
