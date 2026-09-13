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

/** Selected capture/playback devices (ids from enumerateDevices). */
export interface DeviceSelection {
  micId: string | null
  camId: string | null
  speakerId: string | null
}

export interface DeviceLists {
  mics: MediaDeviceInfo[]
  cams: MediaDeviceInfo[]
  speakers: MediaDeviceInfo[]
}

export interface ChatMessage {
  id: string
  participantId: string
  displayName: string
  text: string
  /** ms since epoch (server clock). */
  sentAt: number
  /** Sent by us — right-aligned, no name. */
  self: boolean
}

/** Uplink health derived from the publisher PC's getStats. */
export type UplinkQuality = "good" | "fair" | "poor" | "unknown"

/** Reconnect state machine for the signaling socket. */
export type ReconnectState =
  | { kind: "connected" }
  | { kind: "reconnecting"; attempt: number; nextInMs: number }
  | { kind: "failed" }

export type Theme = "system" | "light" | "dark"

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

  // ── devices (owned by lib/devices.ts + lib/media.ts) ─────────────────────
  devices: DeviceLists
  /** Prefs — survive reset(); persisted to localStorage by lib/devices.ts. */
  selectedDevices: DeviceSelection
  /** Front/back on phones: current camera facing, when known. */
  camFacing: "user" | "environment" | null
  /** Live mic input level 0..1 (analyser on the local audio track). */
  micLevel: number

  // ── screen share (owned by lib/session.ts) ───────────────────────────────
  /** Local screen-share track's MediaStream while sharing. */
  screenStream: MediaStream | null
  /** Remote screen-share video mids (trackId === "screen"). */
  screenShareMids: string[]

  // ── reconnect (owned by lib/session.ts) ──────────────────────────────────
  reconnect: ReconnectState
  /** Why the last call ended — shown on the "call ended" screen. */
  endedReason: string | null

  // ── chat (owned by lib/session.ts) ───────────────────────────────────────
  chat: ChatMessage[]
  chatOpen: boolean
  /** Messages received while the chat panel was closed. */
  chatUnread: number

  // ── quality / speaking (owned by lib/webrtc.ts stats + lib/session.ts) ──
  /** Our own uplink health from qualityLimitationReason/loss/RTT. */
  uplinkQuality: UplinkQuality
  /** Per-remote-participant quality from inbound stats (loss/jitter). */
  remoteQuality: Record<string, UplinkQuality>
  /** Mic muted but the analyser hears speech — "you're muted" hint. */
  talkingWhileMuted: boolean
  /** Deafen: every remote <audio> sink muted locally (peers unaffected). */
  remoteAudioMuted: boolean

  // ── UI prefs (survive reset()) ──────────────────────────────────────────
  theme: Theme
  shortcutsOpen: boolean
  /** Auto-pin whoever is speaking (speaker view). */
  speakerView: boolean

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
  camFacing: null as "user" | "environment" | null,
  micLevel: 0,
  screenStream: null,
  screenShareMids: [] as string[],
  reconnect: { kind: "connected" } as ReconnectState,
  endedReason: null as string | null,
  chat: [] as ChatMessage[],
  chatOpen: false,
  chatUnread: 0,
  uplinkQuality: "unknown" as UplinkQuality,
  remoteQuality: {} as Record<string, UplinkQuality>,
  talkingWhileMuted: false,
  remoteAudioMuted: false,
  shortcutsOpen: false,
}

export const useCallStore = create<CallState>((set) => ({
  ...initial,
  soundsEnabled: true,
  showStats: false,
  devices: { mics: [], cams: [], speakers: [] },
  selectedDevices: { micId: null, camId: null, speakerId: null },
  theme: "system",
  speakerView: false,
  set: (partial) => set(partial),
  setPinned: (id) => set({ pinnedId: id }),
  reset: () => set({ ...initial }),
}))
