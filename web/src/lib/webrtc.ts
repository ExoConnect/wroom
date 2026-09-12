// Dual-RTCPeerConnection media manager (locked design: one PC for publishing,
// one for subscribing — SignalTarget.PUBLISHER / SignalTarget.SUBSCRIBER).
//
//   PUBLISHER  — client is the offerer. Cam/mic are attached as sendonly
//                transceivers, we createOffer and ship the SDP over signaling.
//   SUBSCRIBER — server is the offerer. Its offer arrives in JoinResponse (or
//                later as subscriptions change), we answer.
//
// The manager never talks to the socket itself; it emits SessionDescription /
// IceCandidates payloads through callbacks and the session layer sends them.
//
// ICE candidates travel as JSON-serialized RTCIceCandidateInit inside
// IceCandidates.candidates (repeated string). If the server ends up expecting
// bare "candidate:" attribute strings instead, only encodeIceCandidate /
// decodeIceCandidate need to change.

import { create } from "@bufbuild/protobuf"
import {
  LayerSchema,
  SessionDescriptionSchema,
  SessionDescription_Type,
  SignalTarget,
  type Demand,
  type IceServer,
  type SessionDescription,
  type Track,
  TrackKind,
  TrackSource,
  TrackSchema,
} from "@/gen/signaling/v1/signaling_pb"
import { LOCAL_TRACK_IDS } from "./media"

export interface RtcEvents {
  /** A locally produced SDP that must be sent over signaling. */
  onLocalDescription?: (sd: SessionDescription) => void
  /** Batched trickle candidates (empty array = end-of-candidates). */
  onIceCandidates?: (target: SignalTarget, candidates: string[]) => void
  /** A remote MediaStreamTrack arrived on the subscriber PC. `mid` correlates
   *  it to SubscriptionGrant.mid / Track.mid. */
  onRemoteTrack?: (mid: string, track: MediaStreamTrack) => void
  /** A remote track ended (stream removal signaled at the RTP level). */
  onRemoteTrackEnded?: (mid: string, track: MediaStreamTrack) => void
  onConnectionStateChange?: (target: SignalTarget, state: RTCPeerConnectionState) => void
}

/** How long to accumulate ICE candidates before flushing a batch (ms). */
const ICE_BATCH_WINDOW_MS = 40

function encodeIceCandidate(candidate: RTCIceCandidate): string {
  return JSON.stringify(candidate.toJSON())
}

function decodeIceCandidate(raw: string): RTCIceCandidateInit {
  try {
    return JSON.parse(raw) as RTCIceCandidateInit
  } catch {
    // Fallback for a bare candidate-attribute string.
    return { candidate: raw }
  }
}

function toRtcIceServers(servers: IceServer[]): RTCIceServer[] {
  return servers.map((s) => ({
    urls: s.urls,
    username: s.username || undefined,
    credential: s.credential || undefined,
  }))
}

function sdToProto(
  target: SignalTarget,
  desc: RTCSessionDescriptionInit,
): SessionDescription {
  return create(SessionDescriptionSchema, {
    target,
    type:
      desc.type === "offer" ? SessionDescription_Type.OFFER : SessionDescription_Type.ANSWER,
    sdp: desc.sdp ?? "",
  })
}

export class RtcManager {
  private publisher: RTCPeerConnection
  private subscriber: RTCPeerConnection
  private iceServers: IceServer[] = []

  private audioTransceiver: RTCRtpTransceiver | null = null
  private videoTransceiver: RTCRtpTransceiver | null = null

  /** ICE candidates arriving from the server before remoteDescription is set. */
  private pendingRemoteCandidates: Record<"publisher" | "subscriber", string[]> = {
    publisher: [],
    subscriber: [],
  }
  /** Outbound candidate batching per PC. */
  private localCandidateBuf: Record<"publisher" | "subscriber", string[]> = {
    publisher: [],
    subscriber: [],
  }
  private localCandidateTimer: Record<"publisher" | "subscriber", number | null> = {
    publisher: null,
    subscriber: null,
  }
  /** mid → remote track bookkeeping for ended/removal. */
  private remoteTracks = new Map<string, MediaStreamTrack>()
  /** Local tracks paused by TrackDemand — kept so they can be restored. */
  private pausedTracks = new Map<string, MediaStreamTrack>()

  constructor(private readonly events: RtcEvents) {
    this.publisher = this.createPeer("publisher")
    this.subscriber = this.createPeer("subscriber")
  }

  private createPeer(which: "publisher" | "subscriber"): RTCPeerConnection {
    // STUN-less by default: wroomd supplies ice_servers in JoinResponse
    // (server may run ICE-lite on a public address; TURN arrives the same way).
    const pc = new RTCPeerConnection({ iceServers: toRtcIceServers(this.iceServers) })
    const target = which === "publisher" ? SignalTarget.PUBLISHER : SignalTarget.SUBSCRIBER

    pc.onicecandidate = (ev) => {
      if (ev.candidate) {
        this.localCandidateBuf[which].push(encodeIceCandidate(ev.candidate))
        this.scheduleCandidateFlush(which, target)
      } else {
        // null candidate: gathering finished — flush what we have, then send
        // the empty list that marks end-of-candidates.
        this.flushCandidates(which, target)
        this.events.onIceCandidates?.(target, [])
      }
    }
    pc.onconnectionstatechange = () => {
      this.events.onConnectionStateChange?.(target, pc.connectionState)
    }
    if (which === "subscriber") {
      pc.ontrack = (ev) => {
        const mid = ev.transceiver.mid ?? ""
        this.remoteTracks.set(mid, ev.track)
        ev.track.onended = () => {
          this.remoteTracks.delete(mid)
          this.events.onRemoteTrackEnded?.(mid, ev.track)
        }
        this.events.onRemoteTrack?.(mid, ev.track)
      }
    }
    return pc
  }

  // ── ICE configuration ────────────────────────────────────────────────────

  /** Apply the ice_servers from JoinResponse to both PCs. */
  setIceServers(servers: IceServer[]): void {
    this.iceServers = servers
    const config = { iceServers: toRtcIceServers(servers) }
    this.publisher.setConfiguration(config)
    this.subscriber.setConfiguration(config)
  }

  // ── Publisher side ───────────────────────────────────────────────────────

  /**
   * Attach local media as sendonly transceivers (audio first, then video —
   * conventional m-line order) and produce the publisher offer. When a track
   * is missing we still add the transceiver by kind so the m-line exists and
   * media can be attached later via replaceTrack.
   *
   * Does NOT wait for ICE gathering — candidates trickle separately.
   */
  async createPublisherOffer(stream: MediaStream | null): Promise<SessionDescription> {
    const audio = stream?.getAudioTracks()[0] ?? null
    const video = stream?.getVideoTracks()[0] ?? null

    this.audioTransceiver = this.publisher.addTransceiver(audio ?? "audio", {
      direction: "sendonly",
    })
    this.videoTransceiver = this.publisher.addTransceiver(video ?? "video", {
      direction: "sendonly",
      // M0 sends a single layer; simulcast encodings land with layer
      // selection in a later milestone.
    })

    const offer = await this.publisher.createOffer()
    await this.publisher.setLocalDescription(offer)
    return sdToProto(SignalTarget.PUBLISHER, this.publisher.localDescription!)
  }

  /**
   * The local Track objects for UpdateLocalTracks.publish. Call only after
   * createPublisherOffer — `mid` is assigned by setLocalDescription. Mute
   * state is read from track.enabled so the PC stays the single source of
   * truth.
   */
  localTrackAnnouncements(): Track[] {
    const tracks: Track[] = []
    const audioTrack = this.audioTransceiver?.sender.track
    if (audioTrack) {
      tracks.push(
        create(TrackSchema, {
          id: LOCAL_TRACK_IDS.mic,
          kind: TrackKind.AUDIO,
          source: TrackSource.MICROPHONE,
          muted: !audioTrack.enabled,
          layers: [create(LayerSchema, { spatial: 0, temporal: 0 })],
          mid: this.audioTransceiver!.mid ?? "",
        }),
      )
    }
    const videoTrack = this.videoTransceiver?.sender.track
    if (videoTrack) {
      tracks.push(
        create(TrackSchema, {
          id: LOCAL_TRACK_IDS.cam,
          kind: TrackKind.VIDEO,
          source: TrackSource.CAMERA,
          muted: !videoTrack.enabled,
          layers: [create(LayerSchema, { spatial: 0, temporal: 0 })],
          mid: this.videoTransceiver!.mid ?? "",
        }),
      )
    }
    return tracks
  }

  /** The announce Track for one local id (for mute updates), or null. */
  localTrackAnnouncement(id: string): Track | null {
    return this.localTrackAnnouncements().find((t) => t.id === id) ?? null
  }

  /** Toggle capture on a local track (track.enabled — keeps the sender live). */
  setTrackEnabled(id: string, enabled: boolean): boolean {
    const tx = id === LOCAL_TRACK_IDS.mic ? this.audioTransceiver : this.videoTransceiver
    const track = tx?.sender.track ?? this.pausedTracks.get(id)
    if (!track) return false
    track.enabled = enabled
    return true
  }

  /**
   * Apply TrackDemand: paused tracks stop sending (replaceTrack(null)), and
   * resume by restoring the original track. max_needed (layer ceiling) is
   * ignored in M0 — a single layer is produced; layered encoding is a later
   * milestone.
   */
  async applyTrackDemands(demands: Demand[]): Promise<void> {
    for (const d of demands) {
      const tx =
        d.trackId === LOCAL_TRACK_IDS.mic
          ? this.audioTransceiver
          : d.trackId === LOCAL_TRACK_IDS.cam
            ? this.videoTransceiver
            : null
      if (!tx) continue
      if (d.paused && tx.sender.track) {
        this.pausedTracks.set(d.trackId, tx.sender.track)
        await tx.sender.replaceTrack(null)
      } else if (!d.paused && !tx.sender.track) {
        const track = this.pausedTracks.get(d.trackId)
        if (track) {
          await tx.sender.replaceTrack(track)
          this.pausedTracks.delete(d.trackId)
        }
      }
    }
  }

  // ── Subscriber side / remote SDP ─────────────────────────────────────────

  /**
   * Handle a server SessionDescription:
   *   target=SUBSCRIBER + OFFER  → set remote, create + set local, emit answer
   *   target=PUBLISHER + ANSWER  → set remote on the publisher PC
   * Anything else is logged — the roles are fixed by design.
   */
  async handleRemoteDescription(sd: SessionDescription): Promise<void> {
    if (sd.target === SignalTarget.SUBSCRIBER && sd.type === SessionDescription_Type.OFFER) {
      const pc = this.subscriber
      await pc.setRemoteDescription({ type: "offer", sdp: sd.sdp })
      await this.flushPendingRemoteCandidates("subscriber", pc)
      const answer = await pc.createAnswer()
      await pc.setLocalDescription(answer)
      this.events.onLocalDescription?.(
        sdToProto(SignalTarget.SUBSCRIBER, pc.localDescription!),
      )
      return
    }
    if (sd.target === SignalTarget.PUBLISHER && sd.type === SessionDescription_Type.ANSWER) {
      const pc = this.publisher
      await pc.setRemoteDescription({ type: "answer", sdp: sd.sdp })
      await this.flushPendingRemoteCandidates("publisher", pc)
      return
    }
    console.warn("[rtc] unexpected SessionDescription direction/type", {
      target: sd.target,
      type: sd.type,
    })
  }

  /** Handle trickled candidates from the server for a given PC. */
  async handleRemoteCandidates(target: SignalTarget, candidates: string[]): Promise<void> {
    if (candidates.length === 0) return // end-of-candidates marker — nothing to add
    const which = target === SignalTarget.PUBLISHER ? "publisher" : "subscriber"
    const pc = which === "publisher" ? this.publisher : this.subscriber
    if (!pc.remoteDescription) {
      // Queue until the remote description lands — standard trickle handling.
      this.pendingRemoteCandidates[which].push(...candidates)
      return
    }
    for (const raw of candidates) {
      try {
        await pc.addIceCandidate(decodeIceCandidate(raw))
      } catch (err) {
        console.warn("[rtc] addIceCandidate failed", err)
      }
    }
  }

  private async flushPendingRemoteCandidates(
    which: "publisher" | "subscriber",
    pc: RTCPeerConnection,
  ): Promise<void> {
    const queued = this.pendingRemoteCandidates[which]
    this.pendingRemoteCandidates[which] = []
    for (const raw of queued) {
      try {
        await pc.addIceCandidate(decodeIceCandidate(raw))
      } catch (err) {
        console.warn("[rtc] addIceCandidate (queued) failed", err)
      }
    }
  }

  // ── candidate batching ───────────────────────────────────────────────────

  private scheduleCandidateFlush(
    which: "publisher" | "subscriber",
    target: SignalTarget,
  ): void {
    if (this.localCandidateTimer[which] !== null) return
    this.localCandidateTimer[which] = window.setTimeout(() => {
      this.localCandidateTimer[which] = null
      this.flushCandidates(which, target)
    }, ICE_BATCH_WINDOW_MS)
  }

  private flushCandidates(which: "publisher" | "subscriber", target: SignalTarget): void {
    const buf = this.localCandidateBuf[which]
    if (buf.length === 0) return
    this.localCandidateBuf[which] = []
    this.events.onIceCandidates?.(target, buf)
  }

  // ── teardown ─────────────────────────────────────────────────────────────

  close(): void {
    for (const which of ["publisher", "subscriber"] as const) {
      if (this.localCandidateTimer[which] !== null) {
        clearTimeout(this.localCandidateTimer[which]!)
        this.localCandidateTimer[which] = null
      }
    }
    this.publisher.close()
    this.subscriber.close()
    this.remoteTracks.clear()
    this.pausedTracks.clear()
    this.pendingRemoteCandidates = { publisher: [], subscriber: [] }
    this.localCandidateBuf = { publisher: [], subscriber: [] }
  }
}
