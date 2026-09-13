// Call orchestration: owns the SignalingClient + RtcManager pair and applies
// every ServerMessage to the zustand store. Module-level singleton — join is
// user-triggered, so it is immune to StrictMode remounts.
//
// Join flow (two PCs, fixed roles):
//   1. local media is captured on the join screen and passed in
//   2. publisher offer is created in parallel with the WS connect; if it is
//      ready when the socket opens it rides inside JoinRequest.publisher_offer
//      (one-RTT join), otherwise it is sent right after as a standalone
//      SessionDescription — per the proto contract
//   3. JoinResponse carries ice_servers (applied to both PCs via
//      setConfiguration) and usually the subscriber offer → we answer
//   4. UpdateLocalTracks publishes our announced tracks (mids known after
//      setLocalDescription); remote tracks are subscribed to in bulk
//      (M0 forward-everything policy lives in subscribeToRemoteTracks)

import { create } from "@bufbuild/protobuf"
import {
  ClientInfoSchema,
  JoinRequestSchema,
  LayerSchema,
  ParticipantSchema,
  SubscriptionSchema,
  TrackRefSchema,
  UpdateLocalTracksSchema,
  UpdateSubscriptionsSchema,
  type Demand,
  type Disconnect,
  type JoinResponse,
  type Participant,
  type RoomDelta,
  type SessionDescription,
  type SubscriptionUpdate,
  type TrackRef,
  type UpdateLocalTracks,
  SignalTarget,
  TrackKind,
} from "@/gen/signaling/v1/signaling_pb"
import { CLIENT_NAME, CLIENT_VERSION, signalingUrl } from "./config"
import { getLocalMedia, releaseLocalMedia, LOCAL_TRACK_IDS } from "./media"
import { mintDevToken } from "./token"
import { SignalingClient } from "./signaling"
import { RtcManager } from "./webrtc"
import { useCallStore } from "@/store/call"

/** M0 subscription policy: subscribe to everything, audio outranks video. */
const SUB_PRIORITY: Record<number, number> = {
  [TrackKind.AUDIO]: 200,
  [TrackKind.VIDEO]: 100,
}
/** Wait this long after socket-open for the publisher offer before joining
 *  without it (offer then goes out as a standalone SessionDescription). */
const OFFER_GRACE_MS = 1500

const store = () => useCallStore.getState()

export class CallSession {
  private sig: SignalingClient | null = null
  private rtc: RtcManager | null = null
  private subRevision = 0n
  private joined = false
  /** `join` has been written to the socket. Publisher ICE gathering starts
   *  while the socket is still connecting, so candidates can be ready before
   *  join — the server requires join to be the first frame, so anything
   *  produced earlier is held here and flushed right after join. */
  private joinSent = false
  private preJoinCandidates: Array<[SignalTarget, string[]]> = []
  /** Local media captured for this session (stopped on teardown). */
  private localStream: MediaStream | null = null

  async join(roomName: string, displayName: string): Promise<void> {
    const s = store()
    if (s.phase !== "idle" && s.phase !== "closed") return
    s.set({ phase: "media", notice: null, roomName, selfName: displayName })

    // 1. Local media — usually already captured by the join-screen preview.
    const media = await getLocalMedia()
    this.localStream = media.stream
    store().set({
      localStream: media.stream,
      micEnabled: media.stream.getAudioTracks()[0]?.enabled ?? false,
      camEnabled: media.stream.getVideoTracks()[0]?.enabled ?? false,
      notice: media.ok ? null : (media.error ?? null),
    })

    // 2. Signaling socket + RTC manager, connected in parallel.
    store().set({ phase: "connecting" })
    this.rtc = new RtcManager({
      onLocalDescription: (sd) => this.sig?.sendSessionDescription(sd),
      onIceCandidates: (target, candidates) => {
        if (this.joinSent) this.sig?.sendIceCandidates(target, candidates)
        else this.preJoinCandidates.push([target, candidates])
      },
      onRemoteTrack: (mid, track) => this.addRemoteMedia(mid, track),
      onRemoteTrackEnded: (mid) => this.removeRemoteMedia(mid),
      onConnectionStateChange: (target, state) => {
        const key =
          target === SignalTarget.PUBLISHER ? "pubConnState" : "subConnState"
        store().set({ [key]: state })
      },
    })
    // Debug handle for E2E/inspection tooling (D15).
    ;(window as unknown as { __wroom?: unknown }).__wroom = this.rtc
    this.sig = new SignalingClient(signalingUrl(), {
      onJoin: (msg) => void this.handleJoinResponse(msg),
      onSessionDescription: (sd) => void this.handleServerDescription(sd),
      onIceCandidates: (msg) =>
        void this.rtc?.handleRemoteCandidates(msg.target, msg.candidates),
      onRoomDelta: (d) => this.applyRoomDelta(d),
      onSubscriptionUpdate: (u) => this.applySubscriptionUpdate(u),
      onTrackDemand: (d) => void this.handleTrackDemand(d.demands),
      onActiveSpeakers: (a) =>
        store().set({ activeSpeakers: a.speakers.map((sp) => sp.participantId) }),
      onConnectionQuality: (q) =>
        store().set({
          connectionQuality: Object.fromEntries(
            q.entries.map((e) => [e.participantId, e.quality]),
          ),
        }),
      onDisconnect: (d) => this.handleServerDisconnect(d),
      onProtocolError: (err) => console.warn("[session] protocol error", err),
      onClose: () => {
        // Any close while a session object is live ends the call — including
        // closes before JoinResponse (join rejected / server down).
        if (this.sig) this.teardown("Connection to the server was lost.")
      },
    })
    this.sig.connect()

    // 3. Publisher offer, racing socket open. Whichever finishes first decides
    //    whether the offer rides inside JoinRequest (fast path) or goes out as
    //    a standalone SessionDescription right after.
    const offerPromise = this.rtc
      .createPublisherOffer(media.stream)
      .catch((err) => {
        console.warn("[session] publisher offer failed", err)
        return null
      })

    try {
      await this.sig.waitOpen()
    } catch {
      this.teardown("Could not reach the signaling server.")
      return
    }
    store().set({ phase: "joining" })

    let publisherOffer = await Promise.race([
      offerPromise,
      new Promise<null>((r) => setTimeout(() => r(null), OFFER_GRACE_MS)),
    ])
    this.sig.join(
      create(JoinRequestSchema, {
        token: mintDevToken(roomName, displayName),
        client: create(ClientInfoSchema, { name: CLIENT_NAME, version: CLIENT_VERSION }),
        publisherOffer: publisherOffer ?? undefined,
      }),
    )
    this.joinSent = true
    for (const [target, candidates] of this.preJoinCandidates) {
      this.sig.sendIceCandidates(target, candidates)
    }
    this.preJoinCandidates = []
    // Late offer → send standalone right after join.
    if (!publisherOffer) {
      publisherOffer = await offerPromise
      if (publisherOffer) this.sig.sendSessionDescription(publisherOffer)
    }
  }

  leave(): void {
    this.sig?.leave()
    this.teardown(null)
  }

  /** Toggle mic/cam: flips track.enabled and republishes the Track (mute). */
  setTrackEnabled(id: string, enabled: boolean): void {
    if (!this.rtc?.setTrackEnabled(id, enabled)) return
    const s = store()
    if (id === LOCAL_TRACK_IDS.mic) s.set({ micEnabled: enabled })
    if (id === LOCAL_TRACK_IDS.cam) s.set({ camEnabled: enabled })
    const track = this.rtc.localTrackAnnouncement(id)
    if (track) {
      const msg: UpdateLocalTracks = create(UpdateLocalTracksSchema, {
        publish: [track],
        unpublish: [],
      })
      this.sig?.updateLocalTracks(msg)
    }
  }

  // ── server message application ───────────────────────────────────────────

  private handleJoinResponse(msg: JoinResponse): void {
    this.joined = true
    this.rtc?.setIceServers(msg.iceServers)

    const participants: Record<string, Participant> = {}
    for (const p of msg.room?.participants ?? []) participants[p.id] = p
    // If the snapshot doesn't echo us back, add ourselves for the UI.
    if (msg.participantId && !participants[msg.participantId]) {
      participants[msg.participantId] = create(ParticipantSchema, {
        id: msg.participantId,
        name: store().selfName,
        tracks: this.rtc?.localTrackAnnouncements() ?? [],
      })
    }

    store().set({
      phase: "joined",
      selfId: msg.participantId,
      participants,
    })

    // Announce our published tracks (mids are known post-setLocalDescription).
    const localTracks = this.rtc?.localTrackAnnouncements() ?? []
    if (localTracks.length > 0) {
      this.sig?.updateLocalTracks(
        create(UpdateLocalTracksSchema, { publish: localTracks, unpublish: [] }),
      )
    }

    // M0: subscribe to every remote track in the snapshot.
    this.subscribeToRemoteTracks()

    // The server usually ships the subscriber offer inside JoinResponse.
    if (msg.subscriberOffer) void this.handleServerDescription(msg.subscriberOffer)
  }

  private async handleServerDescription(sd: SessionDescription): Promise<void> {
    try {
      await this.rtc?.handleRemoteDescription(sd)
    } catch (err) {
      console.warn("[session] remote description failed", err)
    }
  }

  private applyRoomDelta(d: RoomDelta): void {
    const s = store()
    const participants = { ...s.participants }
    let changed = false

    for (const p of d.joined) {
      participants[p.id] = p
      changed = true
    }
    for (const id of d.left) {
      if (participants[id]) {
        delete participants[id]
        changed = true
      }
      this.dropRemoteMediaFor(id)
    }
    for (const pub of d.published) {
      const p = participants[pub.participantId]
      if (p && pub.track) {
        participants[pub.participantId] = { ...p, tracks: [...p.tracks, pub.track] }
        changed = true
      }
    }
    for (const ref of d.unpublished) {
      const p = participants[ref.participantId]
      if (p) {
        participants[ref.participantId] = {
          ...p,
          tracks: p.tracks.filter((t) => t.id !== ref.trackId),
        }
        changed = true
      }
      this.dropRemoteMediaForRef(ref)
    }
    for (const mc of d.muteChanges) {
      const ref = mc.track
      const p = ref ? participants[ref.participantId] : undefined
      if (p && ref) {
        participants[p.id] = {
          ...p,
          tracks: p.tracks.map((t) => (t.id === ref.trackId ? { ...t, muted: mc.muted } : t)),
        }
        changed = true
      }
    }

    if (changed) s.set({ participants })
    this.subscribeToRemoteTracks()
  }

  private applySubscriptionUpdate(u: SubscriptionUpdate): void {
    const midToTrackRef = { ...store().midToTrackRef }
    for (const g of u.grants) {
      if (g.mid && g.track) midToTrackRef[g.mid] = g.track
    }
    store().set({ midToTrackRef })
  }

  private async handleTrackDemand(demands: Demand[]): Promise<void> {
    await this.rtc?.applyTrackDemands(demands)
    const paused: Record<string, boolean> = {}
    for (const d of demands) paused[d.trackId] = d.paused
    store().set({ pausedLocalTracks: { ...store().pausedLocalTracks, ...paused } })
  }

  private handleServerDisconnect(d: Disconnect): void {
    const reason = d.detail || `Disconnected (reason ${d.reason})`
    this.teardown(reason)
  }

  // ── subscriptions (M0 policy: subscribe to every remote track) ──────────

  /** Requested subscription set, keyed "participantId/trackId". Diffed against
   *  desired state; the server's SubscriptionUpdate only supplies mid mapping. */
  private requested = new Set<string>()

  private subscribeToRemoteTracks(): void {
    if (!this.sig?.isOpen || !this.joined) return
    const { participants, selfId } = store()

    // Desired set: every track belonging to remote participants.
    const desired = new Map<string, { ref: TrackRef; kind: TrackKind }>()
    for (const p of Object.values(participants)) {
      if (p.id === selfId) continue
      for (const t of p.tracks) {
        desired.set(`${p.id}/${t.id}`, {
          ref: create(TrackRefSchema, { participantId: p.id, trackId: t.id }),
          kind: t.kind,
        })
      }
    }

    const upsert = [...desired.entries()]
      .filter(([key]) => !this.requested.has(key))
      .map(([, d]) =>
        create(SubscriptionSchema, {
          track: d.ref,
          maxLayer: create(LayerSchema, { spatial: 0, temporal: 0 }),
          priority: SUB_PRIORITY[d.kind] ?? 50,
        }),
      )
    const remove = [...this.requested]
      .filter((key) => !desired.has(key))
      .map((key) => {
        const [participantId, trackId] = key.split("/")
        return create(TrackRefSchema, { participantId, trackId })
      })

    if (upsert.length === 0 && remove.length === 0) return
    for (const s of upsert) {
      if (s.track) this.requested.add(`${s.track.participantId}/${s.track.trackId}`)
    }
    for (const r of remove) this.requested.delete(`${r.participantId}/${r.trackId}`)
    this.sig.updateSubscriptions(
      create(UpdateSubscriptionsSchema, {
        upsert,
        remove,
        revision: ++this.subRevision,
      }),
    )
  }

  // ── remote media bookkeeping ─────────────────────────────────────────────

  private addRemoteMedia(mid: string, track: MediaStreamTrack): void {
    const stream = new MediaStream([track])
    // The subscriber offer names each m-line `a=msid:- <participant>/<track>`
    // (owner-namespaced — see wroomd offer_subscriber), which the browser
    // surfaces as track.id. That is the authoritative mid → room-track
    // binding; SubscriptionUpdate.grants may lag or be empty.
    const midToTrackRef = { ...store().midToTrackRef }
    const slash = track.id.indexOf("/")
    if (slash > 0 && !midToTrackRef[mid]) {
      midToTrackRef[mid] = create(TrackRefSchema, {
        participantId: track.id.slice(0, slash),
        trackId: track.id.slice(slash + 1),
      })
    }
    store().set({
      midToTrackRef,
      remoteMedia: { ...store().remoteMedia, [mid]: { mid, track, stream } },
    })
  }

  private removeRemoteMedia(mid: string): void {
    const remoteMedia = { ...store().remoteMedia }
    delete remoteMedia[mid]
    store().set({ remoteMedia })
  }

  private dropRemoteMediaFor(participantId: string): void {
    const midToTrackRef = { ...store().midToTrackRef }
    for (const [mid, ref] of Object.entries(midToTrackRef)) {
      if (ref.participantId === participantId) {
        this.removeRemoteMedia(mid)
        delete midToTrackRef[mid]
      }
    }
    store().set({ midToTrackRef })
  }

  private dropRemoteMediaForRef(ref: TrackRef): void {
    const midToTrackRef = { ...store().midToTrackRef }
    for (const [mid, r] of Object.entries(midToTrackRef)) {
      if (r.participantId === ref.participantId && r.trackId === ref.trackId) {
        this.removeRemoteMedia(mid)
        delete midToTrackRef[mid]
      }
    }
    store().set({ midToTrackRef })
  }

  // ── teardown ─────────────────────────────────────────────────────────────

  private teardown(notice: string | null): void {
    this.joined = false
    this.joinSent = false
    this.preJoinCandidates = []
    this.subRevision = 0n
    this.requested.clear()
    this.sig?.close()
    this.sig = null
    this.rtc?.close()
    this.rtc = null
    releaseLocalMedia(this.localStream)
    this.localStream = null
    store().reset()
    store().set({ phase: "closed", notice })
  }
}

export const session = new CallSession()
