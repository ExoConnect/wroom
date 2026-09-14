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
//
// Reconnect: a socket that closes after a successful join (or an ICE "failed"
// on either PC) triggers a rejoin loop — bounded exponential backoff, fresh
// SignalingClient + fresh RtcManager per attempt, same capture reused. The
// server treats the rejoin as a NEW participant, so remote-side state is
// cleared when the new JoinResponse lands.

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
  type ChatMessage as ChatMessageProto,
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
} from "@/gen/wroom/signaling/v1/signaling_pb"
import { CLIENT_NAME, CLIENT_VERSION, signalingUrl } from "./config"
import {
  getLocalMedia,
  releaseLocalMedia,
  setCameraEnabled,
  setMicEnabled,
  setRtcForMedia,
  startMicMeter,
  stopMicMeter,
  LOCAL_TRACK_IDS,
} from "./media"
import { mintDevToken } from "./token"
import { SignalingClient } from "./signaling"
import { RtcManager, type RtcEvents } from "./webrtc"
import { useCallStore, type ChatMessage } from "@/store/call"

/** M0 subscription policy: subscribe to everything, audio outranks video. */
const SUB_PRIORITY: Record<number, number> = {
  [TrackKind.AUDIO]: 200,
  [TrackKind.VIDEO]: 100,
}
/** Wait this long after socket-open for the publisher offer before joining
 *  without it (offer then goes out as a standalone SessionDescription). */
const OFFER_GRACE_MS = 1500
/** Signaling reconnect: exponential backoff 500ms → 8s, ×2 with ±20% jitter. */
const RECONNECT_BASE_MS = 500
const RECONNECT_MAX_MS = 8000
const RECONNECT_ATTEMPTS = 8
/** Chat history is bounded — oldest messages drop off the front. */
const CHAT_LIMIT = 500

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

  // ── reconnect state ─────────────────────────────────────────────────────
  /** True while the backoff/reattempt loop owns the session. */
  private reconnecting = false
  /** Resolves the in-flight backoff sleep early (visibility / user retry). */
  private reconnectWake: (() => void) | null = null
  /** Settle handles for the join attempt currently in flight — resolved by
   *  the next JoinResponse, rejected if the socket closes first. */
  private attemptDone: { ok: () => void; fail: (err: Error) => void } | null = null
  /** The next JoinResponse is a rejoin — remote state must be cleared. */
  private rejoinPending = false
  /** Every participant id we have joined as — reconnects change our id, but
   *  chat messages we sent earlier must keep rendering as ours. */
  private selfIds = new Set<string>()

  constructor() {
    // A socket that died while the tab was hidden is retried the moment the
    // tab comes back — no reason to sit out the rest of the backoff.
    document.addEventListener("visibilitychange", () => {
      if (
        document.visibilityState === "visible" &&
        this.reconnecting &&
        !this.sig?.isOpen
      ) {
        this.reconnectWake?.()
      }
    })
  }

  async join(roomName: string, displayName: string): Promise<void> {
    const s = store()
    if (s.phase !== "idle" && s.phase !== "closed") return
    s.set({
      phase: "media",
      notice: null,
      endedReason: null,
      roomName,
      selfName: displayName,
    })

    // 1. Local media — usually already captured by the join-screen preview.
    const media = await getLocalMedia()
    this.localStream = media.stream
    const micTrack = media.stream.getAudioTracks()[0]
    if (micTrack) startMicMeter(micTrack)
    store().set({
      localStream: media.stream,
      micEnabled: micTrack?.enabled ?? false,
      camEnabled: media.stream.getVideoTracks()[0]?.enabled ?? false,
      notice: media.ok ? null : (media.error ?? null),
    })

    // 2. Signaling socket + RTC manager, connected in parallel.
    store().set({ phase: "connecting" })
    this.rtc = this.newRtcManager()
    this.sig = this.newSignalingClient()
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
    // The socket may have died while the offer was being built — its onClose
    // already ran teardown; don't touch the dead session.
    if (!this.sig) return
    this.sendJoin(this.sig, publisherOffer)
    // Late offer → send standalone right after join.
    if (!publisherOffer) {
      publisherOffer = await offerPromise
      if (publisherOffer) this.sig?.sendSessionDescription(publisherOffer)
    }
  }

  leave(): void {
    this.sig?.leave()
    this.teardown(null)
  }

  /** Retry a broken connection: skip the remaining backoff while the loop is
   *  running, or rejoin outright once the call has already ended. */
  retryReconnect(): void {
    if (this.reconnecting) {
      this.reconnectWake?.()
      return
    }
    const s = store()
    if (s.phase === "closed" && s.roomName) {
      void this.join(s.roomName, s.selfName)
    } else if (this.joined) {
      this.beginReconnect()
    }
  }

  /** Toggle mic/cam: delegates capture control to lib/media, then
   *  republishes the Track announcement (mute flag). */
  setTrackEnabled(id: string, enabled: boolean): void {
    void this.applyTrackEnabled(id, enabled)
  }

  private async applyTrackEnabled(id: string, enabled: boolean): Promise<void> {
    try {
      if (id === LOCAL_TRACK_IDS.mic) setMicEnabled(enabled)
      else if (id === LOCAL_TRACK_IDS.cam) await setCameraEnabled(enabled)
      else return
    } catch (err) {
      console.warn("[session] track toggle failed", err)
      return
    }
    store().set(
      id === LOCAL_TRACK_IDS.mic ? { micEnabled: enabled } : { camEnabled: enabled },
    )
    const track = this.rtc?.localTrackAnnouncement(id)
    if (track) {
      const msg: UpdateLocalTracks = create(UpdateLocalTracksSchema, {
        publish: [track],
        unpublish: [],
      })
      this.sig?.updateLocalTracks(msg)
    }
  }

  /** Send a room chat message. The server echoes it back as a ChatMessage —
   *  no local echo, ordering is server-defined. */
  sendChat(text: string): void {
    const trimmed = text.trim()
    if (!trimmed || !this.joined) return
    this.sig?.sendChat(trimmed)
  }

  // ── screen share ─────────────────────────────────────────────────────────

  /** Capture the screen, add a third sendonly transceiver on the publisher
   *  PC, send the renegotiation offer, then announce the "screen" track. */
  async startScreenShare(): Promise<void> {
    const rtc = this.rtc
    if (!rtc || !this.joined || store().screenStream) return
    let stream: MediaStream
    try {
      stream = await navigator.mediaDevices.getDisplayMedia({
        video: { frameRate: { ideal: 30 } },
        audio: false,
      })
    } catch (err) {
      // Canceling the picker (NotAllowedError) is not an error worth logging.
      if (!(err instanceof DOMException && err.name === "NotAllowedError")) {
        console.warn("[session] getDisplayMedia failed", err)
      }
      return
    }
    const track = stream.getVideoTracks()[0]
    if (!track) {
      stream.getTracks().forEach((t) => t.stop())
      return
    }
    store().set({ screenStream: stream })
    try {
      const offer = await rtc.addScreenShare(track)
      this.sig?.sendSessionDescription(offer)
    } catch (err) {
      console.warn("[session] addScreenShare failed", err)
      store().set({ screenStream: null })
      stream.getTracks().forEach((t) => t.stop())
      return
    }
    const announcement = rtc.localTrackAnnouncement(LOCAL_TRACK_IDS.screen)
    if (announcement) {
      this.sig?.updateLocalTracks(
        create(UpdateLocalTracksSchema, {
          publish: [announcement],
          unpublish: [],
        }),
      )
    }
  }

  /** Stop sharing: stop the capture, drop the transceiver (new publisher
   *  offer), and unpublish the "screen" track id. */
  async stopScreenShare(): Promise<void> {
    const stream = store().screenStream
    if (!stream) return
    store().set({ screenStream: null })
    stream.getTracks().forEach((t) => t.stop())
    if (!this.rtc || !this.sig?.isOpen) return
    try {
      const offer = await this.rtc.removeScreenShare()
      this.sig.sendSessionDescription(offer)
    } catch (err) {
      console.warn("[session] removeScreenShare failed", err)
    }
    this.sig.updateLocalTracks(
      create(UpdateLocalTracksSchema, {
        publish: [],
        // UpdateLocalTracks.unpublish is `repeated string` — bare track ids.
        unpublish: [LOCAL_TRACK_IDS.screen],
      }),
    )
  }

  // ── transport construction ───────────────────────────────────────────────

  /** The RtcEvents surface — identical for the initial join and every
   *  reconnect attempt so the new PC behaves exactly like the old one. */
  private rtcEvents(): RtcEvents {
    const events: RtcEvents = {
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
        // A dead ICE path cannot be revived in place — rejoin with fresh PCs.
        if (state === "failed" && this.joined) this.beginReconnect()
      },
      // The browser's own "stop sharing" chrome ends the screen track outside
      // our control — run the same teardown path as the UI button.
      onScreenShareEnded: () => void this.stopScreenShare(),
    }
    return events
  }

  private newRtcManager(): RtcManager {
    const rtc = new RtcManager(this.rtcEvents())
    setRtcForMedia(rtc)
    // Debug handle for E2E/inspection tooling (D15).
    ;(window as unknown as { __wroom?: unknown }).__wroom = rtc
    return rtc
  }

  private newSignalingClient(): SignalingClient {
    const sig = new SignalingClient(signalingUrl(), {
      onJoin: (msg) => void this.handleJoinResponse(msg),
      onSessionDescription: (sd) => void this.handleServerDescription(sd),
      onIceCandidates: (msg) =>
        void this.rtc?.handleRemoteCandidates(msg.target, msg.candidates),
      onRoomDelta: (d) => this.applyRoomDelta(d),
      onSubscriptionUpdate: (u) => this.applySubscriptionUpdate(u),
      onTrackDemand: (d) => void this.handleTrackDemand(d.demands),
      onActiveSpeakers: (a) => {
        store().set({
          activeSpeakers: a.speakers.map((sp) => sp.participantId),
        })
      },
      onConnectionQuality: (q) =>
        store().set({
          connectionQuality: Object.fromEntries(
            q.entries.map((e) => [e.participantId, e.quality]),
          ),
        }),
      onChat: (m) => this.appendChat(m),
      onDisconnect: (d) => this.handleServerDisconnect(d),
      onProtocolError: (err) => console.warn("[session] protocol error", err),
      onClose: () => this.handleSocketClose(sig),
    })
    return sig
  }

  /** Write the JoinRequest and flush any candidates the PC produced while
   *  the socket was connecting — join MUST be the first frame on the wire. */
  private sendJoin(
    sig: SignalingClient,
    publisherOffer: SessionDescription | null,
  ): void {
    const s = store()
    sig.join(
      create(JoinRequestSchema, {
        token: mintDevToken(s.roomName, s.selfName),
        client: create(ClientInfoSchema, {
          name: CLIENT_NAME,
          version: CLIENT_VERSION,
        }),
        publisherOffer: publisherOffer ?? undefined,
      }),
    )
    this.joinSent = true
    for (const [target, candidates] of this.preJoinCandidates) {
      sig.sendIceCandidates(target, candidates)
    }
    this.preJoinCandidates = []
  }

  // ── reconnect ────────────────────────────────────────────────────────────

  /** Socket lifecycle: only the currently-owned client's close matters —
   *  stale sockets from prior attempts (or leave()) are ignored. */
  private handleSocketClose(sig: SignalingClient): void {
    if (sig !== this.sig) return
    this.sig = null
    // A close mid-attempt fails that attempt; the loop decides what follows.
    this.attemptDone?.fail(new Error("socket closed"))
    this.attemptDone = null
    if (this.reconnecting) return // the loop is already recovering
    if (this.joined) {
      this.beginReconnect()
    } else if (store().phase !== "closed" && store().phase !== "idle") {
      // Died before JoinResponse — join rejected or server unreachable.
      this.teardown("Connection to the server was lost.")
    }
  }

  private beginReconnect(): void {
    if (this.reconnecting || !this.joined) return
    this.reconnecting = true
    this.rejoinPending = true
    // Drop the dead transport — if its onClose ever fires it sees a stale
    // sig and is ignored.
    const stale = this.sig
    this.sig = null
    stale?.close()
    void this.reconnectLoop()
  }

  /** Backoff/reattempt loop: 500ms → 8s (×2, ±20% jitter), 8 attempts max.
   *  Runs while `reconnecting`; teardown/leave clears the flag to stop it. */
  private async reconnectLoop(): Promise<void> {
    for (let attempt = 1; attempt <= RECONNECT_ATTEMPTS; attempt++) {
      if (!this.reconnecting) return
      const delay = Math.round(
        Math.min(RECONNECT_BASE_MS * 2 ** (attempt - 1), RECONNECT_MAX_MS) *
          (0.8 + Math.random() * 0.4),
      )
      store().set({
        reconnect: { kind: "reconnecting", attempt, nextInMs: delay },
      })
      await this.backoff(delay)
      if (!this.reconnecting) return // leave()/teardown while waiting
      try {
        await this.reconnectOnce()
        // The socket can die in the gap between JoinResponse and here — its
        // onClose saw `reconnecting` and deferred to the loop. Treat it as a
        // failed attempt instead of declaring victory on a dead socket.
        if (!this.sig?.isOpen) throw new Error("socket closed during rejoin")
        this.reconnecting = false
        store().set({ reconnect: { kind: "connected" } })
        return
      } catch (err) {
        console.warn(`[session] reconnect attempt ${attempt} failed`, err)
      }
    }
    store().set({ reconnect: { kind: "failed" } })
    this.teardown("Could not reconnect.")
  }

  /** Interruptible sleep — `reconnectWake` resolves it early. */
  private backoff(ms: number): Promise<void> {
    return new Promise((resolve) => {
      const timer = window.setTimeout(() => {
        this.reconnectWake = null
        resolve()
      }, ms)
      this.reconnectWake = () => {
        window.clearTimeout(timer)
        this.reconnectWake = null
        resolve()
      }
    })
  }

  /**
   * One rejoin attempt: fresh socket, fresh RtcManager on the still-live
   * capture, JoinRequest (publisher offer inside when ready), resolved by
   * the JoinResponse in handleJoinResponse.
   *
   * A brand-new PC per attempt (rather than restartIce on the old one) is
   * deliberate: the server treats the rejoin as a new participant, so the
   * old transceivers/mids are meaningless — and candidates gathered during
   * a dead socket would be lost, while a fresh PC re-trickles them on the
   * live one. The local capture (cam/mic/screen tracks) survives untouched.
   */
  private async reconnectOnce(): Promise<void> {
    const sig = this.newSignalingClient()
    this.sig = sig
    sig.connect()
    await sig.waitOpen() // rejects on close → attempt fails

    this.rtc?.close()
    const rtc = this.newRtcManager()
    this.rtc = rtc

    // Candidates the new PC produces before join must not hit the wire first.
    this.joinSent = false
    this.preJoinCandidates = []

    const offerPromise = (async (): Promise<SessionDescription> => {
      const offer = await rtc.createPublisherOffer(this.localStream)
      // Screen share re-attaches on the fresh PC — the old transceiver's mid
      // means nothing to the new server session.
      const screenTrack = store().screenStream?.getVideoTracks()[0] ?? null
      if (screenTrack && screenTrack.readyState === "live") {
        return rtc.addScreenShare(screenTrack)
      }
      return offer
    })().catch((err) => {
      console.warn("[session] publisher offer failed", err)
      return null
    })

    let publisherOffer = await Promise.race([
      offerPromise,
      new Promise<null>((r) => setTimeout(() => r(null), OFFER_GRACE_MS)),
    ])

    // The socket may have died while the offer was being built — its onClose
    // ran before `attemptDone` existed, so `done` would never settle.
    if (this.sig !== sig || !sig.isOpen) {
      throw new Error("socket lost mid-attempt")
    }

    const done = new Promise<void>((ok, fail) => {
      this.attemptDone = { ok, fail }
    })
    try {
      this.sendJoin(sig, publisherOffer)
      // Late offer → standalone SessionDescription right after join.
      if (!publisherOffer) {
        publisherOffer = await offerPromise
        if (publisherOffer) sig.sendSessionDescription(publisherOffer)
      }
      await done
    } finally {
      this.attemptDone = null
    }
  }

  // ── server message application ───────────────────────────────────────────

  private handleJoinResponse(msg: JoinResponse): void {
    this.joined = true
    this.selfIds.add(msg.participantId)
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

    if (this.rejoinPending) {
      // Rejoin = new participant on a fresh server session: every remote-side
      // binding (mids, screen-share mids, demanded pauses, the pin target)
      // is void. Local state — capture, chat, prefs — survives.
      this.rejoinPending = false
      this.requested.clear()
      this.subRevision = 0n
      store().set({
        remoteMedia: {},
        midToTrackRef: {},
        screenShareMids: [],
        pausedLocalTracks: {},
        pinnedId: null,
      })
    }

    store().set({
      phase: "joined",
      selfId: msg.participantId,
      participants,
      joinedAt: Date.now(),
    })

    // Announce our published tracks (mids are known post-setLocalDescription).
    const localTracks = this.rtc?.localTrackAnnouncements() ?? []
    // localTrackAnnouncements predates screen share — if it doesn't cover the
    // screen transceiver yet, announce the screen track explicitly.
    if (
      store().screenStream &&
      !localTracks.some((t) => t.id === LOCAL_TRACK_IDS.screen)
    ) {
      const screen = this.rtc?.localTrackAnnouncement(LOCAL_TRACK_IDS.screen)
      if (screen) localTracks.push(screen)
    }
    if (localTracks.length > 0) {
      this.sig?.updateLocalTracks(
        create(UpdateLocalTracksSchema, { publish: localTracks, unpublish: [] }),
      )
    }

    // M0: subscribe to every remote track in the snapshot.
    this.subscribeToRemoteTracks()

    // The server usually ships the subscriber offer inside JoinResponse.
    if (msg.subscriberOffer) void this.handleServerDescription(msg.subscriberOffer)

    // Settles a reconnect attempt — state is fully applied by this point.
    this.attemptDone?.ok()
    this.attemptDone = null
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
    // A grant can bind a screen mid after the media already arrived — catch
    // screen tracks here too, not just in addRemoteMedia.
    const s = store()
    let screenShareMids = s.screenShareMids
    for (const g of u.grants) {
      if (
        g.mid &&
        g.track?.trackId === LOCAL_TRACK_IDS.screen &&
        s.remoteMedia[g.mid] &&
        !screenShareMids.includes(g.mid)
      ) {
        screenShareMids = [...screenShareMids, g.mid]
      }
    }
    store().set({ midToTrackRef, screenShareMids })
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

  private appendChat(m: ChatMessageProto): void {
    const s = store()
    const msg: ChatMessage = {
      id: m.id || `${m.participantId}:${m.sentAtMs}`,
      participantId: m.participantId,
      displayName: m.displayName,
      text: m.text,
      sentAt: Number(m.sentAtMs),
      self: this.selfIds.has(m.participantId),
    }
    s.set({
      chat: [...s.chat, msg].slice(-CHAT_LIMIT),
      chatUnread: s.chatOpen ? s.chatUnread : s.chatUnread + 1,
    })
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
    const s = store()
    const midToTrackRef = { ...s.midToTrackRef }
    const slash = track.id.indexOf("/")
    if (slash > 0 && !midToTrackRef[mid]) {
      midToTrackRef[mid] = create(TrackRefSchema, {
        participantId: track.id.slice(0, slash),
        trackId: track.id.slice(slash + 1),
      })
    }
    const ref = midToTrackRef[mid]
    const screenShareMids =
      ref?.trackId === LOCAL_TRACK_IDS.screen && !s.screenShareMids.includes(mid)
        ? [...s.screenShareMids, mid]
        : s.screenShareMids
    s.set({
      midToTrackRef,
      remoteMedia: { ...s.remoteMedia, [mid]: { mid, track, stream } },
      screenShareMids,
    })
  }

  private removeRemoteMedia(mid: string): void {
    const s = store()
    const remoteMedia = { ...s.remoteMedia }
    delete remoteMedia[mid]
    const screenShareMids = s.screenShareMids.includes(mid)
      ? s.screenShareMids.filter((m) => m !== mid)
      : s.screenShareMids
    s.set({ remoteMedia, screenShareMids })
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
    // Stop the reconnect machinery before dismantling what it would reuse.
    this.reconnecting = false
    this.rejoinPending = false
    this.reconnectWake?.()
    this.attemptDone?.fail(new Error("session torn down"))
    this.attemptDone = null
    this.selfIds.clear()

    stopMicMeter()
    this.sig?.close()
    this.sig = null
    this.rtc?.close()
    this.rtc = null
    releaseLocalMedia(this.localStream)
    this.localStream = null
    const { roomName, selfName, screenStream } = store()
    screenStream?.getTracks().forEach((t) => t.stop())
    store().reset()
    // Keep the room identity so the call-ended screen can offer "Rejoin";
    // endedReason is null for a user-initiated leave, the detail otherwise.
    store().set({
      phase: "closed",
      notice,
      endedReason: notice,
      roomName,
      selfName,
    })
  }
}

export const session = new CallSession()

// Debug handle for reconnect/E2E tooling (D15) — sits next to __wroom (rtc).
;(window as unknown as { __wroomSession?: unknown }).__wroomSession = session

// Tab title: "wroom · <room> (<n>)" while in a call, plain "wroom" otherwise.
useCallStore.subscribe((s) => {
  document.title =
    s.phase === "joined"
      ? `wroom · ${s.roomName} (${Object.keys(s.participants).length})`
      : "wroom"
})
