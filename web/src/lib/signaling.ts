// WebSocket signaling client for wroom.signaling.v1.
//
// Transport: one binary WebSocket frame == one protobuf message —
// ClientMessage upstream, ServerMessage downstream (see
// proto/signaling/v1/signaling.proto). Encoding uses protobuf-es v2
// (create/toBinary/fromBinary/toJsonString).
//
// Debug mode (decision 15 — human-readable inspection tooling): when enabled
// via lib/config.ts#signalingDebug(), every frame is logged to the console as
// JSON, prefixed with direction arrows.

import { create, fromBinary, toBinary, toJsonString } from "@bufbuild/protobuf"
import {
  ClientMessageSchema,
  IceCandidatesSchema,
  LeaveRequestSchema,
  PongSchema,
  ServerMessageSchema,
  type ActiveSpeakers,
  type ClientMessage,
  type ConnectionQualityUpdate,
  type Disconnect,
  type IceCandidates,
  type JoinRequest,
  type JoinResponse,
  type Ping,
  type RoomDelta,
  type ServerMessage,
  type SessionDescription,
  type SignalTarget,
  type SubscriptionUpdate,
  type TrackDemand,
  type UpdateLocalTracks,
  type UpdateSubscriptions,
} from "@/gen/signaling/v1/signaling_pb"
import { signalingDebug } from "./config"

/** Typed callbacks for every ServerMessage variant plus socket lifecycle. */
export interface SignalingHandlers {
  onOpen?: () => void
  /** Socket closed — clean or not. No reconnect logic in M0. */
  onClose?: (ev: CloseEvent) => void
  /** A frame that failed to decode, or a message with no variant set. */
  onProtocolError?: (err: unknown) => void
  onJoin?: (msg: JoinResponse) => void
  onSessionDescription?: (msg: SessionDescription) => void
  onIceCandidates?: (msg: IceCandidates) => void
  onRoomDelta?: (msg: RoomDelta) => void
  onSubscriptionUpdate?: (msg: SubscriptionUpdate) => void
  onTrackDemand?: (msg: TrackDemand) => void
  onActiveSpeakers?: (msg: ActiveSpeakers) => void
  onConnectionQuality?: (msg: ConnectionQualityUpdate) => void
  onPing?: (msg: Ping) => void
  onDisconnect?: (msg: Disconnect) => void
}

export class SignalingClient {
  private ws: WebSocket | null = null
  private readonly debug = signalingDebug()
  /** Frames sent while the socket is still CONNECTING, flushed on open. */
  private outbox: Uint8Array<ArrayBuffer>[] = []

  constructor(
    private readonly url: string,
    private readonly handlers: SignalingHandlers,
  ) {}

  get isOpen(): boolean {
    return this.ws?.readyState === WebSocket.OPEN
  }

  connect(): void {
    if (this.ws && this.ws.readyState !== WebSocket.CLOSED) return
    const ws = new WebSocket(this.url)
    ws.binaryType = "arraybuffer"
    this.ws = ws

    ws.onopen = () => {
      this.log(`open ${this.url}`)
      const queued = this.outbox
      this.outbox = []
      for (const frame of queued) ws.send(frame)
      this.handlers.onOpen?.()
    }
    ws.onclose = (ev) => {
      this.log(`close code=${ev.code} reason=${ev.reason}`)
      this.handlers.onClose?.(ev)
    }
    ws.onerror = () => {
      // Browsers surface no detail here; the close event carries the info.
      this.log("socket error")
    }
    ws.onmessage = (ev) => this.handleFrame(ev.data)
  }

  /** Resolves when the socket opens; rejects if it closes/errors first. */
  waitOpen(): Promise<void> {
    if (this.isOpen) return Promise.resolve()
    const ws = this.ws
    if (!ws) return Promise.reject(new Error("connect() has not been called"))
    return new Promise((resolve, reject) => {
      ws.addEventListener("open", () => resolve(), { once: true })
      ws.addEventListener("close", () => reject(new Error("socket closed before open")), {
        once: true,
      })
    })
  }

  // ── ClientMessage senders ────────────────────────────────────────────────

  join(req: JoinRequest): void {
    this.send(create(ClientMessageSchema, { msg: { case: "join", value: req } }))
  }

  sendSessionDescription(sd: SessionDescription): void {
    this.send(create(ClientMessageSchema, { msg: { case: "sessionDescription", value: sd } }))
  }

  sendIceCandidates(target: SignalTarget, candidates: string[]): void {
    this.send(
      create(ClientMessageSchema, {
        msg: {
          case: "iceCandidates",
          value: create(IceCandidatesSchema, { target, candidates }),
        },
      }),
    )
  }

  updateSubscriptions(msg: UpdateSubscriptions): void {
    this.send(
      create(ClientMessageSchema, { msg: { case: "updateSubscriptions", value: msg } }),
    )
  }

  updateLocalTracks(msg: UpdateLocalTracks): void {
    this.send(
      create(ClientMessageSchema, { msg: { case: "updateLocalTracks", value: msg } }),
    )
  }

  sendPong(timestampMs: bigint): void {
    this.send(
      create(ClientMessageSchema, {
        msg: { case: "pong", value: create(PongSchema, { timestampMs }) },
      }),
    )
  }

  leave(): void {
    this.send(
      create(ClientMessageSchema, {
        msg: { case: "leave", value: create(LeaveRequestSchema, {}) },
      }),
    )
  }

  /** Close the socket. `graceful` sends LeaveRequest first when open. */
  close(opts?: { graceful?: boolean }): void {
    if (opts?.graceful && this.isOpen) this.leave()
    this.ws?.close()
    this.ws = null
    this.outbox = []
  }

  // ── internals ────────────────────────────────────────────────────────────

  private send(msg: ClientMessage): void {
    // toBinary allocates a fresh buffer per message — the cast only narrows
    // the generic ArrayBufferLike so WebSocket.send's BufferSource accepts it.
    const frame = toBinary(ClientMessageSchema, msg) as Uint8Array<ArrayBuffer>
    if (this.debug) {
      this.log("→", toJsonString(ClientMessageSchema, msg))
    }
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(frame)
    } else if (this.ws && this.ws.readyState === WebSocket.CONNECTING) {
      this.outbox.push(frame)
    } else {
      console.warn("[signaling] dropped message on closed socket", msg.msg.case)
    }
  }

  private handleFrame(data: unknown): void {
    let msg: ServerMessage
    try {
      const bytes =
        data instanceof Uint8Array
          ? data
          : data instanceof ArrayBuffer
            ? new Uint8Array(data)
            : new Uint8Array(data as ArrayBufferLike)
      msg = fromBinary(ServerMessageSchema, bytes)
    } catch (err) {
      this.handlers.onProtocolError?.(err)
      return
    }
    if (this.debug) {
      this.log("←", toJsonString(ServerMessageSchema, msg))
    }
    const m = msg.msg
    switch (m.case) {
      case "join":
        this.handlers.onJoin?.(m.value)
        break
      case "sessionDescription":
        this.handlers.onSessionDescription?.(m.value)
        break
      case "iceCandidates":
        this.handlers.onIceCandidates?.(m.value)
        break
      case "roomDelta":
        this.handlers.onRoomDelta?.(m.value)
        break
      case "subscriptionUpdate":
        this.handlers.onSubscriptionUpdate?.(m.value)
        break
      case "trackDemand":
        this.handlers.onTrackDemand?.(m.value)
        break
      case "activeSpeakers":
        this.handlers.onActiveSpeakers?.(m.value)
        break
      case "connectionQuality":
        this.handlers.onConnectionQuality?.(m.value)
        break
      case "ping":
        // Keepalive is answered in-band; surface it too so callers can observe.
        this.sendPong(m.value.timestampMs)
        this.handlers.onPing?.(m.value)
        break
      case "disconnect":
        this.handlers.onDisconnect?.(m.value)
        break
      default:
        this.handlers.onProtocolError?.(new Error("ServerMessage with no variant set"))
    }
  }

  private log(...args: unknown[]): void {
    console.log("[signaling]", ...args)
  }
}
