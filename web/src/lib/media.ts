// Local media capture + device routing.
//
// getUserMedia is wrapped in a module-level promise so React StrictMode's
// double-invoked effects (and the join screen → call transition) share one
// capture instead of opening the camera twice.
//
// Device switches swap the track INSIDE the existing MediaStream (same
// object) so <video> tiles never remount, then forward the new track to the
// publisher PC through the RtcManager wired in by setRtcForMedia().
//
// Mute policy (honest mute):
//   mic — track.enabled = false. The track keeps feeding the analyser (mic
//         meter / talking-while-muted) and AEC stays warm; Opus DTX makes a
//         disabled track ~zero bandwidth on the wire.
//   cam — rtc.replaceVideoTrack(null) + track.stop(). The encoder and the
//         camera LED actually turn off; re-enabling re-acquires via gUM.

import { loadSelection, setSelectedDevices } from "./devices"
import { useCallStore } from "@/store/call"
import type { RtcManager } from "./webrtc"

export interface LocalMedia {
  stream: MediaStream
  /** False when permission was denied or no devices exist — join proceeds audio/video-less. */
  ok: boolean
  /** True when the failure was a permission denial (NotAllowedError) — the
   *  join screen shows the site-permissions hint + Retry affordance. */
  denied?: boolean
  error?: string
}

let pending: Promise<LocalMedia> | null = null

/** The session's RtcManager, wired by session.ts right after construction
 *  (and cleared on teardown) so device switches and the honest camera-off can
 *  reach the publisher senders. */
let rtc: RtcManager | null = null

export function setRtcForMedia(next: RtcManager | null): void {
  rtc = next
}

// ── constraints ─────────────────────────────────────────────────────────────

function audioConstraints(deviceId?: string | null): MediaTrackConstraints {
  return {
    ...(deviceId ? { deviceId: { exact: deviceId } } : {}),
    echoCancellation: true,
    noiseSuppression: true,
    autoGainControl: true,
    channelCount: 1,
  }
}

function videoConstraints(opts: {
  deviceId?: string | null
  facingMode?: "user" | "environment" | null
} = {}): MediaTrackConstraints {
  return {
    ...(opts.deviceId ? { deviceId: { exact: opts.deviceId } } : {}),
    ...(opts.facingMode ? { facingMode: { exact: opts.facingMode } } : {}),
    width: { ideal: 1280 },
    height: { ideal: 720 },
    frameRate: { ideal: 30, max: 30 },
  }
}

/** gUM with a one-step fallback to looser constraints on OverconstrainedError
 *  (a saved deviceId may have vanished between sessions). */
async function capture(
  constraints: MediaStreamConstraints,
  fallback: MediaStreamConstraints,
): Promise<MediaStream> {
  try {
    return await navigator.mediaDevices.getUserMedia(constraints)
  } catch (err) {
    if (err instanceof DOMException && err.name === "OverconstrainedError") {
      return navigator.mediaDevices.getUserMedia(fallback)
    }
    throw err
  }
}

function asFacing(v: unknown): "user" | "environment" | null {
  return v === "user" || v === "environment" ? v : null
}

/** Record what the hardware reports about the active camera. */
function noteFacing(stream: MediaStream): void {
  useCallStore
    .getState()
    .set({ camFacing: asFacing(stream.getVideoTracks()[0]?.getSettings().facingMode) })
}

/** Capture cam + mic once; subsequent calls return the same promise. */
export function getLocalMedia(): Promise<LocalMedia> {
  if (pending) return pending
  pending = (async (): Promise<LocalMedia> => {
    const sel = loadSelection()
    let err: unknown
    try {
      const stream = await capture(
        {
          audio: audioConstraints(sel.micId),
          video: videoConstraints({ deviceId: sel.camId }),
        },
        { audio: audioConstraints(), video: videoConstraints() },
      )
      noteFacing(stream)
      return { stream, ok: true }
    } catch (e) {
      err = e
    }
    // Retry once with audio only — a missing camera shouldn't block joining.
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true })
      return { stream, ok: true, error: "Camera unavailable — joined with mic only." }
    } catch (audioErr) {
      const denied =
        (err instanceof DOMException && err.name === "NotAllowedError") ||
        (audioErr instanceof DOMException && audioErr.name === "NotAllowedError")
      return {
        stream: new MediaStream(),
        ok: false,
        denied,
        error: denied
          ? "Camera/mic permission denied — joining without media."
          : "No camera/mic available — joining without media.",
      }
    }
  })()
  // A fully failed capture shouldn't poison future attempts forever — allow
  // one retry per page load by clearing on denial is deliberately NOT done so
  // the permission state stays stable within a session. The join screen's
  // Retry button calls releaseLocalMedia() first, which does clear it.
  return pending
}

/** Stop all local tracks, stop the mic meter, and reset so a future join
 *  re-captures. */
export function releaseLocalMedia(stream: MediaStream | null | undefined): void {
  stream?.getTracks().forEach((t) => t.stop())
  stopMicMeter()
  rtc = null
  pending = null
}

// Stable per-participant track ids for M0's fixed cam+mic set. Track ids are
// unique per participant (see TrackRef); readable ids keep debug logs legible.
export const LOCAL_TRACK_IDS = { mic: "mic", cam: "cam", screen: "screen" } as const

// ── device switching ─────────────────────────────────────────────────────────

/**
 * Swap `track` into the store's localStream for `kind`, keeping the same
 * MediaStream object so mounted <video> elements keep playing. The replaced
 * track is stopped (LED off).
 */
function swapLocalTrack(kind: "audio" | "video", track: MediaStreamTrack): void {
  const s = useCallStore.getState()
  const stream = s.localStream ?? new MediaStream()
  const old =
    kind === "audio" ? stream.getAudioTracks()[0] : stream.getVideoTracks()[0]
  if (old) stream.removeTrack(old)
  stream.addTrack(track)
  if (s.localStream !== stream) s.set({ localStream: stream })
  old?.stop()
}

/** Switch microphone input. Safe on the join screen (rtc not wired yet) and
 *  in-call (replaceTrack, no renegotiation). */
export async function switchMic(deviceId: string): Promise<void> {
  const stream = await capture(
    { audio: audioConstraints(deviceId) },
    { audio: audioConstraints() },
  )
  const track = stream.getAudioTracks()[0]
  if (!track) throw new Error("no audio track")
  // Preserve mute state across the swap (honest mute lives on track.enabled).
  track.enabled = useCallStore.getState().micEnabled
  swapLocalTrack("audio", track)
  await rtc?.replaceAudioTrack(track)
  if (deviceId) setSelectedDevices({ micId: deviceId })
  // The analyser taps one track — restart it on the new source.
  if (meterTrack) startMicMeter(track)
}

/** Switch camera input by deviceId. */
export async function switchCam(deviceId: string): Promise<void> {
  const stream = await capture(
    { video: videoConstraints({ deviceId }) },
    { video: videoConstraints() },
  )
  const track = stream.getVideoTracks()[0]
  if (!track) throw new Error("no video track")
  track.enabled = true // cam "enabled" lives on the sender; a fresh track is on
  swapLocalTrack("video", track)
  await rtc?.replaceVideoTrack(track)
  noteFacing(stream)
  if (deviceId) setSelectedDevices({ camId: deviceId })
}

/**
 * Front/back toggle for phones (camFacing is set from the track's reported
 * facingMode). On desktops — where facingMode is absent — with two or more
 * cameras, cycle to the next device instead.
 */
export async function flipCamera(): Promise<void> {
  const s = useCallStore.getState()
  const cams = s.devices.cams
  if (s.camFacing === null && cams.length >= 2) {
    const current =
      s.selectedDevices.camId ??
      s.localStream?.getVideoTracks()[0]?.getSettings().deviceId
    const idx = cams.findIndex((c) => c.deviceId === current)
    await switchCam(cams[(idx + 1 + cams.length) % cams.length].deviceId)
    return
  }
  const next = s.camFacing === "environment" ? "user" : "environment"
  const stream = await capture(
    { video: videoConstraints({ facingMode: next }) },
    { video: videoConstraints({ facingMode: null }) },
  )
  const track = stream.getVideoTracks()[0]
  if (!track) throw new Error("no video track")
  track.enabled = true
  swapLocalTrack("video", track)
  await rtc?.replaceVideoTrack(track)
  // The browser may ignore facingMode (single-cam laptop) — record the truth.
  useCallStore.getState().set({ camFacing: asFacing(track.getSettings().facingMode) ?? next })
}

// ── honest mute ─────────────────────────────────────────────────────────────

/**
 * Mic on/off — flips track.enabled. The capture keeps running so the analyser
 * still hears speech (talking-while-muted hint) and AEC stays converged; the
 * sender ships silence which Opus DTX encodes at ~zero bitrate.
 */
export function setMicEnabled(on: boolean): void {
  const s = useCallStore.getState()
  const track = s.localStream?.getAudioTracks()[0]
  if (track) track.enabled = on
  s.set({ micEnabled: on, ...(on ? { talkingWhileMuted: false } : {}) })
}

/**
 * Camera on/off — honest version: OFF detaches the sender (encoder stops) and
 * stops the capture (LED off); ON re-acquires the selected camera and
 * re-attaches via replaceTrack (no renegotiation).
 */
export async function setCameraEnabled(on: boolean): Promise<void> {
  const s = useCallStore.getState()
  if (!on) {
    const track = s.localStream?.getVideoTracks()[0]
    await rtc?.replaceVideoTrack(null)
    if (track) {
      s.localStream?.removeTrack(track)
      track.stop()
    }
    s.set({ camEnabled: false })
    return
  }
  if (s.camEnabled && s.localStream?.getVideoTracks()[0]) return // already on
  const stream = await capture(
    {
      video: videoConstraints({
        deviceId: s.selectedDevices.camId,
        facingMode: s.selectedDevices.camId ? null : s.camFacing,
      }),
    },
    { video: videoConstraints() },
  )
  const track = stream.getVideoTracks()[0]
  if (!track) throw new Error("no video track")
  swapLocalTrack("video", track)
  await rtc?.replaceVideoTrack(track)
  useCallStore
    .getState()
    .set({ camEnabled: true, camFacing: asFacing(track.getSettings().facingMode) })
}

// ── audio output routing ─────────────────────────────────────────────────────

/** CSS selector marking the hidden remote-audio sinks (see RemoteAudio). */
const REMOTE_AUDIO_SELECTOR = "audio[data-remote-audio]"

type Sinkable = HTMLMediaElement & { setSinkId?: (sinkId: string) => Promise<void> }

/** setSinkId is Chromium-only — Safari/Firefox hide speaker selection. */
export function supportsSinkSelection(): boolean {
  return (
    typeof HTMLMediaElement !== "undefined" &&
    "setSinkId" in HTMLMediaElement.prototype
  )
}

/**
 * Apply the selected speaker to one media element. Exported so the RemoteAudio
 * component can call it on mount — future <audio data-remote-audio> elements
 * get the sink without a setSpeaker() round-trip.
 */
export function applySinkTo(el: HTMLMediaElement): void {
  const sinkId = useCallStore.getState().selectedDevices.speakerId
  const sinkable = el as Sinkable
  if (!sinkId || typeof sinkable.setSinkId !== "function") return
  void sinkable.setSinkId(sinkId).catch(() => {})
}

/** Route all remote audio to the given output device and persist the choice. */
export function setSpeaker(deviceId: string): void {
  if (deviceId) setSelectedDevices({ speakerId: deviceId })
  for (const el of document.querySelectorAll<HTMLAudioElement>(REMOTE_AUDIO_SELECTOR)) {
    applySinkTo(el)
  }
}

/**
 * Play a short two-note tone through the selected speaker. WebAudio's own
 * destination can't be retargeted cross-browser, so the tone is rendered into
 * a MediaStreamDestination piped through an <audio> element — the element is
 * what honors setSinkId.
 */
export function testSpeaker(): void {
  const ac = new AudioContext()
  const dest = ac.createMediaStreamDestination()
  const osc = ac.createOscillator()
  const gain = ac.createGain()
  gain.gain.value = 0.12
  osc.connect(gain)
  gain.connect(dest)
  const t0 = ac.currentTime
  osc.frequency.setValueAtTime(660, t0)
  osc.frequency.setValueAtTime(990, t0 + 0.09)
  osc.start(t0)
  osc.stop(t0 + 0.22)

  const el = document.createElement("audio")
  el.srcObject = dest.stream
  applySinkTo(el)
  void el.play().catch(() => {})

  window.setTimeout(() => {
    el.pause()
    el.srcObject = null
    void ac.close().catch(() => {})
  }, 600)
}

// ── mic level meter + talking-while-muted ────────────────────────────────────

const METER_WRITE_MS = 50 // ~20 Hz store writes
const TALK_RMS = 0.08 // raw-RMS speech threshold
const TALK_ONSET_MS = 500 // sustained speech before flagging
const TALK_QUIET_MS = 3000 // quiet needed to clear the flag

let meterCtx: AudioContext | null = null
let meterSource: MediaStreamAudioSourceNode | null = null
let meterAnalyser: AnalyserNode | null = null
let meterRaf = 0
/** The track the analyser is tapped into — non-null while the meter runs. */
let meterTrack: MediaStreamTrack | null = null
let lastWrite = 0
let speechSince = 0 // ts when the current loud stretch began (0 = quiet)
let quietSince = 0 // ts when the post-speech quiet stretch began

/**
 * Tap a mic track with an AnalyserNode and publish RMS level (0..1) to store
 * `micLevel` at ~20 Hz via rAF. Also drives `talkingWhileMuted`: while the mic
 * is muted (track.enabled=false — the analyser still hears the raw capture),
 * speech above threshold for 500 ms flags the user; 3 s of quiet or unmuting
 * clears it.
 */
export function startMicMeter(track: MediaStreamTrack): void {
  stopMicMeter()
  meterTrack = track
  const ac = new AudioContext()
  meterCtx = ac
  if (ac.state === "suspended") {
    // Autoplay policy: resume on the first user gesture.
    const unlock = () => void ac.resume().catch(() => {})
    window.addEventListener("pointerdown", unlock, { once: true, capture: true })
    window.addEventListener("keydown", unlock, { once: true, capture: true })
  }
  meterSource = ac.createMediaStreamSource(new MediaStream([track]))
  const analyser = ac.createAnalyser()
  analyser.fftSize = 512
  meterSource.connect(analyser)
  meterAnalyser = analyser
  const buf = new Float32Array(analyser.fftSize)
  speechSince = 0
  quietSince = 0

  const tick = () => {
    meterRaf = requestAnimationFrame(tick)
    if (!meterAnalyser) return
    meterAnalyser.getFloatTimeDomainData(buf)
    let sum = 0
    for (let i = 0; i < buf.length; i++) sum += buf[i] * buf[i]
    const rms = Math.sqrt(sum / buf.length)
    // Perceptual-ish scale with a small noise gate.
    const level = Math.min(1, Math.max(0, (rms - 0.015) * 5))

    const now = performance.now()
    const s = useCallStore.getState()
    if (now - lastWrite >= METER_WRITE_MS) {
      lastWrite = now
      if (Math.abs(level - s.micLevel) > 0.01 || (level === 0) !== (s.micLevel === 0)) {
        s.set({ micLevel: level })
      }
    }

    if (s.micEnabled) {
      if (s.talkingWhileMuted) s.set({ talkingWhileMuted: false })
      speechSince = 0
      quietSince = 0
      return
    }
    if (rms > TALK_RMS) {
      quietSince = 0
      if (speechSince === 0) speechSince = now
      else if (now - speechSince >= TALK_ONSET_MS && !s.talkingWhileMuted) {
        s.set({ talkingWhileMuted: true })
      }
    } else {
      speechSince = 0
      if (s.talkingWhileMuted) {
        if (quietSince === 0) quietSince = now
        else if (now - quietSince >= TALK_QUIET_MS) {
          s.set({ talkingWhileMuted: false })
          quietSince = 0
        }
      }
    }
  }
  meterRaf = requestAnimationFrame(tick)
}

export function stopMicMeter(): void {
  if (meterRaf) {
    cancelAnimationFrame(meterRaf)
    meterRaf = 0
  }
  meterSource?.disconnect()
  meterSource = null
  meterAnalyser = null
  meterTrack = null
  if (meterCtx && meterCtx.state !== "closed") {
    void meterCtx.close().catch(() => {})
  }
  meterCtx = null
  speechSince = 0
  quietSince = 0
  const s = useCallStore.getState()
  if (s.micLevel !== 0 || s.talkingWhileMuted) {
    s.set({ micLevel: 0, talkingWhileMuted: false })
  }
}
