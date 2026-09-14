// Connection-quality presentation — single source for labels, colors,
// and stats formatting so tiles, header, and participant list agree.
//
// Visuals are unchanged from the pre-refactor UI; the redesign pass will
// retoken these in one place.

import type { UplinkQuality } from "@/store/call"
import type { AudioTrackStats, TrackStats } from "@/store/stats"

/** Title-case label for indicators ("Good connection"). */
export const QUALITY_LABEL: Record<UplinkQuality, string> = {
  good: "Good connection",
  fair: "Fair connection",
  poor: "Poor connection",
  unknown: "Measuring connection…",
}

/** Lowercase label for inline prose ("good connection"). */
export const QUALITY_LABEL_SHORT: Record<UplinkQuality, string> = {
  good: "good connection",
  fair: "fair connection",
  poor: "poor connection",
  unknown: "connection unknown",
}

/** Signal-bar text color per quality. */
export const QUALITY_COLOR: Record<UplinkQuality, string> = {
  good: "text-emerald-400",
  fair: "text-amber-400",
  poor: "text-red-400",
  unknown: "text-muted-foreground",
}

/** Participant-list presence dot per quality. */
export const QUALITY_DOT: Record<UplinkQuality, string> = {
  good: "bg-emerald-400",
  fair: "bg-amber-400",
  poor: "bg-red-400",
  unknown: "bg-muted-foreground/40",
}

/** Lit bars (of 3) per quality level. */
export const QUALITY_BARS: Record<UplinkQuality, number> = {
  good: 3,
  fair: 2,
  poor: 1,
  unknown: 0,
}

/** Per-tile stats badge text ("1280×720 · 30fps · 1200kbps · jb 40ms"). */
export function formatTrackStats(s: TrackStats, a?: AudioTrackStats): string {
  return (
    `${s.width}×${s.height} · ${Math.round(s.fps)}fps · ${Math.round(s.kbps)}kbps` +
    (s.jbMs != null ? ` · jb ${Math.round(s.jbMs)}ms` : "") +
    (a ? ` · a-jb ${Math.round(a.jbMs)}/${Math.round(a.targetJbMs)}ms` : "")
  )
}

/** Tooltip detail from inbound stats ("RTT 40ms · 3 packets lost"). */
export function statsQualityDetail(
  s: TrackStats | null | undefined,
): string | undefined {
  if (!s) return undefined
  const parts = [
    s.rttMs != null ? `RTT ${Math.round(s.rttMs)}ms` : null,
    s.jitterMs != null ? `jitter ${Math.round(s.jitterMs)}ms` : null,
    s.packetsLost != null ? `${s.packetsLost} packets lost` : null,
  ].filter(Boolean)
  return parts.length ? parts.join(" · ") : undefined
}

/** Header uplink tooltip from local stats ("RTT 40ms · 3 packets lost"). */
export function uplinkQualityDetail(
  localStats: TrackStats | null | undefined,
): string | undefined {
  if (!localStats) return undefined
  const { rttMs, packetsLost } = localStats
  if (rttMs == null && packetsLost == null) return undefined
  return [
    rttMs != null ? `RTT ${Math.round(rttMs)}ms` : null,
    packetsLost != null ? `${packetsLost} packets lost` : null,
  ]
    .filter(Boolean)
    .join(" · ")
}
