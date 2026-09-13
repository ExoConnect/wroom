// Device enumeration + selection persistence.
//
// Device labels are empty until the document holds a getUserMedia grant —
// always enumerate() after capture succeeds (the join screen does), and
// re-enumerate on devicechange via watchDevices(). The selection persists to
// localStorage so the join screen remembers the last-used mic/cam/speaker
// across sessions.

import { useCallStore, type DeviceLists, type DeviceSelection } from "@/store/call"

const STORAGE_KEY = "wroom:devices"

const EMPTY_SELECTION: DeviceSelection = { micId: null, camId: null, speakerId: null }

/** Read the persisted device selection (all nulls when absent/corrupt). */
export function loadSelection(): DeviceSelection {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return { ...EMPTY_SELECTION }
    const parsed = JSON.parse(raw) as Partial<DeviceSelection>
    return {
      micId: typeof parsed.micId === "string" ? parsed.micId : null,
      camId: typeof parsed.camId === "string" ? parsed.camId : null,
      speakerId: typeof parsed.speakerId === "string" ? parsed.speakerId : null,
    }
  } catch {
    return { ...EMPTY_SELECTION }
  }
}

export function saveSelection(sel: DeviceSelection): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(sel))
  } catch {
    // Private mode / quota — prefs are best-effort.
  }
}

/** Merge a patch into the store's selectedDevices and persist the result. */
export function setSelectedDevices(patch: Partial<DeviceSelection>): void {
  const next = { ...useCallStore.getState().selectedDevices, ...patch }
  useCallStore.getState().set({ selectedDevices: next })
  saveSelection(next)
}

/**
 * Snapshot enumerateDevices() into the store. Selections whose deviceId is no
 * longer present (unplugged, permissions reset) are dropped back to "default".
 * Call after getUserMedia — before a grant, labels come back empty.
 */
export async function enumerate(): Promise<DeviceLists> {
  const empty: DeviceLists = { mics: [], cams: [], speakers: [] }
  if (!navigator.mediaDevices?.enumerateDevices) return empty
  const all = await navigator.mediaDevices.enumerateDevices()
  const lists: DeviceLists = {
    mics: all.filter((d) => d.kind === "audioinput"),
    cams: all.filter((d) => d.kind === "videoinput"),
    speakers: all.filter((d) => d.kind === "audiooutput"),
  }
  const s = useCallStore.getState()
  s.set({ devices: lists })

  const sel = s.selectedDevices
  const drop: Partial<DeviceSelection> = {}
  if (sel.micId && !lists.mics.some((d) => d.deviceId === sel.micId)) drop.micId = null
  if (sel.camId && !lists.cams.some((d) => d.deviceId === sel.camId)) drop.camId = null
  if (sel.speakerId && !lists.speakers.some((d) => d.deviceId === sel.speakerId)) {
    drop.speakerId = null
  }
  if (Object.keys(drop).length > 0) setSelectedDevices(drop)
  return lists
}

/**
 * Re-enumerate on hotplug / permission changes. Returns the unsubscribe
 * function — safe to call from a React effect cleanup.
 */
export function watchDevices(): () => void {
  if (!navigator.mediaDevices?.addEventListener) return () => {}
  const onChange = () => {
    void enumerate().catch(() => {})
  }
  navigator.mediaDevices.addEventListener("devicechange", onChange)
  return () => navigator.mediaDevices.removeEventListener("devicechange", onChange)
}
