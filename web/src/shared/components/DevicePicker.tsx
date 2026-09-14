import type { ReactNode } from "react"
import { ChevronDown, Mic, SwitchCamera, Video, Volume2 } from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  flipCamera,
  setSpeaker,
  supportsSinkSelection,
  switchCam,
  switchMic,
} from "@/lib/media"
import { useCallStore, type DeviceSelection } from "@/store/call"

export type DeviceKind = "mic" | "cam" | "speaker"

interface DevicePickerProps {
  kind: DeviceKind
  /** Custom trigger (e.g. the caret next to a control-bar button). Defaults
   *  to a select-styled button showing the active device label. */
  trigger?: ReactNode
}

const KIND_LABEL: Record<DeviceKind, string> = {
  mic: "Microphone",
  cam: "Camera",
  speaker: "Speaker",
}

const KIND_ICON = { mic: Mic, cam: Video, speaker: Volume2 } as const

const SELECT_KEY = {
  mic: "micId",
  cam: "camId",
  speaker: "speakerId",
} as const satisfies Record<DeviceKind, keyof DeviceSelection>

/** Which device is actually in use when no explicit selection exists: the
 *  live capture track's settings (mic/cam) or the "default" sink. */
function activeDeviceId(
  kind: DeviceKind,
  selected: DeviceSelection,
  localStream: MediaStream | null,
): string {
  const sel = selected[SELECT_KEY[kind]]
  if (sel) return sel
  if (kind === "mic") return localStream?.getAudioTracks()[0]?.getSettings().deviceId ?? ""
  if (kind === "cam") return localStream?.getVideoTracks()[0]?.getSettings().deviceId ?? ""
  return "default"
}

/**
 * Device selector for mic / camera / speaker. Renders a checked radio list in
 * a DropdownMenu; the camera menu gains a "Flip camera" item when there's
 * something to flip to. The speaker picker renders nothing where setSinkId
 * is unsupported (Safari/Firefox).
 */
export function DevicePicker({ kind, trigger }: DevicePickerProps) {
  const devices = useCallStore((s) => s.devices)
  const selected = useCallStore((s) => s.selectedDevices)
  const camFacing = useCallStore((s) => s.camFacing)
  const localStream = useCallStore((s) => s.localStream)

  const list =
    kind === "mic" ? devices.mics : kind === "cam" ? devices.cams : devices.speakers
  const Icon = KIND_ICON[kind]

  if (kind === "speaker" && !supportsSinkSelection()) return null

  const activeId = activeDeviceId(kind, selected, localStream)
  const activeLabel =
    list.find((d) => d.deviceId === activeId)?.label || KIND_LABEL[kind]

  const onPick = (deviceId: string) => {
    if (!deviceId) return // pre-permission entries have no usable id
    if (kind === "mic") void switchMic(deviceId).catch(() => {})
    else if (kind === "cam") void switchCam(deviceId).catch(() => {})
    else setSpeaker(deviceId)
  }

  const canFlip = kind === "cam" && (camFacing !== null || list.length >= 2)

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        {trigger ?? (
          <Button
            variant="outline"
            className="w-full justify-between gap-2 font-normal"
          >
            <span className="flex min-w-0 items-center gap-2">
              <Icon className="size-4 shrink-0 text-muted-foreground" />
              <span className="truncate">{activeLabel}</span>
            </span>
            <ChevronDown className="size-4 shrink-0 text-muted-foreground" />
          </Button>
        )}
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-72">
        <DropdownMenuLabel>{KIND_LABEL[kind]}</DropdownMenuLabel>
        <DropdownMenuRadioGroup value={activeId} onValueChange={onPick}>
          {list.map((d, i) => (
            <DropdownMenuRadioItem
              key={d.deviceId || `${kind}-${i}`}
              value={d.deviceId}
            >
              <span className="truncate">
                {d.label || `${KIND_LABEL[kind]} ${i + 1}`}
              </span>
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
        {list.length === 0 && (
          <DropdownMenuItem disabled>No devices found</DropdownMenuItem>
        )}
        {canFlip && (
          <>
            <DropdownMenuSeparator />
            <DropdownMenuItem onSelect={() => void flipCamera().catch(() => {})}>
              <SwitchCamera />
              Flip camera
            </DropdownMenuItem>
          </>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
