// Single theme control — one icon map + one menu body shared by the room
// header dropdown and the control-bar "more" menu. The compact sheet keeps
// its segmented buttons (different UX) but reads/writes the same useTheme.

import { MonitorSmartphone, Moon, Sun } from "lucide-react"
import {
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
} from "@/components/ui/dropdown-menu"
import { useTheme } from "@/hooks/useTheme"
import type { Theme } from "@/store/call"

const THEME_ICON: Record<Theme, typeof Sun> = {
  system: MonitorSmartphone,
  light: Sun,
  dark: Moon,
}

export function ThemeIcon({ theme }: { theme: Theme }) {
  const Icon = THEME_ICON[theme]
  return <Icon />
}

/** Radio rows for a DropdownMenu — value + onChange default to the app theme. */
export function ThemeMenuItems() {
  const { theme, setTheme } = useTheme()
  return (
    <DropdownMenuRadioGroup
      value={theme}
      onValueChange={(v) => setTheme(v as Theme)}
    >
      <DropdownMenuRadioItem value="system">
        <MonitorSmartphone /> System
      </DropdownMenuRadioItem>
      <DropdownMenuRadioItem value="light">
        <Sun /> Light
      </DropdownMenuRadioItem>
      <DropdownMenuRadioItem value="dark">
        <Moon /> Dark
      </DropdownMenuRadioItem>
    </DropdownMenuRadioGroup>
  )
}
