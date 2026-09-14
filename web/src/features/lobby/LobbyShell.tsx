// Shared lobby page shell — wordmark + theme control + footer around a
// centered single column. Used by JoinScreen and CallEnded so the
// pre/post-call screens read as one product.

import type { ReactNode } from "react"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { useTheme } from "@/hooks/useTheme"
import { ThemeIcon, ThemeMenuItems } from "@/shared/components/ThemeToggle"

export function LobbyShell({ children }: { children: ReactNode }) {
  const { theme } = useTheme()
  return (
    <div className="relative flex min-h-svh animate-in flex-col overflow-hidden fade-in duration-300 motion-reduce:animate-none">
      {/* Ambient brand glow — static gradient, no animation. */}
      <div aria-hidden className="pointer-events-none absolute inset-0">
        <div className="absolute left-1/2 top-[-22vmin] h-[52vmin] w-[84vmin] max-w-none -translate-x-1/2 rounded-full bg-brand/[0.07] blur-3xl" />
      </div>

      <header className="relative z-10 mx-auto flex w-full max-w-lg items-center justify-between px-4 pt-4">
        <span className="text-sm font-semibold tracking-tight">wroom</span>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              className="size-8"
              aria-label={`Theme: ${theme}`}
            >
              <ThemeIcon theme={theme} />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-40">
            <ThemeMenuItems />
          </DropdownMenuContent>
        </DropdownMenu>
      </header>

      <main className="relative z-10 mx-auto flex w-full max-w-lg flex-1 flex-col justify-center px-4 pb-6">
        {children}
      </main>

      <footer className="relative z-10 mx-auto w-full max-w-lg px-4 pb-4 text-center text-xs text-muted-foreground">
        Ephemeral rooms — the link is the room · open source (MIT)
      </footer>
    </div>
  )
}
