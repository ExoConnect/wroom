import { Loader2, WifiOff } from "lucide-react"
import { Button } from "@/components/ui/button"
import { session } from "@/lib/session"
import { useCallStore } from "@/store/call"

/**
 * Top-of-screen connection status. Visible while the session's reconnect
 * loop is running ("reconnecting") or after it gave up ("failed"). Hidden
 * in the normal "connected" state.
 */
export function ReconnectBanner() {
  const reconnect = useCallStore((s) => s.reconnect)
  if (reconnect.kind === "connected") return null

  return (
    <div className="pointer-events-none absolute inset-x-0 top-0 z-40 flex justify-center pt-3">
      <div
        role="status"
        className="pointer-events-auto flex animate-in items-center gap-2.5 rounded-full border bg-card/90 px-4 py-2 text-sm shadow-lg backdrop-blur duration-200 fade-in slide-in-from-top-2"
      >
        {reconnect.kind === "reconnecting" ? (
          <>
            <Loader2 className="size-4 animate-spin text-muted-foreground" />
            <span>Reconnecting… (attempt {reconnect.attempt})</span>
          </>
        ) : (
          <>
            <WifiOff className="size-4 text-destructive" />
            <span>Connection failed</span>
            <Button
              size="sm"
              variant="secondary"
              onClick={() => session.retryReconnect()}
            >
              Retry
            </Button>
          </>
        )}
      </div>
    </div>
  )
}

export default ReconnectBanner
