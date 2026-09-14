// Copy-invite confirmation without toasts: the control morphs to a
// checkmark + "Copied" for 2s where the user's eyes already are.

import { Check, Link2 } from "lucide-react"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"
import { useCopyInvite } from "./useCopyInvite"

/** Brand invite button for the empty-call moment. */
export function CopyInviteButton({ className }: { className?: string }) {
  const { copied, copy } = useCopyInvite()
  return (
    <Button
      size="sm"
      onClick={() => void copy()}
      className={cn(
        "bg-brand font-semibold text-brand-foreground hover:bg-brand/90",
        className,
      )}
    >
      {copied ? <Check /> : <Link2 />}
      {copied ? "Copied!" : "Copy invite link"}
    </Button>
  )
}
