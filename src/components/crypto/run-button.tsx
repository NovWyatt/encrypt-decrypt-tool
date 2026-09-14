import type { Icon } from '@phosphor-icons/react'
import { Button } from '@/components/ui/button'
import { Kbd, KbdGroup } from '@/components/ui/kbd'

const IS_MAC = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.userAgent)

/** Primary action for a tool input, with the Ctrl/Cmd+Enter hint the text area supports. */
export function RunButton({
  icon: IconComponent,
  label,
  onClick,
  disabled,
}: {
  icon: Icon
  label: string
  onClick: () => void
  disabled?: boolean
}) {
  return (
    <div className="flex items-center gap-3">
      <KbdGroup className="hidden text-muted-foreground sm:inline-flex" aria-hidden>
        <Kbd>{IS_MAC ? '⌘' : 'Ctrl'}</Kbd>
        <Kbd>Enter</Kbd>
      </KbdGroup>
      {/* aria-disabled rather than disabled: disabling the focused button would drop keyboard focus to the page. */}
      <Button
        size="lg"
        aria-disabled={disabled || undefined}
        onClick={disabled ? undefined : onClick}
        className="min-w-32 px-4 aria-disabled:opacity-50"
      >
        <IconComponent weight="bold" />
        {label}
      </Button>
    </div>
  )
}
