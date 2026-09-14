import type { FocusEvent } from 'react'

/**
 * Radix moves focus with preventScroll when a dialog opens and when Tab wraps around, which can leave the focused
 * control out of sight in a dialog that scrolls. Scrolling it to the nearest edge honours the dialog's scroll padding.
 */
export function revealFocused(event: FocusEvent<HTMLElement>) {
  if (event.target !== event.currentTarget) event.target.scrollIntoView({ block: 'nearest' })
}
