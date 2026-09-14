import { cn } from 'cn'
import { SpinnerIcon } from '@phosphor-icons/react'

/** Decorative: every spinner here sits next to text that says what is happening. */
function Spinner({ className, ...props }: React.ComponentProps<'svg'>) {
  return <SpinnerIcon data-slot="spinner" aria-hidden className={cn('size-4 animate-spin', className)} {...props} />
}

export { Spinner }
