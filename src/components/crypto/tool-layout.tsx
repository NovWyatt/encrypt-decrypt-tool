import type { ReactNode } from 'react'
import { cn } from 'cn'
import { useFitsViewport } from '@/hooks/use-fits-viewport'

/** Settings column on the left, input and result on the right; stacks on small screens. */
export function ToolLayout({ aside, children }: { aside: ReactNode; children: ReactNode }) {
  const [asideRef, asideFits] = useFitsViewport<HTMLDivElement>()
  return (
    <div className="grid items-start gap-5 lg:grid-cols-[minmax(300px,360px)_minmax(0,1fr)] xl:grid-cols-[380px_minmax(0,1fr)]">
      {/* Sticky only while the whole column fits, so its lower part never becomes unreachable. */}
      <div ref={asideRef} className={cn(asideFits && 'lg:sticky lg:top-6')}>
        {aside}
      </div>
      <div className="grid min-w-0 gap-5">{children}</div>
    </div>
  )
}
