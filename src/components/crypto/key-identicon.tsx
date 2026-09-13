import { useMemo } from 'react'
import { cn } from 'cn'

/**
 * A 5x5 mirrored pattern derived from the key ID, so the same key is recognizable at a glance
 * everywhere it appears (keyring, recipients, signatures). It is a visual aid, not a security check.
 */
export function KeyIdenticon({ id, className }: { id: string; className?: string }) {
  const { cells, hue } = useMemo(() => {
    const bytes = id.match(/.{2}/g)?.map((pair) => parseInt(pair, 16)) ?? [0]
    const bits = bytes.flatMap((byte) => [7, 6, 5, 4, 3, 2, 1, 0].map((shift) => (byte >> shift) & 1))
    const cells: Array<[number, number]> = []
    for (let row = 0; row < 5; row++) {
      for (let col = 0; col < 3; col++) {
        if (!bits[8 + row * 3 + col]) continue
        cells.push([col, row])
        if (col < 2) cells.push([4 - col, row])
      }
    }
    return { cells, hue: Math.round((bytes[0] / 256) * 360) }
  }, [id])

  return (
    <span
      aria-hidden
      className={cn('grid size-9 shrink-0 place-items-center rounded-lg', className)}
      style={{ color: `oklch(0.6 0.13 ${hue})`, backgroundColor: `oklch(0.6 0.13 ${hue} / 0.13)` }}
    >
      <svg viewBox="0 0 5 5" className="size-[58%]" shapeRendering="crispEdges">
        {cells.map(([x, y]) => (
          <rect key={`${x}-${y}`} x={x} y={y} width="1" height="1" fill="currentColor" />
        ))}
      </svg>
    </span>
  )
}
