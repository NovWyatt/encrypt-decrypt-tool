import { useEffect, useState } from 'react'

/**
 * Reports whether an element (plus `margin` pixels) is shorter than the viewport.
 * Used to make side panels sticky only when sticking would not hide their lower part.
 */
export function useFitsViewport<T extends HTMLElement>(margin = 48) {
  const [element, setElement] = useState<T | null>(null)
  const [fits, setFits] = useState(true)

  useEffect(() => {
    if (!element) return
    const update = () => setFits(element.offsetHeight + margin <= window.innerHeight)
    // ResizeObserver also reports the initial size right after observe().
    const observer = new ResizeObserver(update)
    observer.observe(element)
    window.addEventListener('resize', update)
    return () => {
      observer.disconnect()
      window.removeEventListener('resize', update)
    }
  }, [element, margin])

  return [setElement, fits] as const
}
