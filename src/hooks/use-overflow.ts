import { useLayoutEffect, useState } from 'react'

/** Reports whether an element's content is larger than its box, so it scrolls. */
export function useOverflow<T extends HTMLElement>() {
  const [element, setElement] = useState<T | null>(null)
  const [overflows, setOverflows] = useState(false)

  useLayoutEffect(() => {
    if (!element) return
    const update = () =>
      setOverflows(element.scrollWidth > element.clientWidth + 1 || element.scrollHeight > element.clientHeight + 1)
    // Measure before the first paint too, so a box that scrolls is never shown without its keyboard access.
    update()
    // Watching the children too catches content that grows while the box keeps its size.
    const observer = new ResizeObserver(update)
    observer.observe(element)
    for (const child of element.children) observer.observe(child)
    return () => observer.disconnect()
  }, [element])

  return [setElement, overflows] as const
}
