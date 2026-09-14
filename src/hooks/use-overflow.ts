import { useEffect, useState } from 'react'

/** Reports whether an element's content is larger than its box, so it scrolls. */
export function useOverflow<T extends HTMLElement>() {
  const [element, setElement] = useState<T | null>(null)
  const [overflows, setOverflows] = useState(false)

  useEffect(() => {
    if (!element) return
    const update = () =>
      setOverflows(element.scrollWidth > element.clientWidth + 1 || element.scrollHeight > element.clientHeight + 1)
    // Watching the children too catches content that grows while the box keeps its size.
    const observer = new ResizeObserver(update)
    observer.observe(element)
    for (const child of element.children) observer.observe(child)
    return () => observer.disconnect()
  }, [element])

  return [setElement, overflows] as const
}
