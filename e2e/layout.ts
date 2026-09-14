import type { Page } from '@playwright/test'

export interface LayoutIssue {
  kind: string
  element: string
  detail: string
}

/** Kinds that describe the layout rather than a fault in it. */
const INFO_KINDS = new Set(['scrolls-x', 'truncated', 'field-scrolls'])

/**
 * Inspects the rendered page for layout faults: elements outside the viewport, text fields under 16px on phones
 * (iOS Safari zooms into them), content clipped by its box, text spilling out of its box, and controls or text
 * drawn over each other. Scrolling containers and ellipses are intended and not reported.
 */
export async function layoutFaults(page: Page): Promise<{ overflow: number; faults: LayoutIssue[] }> {
  const { overflow, issues } = await page.evaluate(() => {
    const vw = document.documentElement.clientWidth
    const issues: LayoutIssue[] = []
    const style = (el: Element) => getComputedStyle(el)
    const describe = (el: Element) => {
      const cls = typeof el.className === 'string' ? el.className.trim().split(/\s+/).slice(0, 3).join('.') : ''
      const text = el.getAttribute('aria-label') ?? ('innerText' in el ? (el as HTMLElement).innerText : el.textContent)
      return `${el.tagName.toLowerCase()}${cls ? `.${cls}` : ''} "${(text ?? '').trim().replace(/\s+/g, ' ').slice(0, 36)}"`
    }
    const srOnly = (el: Element) => {
      for (let node: Element | null = el; node && node !== document.body; node = node.parentElement) {
        const rect = node.getBoundingClientRect()
        const s = style(node)
        if ((rect.width <= 1 && rect.height <= 1 && s.overflow !== 'visible') || s.clipPath === 'inset(50%)')
          return true
      }
      return false
    }
    const shown = (el: Element) => {
      if (el.closest('[hidden]')) return false
      const rect = el.getBoundingClientRect()
      if (rect.width === 0 && rect.height === 0) return false
      const s = style(el)
      return s.visibility !== 'hidden' && s.display !== 'none' && Number(s.opacity) > 0.01 && !srOnly(el)
    }
    const clipped = (el: Element) => {
      for (
        let node = el.parentElement;
        node && node !== document.body && node !== document.documentElement;
        node = node.parentElement
      ) {
        const s = style(node)
        if (s.overflowX !== 'visible' || s.overflowY !== 'visible') return true
        if (s.position === 'fixed') return false
      }
      return false
    }
    // Content scrolled under the sticky header, toasts and open sheets sit on separate layers on purpose.
    const layer = (el: Element) => {
      for (let node: Element | null = el; node && node !== document.body; node = node.parentElement) {
        if (['fixed', 'sticky'].includes(style(node).position)) return node
      }
      return document.body
    }

    // Elements outside the viewport that nothing clips. Sonner's list spans the viewport plus its offset on phones.
    for (const el of document.querySelectorAll('body *')) {
      if (!shown(el) || clipped(el) || el.matches('[data-sonner-toaster]')) continue
      const rect = el.getBoundingClientRect()
      if (rect.right > vw + 0.5 || rect.left < -0.5) {
        issues.push({
          kind: 'outside-viewport',
          element: describe(el),
          detail: `${Math.round(rect.left)}..${Math.round(rect.right)} of ${vw}`,
        })
      }
    }

    const textField =
      'input:not([type]), input[type="text"], input[type="password"], input[type="number"], input[type="search"], textarea'
    for (const el of document.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>(textField)) {
      if (!shown(el)) continue
      const size = parseFloat(style(el).fontSize)
      if (vw < 768 && size < 16) issues.push({ kind: 'small-field', element: describe(el), detail: `${size}px` })
      if (el.tagName === 'INPUT' && el.scrollWidth > el.clientWidth + 1) {
        issues.push({ kind: 'field-scrolls', element: describe(el), detail: `${el.scrollWidth} in ${el.clientWidth}` })
      }
    }

    // Containers whose content does not fit: scrolling is fine, hiding is a fault unless it ends in an ellipsis.
    for (const el of document.querySelectorAll('body *')) {
      if (!shown(el) || el.matches(textField)) continue
      const s = style(el)
      const overX = el.scrollWidth > el.clientWidth + 1
      const overY = el.scrollHeight > el.clientHeight + 3
      if (overX && ['auto', 'scroll'].includes(s.overflowX)) {
        issues.push({ kind: 'scrolls-x', element: describe(el), detail: `${el.scrollWidth} in ${el.clientWidth}` })
      }
      if (overX && ['hidden', 'clip'].includes(s.overflowX)) {
        const kind = s.textOverflow === 'ellipsis' ? 'truncated' : 'clipped-x'
        issues.push({ kind, element: describe(el), detail: `${el.scrollWidth} in ${el.clientWidth}` })
      }
      if (overY && ['hidden', 'clip'].includes(s.overflowY)) {
        issues.push({ kind: 'clipped-y', element: describe(el), detail: `${el.scrollHeight} in ${el.clientHeight}` })
      }
    }

    // Text running outside its nearest box.
    const range = document.createRange()
    const spilled = new Set<Element>()
    const texts = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT)
    for (let node = texts.nextNode(); node; node = texts.nextNode()) {
      const parent = node.parentElement
      if (!node.textContent?.trim() || !parent || !shown(parent)) continue
      if (['SCRIPT', 'STYLE', 'TEXTAREA', 'OPTION'].includes(parent.tagName)) continue
      let box: Element | null = parent
      while (
        box &&
        style(box).display.startsWith('inline') &&
        !['inline-block', 'inline-flex', 'inline-grid'].includes(style(box).display)
      ) {
        box = box.parentElement
      }
      if (!box || spilled.has(box) || style(box).overflowX !== 'visible') continue
      range.selectNodeContents(node)
      const text = range.getBoundingClientRect()
      const rect = box.getBoundingClientRect()
      const font = parseFloat(style(box).fontSize)
      const spillX = text.right - rect.right > 1.5 || rect.left - text.left > 1.5
      const spillY = text.bottom - rect.bottom > font * 0.5 || rect.top - text.top > font * 0.5
      if (spillX || spillY) {
        spilled.add(box)
        issues.push({
          kind: 'text-spill',
          element: describe(box),
          detail: `text ${Math.round(text.left)}..${Math.round(text.right)}, box ${Math.round(rect.left)}..${Math.round(rect.right)}`,
        })
      }
    }

    // Controls drawn on top of each other, apart from buttons placed inside a field on purpose.
    const controls = [
      ...document.querySelectorAll(
        'button, a[href], input:not([type="hidden"]), textarea, select, [role="radio"], [role="tab"], [role="checkbox"], [role="switch"], [tabindex="0"]',
      ),
    ].filter((el) => shown(el) && !el.closest('[aria-hidden="true"]'))
    const rects = controls.map((el) => el.getBoundingClientRect())
    const layers = controls.map(layer)
    const isField = (el: Element) => ['INPUT', 'TEXTAREA'].includes(el.tagName)
    const related = (a: Element, b: Element) => Boolean(a.parentElement?.contains(b) || b.parentElement?.contains(a))
    const insetIn = (field: Element, other: Element) => {
      if (!isField(field)) return false
      if (style(other).position === 'absolute' && related(field, other)) return true
      const group = other.closest('[class*="absolute"]')
      return Boolean(group && related(field, group))
    }
    for (let i = 0; i < controls.length; i++) {
      for (let j = i + 1; j < controls.length; j++) {
        const [a, b] = [controls[i], controls[j]]
        if (a.contains(b) || b.contains(a) || layers[i] !== layers[j] || insetIn(a, b) || insetIn(b, a)) continue
        const width = Math.min(rects[i].right, rects[j].right) - Math.max(rects[i].left, rects[j].left)
        const height = Math.min(rects[i].bottom, rects[j].bottom) - Math.max(rects[i].top, rects[j].top)
        if (width > 1 && height > 1) {
          issues.push({
            kind: 'overlap',
            element: `${describe(a)} × ${describe(b)}`,
            detail: `${Math.round(width)}×${Math.round(height)}`,
          })
        }
      }
    }

    // Text drawn over an icon or badge next to it, which the box checks above cannot see.
    const marks = [
      ...document.querySelectorAll('svg, [data-slot="badge"], .rounded-full, [class*="identicon"]'),
    ].filter((el) => shown(el) && el.getBoundingClientRect().width > 4)
    const markRects = marks.map((el) => el.getBoundingClientRect())
    const markLayers = marks.map(layer)
    const covered = new Set<Element>()
    const words = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT)
    for (let node = words.nextNode(); node; node = words.nextNode()) {
      const parent = node.parentElement
      if (!node.textContent?.trim() || !parent || !shown(parent) || parent.closest('svg')) continue
      if (['SCRIPT', 'STYLE', 'TEXTAREA', 'OPTION'].includes(parent.tagName)) continue
      range.selectNodeContents(node)
      // Line boxes ignore clipping, so trim them to every ancestor that hides or scrolls its overflow.
      let clip = { left: -Infinity, top: -Infinity, right: Infinity, bottom: Infinity }
      for (
        let ancestor: Element | null = parent;
        ancestor && ancestor !== document.documentElement;
        ancestor = ancestor.parentElement
      ) {
        const s = style(ancestor)
        if (s.overflowX === 'visible' && s.overflowY === 'visible') continue
        const r = ancestor.getBoundingClientRect()
        clip = {
          left: Math.max(clip.left, r.left),
          top: Math.max(clip.top, r.top),
          right: Math.min(clip.right, r.right),
          bottom: Math.min(clip.bottom, r.bottom),
        }
      }
      const lines = [...range.getClientRects()]
        .map((line) => ({
          left: Math.max(line.left, clip.left),
          top: Math.max(line.top, clip.top),
          right: Math.min(line.right, clip.right),
          bottom: Math.min(line.bottom, clip.bottom),
        }))
        .filter((line) => line.right > line.left && line.bottom > line.top)
      const parentLayer = layer(parent)
      marks.forEach((mark, m) => {
        if (covered.has(mark) || mark.contains(parent) || markLayers[m] !== parentLayer) return
        const r = markRects[m]
        const hit = lines.some(
          (line) =>
            Math.min(line.right, r.right) - Math.max(line.left, r.left) > 2 &&
            Math.min(line.bottom, r.bottom) - Math.max(line.top, r.top) > 2,
        )
        if (!hit) return
        covered.add(mark)
        issues.push({
          kind: 'text-over-mark',
          element: `${describe(parent)} × ${describe(mark)}`,
          detail: `${Math.round(r.left)},${Math.round(r.top)}`,
        })
      })
    }

    return { overflow: document.documentElement.scrollWidth - vw, issues }
  })
  return { overflow, faults: issues.filter((issue) => !INFO_KINDS.has(issue.kind)) }
}
