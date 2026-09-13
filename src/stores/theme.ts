import { useSyncExternalStore } from 'react'
import { readStorage, writeStorage } from '@/lib/storage'

export type ThemePreference = 'light' | 'dark' | 'system'
export type ResolvedTheme = 'light' | 'dark'

interface ThemeState {
  preference: ThemePreference
  resolved: ResolvedTheme
}

// index.html reads the same key before first paint.
const STORAGE_KEY = 'edt.theme'
const darkQuery = window.matchMedia('(prefers-color-scheme: dark)')

function isPreference(value: unknown): value is ThemePreference {
  return value === 'light' || value === 'dark' || value === 'system'
}

function resolve(preference: ThemePreference): ResolvedTheme {
  if (preference === 'system') return darkQuery.matches ? 'dark' : 'light'
  return preference
}

function paint(resolved: ResolvedTheme, freezeTransitions: boolean): void {
  const root = document.documentElement
  // Without this, surfaces with color transitions would fade at different speeds.
  const freeze = freezeTransitions ? document.createElement('style') : null
  if (freeze) {
    freeze.textContent = '*,*::before,*::after{transition:none!important}'
    document.head.appendChild(freeze)
  }
  root.classList.toggle('dark', resolved === 'dark')
  root.style.colorScheme = resolved
  if (freeze) {
    void getComputedStyle(root).opacity
    setTimeout(() => freeze.remove(), 1)
  }
}

const preference = readStorage<ThemePreference>(STORAGE_KEY, 'system', isPreference)
let state: ThemeState = { preference, resolved: resolve(preference) }
const listeners = new Set<() => void>()
paint(state.resolved, false)

function commit(next: ThemeState): void {
  if (next.resolved !== state.resolved) paint(next.resolved, true)
  state = next
  listeners.forEach((listener) => listener())
}

darkQuery.addEventListener('change', () => {
  if (state.preference === 'system') commit({ preference: 'system', resolved: resolve('system') })
})

export function setTheme(preference: ThemePreference): void {
  writeStorage(STORAGE_KEY, preference)
  commit({ preference, resolved: resolve(preference) })
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

export function useTheme(): ThemeState {
  return useSyncExternalStore(
    subscribe,
    () => state,
    () => state,
  )
}
