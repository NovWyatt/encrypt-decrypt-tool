import { useSyncExternalStore } from 'react'
import type { Lang } from '@/i18n'
import { readStorage, writeStorage } from '@/lib/storage'

export type Level = 'basic' | 'advanced'

export interface Settings {
  level: Level
  lang: Lang
}

const STORAGE_KEY = 'edt.settings'

function isSettings(value: unknown): value is Settings {
  const v = value as Settings
  return (
    typeof v === 'object' &&
    v !== null &&
    (v.level === 'basic' || v.level === 'advanced') &&
    (v.lang === 'vi' || v.lang === 'en')
  )
}

function initialSettings(): Settings {
  const fallback: Settings = {
    level: 'basic',
    lang: typeof navigator !== 'undefined' && !navigator.language.toLowerCase().startsWith('vi') ? 'en' : 'vi',
  }
  return typeof window === 'undefined' ? fallback : readStorage(STORAGE_KEY, fallback, isSettings)
}

let state = initialSettings()
const listeners = new Set<() => void>()

export function updateSettings(patch: Partial<Settings>): void {
  state = { ...state, ...patch }
  writeStorage(STORAGE_KEY, state)
  listeners.forEach((listener) => listener())
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

export function useSettings(): Settings {
  return useSyncExternalStore(
    subscribe,
    () => state,
    () => state,
  )
}
