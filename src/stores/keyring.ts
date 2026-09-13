import { useSyncExternalStore } from 'react'
import { fromBase64, toBase64 } from '@/lib/crypto/encoding'
import type { KeySource } from '@/lib/crypto/rsa-keys'
import type { KeyInfo } from '@/lib/crypto/service'
import { readStorage, writeStorage } from '@/lib/storage'

export interface RingKey {
  /** First 8 bytes of SHA-256(SPKI), hex. Stable across formats. */
  id: string
  name: string
  spki: Uint8Array<ArrayBuffer>
  /** Private part. Lives in memory only and is never written to storage. */
  pkcs8?: Uint8Array<ArrayBuffer>
  fingerprint: string
  bits: number
  publicExponent: number
  origin: 'generated' | 'imported'
  source?: KeySource
  addedAt: number
  /** The private part was downloaded or copied during this session. */
  privateSaved: boolean
}

interface PersistedKey {
  id: string
  name: string
  spki: string
  fingerprint: string
  bits: number
  publicExponent: number
  origin: 'generated' | 'imported'
  source?: KeySource
  addedAt: number
}

export interface MergeResult {
  keys: RingKey[]
  added: RingKey[]
  /** Existing public keys that received their private part. */
  upgraded: RingKey[]
  duplicates: RingKey[]
}

/** Adds new keys first; a private key for a known public key completes the existing entry. */
export function mergeKeys(current: readonly RingKey[], incoming: readonly RingKey[]): MergeResult {
  const keys = [...current]
  const result: Omit<MergeResult, 'keys'> = { added: [], upgraded: [], duplicates: [] }
  for (const key of incoming) {
    const index = keys.findIndex((existing) => existing.id === key.id)
    if (index === -1) {
      keys.unshift(key)
      result.added.push(key)
    } else if (!keys[index].pkcs8 && key.pkcs8) {
      keys[index] = { ...keys[index], pkcs8: key.pkcs8, privateSaved: key.privateSaved }
      result.upgraded.push(keys[index])
    } else {
      result.duplicates.push(keys[index])
    }
  }
  return { keys, ...result }
}

const STORAGE_KEY = 'edt.keyring'

function isPersistedList(value: unknown): value is PersistedKey[] {
  return (
    Array.isArray(value) &&
    value.every(
      (item: PersistedKey) =>
        typeof item === 'object' &&
        item !== null &&
        typeof item.id === 'string' &&
        typeof item.name === 'string' &&
        typeof item.spki === 'string' &&
        typeof item.fingerprint === 'string' &&
        typeof item.bits === 'number',
    )
  )
}

function load(): RingKey[] {
  if (typeof window === 'undefined') return []
  return readStorage<PersistedKey[]>(STORAGE_KEY, [], isPersistedList).flatMap((item) => {
    try {
      return [{ ...item, spki: fromBase64(item.spki), privateSaved: false }]
    } catch {
      return []
    }
  })
}

function persist(keys: readonly RingKey[]): void {
  // Only public information is stored.
  const items: PersistedKey[] = keys.map(
    ({ id, name, spki, fingerprint, bits, publicExponent, origin, source, addedAt }) => ({
      id,
      name,
      spki: toBase64(spki),
      fingerprint,
      bits,
      publicExponent,
      origin,
      source,
      addedAt,
    }),
  )
  writeStorage(STORAGE_KEY, items)
}

let state: RingKey[] = load()
const listeners = new Set<() => void>()

function commit(next: RingKey[]): void {
  state = next
  persist(next)
  listeners.forEach((listener) => listener())
}

export function toRingKey(info: KeyInfo, origin: RingKey['origin'], name: string): RingKey {
  return {
    id: info.id,
    name,
    spki: info.spki,
    pkcs8: info.pkcs8,
    fingerprint: info.fingerprint,
    bits: info.bits,
    publicExponent: info.publicExponent,
    origin,
    source: info.source,
    addedAt: Date.now(),
    privateSaved: false,
  }
}

export function addKeys(keys: RingKey[]): MergeResult {
  const result = mergeKeys(state, keys)
  commit(result.keys)
  return result
}

export function renameKey(id: string, name: string): void {
  const trimmed = name.trim()
  if (!trimmed) return
  commit(state.map((key) => (key.id === id ? { ...key, name: trimmed } : key)))
}

export function removeKey(id: string): void {
  commit(state.filter((key) => key.id !== id))
}

export function forgetPrivateKey(id: string): void {
  commit(state.map((key) => (key.id === id ? { ...key, pkcs8: undefined, privateSaved: false } : key)))
}

export function markPrivateSaved(id: string): void {
  commit(state.map((key) => (key.id === id ? { ...key, privateSaved: true } : key)))
}

export function getKeyring(): readonly RingKey[] {
  return state
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

export function useKeyring(): readonly RingKey[] {
  return useSyncExternalStore(
    subscribe,
    () => state,
    () => state,
  )
}

if (typeof window !== 'undefined') {
  // Private keys disappear with the tab, so warn before losing one that was never saved.
  window.addEventListener('beforeunload', (event) => {
    if (state.some((key) => key.pkcs8 && !key.privateSaved)) event.preventDefault()
  })
}
