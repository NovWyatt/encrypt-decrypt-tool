import { useSyncExternalStore } from 'react'

/** Keys chosen on the RSA and signature pages, shared so the keyring can preselect them. Memory only. */
export interface KeySelection {
  recipients: string[]
  signer: string | null
  /** Null lets the page match the key named by an EDT signature. */
  verifier: string | null
  rawDecryptKey: string | null
}

let state: KeySelection = { recipients: [], signer: null, verifier: null, rawDecryptKey: null }
const listeners = new Set<() => void>()

export function updateSelection(patch: Partial<KeySelection>): void {
  state = { ...state, ...patch }
  listeners.forEach((listener) => listener())
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

export function useSelection(): KeySelection {
  return useSyncExternalStore(
    subscribe,
    () => state,
    () => state,
  )
}
