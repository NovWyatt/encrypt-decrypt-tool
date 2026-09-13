import { useSyncExternalStore } from 'react'
import type { Icon } from '@phosphor-icons/react'
import { GraduationCapIcon, KeyIcon, LockKeyIcon, SignatureIcon, VaultIcon } from '@phosphor-icons/react'
import type { TKey } from '@/i18n'

export type RouteId = 'aes' | 'rsa' | 'sign' | 'keys' | 'learn'

export interface RouteDef {
  id: RouteId
  label: TKey
  icon: Icon
  group: 'tools' | 'manage' | 'learn'
}

export const ROUTES: readonly RouteDef[] = [
  { id: 'aes', label: 'nav.aes', icon: LockKeyIcon, group: 'tools' },
  { id: 'rsa', label: 'nav.rsa', icon: KeyIcon, group: 'tools' },
  { id: 'sign', label: 'nav.sign', icon: SignatureIcon, group: 'tools' },
  { id: 'keys', label: 'nav.keys', icon: VaultIcon, group: 'manage' },
  { id: 'learn', label: 'nav.learn', icon: GraduationCapIcon, group: 'learn' },
]

export const ROUTE_GROUPS: ReadonlyArray<{ id: RouteDef['group']; label: TKey }> = [
  { id: 'tools', label: 'nav.groupTools' },
  { id: 'manage', label: 'nav.groupManage' },
  { id: 'learn', label: 'nav.groupLearn' },
]

const DEFAULT_ROUTE: RouteId = 'aes'

function parseHash(): RouteId {
  const id = window.location.hash.replace(/^#\/?/, '').split(/[/?]/)[0]
  return ROUTES.some((route) => route.id === id) ? (id as RouteId) : DEFAULT_ROUTE
}

function subscribe(listener: () => void): () => void {
  window.addEventListener('hashchange', listener)
  return () => window.removeEventListener('hashchange', listener)
}

/** Hash routing keeps working when the built app is opened straight from disk (file://). */
export function useRoute(): RouteId {
  return useSyncExternalStore(subscribe, parseHash, () => DEFAULT_ROUTE)
}

export function navigate(id: RouteId): void {
  if (parseHash() !== id || !window.location.hash) window.location.hash = `/${id}`
}
