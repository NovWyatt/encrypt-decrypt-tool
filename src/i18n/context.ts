import { createContext, useContext } from 'react'
import type { Dictionary } from './vi'

export type Lang = 'vi' | 'en'
export const LANGS: readonly Lang[] = ['vi', 'en']

type Leaves<T, Prefix extends string = ''> = {
  [K in keyof T & string]: T[K] extends string ? `${Prefix}${K}` : Leaves<T[K], `${Prefix}${K}.`>
}[keyof T & string]

export type TKey = Leaves<Dictionary>
export type TParams = Record<string, string | number>
export type TFunction = (key: TKey, params?: TParams) => string

export interface I18nValue {
  lang: Lang
  t: TFunction
  /** Formats numbers with the active locale (thousands separators differ between vi and en). */
  formatNumber: (value: number, options?: Intl.NumberFormatOptions) => string
}

export const I18nContext = createContext<I18nValue | null>(null)

export function useI18n(): I18nValue {
  const value = useContext(I18nContext)
  if (!value) throw new Error('useI18n must be used inside I18nProvider')
  return value
}

export function lookup(dictionary: Dictionary, key: string): string {
  let node: unknown = dictionary
  for (const part of key.split('.')) {
    node = (node as Record<string, unknown> | undefined)?.[part]
  }
  return typeof node === 'string' ? node : key
}

export function interpolate(template: string, params?: TParams): string {
  if (!params) return template
  return template.replace(/\{(\w+)\}/g, (match, name: string) => (name in params ? String(params[name]) : match))
}
