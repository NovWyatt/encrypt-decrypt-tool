import { useCallback, useEffect, useMemo, type ReactNode } from 'react'
import { useSettings } from '@/stores/settings'
import { I18nContext, interpolate, lookup, type Lang, type TFunction } from './context'
import { en } from './en'
import { vi, type Dictionary } from './vi'

const DICTIONARIES: Record<Lang, Dictionary> = { vi, en }

export function I18nProvider({ children }: { children: ReactNode }) {
  const { lang } = useSettings()

  useEffect(() => {
    document.documentElement.lang = lang
  }, [lang])

  const t = useCallback<TFunction>((key, params) => interpolate(lookup(DICTIONARIES[lang], key), params), [lang])
  const formatNumber = useCallback(
    (value: number, options?: Intl.NumberFormatOptions) =>
      new Intl.NumberFormat(lang === 'vi' ? 'vi-VN' : 'en-US', options).format(value),
    [lang],
  )
  const value = useMemo(() => ({ lang, t, formatNumber }), [lang, t, formatNumber])
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>
}
