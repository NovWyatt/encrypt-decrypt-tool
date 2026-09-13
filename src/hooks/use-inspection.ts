import { useCallback, useEffect, useState } from 'react'
import { callCrypto } from '@/lib/crypto/client'
import type { InspectResult } from '@/lib/crypto/service'
import { isInputEmpty, type InputValue } from '@/lib/files'
import { inputForDetection } from '@/lib/input-data'

export type InspectState =
  { status: 'empty' } | { status: 'ok'; result: InspectResult } | { status: 'invalid'; error: unknown }

const EMPTY: InspectState = { status: 'empty' }

/**
 * Describes pasted or dropped ciphertext in the background so forms can ask for the right secret.
 * While new input is being inspected the previous result stays visible, which avoids flicker.
 */
export function useInspection(input: InputValue, delay = 200): [InspectState, () => void] {
  const [last, setLast] = useState<InspectState>(EMPTY)

  useEffect(() => {
    if (isInputEmpty(input)) return
    let cancelled = false
    const timer = setTimeout(() => {
      callCrypto('inspectCiphertext', inputForDetection(input)).then(
        (result) => !cancelled && setLast({ status: 'ok', result }),
        (error: unknown) => !cancelled && setLast({ status: 'invalid', error }),
      )
    }, delay)
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [input, delay])

  const reset = useCallback(() => setLast(EMPTY), [])
  return [isInputEmpty(input) ? EMPTY : last, reset]
}
