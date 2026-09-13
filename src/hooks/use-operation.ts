import { useCallback, useRef, useState } from 'react'

export type OperationState<T, Stage extends string = string> =
  | { status: 'idle' }
  | { status: 'running'; stage: Stage; startedAt: number }
  | { status: 'success'; data: T; id: number }
  | { status: 'error'; error: unknown; id: number }

/** Tracks one async operation at a time; results of superseded runs are ignored. */
export function useOperation<T, Stage extends string = string>() {
  const [state, setState] = useState<OperationState<T, Stage>>({ status: 'idle' })
  const current = useRef(0)

  const run = useCallback(async (stage: Stage, task: () => Promise<T>): Promise<T | undefined> => {
    const id = ++current.current
    setState({ status: 'running', stage, startedAt: performance.now() })
    try {
      const data = await task()
      if (id === current.current) setState({ status: 'success', data, id })
      return data
    } catch (error) {
      if (id === current.current) setState({ status: 'error', error, id })
      return undefined
    }
  }, [])

  const fail = useCallback((error: unknown) => {
    const id = ++current.current
    setState({ status: 'error', error, id })
  }, [])

  const reset = useCallback(() => {
    current.current++
    setState({ status: 'idle' })
  }, [])

  return { state, run, fail, reset }
}
