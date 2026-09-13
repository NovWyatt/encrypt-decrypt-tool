import { useEffect, useState, type Dispatch, type SetStateAction } from 'react'
import { readStorage, writeStorage } from '@/lib/storage'

/** useState mirrored to localStorage. Never use it for passwords, keys or plaintext. */
export function usePersistentState<T>(
  key: string,
  initial: T,
  validate: (value: unknown) => value is T,
): [T, Dispatch<SetStateAction<T>>] {
  const [value, setValue] = useState<T>(() => readStorage(key, initial, validate))
  useEffect(() => {
    writeStorage(key, value)
  }, [key, value])
  return [value, setValue]
}
