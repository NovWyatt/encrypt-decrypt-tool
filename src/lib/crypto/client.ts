import { wrap, type Remote } from 'comlink'
import { CryptoError, type SerializedCryptoError } from './errors'
import type * as Service from './service'

type ServiceModule = typeof Service
type FunctionKeys<T> = { [K in keyof T]: T[K] extends (...args: never[]) => unknown ? K : never }[keyof T]
export type ServiceName = FunctionKeys<ServiceModule>
type ServiceFn<K extends ServiceName> = ServiceModule[K] extends (...args: infer A) => infer R ? { args: A; result: Awaited<R> } : never

type Result<T> = { ok: true; value: T } | { ok: false; error: SerializedCryptoError }

export type WorkerApi = {
  [K in ServiceName]: (...args: ServiceFn<K>['args']) => Promise<Result<ServiceFn<K>['result']>>
}

let remote: Promise<Remote<WorkerApi> | null> | null = null

/**
 * Crypto runs in a module worker so key derivation (Argon2id, scrypt) and RSA key generation
 * never freeze the interface. If workers are unavailable, calls fall back to the main thread.
 */
function getRemote(): Promise<Remote<WorkerApi> | null> {
  if (remote) return remote
  remote = new Promise((resolve) => {
    let worker: Worker
    try {
      worker = new Worker(new URL('./crypto.worker.ts', import.meta.url), { type: 'module', name: 'crypto' })
    } catch {
      resolve(null)
      return
    }
    const proxy = wrap<WorkerApi>(worker)
    const timeout = setTimeout(() => {
      worker.terminate()
      resolve(null)
    }, 4000)
    worker.addEventListener('error', () => {
      clearTimeout(timeout)
      resolve(null)
    })
    proxy
      .ping()
      .then((result) => {
        clearTimeout(timeout)
        resolve(result.ok ? proxy : null)
      })
      .catch(() => {
        clearTimeout(timeout)
        resolve(null)
      })
  })
  return remote
}

export async function callCrypto<K extends ServiceName>(
  name: K,
  ...args: ServiceFn<K>['args']
): Promise<ServiceFn<K>['result']> {
  const proxy = await getRemote()
  if (proxy) {
    const call = proxy[name] as unknown as (...a: ServiceFn<K>['args']) => Promise<Result<ServiceFn<K>['result']>>
    const result = await call(...args)
    if (result.ok) return result.value
    throw new CryptoError(result.error.code, result.error.message, result.error.details)
  }
  const service = await import('./service')
  const fn = service[name] as unknown as (...a: ServiceFn<K>['args']) => ServiceFn<K>['result'] | Promise<ServiceFn<K>['result']>
  try {
    return await fn(...args)
  } catch (error) {
    if (error instanceof CryptoError) throw error
    throw new CryptoError('INTERNAL', error instanceof Error ? error.message : String(error))
  }
}

/** Starts the worker early so the first operation does not pay the startup cost. */
export function warmUpCrypto(): void {
  void getRemote()
}
