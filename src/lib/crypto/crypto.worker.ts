import { expose } from 'comlink'
import { serializeError } from './errors'
import * as service from './service'
import type { WorkerApi } from './client'

type AnyFunction = (...args: unknown[]) => unknown

// Errors are returned as values: structured cloning would drop CryptoError's code and details.
const entries = Object.entries(service) as Array<[string, unknown]>
const api = Object.fromEntries(
  entries
    .filter((entry): entry is [string, AnyFunction] => typeof entry[1] === 'function')
    .map(([name, fn]) => [
      name,
      async (...args: unknown[]) => {
        try {
          return { ok: true, value: await fn(...args) }
        } catch (error) {
          return { ok: false, error: serializeError(error) }
        }
      },
    ]),
) as unknown as WorkerApi

expose(api)
