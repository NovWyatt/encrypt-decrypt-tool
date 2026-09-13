const MAX_CHUNK = 65536

/** Cryptographically secure random bytes (getRandomValues caps each call at 65536 bytes). */
export function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(length)
  for (let offset = 0; offset < length; offset += MAX_CHUNK) {
    crypto.getRandomValues(out.subarray(offset, Math.min(offset + MAX_CHUNK, length)))
  }
  return out
}

/** Unbiased random integer in [0, max) via rejection sampling. */
export function randomInt(max: number): number {
  if (!Number.isInteger(max) || max <= 0 || max > 2 ** 32) throw new RangeError('max out of range')
  const limit = 2 ** 32 - (2 ** 32 % max)
  const buf = new Uint32Array(1)
  for (;;) {
    crypto.getRandomValues(buf)
    if (buf[0] < limit) return buf[0] % max
  }
}
