/**
 * Number theory behind "textbook" RSA, using BigInt so every step can be shown with real numbers.
 * Textbook RSA has no padding and tiny keys here; it exists only to teach how RSA works.
 */

export const abs = (value: bigint) => (value < 0n ? -value : value)

export function gcd(a: bigint, b: bigint): bigint {
  a = abs(a)
  b = abs(b)
  while (b) [a, b] = [b, a % b]
  return a
}

export function bitLength(value: bigint): number {
  return value === 0n ? 0 : value.toString(2).length
}

export interface EuclidRow {
  /** Quotient that produced this row; absent for the two starting rows. */
  quotient?: bigint
  remainder: bigint
  /** Coefficient of the second argument: remainder ≡ t · b (mod a). */
  t: bigint
}

/** Extended Euclid on (a, b), keeping the rows of the usual hand-worked table. */
export function extendedEuclid(a: bigint, b: bigint): { gcd: bigint; t: bigint; rows: EuclidRow[] } {
  const rows: EuclidRow[] = [
    { remainder: a, t: 0n },
    { remainder: b, t: 1n },
  ]
  while (rows.at(-1)!.remainder !== 0n) {
    const [previous, current] = rows.slice(-2)
    const quotient = previous.remainder / current.remainder
    rows.push({
      quotient,
      remainder: previous.remainder - quotient * current.remainder,
      t: previous.t - quotient * current.t,
    })
  }
  const last = rows.at(-2)!
  return { gcd: last.remainder, t: last.t, rows }
}

/** The inverse of `value` modulo `modulus`, or null when they share a factor. */
export function modInverse(value: bigint, modulus: bigint): bigint | null {
  const { gcd: divisor, t } = extendedEuclid(modulus, ((value % modulus) + modulus) % modulus)
  if (divisor !== 1n) return null
  return ((t % modulus) + modulus) % modulus
}

export interface PowStep {
  bit: 0 | 1
  /** Accumulated result after squaring (and multiplying when the bit is 1). */
  result: bigint
}

/** Left-to-right square-and-multiply, the way modular exponentiation is taught. */
export function modPowTrace(base: bigint, exponent: bigint, modulus: bigint): { result: bigint; steps: PowStep[] } {
  if (modulus === 1n) return { result: 0n, steps: [] }
  const steps: PowStep[] = []
  let result = 1n
  base %= modulus
  for (const digit of exponent.toString(2)) {
    result = (result * result) % modulus
    if (digit === '1') result = (result * base) % modulus
    steps.push({ bit: digit === '1' ? 1 : 0, result })
  }
  return { result, steps }
}

export function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  if (modulus === 1n) return 0n
  let result = 1n
  base %= modulus
  while (exponent > 0n) {
    if (exponent & 1n) result = (result * base) % modulus
    base = (base * base) % modulus
    exponent >>= 1n
  }
  return result
}

const SMALL_PRIMES = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]

/** Miller–Rabin; these bases make the answer exact for every n below 3.3 · 10^24. */
export function isPrime(n: bigint): boolean {
  if (n < 2n) return false
  for (const prime of SMALL_PRIMES) {
    if (n === prime) return true
    if (n % prime === 0n) return false
  }
  let d = n - 1n
  let shifts = 0
  while ((d & 1n) === 0n) {
    d >>= 1n
    shifts++
  }
  witness: for (const base of SMALL_PRIMES) {
    let x = modPow(base, d, n)
    if (x === 1n || x === n - 1n) continue
    for (let round = 1; round < shifts; round++) {
      x = (x * x) % n
      if (x === n - 1n) continue witness
    }
    return false
  }
  return true
}

function randomBigInt(bits: number): bigint {
  const bytes = new Uint8Array(Math.ceil(bits / 8))
  crypto.getRandomValues(bytes)
  let value = 0n
  for (const byte of bytes) value = (value << 8n) | BigInt(byte)
  return value & ((1n << BigInt(bits)) - 1n)
}

/** A random prime with exactly `bits` bits (top two bits set, so p · q has exactly 2 · bits bits). */
export function randomPrime(bits: number): bigint {
  if (bits < 4 || bits > 64) throw new Error('Demo primes have 4 to 64 bits')
  const top = 3n << BigInt(bits - 2)
  for (;;) {
    const candidate = randomBigInt(bits) | top | 1n
    if (isPrime(candidate)) return candidate
  }
}

/**
 * Pollard's rho with Brent's cycle detection. Finds a factor of a semiprime in roughly √p steps,
 * which is why the demo breaks small keys instantly while real keys stay out of reach.
 */
export function factorSemiprime(n: bigint): { p: bigint; q: bigint; steps: number } | null {
  if (n < 4n) return null
  if (n % 2n === 0n) return { p: 2n, q: n / 2n, steps: 1 }
  if (isPrime(n)) return null
  let steps = 0
  for (let c = 1n; c < 64n; c++) {
    const f = (value: bigint) => {
      steps++
      return (value * value + c) % n
    }
    let y = 2n
    let x = 2n
    let saved = 2n
    let product = 1n
    let divisor = 1n
    let length = 1
    while (divisor === 1n) {
      x = y
      for (let i = 0; i < length; i++) y = f(y)
      for (let done = 0; done < length && divisor === 1n; done += 64) {
        saved = y
        for (let i = 0; i < Math.min(64, length - done); i++) {
          y = f(y)
          product = (product * abs(x - y)) % n
        }
        divisor = gcd(product, n)
      }
      length *= 2
    }
    if (divisor === n) {
      // The batch overshot: replay it one step at a time.
      do {
        saved = f(saved)
        divisor = gcd(abs(x - saved), n)
      } while (divisor === 1n)
    }
    if (divisor !== n) {
      const other = n / divisor
      return divisor < other ? { p: divisor, q: other, steps } : { p: other, q: divisor, steps }
    }
  }
  return null
}

/** A public exponent for the demo: 65537 when it fits, otherwise the smallest valid choice. */
export function chooseExponent(phi: bigint): bigint {
  for (const candidate of [65537n, 257n, 17n, 5n, 3n]) {
    if (candidate < phi && gcd(candidate, phi) === 1n) return candidate
  }
  for (let candidate = 3n; candidate < phi; candidate += 2n) {
    if (gcd(candidate, phi) === 1n) return candidate
  }
  throw new Error('No valid exponent')
}
