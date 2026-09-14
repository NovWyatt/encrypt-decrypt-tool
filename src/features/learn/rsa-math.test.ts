import { describe, expect, it } from 'vitest'
import {
  bitLength,
  chooseExponent,
  extendedEuclid,
  factorSemiprime,
  gcd,
  isPrime,
  modInverse,
  modPow,
  modPowTrace,
  randomPrime,
} from './rsa-math'

describe('textbook RSA math', () => {
  it('computes the classic 61 × 53 example', () => {
    const p = 61n
    const q = 53n
    const n = p * q
    const phi = (p - 1n) * (q - 1n)
    expect(n).toBe(3233n)
    expect(phi).toBe(3120n)
    expect(gcd(17n, phi)).toBe(1n)
    const d = modInverse(17n, phi)
    expect(d).toBe(2753n)
    const c = modPow(65n, 17n, n)
    expect(c).toBe(2790n)
    expect(modPow(c, d!, n)).toBe(65n)
  })

  it('keeps the rows of the extended Euclid table', () => {
    const { gcd: divisor, t, rows } = extendedEuclid(3120n, 17n)
    expect(divisor).toBe(1n)
    expect(((t % 3120n) + 3120n) % 3120n).toBe(2753n)
    expect(rows.map((row) => row.remainder)).toEqual([3120n, 17n, 9n, 8n, 1n, 0n])
    expect(rows[2].quotient).toBe(183n)
    expect(modInverse(6n, 9n)).toBeNull()
  })

  it('traces square-and-multiply bit by bit', () => {
    const { result, steps } = modPowTrace(65n, 17n, 3233n)
    expect(result).toBe(2790n)
    expect(steps.map((step) => step.bit)).toEqual([1, 0, 0, 0, 1])
  })

  it('tests primality exactly for demo sizes', () => {
    expect([2n, 3n, 61n, 65537n, 4294967291n].every(isPrime)).toBe(true)
    expect([1n, 561n, 3233n, 4294967297n, 3215031751n].some(isPrime)).toBe(false)
    for (const bits of [8, 16, 32]) {
      const prime = randomPrime(bits)
      expect(bitLength(prime)).toBe(bits)
      expect(isPrime(prime)).toBe(true)
    }
  })

  it('factors small semiprimes with Pollard rho', () => {
    expect(factorSemiprime(3233n)).toMatchObject({ p: 53n, q: 61n })
    const p = randomPrime(28)
    const q = randomPrime(28)
    const found = factorSemiprime(p * q)
    expect(found && found.p * found.q).toBe(p * q)
    expect(factorSemiprime(4294967291n)).toBeNull()
  })

  it('chooses 65537 unless phi is too small or shares a factor', () => {
    expect(chooseExponent(10n ** 12n + 1n)).toBe(65537n)
    expect(chooseExponent(3120n)).toBe(257n)
    // Below 65537, and 257, 17 and 5 all divide 2 · 5 · 17 · 257, so the search moves on to 3.
    expect(chooseExponent(43690n)).toBe(3n)
    expect(gcd(chooseExponent(96n), 96n)).toBe(1n)
  })
})
