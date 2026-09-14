import { describe, expect, it } from 'vitest'
import { fromHex, toHex } from '@/lib/crypto/encoding'
import { avalanche, expandKey, gfMultiply, mixColumn, SBOX, traceEncrypt } from './aes-trace'

describe('teaching AES', () => {
  it('builds the standard S-box', () => {
    expect(SBOX[0x00]).toBe(0x63)
    expect(SBOX[0x53]).toBe(0xed)
    expect(SBOX[0xff]).toBe(0x16)
    expect(new Set(SBOX).size).toBe(256)
  })

  it('multiplies in GF(2^8) and mixes columns as in FIPS-197', () => {
    expect(gfMultiply(0x57, 0x13)).toBe(0xfe)
    expect(mixColumn([0xdb, 0x13, 0x53, 0x45])).toEqual([0x8e, 0x4d, 0xa1, 0xbc])
  })

  it('matches the round states of FIPS-197 appendix B', () => {
    const trace = traceEncrypt(fromHex('3243f6a8885a308d313198a2e0370734'), fromHex('2b7e151628aed2a6abf7158809cf4f3c'))
    const round1 = trace.steps.filter((step) => step.round === 1).map((step) => [step.kind, toHex(step.after)])
    expect(toHex(trace.steps[1].after)).toBe('193de3bea0f4e22b9ac68d2ae9f84808')
    expect(round1).toEqual([
      ['subBytes', 'd42711aee0bf98f1b8b45de51e415230'],
      ['shiftRows', 'd4bf5d30e0b452aeb84111f11e2798e5'],
      ['mixColumns', '046681e5e0cb199a48f8d37a2806264c'],
      ['addRoundKey', 'a49c7ff2689f352b6b5bea43026a5049'],
    ])
    expect(toHex(trace.output)).toBe('3925841d02dc09fbdc118597196a0b32')
    expect(trace.steps.filter((step) => step.kind === 'mixColumns')).toHaveLength(9)
  })

  it('encrypts the appendix C vectors for all key sizes', () => {
    const plaintext = fromHex('00112233445566778899aabbccddeeff')
    const key = (bytes: number) => Uint8Array.from({ length: bytes }, (_, index) => index)
    expect(toHex(traceEncrypt(plaintext, key(16)).output)).toBe('69c4e0d86a7b0430d8cdb78070b4c55a')
    expect(toHex(traceEncrypt(plaintext, key(24)).output)).toBe('dda97ca4864cdfe06eaf70a0ec0d7191')
    expect(toHex(traceEncrypt(plaintext, key(32)).output)).toBe('8ea2b7ca516745bfeafc49904b496089')
  })

  it('expands keys with the documented schedule', () => {
    const { roundKeys, words } = expandKey(fromHex('2b7e151628aed2a6abf7158809cf4f3c'))
    expect(toHex(roundKeys[10])).toBe('d014f9a8c9ee2589e13f0cc8b6630ca6')
    expect(toHex(words[4].rotated!)).toBe('cf4f3c09')
    expect(toHex(words[4].substituted!)).toBe('8a84eb01')
    expect(toHex(words[4].word)).toBe('a0fafe17')
  })

  it('spreads a one-bit change across the whole block within two rounds', () => {
    const distances = avalanche(new Uint8Array(16), new Uint8Array(16), 0)
    expect(distances[0]).toBe(1)
    expect(distances.at(-1)).toBeGreaterThan(40)
    expect(distances[2]).toBeGreaterThan(30)
  })
})
