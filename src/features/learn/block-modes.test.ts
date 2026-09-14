import { describe, expect, it } from 'vitest'
import { fromHex, toHex, utf8Encode } from '@/lib/crypto/encoding'
import { traceEncrypt } from './aes-trace'
import { encryptBlocks, encryptPixels, randomDemoKey, repeatedBlocks, repeatRatio, sampleScene } from './block-modes'

describe('block modes demo', () => {
  it('agrees with the teaching AES on a single ECB block', () => {
    const key = fromHex('000102030405060708090a0b0c0d0e0f')
    const block = fromHex('00112233445566778899aabbccddeeff')
    const cipher = encryptBlocks('ECB', { key, iv: new Uint8Array(16) }, block)
    expect(toHex(cipher)).toBe('69c4e0d86a7b0430d8cdb78070b4c55a')
    expect(toHex(cipher)).toBe(toHex(traceEncrypt(block, key).output))
  })

  it('leaks repeated blocks in ECB only', () => {
    const text = utf8Encode('STATUS: OK      STATUS: OK      STATUS: ERROR   STATUS: OK      ')
    const demoKey = randomDemoKey()
    expect(repeatedBlocks(encryptBlocks('ECB', demoKey, text)).firstSeen).toEqual([-1, 0, -1, 0])
    expect(repeatedBlocks(encryptBlocks('CBC', demoKey, text)).firstSeen).toEqual([-1, -1, -1, -1])
    expect(repeatedBlocks(encryptBlocks('CTR', demoKey, text)).firstSeen).toEqual([-1, -1, -1, -1])
  })

  it('pads to whole blocks with zeros', () => {
    const demoKey = randomDemoKey()
    expect(encryptBlocks('CBC', demoKey, utf8Encode('short')).length).toBe(16)
    expect(encryptBlocks('ECB', demoKey, new Uint8Array(32)).length).toBe(32)
  })

  it('shows the picture through ECB but not through CBC or CTR', () => {
    const pixels = sampleScene()
    expect(pixels.length).toBe(256 * 160 * 4)
    const demoKey = randomDemoKey()
    const ecbImage = encryptPixels('ECB', demoKey, pixels)
    expect(ecbImage.length).toBe(pixels.length)
    expect(ecbImage.filter((_, index) => index % 4 === 3).every((alpha) => alpha === 255)).toBe(true)
    const bytes = (image: Uint8ClampedArray) => new Uint8Array(image.buffer)
    expect(repeatRatio(bytes(pixels))).toBeGreaterThan(0.8)
    expect(repeatRatio(encryptBlocks('ECB', demoKey, bytes(pixels)))).toBeGreaterThan(0.8)
    expect(repeatRatio(encryptBlocks('CBC', demoKey, bytes(pixels)))).toBe(0)
    expect(repeatRatio(encryptBlocks('CTR', demoKey, bytes(pixels)))).toBe(0)
  })
})
