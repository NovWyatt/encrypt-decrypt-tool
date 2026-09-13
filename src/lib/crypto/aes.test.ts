import { createCipheriv, randomBytes as nodeRandomBytes } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { aesDecrypt, aesEncrypt, type AesKeyBits, type AesMode } from './aes'
import { fromHex, toHex } from './encoding'
import { CryptoError } from './errors'

// NIST SP 800-38A, Appendix F: first two plaintext blocks.
const PLAINTEXT = fromHex('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51')
const KEYS: Record<AesKeyBits, string> = {
  128: '2b7e151628aed2a6abf7158809cf4f3c',
  192: '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
  256: '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
}
const IV = fromHex('000102030405060708090a0b0c0d0e0f')
const COUNTER = fromHex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')

const KAT: Record<Exclude<AesMode, 'GCM'>, Record<AesKeyBits, string>> = {
  ECB: {
    128: '3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf',
    192: 'bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eef',
    256: 'f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870',
  },
  CBC: {
    128: '7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2',
    192: '4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a',
    256: 'f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d',
  },
  CTR: {
    128: '874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff',
    192: '1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e94',
    256: '601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5',
  },
}

const SIZES: AesKeyBits[] = [128, 192, 256]

describe('AES known-answer tests (NIST SP 800-38A)', () => {
  for (const mode of ['ECB', 'CBC', 'CTR'] as const) {
    for (const bits of SIZES) {
      it(`AES-${bits}-${mode}`, async () => {
        const iv = mode === 'CTR' ? COUNTER : mode === 'CBC' ? IV : new Uint8Array()
        const out = await aesEncrypt(mode, fromHex(KEYS[bits]), iv, PLAINTEXT)
        // CBC/ECB append a PKCS#7 padding block; the first two blocks must match the vector.
        expect(toHex(out.subarray(0, 32))).toBe(KAT[mode][bits])
        const back = await aesDecrypt(mode, fromHex(KEYS[bits]), iv, out)
        expect(toHex(back)).toBe(toHex(PLAINTEXT))
      })
    }
  }

  it('AES-128-GCM (McGrew & Viega test cases 1 and 2)', async () => {
    const key = new Uint8Array(16)
    const iv = new Uint8Array(12)
    expect(toHex(await aesEncrypt('GCM', key, iv, new Uint8Array()))).toBe('58e2fccefa7e3061367f1d57a4e7455a')
    expect(toHex(await aesEncrypt('GCM', key, iv, new Uint8Array(16)))).toBe(
      '0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf',
    )
  })
})

function nodeEncrypt(mode: AesMode, key: Uint8Array, iv: Uint8Array, data: Uint8Array, aad?: Uint8Array): string {
  const name = `aes-${key.length * 8}-${mode.toLowerCase()}`
  const cipher = createCipheriv(name, key, mode === 'ECB' ? null : iv)
  if (mode === 'GCM' && aad) (cipher as ReturnType<typeof createCipheriv> & { setAAD(b: Uint8Array): void }).setAAD(aad)
  const body = Buffer.concat([cipher.update(data), cipher.final()])
  const tag = mode === 'GCM' ? (cipher as unknown as { getAuthTag(): Buffer }).getAuthTag() : Buffer.alloc(0)
  return toHex(Buffer.concat([body, tag]))
}

describe('AES cross-check against OpenSSL (node:crypto)', () => {
  for (const mode of ['GCM', 'CBC', 'CTR', 'ECB'] as const) {
    for (const bits of SIZES) {
      it(`AES-${bits}-${mode} matches for random inputs`, async () => {
        for (const length of [0, 1, 15, 16, 17, 100, 4096]) {
          if (length === 0 && mode === 'CTR') continue
          const key = new Uint8Array(nodeRandomBytes(bits / 8))
          const iv = new Uint8Array(nodeRandomBytes(mode === 'GCM' ? 12 : 16))
          const data = new Uint8Array(nodeRandomBytes(length))
          const aad = mode === 'GCM' ? new Uint8Array(nodeRandomBytes(20)) : undefined
          const ours = await aesEncrypt(mode, key, iv, data, aad)
          expect(toHex(ours)).toBe(nodeEncrypt(mode, key, iv, data, aad))
          expect(toHex(await aesDecrypt(mode, key, iv, ours, aad))).toBe(toHex(data))
        }
      })
    }
  }

  it('CTR counter carries across the full 128-bit block like OpenSSL', async () => {
    const key = new Uint8Array(nodeRandomBytes(32))
    const iv = fromHex('00000000000000ffffffffffffffffff')
    const data = new Uint8Array(64)
    expect(toHex(await aesEncrypt('CTR', key, iv, data))).toBe(nodeEncrypt('CTR', key, iv, data))
  })
})

describe('AES failure handling', () => {
  it('rejects a tampered GCM ciphertext', async () => {
    const key = new Uint8Array(32)
    const iv = new Uint8Array(12)
    const out = await aesEncrypt('GCM', key, iv, new TextEncoder().encode('xin chào'))
    out[0] ^= 1
    await expect(aesDecrypt('GCM', key, iv, out)).rejects.toMatchObject({ code: 'DECRYPT_FAILED' })
  })

  it('rejects GCM when the AAD differs', async () => {
    const key = new Uint8Array(24)
    const iv = new Uint8Array(12)
    const out = await aesEncrypt('GCM', key, iv, new Uint8Array(8), new Uint8Array([1]))
    await expect(aesDecrypt('GCM', key, iv, out, new Uint8Array([2]))).rejects.toBeInstanceOf(CryptoError)
  })

  it('validates key and IV sizes', async () => {
    await expect(aesEncrypt('CBC', new Uint8Array(10), IV, PLAINTEXT)).rejects.toMatchObject({ code: 'INVALID_KEY' })
    await expect(aesEncrypt('CBC', new Uint8Array(16), new Uint8Array(12), PLAINTEXT)).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    })
  })

  it('rejects AAD for non-GCM modes', async () => {
    await expect(aesEncrypt('CBC', new Uint8Array(16), IV, PLAINTEXT, new Uint8Array([1]))).rejects.toMatchObject({
      code: 'UNSUPPORTED',
    })
  })
})
