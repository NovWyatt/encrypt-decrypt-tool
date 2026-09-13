import { describe, expect, it } from 'vitest'
import { AES_KEY_SIZES, AES_MODES } from './aes'
import { decryptAesMessage, encryptAesMessage, type AesEncryptOptions } from './aes-envelope'
import { concatBytes, toBase64, utf8Decode, utf8Encode } from './encoding'
import {
  ARMOR_MESSAGE,
  armorEnvelope,
  decodeEnvelope,
  detectFileInput,
  detectTextInput,
  encodePrefix,
  type AesHeader,
} from './envelope'
import type { KdfParams } from './kdf'
import { randomBytes } from './random'

const MESSAGE = utf8Encode('Hợp đồng số 12/2026: bên A giao cho bên B toàn quyền quyết định. 🔐')

// Cheap parameters keep the suite fast; production defaults are covered in kdf.test.ts.
const FAST_KDFS: KdfParams[] = [
  { name: 'PBKDF2', hash: 'SHA-256', iterations: 1000 },
  { name: 'Argon2id', memoryKiB: 256, iterations: 1, parallelism: 1 },
  { name: 'scrypt', N: 256, r: 8, p: 1 },
]

describe('AES message round trips', () => {
  for (const mode of AES_MODES) {
    for (const keyBits of AES_KEY_SIZES) {
      for (const mac of mode === 'GCM' ? [false] : [false, true]) {
        it(`AES-${keyBits}-${mode}${mac ? ' + HMAC' : ''} with password and raw key`, async () => {
          for (const kdf of FAST_KDFS) {
            const options: AesEncryptOptions = {
              mode,
              keyBits,
              mac,
              secret: { kind: 'password', password: 'mật khẩu' },
              kdf,
            }
            const { bytes, header } = await encryptAesMessage(MESSAGE, options)
            expect(header.mode).toBe(mode)
            const { plaintext } = await decryptAesMessage(bytes, { kind: 'password', password: 'mật khẩu' })
            expect(utf8Decode(plaintext)).toBe(utf8Decode(MESSAGE))
          }
          const key = randomBytes(keyBits / 8)
          const { bytes } = await encryptAesMessage(MESSAGE, { mode, keyBits, mac, secret: { kind: 'raw', key } })
          const { plaintext } = await decryptAesMessage(bytes, { kind: 'raw', key })
          expect(utf8Decode(plaintext)).toBe(utf8Decode(MESSAGE))
        })
      }
    }
  }

  it('encrypts empty input', async () => {
    const key = randomBytes(32)
    const { bytes } = await encryptAesMessage(new Uint8Array(), {
      mode: 'GCM',
      keyBits: 256,
      secret: { kind: 'raw', key },
    })
    const { plaintext } = await decryptAesMessage(bytes, { kind: 'raw', key })
    expect(plaintext.length).toBe(0)
  })

  it('produces a fresh IV and salt every time', async () => {
    const options: AesEncryptOptions = {
      mode: 'GCM',
      keyBits: 256,
      secret: { kind: 'password', password: 'x' },
      kdf: FAST_KDFS[0],
    }
    const a = await encryptAesMessage(MESSAGE, options)
    const b = await encryptAesMessage(MESSAGE, options)
    expect(toBase64(a.bytes)).not.toBe(toBase64(b.bytes))
  })
})

describe('wrong secrets are reported precisely', () => {
  const password = { kind: 'password', password: 'đúng' } as const
  const wrong = { kind: 'password', password: 'sai' } as const
  const kdf = FAST_KDFS[0]

  it('GCM: DECRYPT_FAILED', async () => {
    const { bytes } = await encryptAesMessage(MESSAGE, { mode: 'GCM', keyBits: 256, secret: password, kdf })
    await expect(decryptAesMessage(bytes, wrong)).rejects.toMatchObject({ code: 'DECRYPT_FAILED' })
  })

  it('CBC without MAC: WRONG_KEY via key check value', async () => {
    const { bytes, header } = await encryptAesMessage(MESSAGE, { mode: 'CBC', keyBits: 256, secret: password, kdf })
    expect(header.check).toBeDefined()
    await expect(decryptAesMessage(bytes, wrong)).rejects.toMatchObject({ code: 'WRONG_KEY' })
  })

  it('CTR with MAC: INTEGRITY_FAILED', async () => {
    const { bytes, header } = await encryptAesMessage(MESSAGE, {
      mode: 'CTR',
      keyBits: 128,
      secret: password,
      kdf,
      mac: true,
    })
    expect(header.check).toBeUndefined()
    await expect(decryptAesMessage(bytes, wrong)).rejects.toMatchObject({ code: 'INTEGRITY_FAILED' })
  })

  it('treats NFD input of the same Vietnamese password as correct', async () => {
    const nfc = 'Nguyễn Thị Như Trang'.normalize('NFC')
    const { bytes } = await encryptAesMessage(MESSAGE, {
      mode: 'GCM',
      keyBits: 256,
      secret: { kind: 'password', password: nfc },
      kdf,
    })
    const { plaintext } = await decryptAesMessage(bytes, { kind: 'password', password: nfc.normalize('NFD') })
    expect(utf8Decode(plaintext)).toBe(utf8Decode(MESSAGE))
  })
})

function withEditedHeader(bytes: Uint8Array, edit: (header: AesHeader) => AesHeader): Uint8Array {
  const { header, payload } = decodeEnvelope(bytes)
  return concatBytes(encodePrefix(edit(header as AesHeader)), payload)
}

describe('tamper detection', () => {
  const key = randomBytes(32)

  it('GCM detects header edits (header is additional data)', async () => {
    const { bytes } = await encryptAesMessage(MESSAGE, { mode: 'GCM', keyBits: 256, secret: { kind: 'raw', key } })
    const edited = withEditedHeader(bytes, (h) => ({ ...h, iv: toBase64(randomBytes(12)) }))
    await expect(decryptAesMessage(edited, { kind: 'raw', key })).rejects.toMatchObject({ code: 'DECRYPT_FAILED' })
  })

  it('HMAC detects header and payload edits', async () => {
    const { bytes } = await encryptAesMessage(MESSAGE, {
      mode: 'CBC',
      keyBits: 256,
      secret: { kind: 'raw', key },
      mac: true,
    })
    const edited = withEditedHeader(bytes, (h) => ({ ...h, iv: toBase64(randomBytes(16)) }))
    await expect(decryptAesMessage(edited, { kind: 'raw', key })).rejects.toMatchObject({ code: 'INTEGRITY_FAILED' })
    const flipped = new Uint8Array(bytes)
    flipped[flipped.length - 40] ^= 0x80
    await expect(decryptAesMessage(flipped, { kind: 'raw', key })).rejects.toMatchObject({ code: 'INTEGRITY_FAILED' })
  })

  it('GCM detects a flipped payload bit', async () => {
    const { bytes } = await encryptAesMessage(MESSAGE, {
      mode: 'GCM',
      keyBits: 128,
      secret: { kind: 'raw', key: key.subarray(0, 16) },
    })
    const flipped = new Uint8Array(bytes)
    flipped[flipped.length - 1] ^= 1
    await expect(decryptAesMessage(flipped, { kind: 'raw', key: key.subarray(0, 16) })).rejects.toMatchObject({
      code: 'DECRYPT_FAILED',
    })
  })

  it('requires the same associated data', async () => {
    const aad = utf8Encode('hồ sơ 2026-09')
    const { bytes, header } = await encryptAesMessage(MESSAGE, {
      mode: 'GCM',
      keyBits: 256,
      secret: { kind: 'raw', key },
      aad,
    })
    expect(header.aad).toBe(true)
    await expect(decryptAesMessage(bytes, { kind: 'raw', key })).rejects.toMatchObject({ code: 'AAD_REQUIRED' })
    await expect(decryptAesMessage(bytes, { kind: 'raw', key }, utf8Encode('khác'))).rejects.toMatchObject({
      code: 'DECRYPT_FAILED',
    })
    const { plaintext } = await decryptAesMessage(bytes, { kind: 'raw', key }, aad)
    expect(utf8Decode(plaintext)).toBe(utf8Decode(MESSAGE))
  })

  it('refuses hostile KDF parameters before doing any work', async () => {
    const { bytes } = await encryptAesMessage(MESSAGE, {
      mode: 'GCM',
      keyBits: 256,
      secret: { kind: 'password', password: 'x' },
      kdf: FAST_KDFS[1],
    })
    const hostile = withEditedHeader(bytes, (h) =>
      h.key.source === 'password' && h.key.kdf.name === 'Argon2id'
        ? { ...h, key: { ...h.key, kdf: { ...h.key.kdf, memoryKiB: 64 * 1024 * 1024 } } }
        : h,
    )
    expect(() => decodeEnvelope(hostile)).toThrow(expect.objectContaining({ code: 'PARAMS_OUT_OF_RANGE' }))
  })
})

describe('input detection', () => {
  it('recognizes armored, bare base64, hex and binary containers', async () => {
    const key = randomBytes(32)
    const { bytes } = await encryptAesMessage(MESSAGE, { mode: 'GCM', keyBits: 256, secret: { kind: 'raw', key } })
    const armored = armorEnvelope(bytes)
    expect(armored.startsWith(`-----BEGIN ${ARMOR_MESSAGE}-----`)).toBe(true)
    expect(detectTextInput(`  some note\n${armored}\ntrailing`).kind).toBe('envelope')
    expect(detectTextInput(toBase64(bytes)).kind).toBe('envelope')
    expect(detectTextInput(Buffer.from(bytes).toString('hex')).kind).toBe('envelope')
    expect(detectFileInput(bytes).kind).toBe('envelope')
    expect(detectFileInput(utf8Encode(armored)).kind).toBe('envelope')
  })

  it('recognizes OpenSSL "Salted__" data and falls back to raw', () => {
    const salted = concatBytes(utf8Encode('Salted__'), randomBytes(24))
    expect(detectTextInput(toBase64(salted)).kind).toBe('openssl')
    expect(detectTextInput(toBase64(randomBytes(32))).kind).toBe('raw')
    expect(() => detectTextInput('không phải base64 !!!')).toThrow()
  })
})
