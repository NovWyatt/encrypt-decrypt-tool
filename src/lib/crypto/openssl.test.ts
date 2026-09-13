import { createCipheriv, createDecipheriv, createHash, pbkdf2Sync, randomBytes as nodeRandomBytes } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { concatBytes, toHex, utf8Decode, utf8Encode } from './encoding'
import {
  decryptOpenSsl,
  decryptOpenSslAuto,
  encryptOpenSsl,
  evpBytesToKey,
  OPENSSL_DEFAULTS,
  type OpenSslOptions,
} from './openssl'

const TEXT = utf8Encode('Biên bản bàn giao: 03 bộ hồ sơ gốc.')

function nodeEvp(password: Buffer, salt: Buffer, keyLen: number, ivLen: number) {
  const chunks: Buffer[] = []
  let prev = Buffer.alloc(0)
  while (Buffer.concat(chunks).length < keyLen + ivLen) {
    prev = createHash('md5')
      .update(Buffer.concat([prev, password, salt]))
      .digest()
    chunks.push(prev)
  }
  const all = Buffer.concat(chunks)
  return { key: all.subarray(0, keyLen), iv: all.subarray(keyLen, keyLen + ivLen) }
}

describe('OpenSSL enc format', () => {
  it('matches a manual PBKDF2 + AES-256-CBC construction', async () => {
    const salt = nodeRandomBytes(8)
    const ours = await encryptOpenSsl(TEXT, 'mật khẩu', OPENSSL_DEFAULTS, salt)
    const derived = pbkdf2Sync(Buffer.from('mật khẩu', 'utf8'), salt, 10_000, 48, 'sha256')
    const cipher = createCipheriv('aes-256-cbc', derived.subarray(0, 32), derived.subarray(32))
    const expected = Buffer.concat([Buffer.from('Salted__'), salt, cipher.update(TEXT), cipher.final()])
    expect(toHex(ours)).toBe(expected.toString('hex'))
  })

  it('matches EVP_BytesToKey (MD5) as used by CryptoJS', async () => {
    const salt = nodeRandomBytes(8)
    const options: OpenSslOptions = { mode: 'CBC', keyBits: 256, kdf: { kind: 'md5' } }
    const ours = await encryptOpenSsl(TEXT, 'secret', options, salt)
    const { key, iv } = nodeEvp(Buffer.from('secret'), salt, 32, 16)
    const decipher = createDecipheriv('aes-256-cbc', key, iv)
    const plain = Buffer.concat([decipher.update(ours.subarray(16)), decipher.final()])
    expect(plain.toString('utf8')).toBe(utf8Decode(TEXT))
    expect(toHex(evpBytesToKey(utf8Encode('secret'), salt, 32, 16).key)).toBe(key.toString('hex'))
  })

  it('round-trips CTR and ECB', async () => {
    for (const mode of ['CTR', 'ECB'] as const) {
      const options: OpenSslOptions = { mode, keyBits: 128, kdf: { kind: 'pbkdf2', hash: 'SHA-512', iterations: 2000 } }
      const encrypted = await encryptOpenSsl(TEXT, 'pw', options)
      expect(utf8Decode(await decryptOpenSsl(encrypted, 'pw', options))).toBe(utf8Decode(TEXT))
    }
  })

  it('auto-detects the configuration', async () => {
    const options: OpenSslOptions = { mode: 'CBC', keyBits: 128, kdf: { kind: 'md5' } }
    const encrypted = await encryptOpenSsl(TEXT, 'pw', options)
    const { plaintext, options: found } = await decryptOpenSslAuto(encrypted, 'pw')
    expect(utf8Decode(plaintext)).toBe(utf8Decode(TEXT))
    expect(found).toEqual(options)
    await expect(decryptOpenSslAuto(encrypted, 'wrong')).rejects.toMatchObject({ code: 'DECRYPT_FAILED' })
  })

  it('rejects data without the Salted__ header', async () => {
    await expect(decryptOpenSsl(concatBytes(new Uint8Array(16)), 'pw', OPENSSL_DEFAULTS)).rejects.toMatchObject({
      code: 'UNKNOWN_FORMAT',
    })
  })
})
