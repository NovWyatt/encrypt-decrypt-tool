import * as nodeCrypto from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { fromHex, toHex } from './encoding'
import { deriveKey, isWeakKdf, validateKdfParams, type KdfParams } from './kdf'

const utf8 = (s: string) => new TextEncoder().encode(s)

describe('PBKDF2', () => {
  it('matches RFC 7914 / RFC 6070-style SHA-256 vectors', async () => {
    const params = (iterations: number): KdfParams => ({ name: 'PBKDF2', hash: 'SHA-256', iterations })
    expect(toHex(await deriveKey('password', utf8('salt'), params(1), 32))).toBe(
      '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b',
    )
    expect(toHex(await deriveKey('password', utf8('salt'), params(4096), 32))).toBe(
      'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a',
    )
  })

  it('matches node:crypto for SHA-512', async () => {
    const salt = new Uint8Array(nodeCrypto.randomBytes(16))
    const ours = await deriveKey('mật khẩu', salt, { name: 'PBKDF2', hash: 'SHA-512', iterations: 1000 }, 32)
    expect(toHex(ours)).toBe(nodeCrypto.pbkdf2Sync(utf8('mật khẩu'), salt, 1000, 32, 'sha512').toString('hex'))
  })
})

describe('scrypt', () => {
  it('matches RFC 7914 section 12 vectors', async () => {
    expect(toHex(await deriveKey('', new Uint8Array(), { name: 'scrypt', N: 16, r: 1, p: 1 }, 64))).toBe(
      '77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442' +
        'fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906',
    )
    expect(toHex(await deriveKey('password', utf8('NaCl'), { name: 'scrypt', N: 1024, r: 8, p: 16 }, 64))).toBe(
      'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162' +
        '2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640',
    )
  })

  it('matches node:crypto for random salts', async () => {
    const salt = new Uint8Array(nodeCrypto.randomBytes(16))
    const ours = await deriveKey('hello', salt, { name: 'scrypt', N: 4096, r: 8, p: 1 }, 32)
    expect(toHex(ours)).toBe(nodeCrypto.scryptSync('hello', salt, 32, { N: 4096, r: 8, p: 1 }).toString('hex'))
  })
})

describe('Argon2id', () => {
  const nodeArgon2 = (nodeCrypto as unknown as { argon2Sync?: (alg: string, p: object) => Buffer }).argon2Sync

  it.runIf(typeof nodeArgon2 === 'function')('matches node:crypto argon2id', async () => {
    const salt = fromHex('02020202020202020202020202020202')
    const ours = await deriveKey(
      'mật khẩu',
      salt,
      { name: 'Argon2id', memoryKiB: 1024, iterations: 2, parallelism: 2 },
      32,
    )
    const expected = nodeArgon2!('argon2id', {
      message: utf8('mật khẩu'),
      nonce: salt,
      parallelism: 2,
      tagLength: 32,
      memory: 1024,
      passes: 2,
    })
    expect(toHex(ours)).toBe(expected.toString('hex'))
  })

  it('is deterministic and salt-dependent', async () => {
    const params: KdfParams = { name: 'Argon2id', memoryKiB: 256, iterations: 1, parallelism: 1 }
    const a = await deriveKey('pw', new Uint8Array(16), params, 32)
    const b = await deriveKey('pw', new Uint8Array(16), params, 32)
    const c = await deriveKey('pw', new Uint8Array(16).fill(1), params, 32)
    expect(toHex(a)).toBe(toHex(b))
    expect(toHex(a)).not.toBe(toHex(c))
  })
})

describe('password normalization and limits', () => {
  it('derives the same key for NFC and NFD Vietnamese passwords', async () => {
    const params: KdfParams = { name: 'PBKDF2', hash: 'SHA-256', iterations: 10 }
    const nfc = 'Mật khẩu bí mật'.normalize('NFC')
    const nfd = nfc.normalize('NFD')
    expect(nfc).not.toBe(nfd)
    const salt = new Uint8Array(16)
    expect(toHex(await deriveKey(nfc, salt, params, 32))).toBe(toHex(await deriveKey(nfd, salt, params, 32)))
  })

  it('rejects hostile parameters from untrusted headers', () => {
    expect(() => validateKdfParams({ name: 'Argon2id', memoryKiB: 4_000_000, iterations: 1, parallelism: 1 })).toThrow()
    expect(() => validateKdfParams({ name: 'scrypt', N: 1000, r: 8, p: 1 })).toThrow()
    expect(() => validateKdfParams({ name: 'scrypt', N: 2 ** 20, r: 16, p: 1 })).toThrow()
    expect(() => validateKdfParams({ name: 'PBKDF2', hash: 'SHA-256', iterations: 0 })).toThrow()
    expect(() => validateKdfParams({ name: 'PBKDF2', hash: 'SHA-256', iterations: 600_000 })).not.toThrow()
  })

  it('flags weak settings', () => {
    expect(isWeakKdf({ name: 'PBKDF2', hash: 'SHA-256', iterations: 10_000 })).toBe(true)
    expect(isWeakKdf({ name: 'Argon2id', memoryKiB: 65536, iterations: 3, parallelism: 4 })).toBe(false)
  })
})
