import { beforeAll, describe, expect, it } from 'vitest'
import { toBase64, utf8Decode, utf8Encode } from './encoding'
import { computeKeyId, generateRsaKeyPair, type RsaKeyMaterial } from './rsa-keys'
import { decryptRsa, encryptRsa, sign, verify } from './service'

let alice: RsaKeyMaterial
let bob: RsaKeyMaterial

beforeAll(async () => {
  alice = await generateRsaKeyPair(2048)
  bob = await generateRsaKeyPair(1024)
})

describe('RSA encryption service', () => {
  const data = utf8Encode('Gửi cả nhóm: họp lúc 9 giờ.')

  it('finds the matching private key for hybrid messages, pasted or opened as a file', async () => {
    const encrypted = await encryptRsa({
      data,
      recipients: [
        { spki: alice.spki, hash: 'SHA-512' },
        // A 1024-bit key leaves room for a 32-byte AES key only with short OAEP hashes.
        { spki: bob.spki, hash: 'SHA-256' },
      ],
      scheme: 'hybrid',
      format: 'edt',
    })
    expect(encrypted.summary.recipients).toHaveLength(2)
    for (const input of [{ text: encrypted.text }, { bytes: utf8Encode(encrypted.text) }, { bytes: encrypted.bytes }]) {
      const result = await decryptRsa({ input, keys: [{ spki: alice.spki }, bob] })
      expect(result.text).toBe(utf8Decode(data))
      expect(result.keyId).toBe(await computeKeyId(bob.spki))
    }
  })

  it('decrypts raw OAEP output with the chosen hash', async () => {
    const encrypted = await encryptRsa({
      data,
      recipients: [{ spki: alice.spki, hash: 'SHA-384' }],
      scheme: 'direct',
      format: 'raw',
      encoding: 'hex',
    })
    expect(encrypted.summary.container).toBe('raw')
    const result = await decryptRsa({ input: { text: encrypted.text }, keys: [alice], rawHash: 'SHA-384' })
    expect(result.text).toBe(utf8Decode(data))
    await expect(
      decryptRsa({ input: { text: encrypted.text }, keys: [alice], rawHash: 'SHA-256' }),
    ).rejects.toMatchObject({ code: 'DECRYPT_FAILED' })
  })
})

describe('signature service', () => {
  const data = utf8Encode('Hợp đồng số 42, ký ngày 13/9.')

  it('verifies EDT signatures pasted as text or opened as text and binary files', async () => {
    const signed = await sign({ data, key: alice, scheme: 'RSA-PSS', hash: 'SHA-256', format: 'edt' })
    for (const signature of [{ text: signed.text }, { bytes: utf8Encode(signed.text) }, { bytes: signed.bytes }]) {
      const result = await verify({ data, signature, keys: [{ spki: alice.spki }] })
      expect(result).toMatchObject({ valid: true, container: 'edt', keyMismatch: false })
    }
    const both = [{ spki: bob.spki }, { spki: alice.spki }]
    expect((await verify({ data, signature: { text: signed.text }, keys: both })).valid).toBe(true)
    await expect(
      verify({ data, signature: { text: signed.text }, keys: [{ spki: bob.spki }, { spki: bob.spki }] }),
    ).rejects.toMatchObject({ code: 'NO_MATCHING_KEY' })
  })

  it('verifies bare signatures in hex, base64 and binary form', async () => {
    const signed = await sign({
      data,
      key: alice,
      scheme: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-384',
      format: 'raw',
      encoding: 'hex',
    })
    const raw = { scheme: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' } as const
    const forms = [
      { text: signed.text },
      { bytes: utf8Encode(signed.text) },
      { text: toBase64(signed.bytes) },
      { bytes: signed.bytes },
    ]
    for (const signature of forms) {
      expect((await verify({ data, signature, keys: [{ spki: alice.spki }], raw })).valid).toBe(true)
    }
    const tampered = utf8Encode('Hợp đồng số 43, ký ngày 13/9.')
    expect((await verify({ data: tampered, signature: forms[0], keys: [{ spki: alice.spki }], raw })).valid).toBe(false)
    await expect(verify({ data, signature: forms[0], keys: [{ spki: alice.spki }] })).rejects.toMatchObject({
      code: 'UNKNOWN_FORMAT',
    })
  })
})
