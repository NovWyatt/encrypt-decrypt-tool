import * as nodeCrypto from 'node:crypto'
import { beforeAll, describe, expect, it } from 'vitest'
import { concatBytes, toBase64, toHex, utf8Decode, utf8Encode } from './encoding'
import { decodeEnvelope, encodePrefix } from './envelope'
import {
  decryptHybrid,
  decryptRsaDirect,
  encryptHybrid,
  encryptRsaDirect,
  oaepMaxMessageBytes,
  rsaOaepDecrypt,
  rsaOaepEncrypt,
} from './rsa'
import {
  computeKeyId,
  describeKey,
  encryptPkcs8,
  exportJwk,
  fromOpenSshPublicKey,
  generateRsaKeyPair,
  importJwk,
  importKeysFromText,
  pkcs1PrivateFromPkcs8,
  pkcs1PublicFromSpki,
  toOpenSshPublicKey,
  toPem,
  type RsaHash,
  type RsaKeyMaterial,
} from './rsa-keys'
import { createSignature, pssMaxSaltLength, verifyRawSignature, verifySignatureContainer } from './signature'

const HASHES: RsaHash[] = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']
const nodeHash = (hash: RsaHash) => hash.replace('-', '').toLowerCase()

let ours: RsaKeyMaterial
let nodePair: nodeCrypto.KeyPairKeyObjectResult
let nodeMaterial: RsaKeyMaterial
let third: RsaKeyMaterial

beforeAll(async () => {
  ours = await generateRsaKeyPair(2048)
  third = await generateRsaKeyPair(1024)
  nodePair = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
  nodeMaterial = {
    spki: new Uint8Array(nodePair.publicKey.export({ type: 'spki', format: 'der' })),
    pkcs8: new Uint8Array(nodePair.privateKey.export({ type: 'pkcs8', format: 'der' })),
  }
})

describe('key generation and structure conversions', () => {
  it('generates keys OpenSSL accepts, with matching PKCS#1 forms', () => {
    const pub = nodeCrypto.createPublicKey({ key: Buffer.from(ours.spki), format: 'der', type: 'spki' })
    const priv = nodeCrypto.createPrivateKey({ key: Buffer.from(ours.pkcs8!), format: 'der', type: 'pkcs8' })
    expect(toHex(pkcs1PublicFromSpki(ours.spki))).toBe(pub.export({ type: 'pkcs1', format: 'der' }).toString('hex'))
    expect(toHex(pkcs1PrivateFromPkcs8(ours.pkcs8!))).toBe(
      priv.export({ type: 'pkcs1', format: 'der' }).toString('hex'),
    )
    const details = describeKey(ours)
    expect(details.bits).toBe(2048)
    expect(details.publicExponent).toBe(65537)
    expect(details.hasPrivate).toBe(true)
  })

  it('imports every PEM flavour produced by OpenSSL to the same canonical DER', async () => {
    const { publicKey, privateKey } = nodePair
    const variants = [
      publicKey.export({ type: 'spki', format: 'pem' }),
      publicKey.export({ type: 'pkcs1', format: 'pem' }),
    ]
    for (const pem of variants) {
      const [key] = await importKeysFromText(pem.toString())
      expect(toHex(key.spki)).toBe(toHex(nodeMaterial.spki))
      expect(key.pkcs8).toBeUndefined()
    }
    for (const pem of [
      privateKey.export({ type: 'pkcs8', format: 'pem' }),
      privateKey.export({ type: 'pkcs1', format: 'pem' }),
    ]) {
      const [key] = await importKeysFromText(pem.toString())
      expect(toHex(key.pkcs8!)).toBe(toHex(nodeMaterial.pkcs8!))
      expect(toHex(key.spki)).toBe(toHex(nodeMaterial.spki))
    }
    const [der] = await importKeysFromText(toBase64(nodeMaterial.spki))
    expect(toHex(der.spki)).toBe(toHex(nodeMaterial.spki))
  })

  it('merges a public and private block of the same key', async () => {
    const text = `${toPem('PUBLIC KEY', nodeMaterial.spki)}\n${toPem('PRIVATE KEY', nodeMaterial.pkcs8!)}`
    const keys = await importKeysFromText(text)
    expect(keys).toHaveLength(1)
    expect(keys[0].pkcs8).toBeDefined()
  })

  it('opens passphrase-protected PKCS#8 and legacy PEM from OpenSSL', async () => {
    const passphrase = 'cụm mật khẩu'
    const encrypted = nodePair.privateKey.export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase })
    await expect(importKeysFromText(encrypted.toString())).rejects.toMatchObject({ code: 'PASSPHRASE_REQUIRED' })
    await expect(importKeysFromText(encrypted.toString(), 'sai')).rejects.toMatchObject({ code: 'WRONG_PASSPHRASE' })
    const [key] = await importKeysFromText(encrypted.toString(), passphrase)
    expect(toHex(key.pkcs8!)).toBe(toHex(nodeMaterial.pkcs8!))

    const legacy = nodePair.privateKey.export({
      type: 'pkcs1',
      format: 'pem',
      cipher: 'aes-256-cbc',
      passphrase: 'abc123',
    })
    expect(legacy.toString()).toContain('Proc-Type: 4,ENCRYPTED')
    const [legacyKey] = await importKeysFromText(legacy.toString(), 'abc123')
    expect(toHex(legacyKey.pkcs8!)).toBe(toHex(nodeMaterial.pkcs8!))
  })

  it('writes passphrase-protected PKCS#8 that OpenSSL can open', async () => {
    const der = await encryptPkcs8(ours.pkcs8!, 'khóa riêng', { iterations: 2000 })
    const pem = toPem('ENCRYPTED PRIVATE KEY', der)
    const opened = nodeCrypto.createPrivateKey({ key: pem, format: 'pem', passphrase: 'khóa riêng' })
    expect(opened.export({ type: 'pkcs8', format: 'der' }).toString('hex')).toBe(toHex(ours.pkcs8!))
    const [back] = await importKeysFromText(pem, 'khóa riêng')
    expect(toHex(back.pkcs8!)).toBe(toHex(ours.pkcs8!))
  })

  it('converts JWK both ways', async () => {
    const nodeJwk = nodePair.privateKey.export({ format: 'jwk' })
    const imported = importJwk(nodeJwk)
    expect(toHex(imported.pkcs8!)).toBe(toHex(nodeMaterial.pkcs8!))
    const exported = exportJwk(ours, false)
    const pub = nodeCrypto.createPublicKey({ key: exported as nodeCrypto.JsonWebKey, format: 'jwk' })
    expect(pub.export({ type: 'spki', format: 'der' }).toString('hex')).toBe(toHex(ours.spki))
    const [fromText] = await importKeysFromText(JSON.stringify({ keys: [exportJwk(ours, true)] }))
    expect(toHex(fromText.pkcs8!)).toBe(toHex(ours.pkcs8!))
  })

  it('round-trips OpenSSH public keys', async () => {
    const line = toOpenSshPublicKey(ours.spki, 'hello@may-tinh')
    expect(line).toMatch(/^ssh-rsa AAAAB3NzaC1yc2E/)
    expect(toHex(fromOpenSshPublicKey(line))).toBe(toHex(ours.spki))
    const [key] = await importKeysFromText(line)
    expect(key.source).toBe('openssh')
  })

  it('derives stable key ids', async () => {
    const id = await computeKeyId(ours.spki)
    expect(id).toMatch(/^[0-9a-f]{16}$/)
    const [reimported] = await importKeysFromText(toPem('RSA PUBLIC KEY', pkcs1PublicFromSpki(ours.spki)))
    expect(await computeKeyId(reimported.spki)).toBe(id)
  })
})

describe('RSA-OAEP interoperability', () => {
  for (const hash of HASHES) {
    it(`OAEP with ${hash} works in both directions`, async () => {
      const data = utf8Encode('khóa phiên AES')
      const encrypted = await rsaOaepEncrypt(nodeMaterial.spki, hash, data)
      const viaNode = nodeCrypto.privateDecrypt(
        { key: nodePair.privateKey, padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: nodeHash(hash) },
        encrypted,
      )
      expect(viaNode.toString('utf8')).toBe('khóa phiên AES')
      const fromNode = nodeCrypto.publicEncrypt(
        { key: nodePair.publicKey, padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: nodeHash(hash) },
        data,
      )
      expect(utf8Decode(await rsaOaepDecrypt(nodeMaterial.pkcs8!, hash, fromNode))).toBe('khóa phiên AES')
    })
  }

  it('enforces the OAEP size limit', async () => {
    expect(oaepMaxMessageBytes(2048, 'SHA-256')).toBe(190)
    await expect(rsaOaepEncrypt(ours.spki, 'SHA-256', new Uint8Array(191))).rejects.toMatchObject({
      code: 'MESSAGE_TOO_LONG',
    })
    await expect(rsaOaepEncrypt(ours.spki, 'SHA-256', new Uint8Array(190))).resolves.toHaveLength(256)
  })

  it('reports a wrong private key as DECRYPT_FAILED', async () => {
    const encrypted = await rsaOaepEncrypt(ours.spki, 'SHA-256', utf8Encode('x'))
    await expect(rsaOaepDecrypt(nodeMaterial.pkcs8!, 'SHA-256', encrypted)).rejects.toMatchObject({
      code: 'DECRYPT_FAILED',
    })
  })
})

describe('hybrid and direct RSA messages', () => {
  const big = utf8Encode('Nội dung dài. '.repeat(5000))

  it('encrypts large data for multiple recipients', async () => {
    const { bytes, header } = await encryptHybrid(big, [
      { spki: ours.spki, hash: 'SHA-256' },
      { spki: nodeMaterial.spki, hash: 'SHA-512' },
    ])
    expect(header.recipients).toHaveLength(2)
    for (const key of [ours, nodeMaterial]) {
      const { plaintext, keyId } = await decryptHybrid(bytes, [third, key])
      expect(plaintext.length).toBe(big.length)
      expect(keyId).toBe(await computeKeyId(key.spki))
    }
    await expect(decryptHybrid(bytes, [third])).rejects.toMatchObject({ code: 'NO_MATCHING_KEY' })
    await expect(decryptHybrid(bytes, [{ spki: ours.spki }])).rejects.toMatchObject({ code: 'PRIVATE_KEY_REQUIRED' })
  })

  it('detects modified hybrid payloads and headers', async () => {
    const { bytes } = await encryptHybrid(utf8Encode('bí mật'), [{ spki: ours.spki, hash: 'SHA-256' }])
    const flipped = new Uint8Array(bytes)
    flipped[flipped.length - 5] ^= 1
    await expect(decryptHybrid(flipped, [ours])).rejects.toMatchObject({ code: 'DECRYPT_FAILED' })
    const { header, payload } = decodeEnvelope(bytes)
    if (header.type !== 'rsa-hybrid') throw new Error('unexpected')
    const reordered = concatBytes(encodePrefix({ ...header, iv: toBase64(new Uint8Array(12)) }), payload)
    await expect(decryptHybrid(reordered, [ours])).rejects.toMatchObject({ code: 'DECRYPT_FAILED' })
  })

  it('binds the header of direct RSA messages through the OAEP label', async () => {
    const { bytes } = await encryptRsaDirect(utf8Encode('ngắn gọn'), ours.spki, 'SHA-256')
    const { plaintext } = await decryptRsaDirect(bytes, [third, ours])
    expect(utf8Decode(plaintext)).toBe('ngắn gọn')
    const { header, payload } = decodeEnvelope(bytes)
    // Same meaning, different bytes: key order changes the prefix, so the label no longer matches.
    const json = utf8Encode(
      JSON.stringify({ keyId: (header as { keyId: string }).keyId, hash: 'SHA-256', type: 'rsa' }),
    )
    const prefix = concatBytes(new Uint8Array([0x45, 0x44, 0x54, 1, json.length >> 8, json.length & 0xff]), json)
    await expect(decryptRsaDirect(concatBytes(prefix, payload), [ours])).rejects.toMatchObject({
      code: 'DECRYPT_FAILED',
    })
  })
})

describe('RSA signatures', () => {
  const data = utf8Encode('Tôi xác nhận nội dung văn bản này là đúng.')

  it('PSS signatures verify in OpenSSL and OpenSSL signatures verify here', async () => {
    const { signature, bytes } = await createSignature(data, nodeMaterial, 'RSA-PSS', 'SHA-256')
    expect(
      nodeCrypto.verify(
        'sha256',
        data,
        { key: nodePair.publicKey, padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 },
        signature,
      ),
    ).toBe(true)
    expect((await verifySignatureContainer(data, bytes, nodeMaterial.spki)).valid).toBe(true)

    const nodeSignature = nodeCrypto.sign('sha256', data, {
      key: nodePair.privateKey,
      padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: nodeCrypto.constants.RSA_PSS_SALTLEN_MAX_SIGN,
    })
    const outcome = await verifyRawSignature(data, nodeSignature, nodeMaterial.spki, 'RSA-PSS', 'SHA-256')
    expect(outcome.valid).toBe(true)
    expect(outcome.saltLength).toBe(pssMaxSaltLength(2048, 'SHA-256'))
  })

  it('PKCS#1 v1.5 signatures interoperate', async () => {
    const { signature } = await createSignature(data, nodeMaterial, 'RSASSA-PKCS1-v1_5', 'SHA-512')
    expect(nodeCrypto.verify('sha512', data, nodePair.publicKey, signature)).toBe(true)
    const nodeSignature = nodeCrypto.sign('sha384', data, nodePair.privateKey)
    expect(
      (await verifyRawSignature(data, nodeSignature, nodeMaterial.spki, 'RSASSA-PKCS1-v1_5', 'SHA-384')).valid,
    ).toBe(true)
  })

  it('rejects modified data and flags a different key', async () => {
    const { bytes } = await createSignature(data, ours, 'RSA-PSS', 'SHA-384')
    const modified = utf8Encode('Tôi xác nhận nội dung văn bản này là sai.')
    expect((await verifySignatureContainer(modified, bytes, ours.spki)).valid).toBe(false)
    const other = await verifySignatureContainer(data, bytes, nodeMaterial.spki)
    expect(other.valid).toBe(false)
    expect(other.keyMismatch).toBe(true)
  })
})
