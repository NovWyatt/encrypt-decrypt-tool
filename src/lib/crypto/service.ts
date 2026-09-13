/**
 * High-level operations used by the UI. Everything here takes and returns plain data
 * (strings, Uint8Arrays, plain objects) so it can run inside a Web Worker unchanged.
 */
import { aesDecrypt, aesEncrypt, IV_LENGTH, type AesKeyBits, type AesMode } from './aes'
import { decryptAesMessage, encryptAesMessage, type AesSecret } from './aes-envelope'
import {
  fromBase64,
  fromHex,
  isHex,
  isValidUtf8,
  toBase64,
  toHex,
  utf8Decode,
  utf8Encode,
  wrapLines,
} from './encoding'
import {
  ARMOR_MESSAGE,
  ARMOR_SIGNATURE,
  armorEnvelope,
  decodeEnvelope,
  detectFileInput,
  detectTextInput,
  kdfFromHeader,
  type DetectedInput,
  type EnvelopeHeader,
} from './envelope'
import { CryptoError } from './errors'
import type { KdfParams } from './kdf'
import { decryptOpenSsl, decryptOpenSslAuto, encryptOpenSsl, type OpenSslOptions } from './openssl'
import { randomBytes } from './random'
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
  formatFingerprint,
  generateRsaKeyPair,
  importKeysFromText,
  modulusBits,
  pkcs1PrivateFromPkcs8,
  pkcs1PublicFromSpki,
  spkiFingerprint,
  toOpenSshPublicKey,
  toPem,
  type KeySource,
  type RsaHash,
  type RsaKeyDetails,
  type RsaKeyMaterial,
} from './rsa-keys'
import {
  createSignature,
  verifyRawSignature,
  verifySignatureContainer,
  type SignatureScheme,
  type VerifyOutcome,
} from './signature'

export function ping(): 'pong' {
  return 'pong'
}

// ---------------------------------------------------------------------------------------------
// Shared types

export interface DataInput {
  text?: string
  bytes?: Uint8Array<ArrayBuffer>
}

export type ContainerKind = 'edt' | 'openssl' | 'raw'

export interface CipherSummary {
  container: ContainerKind
  kind: 'aes' | 'rsa-hybrid' | 'rsa' | 'signature' | 'openssl' | 'raw'
  mode?: AesMode
  keyBits?: AesKeyBits
  keySource?: 'password' | 'raw' | 'rsa'
  kdf?: KdfParams
  openssl?: OpenSslOptions
  integrity: 'aead' | 'hmac' | 'check' | 'label' | 'none'
  aad?: boolean
  recipients?: Array<{ keyId: string; hash: RsaHash }>
  rsaHash?: RsaHash
  scheme?: SignatureScheme
  saltLength?: number
  keyId?: string
  ivHex?: string
  saltHex?: string
}

export interface EncryptResponse {
  /** Binary form, for downloading. */
  bytes: Uint8Array<ArrayBuffer>
  /** Text form shown in the output panel (armored container, base64 or hex). */
  text: string
  summary: CipherSummary
  inputBytes: number
  kdfMs: number
  cipherMs: number
  /** Raw format only: values the recipient needs besides the ciphertext. */
  extras?: { ivHex?: string }
}

export interface DecryptResponse {
  bytes: Uint8Array<ArrayBuffer>
  /** Null when the plaintext is not valid UTF-8 (binary file). */
  text: string | null
  summary: CipherSummary
  kdfMs: number
  cipherMs: number
  keyId?: string
}

function detect(input: DataInput): DetectedInput {
  if (input.bytes) return detectFileInput(input.bytes)
  return detectTextInput(input.text ?? '')
}

function toDecryptResponse(
  bytes: Uint8Array<ArrayBuffer>,
  summary: CipherSummary,
  timings: { kdfMs: number; cipherMs: number },
  keyId?: string,
): DecryptResponse {
  return { bytes, text: isValidUtf8(bytes) ? utf8Decode(bytes) : null, summary, ...timings, keyId }
}

export function summarizeHeader(header: EnvelopeHeader): CipherSummary {
  switch (header.type) {
    case 'aes':
      return {
        container: 'edt',
        kind: 'aes',
        mode: header.mode,
        keyBits: header.keyBits,
        keySource: header.key.source,
        kdf: header.key.source === 'password' ? kdfFromHeader(header.key.kdf) : undefined,
        integrity: header.mode === 'GCM' ? 'aead' : header.mac ? 'hmac' : 'check',
        aad: header.aad,
        ivHex: header.iv ? toHex(fromBase64(header.iv)) : undefined,
        saltHex: header.key.source === 'password' ? toHex(fromBase64(header.key.kdf.salt)) : undefined,
      }
    case 'rsa-hybrid':
      return {
        container: 'edt',
        kind: 'rsa-hybrid',
        mode: 'GCM',
        keyBits: header.keyBits,
        keySource: 'rsa',
        integrity: 'aead',
        recipients: header.recipients.map(({ keyId, hash }) => ({ keyId, hash })),
        ivHex: toHex(fromBase64(header.iv)),
      }
    case 'rsa':
      return {
        container: 'edt',
        kind: 'rsa',
        keySource: 'rsa',
        integrity: 'label',
        rsaHash: header.hash,
        keyId: header.keyId,
        recipients: [{ keyId: header.keyId, hash: header.hash }],
      }
    case 'signature':
      return {
        container: 'edt',
        kind: 'signature',
        integrity: 'none',
        scheme: header.scheme,
        rsaHash: header.hash,
        saltLength: header.saltLength,
        keyId: header.keyId,
      }
  }
}

export type InspectResult =
  | { container: 'edt'; summary: CipherSummary; byteLength: number }
  | { container: 'openssl'; summary: CipherSummary; byteLength: number }
  | { container: 'raw'; encoding: 'base64' | 'hex' | 'binary'; byteLength: number }

/** Describes pasted or dropped ciphertext without decrypting it. */
export function inspectCiphertext(input: DataInput): InspectResult {
  const detected = detect(input)
  switch (detected.kind) {
    case 'envelope':
      return { container: 'edt', summary: summarizeHeader(detected.header), byteLength: detected.bytes.length }
    case 'openssl':
      return {
        container: 'openssl',
        summary: {
          container: 'openssl',
          kind: 'openssl',
          keySource: 'password',
          integrity: 'none',
          saltHex: toHex(detected.bytes.subarray(8, 16)),
        },
        byteLength: detected.bytes.length,
      }
    case 'raw':
      return { container: 'raw', encoding: detected.encoding, byteLength: detected.bytes.length }
  }
}

/** Accepts a raw AES key as hex or base64 and checks its size. */
export function parseKeyText(text: string, keyBits?: AesKeyBits): Uint8Array<ArrayBuffer> {
  const trimmed = text.trim()
  if (!trimmed) throw new CryptoError('INVALID_KEY', 'Key is empty')
  let key: Uint8Array<ArrayBuffer> | null = null
  if (isHex(trimmed)) key = fromHex(trimmed)
  else {
    try {
      key = fromBase64(trimmed)
    } catch {
      throw new CryptoError('INVALID_KEY', 'Key must be hex or base64')
    }
  }
  if (keyBits !== undefined && key.length * 8 !== keyBits) {
    throw new CryptoError('INVALID_KEY', 'Key size does not match', { expected: keyBits, actual: key.length * 8 })
  }
  if (![16, 24, 32].includes(key.length)) {
    throw new CryptoError('INVALID_KEY', 'AES key must be 128, 192 or 256 bits', { actual: key.length * 8 })
  }
  return key
}

function parseIvText(text: string | undefined, mode: AesMode): Uint8Array<ArrayBuffer> | undefined {
  if (!text?.trim() || mode === 'ECB') return undefined
  const expected = IV_LENGTH[mode]
  let iv: Uint8Array<ArrayBuffer>
  try {
    iv = isHex(text) ? fromHex(text) : fromBase64(text)
  } catch {
    throw new CryptoError('INVALID_INPUT', 'IV must be hex or base64', { field: 'iv', expected })
  }
  if (mode === 'GCM' ? iv.length < 8 : iv.length !== expected) {
    throw new CryptoError('INVALID_INPUT', 'Invalid IV length', { field: 'iv', expected, actual: iv.length })
  }
  return iv
}

// ---------------------------------------------------------------------------------------------
// AES

export type SecretInput = { kind: 'password'; password: string } | { kind: 'raw'; keyText: string }

export interface AesEncryptRequest {
  data: Uint8Array<ArrayBuffer>
  format: ContainerKind
  secret: SecretInput
  mode: AesMode
  keyBits: AesKeyBits
  kdf: KdfParams
  mac: boolean
  /** UTF-8 associated data (GCM). */
  aad?: string
  /** Hex or base64 IV; random when empty. */
  iv?: string
  /** OpenSSL format: key derivation used by `openssl enc`. */
  opensslKdf?: OpenSslOptions['kdf']
  /** Output text encoding for OpenSSL and raw formats. */
  encoding?: 'base64' | 'hex'
  wrapLines?: boolean
}

function toSecret(secret: SecretInput, keyBits: AesKeyBits): AesSecret {
  return secret.kind === 'password'
    ? { kind: 'password', password: secret.password }
    : { kind: 'raw', key: parseKeyText(secret.keyText, keyBits) }
}

function encodeText(bytes: Uint8Array, encoding: 'base64' | 'hex' = 'base64', wrap = false): string {
  const text = encoding === 'hex' ? toHex(bytes) : toBase64(bytes)
  return wrap ? wrapLines(text, encoding === 'hex' ? 64 : 64) : text
}

export async function encryptAes(req: AesEncryptRequest): Promise<EncryptResponse> {
  const { data, mode, keyBits } = req
  const aad = req.aad ? utf8Encode(req.aad) : undefined

  if (req.format === 'edt') {
    const result = await encryptAesMessage(data, {
      mode,
      keyBits,
      secret: toSecret(req.secret, keyBits),
      kdf: req.kdf,
      mac: req.mac,
      aad,
      iv: parseIvText(req.iv, mode),
    })
    return {
      bytes: result.bytes,
      text: armorEnvelope(result.bytes),
      summary: summarizeHeader(result.header),
      inputBytes: data.length,
      kdfMs: result.kdfMs,
      cipherMs: result.cipherMs,
    }
  }

  if (req.format === 'openssl') {
    if (req.secret.kind !== 'password') throw new CryptoError('INVALID_INPUT', 'OpenSSL format requires a password')
    if (mode === 'GCM') throw new CryptoError('UNSUPPORTED', 'openssl enc does not support GCM')
    const options: OpenSslOptions = {
      mode,
      keyBits,
      kdf: req.opensslKdf ?? { kind: 'pbkdf2', hash: 'SHA-256', iterations: 10_000 },
    }
    const start = performance.now()
    const bytes = await encryptOpenSsl(data, req.secret.password, options)
    return {
      bytes,
      text: encodeText(bytes, req.encoding, req.wrapLines),
      summary: {
        container: 'openssl',
        kind: 'openssl',
        mode,
        keyBits,
        keySource: 'password',
        openssl: options,
        integrity: 'none',
        saltHex: toHex(bytes.subarray(8, 16)),
      },
      inputBytes: data.length,
      kdfMs: 0,
      cipherMs: performance.now() - start,
    }
  }

  if (req.secret.kind !== 'raw') throw new CryptoError('INVALID_INPUT', 'Raw format requires a raw key')
  const key = parseKeyText(req.secret.keyText, keyBits)
  const iv = parseIvText(req.iv, mode) ?? randomBytes(IV_LENGTH[mode])
  const start = performance.now()
  const bytes = await aesEncrypt(mode, key, iv, data, aad)
  return {
    bytes,
    text: encodeText(bytes, req.encoding, req.wrapLines),
    summary: {
      container: 'raw',
      kind: 'raw',
      mode,
      keyBits,
      keySource: 'raw',
      integrity: mode === 'GCM' ? 'aead' : 'none',
      aad: Boolean(aad),
      ivHex: mode === 'ECB' ? undefined : toHex(iv),
    },
    inputBytes: data.length,
    kdfMs: 0,
    cipherMs: performance.now() - start,
    extras: { ivHex: mode === 'ECB' ? undefined : toHex(iv) },
  }
}

export interface AesDecryptRequest {
  input: DataInput
  secret: SecretInput
  aad?: string
  /** OpenSSL data: explicit options, or undefined to auto-detect common ones. */
  openssl?: OpenSslOptions
  /** Raw data: parameters the ciphertext does not carry. */
  raw?: { mode: AesMode; keyBits: AesKeyBits; iv: string }
}

export async function decryptAes(req: AesDecryptRequest): Promise<DecryptResponse> {
  const detected = detect(req.input)
  const aad = req.aad ? utf8Encode(req.aad) : undefined

  if (detected.kind === 'envelope') {
    const envelope = decodeEnvelope(detected.bytes)
    if (envelope.header.type !== 'aes') {
      throw new CryptoError('UNSUPPORTED', 'This container is not an AES message', { type: envelope.header.type })
    }
    const secret: AesSecret =
      req.secret.kind === 'password'
        ? { kind: 'password', password: req.secret.password }
        : { kind: 'raw', key: parseKeyText(req.secret.keyText, envelope.header.keyBits) }
    const result = await decryptAesMessage(envelope, secret, aad)
    return toDecryptResponse(result.plaintext, summarizeHeader(result.header), result)
  }

  if (detected.kind === 'openssl') {
    if (req.secret.kind !== 'password') throw new CryptoError('INVALID_INPUT', 'OpenSSL data requires a password')
    const start = performance.now()
    const { plaintext, options } = req.openssl
      ? { plaintext: await decryptOpenSsl(detected.bytes, req.secret.password, req.openssl), options: req.openssl }
      : await decryptOpenSslAuto(detected.bytes, req.secret.password)
    return toDecryptResponse(
      plaintext,
      {
        container: 'openssl',
        kind: 'openssl',
        mode: options.mode,
        keyBits: options.keyBits,
        keySource: 'password',
        openssl: options,
        integrity: 'none',
        saltHex: toHex(detected.bytes.subarray(8, 16)),
      },
      { kdfMs: 0, cipherMs: performance.now() - start },
    )
  }

  if (!req.raw) throw new CryptoError('UNKNOWN_FORMAT', 'Raw data needs mode, key size and IV')
  if (req.secret.kind !== 'raw') throw new CryptoError('INVALID_INPUT', 'Raw data requires a raw key')
  const { mode, keyBits } = req.raw
  const key = parseKeyText(req.secret.keyText, keyBits)
  const iv = parseIvText(req.raw.iv, mode)
  if (!iv && mode !== 'ECB') {
    throw new CryptoError('INVALID_INPUT', 'IV is required', { field: 'iv', missing: 1, expected: IV_LENGTH[mode] })
  }
  const start = performance.now()
  const plaintext = await aesDecrypt(mode, key, iv ?? new Uint8Array(), detected.bytes, aad)
  return toDecryptResponse(
    plaintext,
    {
      container: 'raw',
      kind: 'raw',
      mode,
      keyBits,
      keySource: 'raw',
      integrity: mode === 'GCM' ? 'aead' : 'none',
      ivHex: iv ? toHex(iv) : undefined,
    },
    { kdfMs: 0, cipherMs: performance.now() - start },
  )
}

// ---------------------------------------------------------------------------------------------
// RSA keys

export interface KeyInfo extends RsaKeyMaterial {
  id: string
  fingerprint: string
  bits: number
  publicExponent: number
  hasPrivate: boolean
  source?: KeySource
}

async function toKeyInfo(material: RsaKeyMaterial, source?: KeySource): Promise<KeyInfo> {
  const details = describeKey(material)
  return {
    spki: material.spki,
    pkcs8: material.pkcs8,
    id: await computeKeyId(material.spki),
    fingerprint: formatFingerprint(await spkiFingerprint(material.spki)),
    bits: details.bits,
    publicExponent: details.publicExponent,
    hasPrivate: details.hasPrivate,
    source,
  }
}

export async function generateKey(bits: number, publicExponent = 65537): Promise<KeyInfo> {
  return toKeyInfo(await generateRsaKeyPair(bits, publicExponent), undefined)
}

export async function importKeys(text: string, passphrase?: string): Promise<KeyInfo[]> {
  const keys = await importKeysFromText(text, passphrase)
  return Promise.all(keys.map((key) => toKeyInfo(key, key.source)))
}

export function keyDetails(material: RsaKeyMaterial): RsaKeyDetails {
  return describeKey(material)
}

export type KeyExportFormat =
  | 'spki-pem'
  | 'pkcs1-public-pem'
  | 'openssh'
  | 'jwk-public'
  | 'pkcs8-pem'
  | 'pkcs1-private-pem'
  | 'encrypted-pkcs8-pem'
  | 'jwk-private'

export async function exportKey(
  material: RsaKeyMaterial,
  format: KeyExportFormat,
  options: { passphrase?: string; comment?: string } = {},
): Promise<{ text: string; extension: string }> {
  const requirePrivate = () => {
    if (!material.pkcs8) throw new CryptoError('PRIVATE_KEY_REQUIRED', 'This key has no private part')
    return material.pkcs8
  }
  switch (format) {
    case 'spki-pem':
      return { text: toPem('PUBLIC KEY', material.spki), extension: '.pub.pem' }
    case 'pkcs1-public-pem':
      return { text: toPem('RSA PUBLIC KEY', pkcs1PublicFromSpki(material.spki)), extension: '.pub.pem' }
    case 'openssh':
      return { text: `${toOpenSshPublicKey(material.spki, options.comment)}\n`, extension: '.pub' }
    case 'jwk-public':
      return { text: `${JSON.stringify(exportJwk(material, false), null, 2)}\n`, extension: '.pub.jwk.json' }
    case 'pkcs8-pem':
      return { text: toPem('PRIVATE KEY', requirePrivate()), extension: '.key.pem' }
    case 'pkcs1-private-pem':
      return { text: toPem('RSA PRIVATE KEY', pkcs1PrivateFromPkcs8(requirePrivate())), extension: '.key.pem' }
    case 'encrypted-pkcs8-pem': {
      if (!options.passphrase) throw new CryptoError('INVALID_INPUT', 'Passphrase is empty')
      const der = await encryptPkcs8(requirePrivate(), options.passphrase)
      return { text: toPem('ENCRYPTED PRIVATE KEY', der), extension: '.key.pem' }
    }
    case 'jwk-private':
      requirePrivate()
      return { text: `${JSON.stringify(exportJwk(material, true), null, 2)}\n`, extension: '.key.jwk.json' }
  }
}

// ---------------------------------------------------------------------------------------------
// RSA encryption

export interface RsaEncryptRequest {
  data: Uint8Array<ArrayBuffer>
  recipients: Array<{ spki: Uint8Array<ArrayBuffer>; hash: RsaHash }>
  /** hybrid: RSA-OAEP wraps an AES-256-GCM key (any size). direct: RSA-OAEP of the data itself. */
  scheme: 'hybrid' | 'direct'
  format: 'edt' | 'raw'
  encoding?: 'base64' | 'hex'
}

export async function encryptRsa(req: RsaEncryptRequest): Promise<EncryptResponse> {
  const start = performance.now()
  if (req.scheme === 'hybrid') {
    const { bytes, header } = await encryptHybrid(req.data, req.recipients)
    return {
      bytes,
      text: armorEnvelope(bytes),
      summary: summarizeHeader(header),
      inputBytes: req.data.length,
      kdfMs: 0,
      cipherMs: performance.now() - start,
    }
  }
  const [recipient] = req.recipients
  if (!recipient) throw new CryptoError('INVALID_INPUT', 'A recipient is required')
  if (req.format === 'edt') {
    const { bytes, header } = await encryptRsaDirect(req.data, recipient.spki, recipient.hash)
    return {
      bytes,
      text: armorEnvelope(bytes),
      summary: summarizeHeader(header),
      inputBytes: req.data.length,
      kdfMs: 0,
      cipherMs: performance.now() - start,
    }
  }
  const bytes = await rsaOaepEncrypt(recipient.spki, recipient.hash, req.data)
  return {
    bytes,
    text: encodeText(bytes, req.encoding),
    summary: {
      container: 'raw',
      kind: 'rsa',
      keySource: 'rsa',
      integrity: 'none',
      rsaHash: recipient.hash,
      keyId: await computeKeyId(recipient.spki),
    },
    inputBytes: req.data.length,
    kdfMs: 0,
    cipherMs: performance.now() - start,
  }
}

export function rsaDirectLimit(spki: Uint8Array, hash: RsaHash): number {
  return oaepMaxMessageBytes(modulusBits(spki), hash)
}

export interface RsaDecryptRequest {
  input: DataInput
  keys: RsaKeyMaterial[]
  /** Raw OAEP ciphertext: which hash to use (the private key is keys[0]). */
  rawHash?: RsaHash
}

export async function decryptRsa(req: RsaDecryptRequest): Promise<DecryptResponse> {
  const detected = detect(req.input)
  const start = performance.now()
  if (detected.kind === 'envelope') {
    const envelope = decodeEnvelope(detected.bytes)
    const { header } = envelope
    if (header.type === 'rsa-hybrid') {
      const result = await decryptHybrid(envelope, req.keys)
      return toDecryptResponse(result.plaintext, summarizeHeader(header), { kdfMs: 0, cipherMs: performance.now() - start }, result.keyId)
    }
    if (header.type === 'rsa') {
      const result = await decryptRsaDirect(envelope, req.keys)
      return toDecryptResponse(result.plaintext, summarizeHeader(header), { kdfMs: 0, cipherMs: performance.now() - start }, result.keyId)
    }
    throw new CryptoError('UNSUPPORTED', 'This container is not an RSA message', { type: header.type })
  }
  if (detected.kind === 'openssl') throw new CryptoError('UNSUPPORTED', 'OpenSSL data is AES, not RSA', { type: 'openssl' })
  const key = req.keys.find((k) => k.pkcs8)
  if (!key?.pkcs8) throw new CryptoError('PRIVATE_KEY_REQUIRED', 'A private key is required')
  const hash = req.rawHash ?? 'SHA-256'
  const plaintext = await rsaOaepDecrypt(key.pkcs8, hash, detected.bytes)
  return toDecryptResponse(
    plaintext,
    { container: 'raw', kind: 'rsa', keySource: 'rsa', integrity: 'none', rsaHash: hash },
    { kdfMs: 0, cipherMs: performance.now() - start },
    await computeKeyId(key.spki),
  )
}

// ---------------------------------------------------------------------------------------------
// Signatures

export interface SignRequest {
  data: Uint8Array<ArrayBuffer>
  key: RsaKeyMaterial
  scheme: SignatureScheme
  hash: RsaHash
  saltLength?: number
  format: 'edt' | 'raw'
  encoding?: 'base64' | 'hex'
}

export interface SignResponse {
  bytes: Uint8Array<ArrayBuffer>
  text: string
  summary: CipherSummary
  ms: number
}

export async function sign(req: SignRequest): Promise<SignResponse> {
  const start = performance.now()
  const { bytes, header, signature } = await createSignature(req.data, req.key, req.scheme, req.hash, req.saltLength)
  const summary = summarizeHeader(header)
  if (req.format === 'edt') {
    return { bytes, text: armorEnvelope(bytes, ARMOR_SIGNATURE), summary, ms: performance.now() - start }
  }
  return {
    bytes: signature,
    text: encodeText(signature, req.encoding),
    summary: { ...summary, container: 'raw' },
    ms: performance.now() - start,
  }
}

export interface VerifyRequest {
  data: Uint8Array<ArrayBuffer>
  signature: DataInput
  keys: RsaKeyMaterial[]
  /** Used for bare signatures and when a specific key must be used. */
  raw?: { scheme: SignatureScheme; hash: RsaHash; saltLength?: number }
}

export interface VerifyResponse extends VerifyOutcome {
  container: 'edt' | 'raw'
}

export async function verify(req: VerifyRequest): Promise<VerifyResponse> {
  if (req.keys.length === 0) throw new CryptoError('INVALID_INPUT', 'A public key is required')
  let signatureBytes: Uint8Array<ArrayBuffer>
  if (req.signature.bytes) signatureBytes = req.signature.bytes
  else {
    const text = (req.signature.text ?? '').trim()
    if (text.includes(`-----BEGIN ${ARMOR_SIGNATURE}-----`)) signatureBytes = detectTextInput(text).bytes
    else if (isHex(text)) signatureBytes = fromHex(text)
    else signatureBytes = fromBase64(text)
  }

  if (signatureBytes[0] === 0x45 && signatureBytes[1] === 0x44 && signatureBytes[2] === 0x54) {
    const { header } = decodeEnvelope(signatureBytes)
    if (header.type !== 'signature') throw new CryptoError('UNSUPPORTED', 'Not a signature container', { type: header.type })
    const ids = await Promise.all(req.keys.map((k) => computeKeyId(k.spki)))
    const index = ids.indexOf(header.keyId)
    if (index === -1 && req.keys.length > 1) {
      throw new CryptoError('NO_MATCHING_KEY', 'No public key matches this signature', { recipients: header.keyId })
    }
    const outcome = await verifySignatureContainer(req.data, signatureBytes, req.keys[Math.max(index, 0)].spki)
    return { ...outcome, container: 'edt' }
  }

  if (!req.raw) throw new CryptoError('UNKNOWN_FORMAT', 'Bare signatures need the scheme and hash')
  const outcome = await verifyRawSignature(
    req.data,
    signatureBytes,
    req.keys[0].spki,
    req.raw.scheme,
    req.raw.hash,
    req.raw.saltLength,
  )
  return { ...outcome, container: 'raw' }
}

export { ARMOR_MESSAGE, ARMOR_SIGNATURE }
