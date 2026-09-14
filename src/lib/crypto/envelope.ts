import { z } from 'zod'
import { armor, concatBytes, dearmorAll, fromBase64, readUint16BE, uint16BE, utf8Decode, utf8Encode } from './encoding'
import { CryptoError } from './errors'
import { validateKdfParams, type KdfParams } from './kdf'

// Without this, Zod probes for eval with Function(''), which the site's Content-Security-Policy reports as a violation.
z.config({ jitless: true })

/**
 * EDT container, version 1.
 *
 *   bytes 0-2   magic "EDT"
 *   byte  3     version (1)
 *   bytes 4-5   header length N, uint16 big-endian
 *   bytes 6..   header: N bytes of UTF-8 JSON
 *   rest        payload (ciphertext, tag, signature...)
 *
 * The "prefix" (magic through header) is bound to the payload as GCM additional data or
 * inside the HMAC, so editing any parameter in the header makes decryption fail.
 */
export const ENVELOPE_MAGIC = new Uint8Array([0x45, 0x44, 0x54])
export const ENVELOPE_VERSION = 1
export const ARMOR_MESSAGE = 'EDT MESSAGE'
export const ARMOR_SIGNATURE = 'EDT SIGNATURE'
const MAX_HEADER_BYTES = 60_000

const base64 = z
  .string()
  .max(8192)
  .regex(/^[A-Za-z0-9+/]*={0,2}$/)
const keyId = z.string().regex(/^[0-9a-f]{16}$/)
const int = z.number().int()

const kdfSchema = z.discriminatedUnion('name', [
  z.object({ name: z.literal('PBKDF2'), hash: z.enum(['SHA-256', 'SHA-512']), iterations: int, salt: base64 }),
  z.object({ name: z.literal('Argon2id'), memoryKiB: int, iterations: int, parallelism: int, salt: base64 }),
  z.object({ name: z.literal('scrypt'), N: int, r: int, p: int, salt: base64 }),
])

const aesModeSchema = z.enum(['GCM', 'CBC', 'CTR', 'ECB'])
const aesKeyBitsSchema = z.union([z.literal(128), z.literal(192), z.literal(256)])
export const rsaHashSchema = z.enum(['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'])

const aesHeaderSchema = z.object({
  type: z.literal('aes'),
  mode: aesModeSchema,
  keyBits: aesKeyBitsSchema,
  iv: base64.optional(),
  key: z.discriminatedUnion('source', [
    z.object({ source: z.literal('password'), kdf: kdfSchema }),
    z.object({ source: z.literal('raw') }),
  ]),
  /** Encrypt-then-MAC for modes without built-in authentication. */
  mac: z.literal('HMAC-SHA256').optional(),
  /** 4-byte key check value, present only when nothing else can detect a wrong key. */
  check: base64.optional(),
  /** Set when the sender bound extra associated data that must be supplied again. */
  aad: z.boolean().optional(),
})

const hybridHeaderSchema = z.object({
  type: z.literal('rsa-hybrid'),
  mode: z.literal('GCM'),
  keyBits: aesKeyBitsSchema,
  iv: base64,
  recipients: z
    .array(z.object({ keyId, hash: rsaHashSchema, wrappedKey: base64 }))
    .min(1)
    .max(32),
})

const rsaHeaderSchema = z.object({
  type: z.literal('rsa'),
  hash: rsaHashSchema,
  keyId,
})

const signatureHeaderSchema = z.object({
  type: z.literal('signature'),
  scheme: z.enum(['RSA-PSS', 'RSASSA-PKCS1-v1_5']),
  hash: rsaHashSchema,
  saltLength: int.min(0).max(2048).optional(),
  keyId,
})

export const headerSchema = z.discriminatedUnion('type', [
  aesHeaderSchema,
  hybridHeaderSchema,
  rsaHeaderSchema,
  signatureHeaderSchema,
])

export type EnvelopeHeader = z.infer<typeof headerSchema>
export type AesHeader = z.infer<typeof aesHeaderSchema>
export type HybridHeader = z.infer<typeof hybridHeaderSchema>
export type RsaHeader = z.infer<typeof rsaHeaderSchema>
export type SignatureHeader = z.infer<typeof signatureHeaderSchema>
export type KdfHeader = z.infer<typeof kdfSchema>

export interface DecodedEnvelope {
  header: EnvelopeHeader
  /** Exact bytes of magic + version + length + header, as authenticated by the sender. */
  prefix: Uint8Array<ArrayBuffer>
  payload: Uint8Array<ArrayBuffer>
}

export function encodePrefix(header: EnvelopeHeader): Uint8Array<ArrayBuffer> {
  const json = utf8Encode(JSON.stringify(header))
  if (json.length > MAX_HEADER_BYTES) throw new CryptoError('INVALID_INPUT', 'Header too large')
  return concatBytes(ENVELOPE_MAGIC, new Uint8Array([ENVELOPE_VERSION]), uint16BE(json.length), json)
}

export function hasEnvelopeMagic(bytes: Uint8Array): boolean {
  return bytes.length >= 4 && bytes[0] === 0x45 && bytes[1] === 0x44 && bytes[2] === 0x54
}

export function decodeEnvelope(bytes: Uint8Array): DecodedEnvelope {
  if (!hasEnvelopeMagic(bytes)) throw new CryptoError('UNKNOWN_FORMAT', 'Not an EDT container')
  if (bytes[3] !== ENVELOPE_VERSION) {
    throw new CryptoError('UNSUPPORTED', 'Unsupported container version', { version: bytes[3] })
  }
  if (bytes.length < 6) throw new CryptoError('INVALID_INPUT', 'Truncated container')
  const headerLength = readUint16BE(bytes, 4)
  const headerEnd = 6 + headerLength
  if (headerLength === 0 || headerEnd > bytes.length) {
    throw new CryptoError('INVALID_INPUT', 'Truncated container header')
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(utf8Decode(bytes.subarray(6, headerEnd)))
  } catch {
    throw new CryptoError('INVALID_INPUT', 'Container header is not valid JSON')
  }
  const result = headerSchema.safeParse(parsed)
  if (!result.success) {
    throw new CryptoError('UNSUPPORTED', 'Container header has unknown or invalid fields')
  }
  const header = result.data
  if (header.type === 'aes' && header.key.source === 'password') {
    validateKdfParams(kdfFromHeader(header.key.kdf))
  }
  return {
    header,
    prefix: new Uint8Array(bytes.subarray(0, headerEnd)),
    payload: new Uint8Array(bytes.subarray(headerEnd)),
  }
}

export function kdfFromHeader(kdf: KdfHeader): KdfParams {
  switch (kdf.name) {
    case 'PBKDF2':
      return { name: 'PBKDF2', hash: kdf.hash, iterations: kdf.iterations }
    case 'Argon2id':
      return { name: 'Argon2id', memoryKiB: kdf.memoryKiB, iterations: kdf.iterations, parallelism: kdf.parallelism }
    case 'scrypt':
      return { name: 'scrypt', N: kdf.N, r: kdf.r, p: kdf.p }
  }
}

export function armorEnvelope(bytes: Uint8Array, label = ARMOR_MESSAGE): string {
  return armor(label, bytes)
}

/**
 * Recognizes what the user pasted or dropped, so decryption can pick the right path
 * without asking. Order matters: armored blocks, then binary magic, then encodings.
 */
export type DetectedInput =
  | { kind: 'envelope'; bytes: Uint8Array<ArrayBuffer>; header: EnvelopeHeader }
  | { kind: 'openssl'; bytes: Uint8Array<ArrayBuffer> }
  | { kind: 'raw'; bytes: Uint8Array<ArrayBuffer>; encoding: 'base64' | 'hex' | 'binary' }

const OPENSSL_MAGIC = [0x53, 0x61, 0x6c, 0x74, 0x65, 0x64, 0x5f, 0x5f] // "Salted__"

export function hasOpenSslMagic(bytes: Uint8Array): boolean {
  return bytes.length >= 16 && OPENSSL_MAGIC.every((value, index) => bytes[index] === value)
}

function classifyBytes(bytes: Uint8Array<ArrayBuffer>, encoding: 'base64' | 'hex' | 'binary'): DetectedInput {
  if (hasEnvelopeMagic(bytes)) {
    const { header } = decodeEnvelope(bytes)
    return { kind: 'envelope', bytes, header }
  }
  if (hasOpenSslMagic(bytes)) return { kind: 'openssl', bytes }
  return { kind: 'raw', bytes, encoding }
}

export function detectTextInput(text: string): DetectedInput {
  const trimmed = text.trim()
  if (!trimmed) throw new CryptoError('INVALID_INPUT', 'Input is empty')
  if (trimmed.includes('-----BEGIN ')) {
    const block = dearmorAll(trimmed).find((b) => b.label === ARMOR_MESSAGE || b.label === ARMOR_SIGNATURE)
    if (!block) throw new CryptoError('UNKNOWN_FORMAT', 'Unrecognized armored block')
    return classifyBytes(block.data, 'base64')
  }
  const compact = trimmed.replace(/\s+/g, '')
  if (/^[0-9a-fA-F]+$/.test(compact) && compact.length % 2 === 0 && compact.length >= 32) {
    const hexBytes = new Uint8Array(compact.length / 2)
    for (let i = 0; i < hexBytes.length; i++) hexBytes[i] = parseInt(compact.slice(i * 2, i * 2 + 2), 16)
    // Pure hex digits are also valid base64; prefer hex only if base64 would not decode to a container.
    const asBase64 = safeBase64(compact)
    if (asBase64 && (hasEnvelopeMagic(asBase64) || hasOpenSslMagic(asBase64))) return classifyBytes(asBase64, 'base64')
    return classifyBytes(hexBytes, 'hex')
  }
  const decoded = safeBase64(compact)
  if (!decoded) throw new CryptoError('INVALID_ENCODING', 'Input is neither base64 nor hex')
  return classifyBytes(decoded, 'base64')
}

function safeBase64(text: string): Uint8Array<ArrayBuffer> | null {
  try {
    return fromBase64(text)
  } catch {
    return null
  }
}

/** For dropped files: binary containers are read directly, text files are parsed as text. */
export function detectFileInput(bytes: Uint8Array<ArrayBuffer>): DetectedInput {
  if (hasEnvelopeMagic(bytes) || hasOpenSslMagic(bytes)) return classifyBytes(bytes, 'binary')
  let text: string | null = null
  try {
    text = utf8Decode(bytes)
  } catch {
    return { kind: 'raw', bytes, encoding: 'binary' }
  }
  return detectTextInput(text)
}
