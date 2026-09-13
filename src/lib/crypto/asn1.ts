import { concatBytes } from './encoding'
import { CryptoError } from './errors'

/** Minimal DER reader/writer covering the structures used by RSA keys and PKCS#8 encryption. */
export const TAG = {
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  SEQUENCE: 0x30,
  SET: 0x31,
  CONTEXT_0: 0xa0,
} as const

export const OID = {
  rsaEncryption: '1.2.840.113549.1.1.1',
  pbes2: '1.2.840.113549.1.5.13',
  pbkdf2: '1.2.840.113549.1.5.12',
  scrypt: '1.3.6.1.4.1.11591.4.11',
  hmacWithSHA1: '1.2.840.113549.2.7',
  hmacWithSHA256: '1.2.840.113549.2.9',
  hmacWithSHA384: '1.2.840.113549.2.10',
  hmacWithSHA512: '1.2.840.113549.2.11',
  aes128Cbc: '2.16.840.1.101.3.4.1.2',
  aes192Cbc: '2.16.840.1.101.3.4.1.22',
  aes256Cbc: '2.16.840.1.101.3.4.1.42',
} as const

export interface Asn1Node {
  tag: number
  /** Content bytes (without tag and length). */
  value: Uint8Array
  /** Whole encoding, tag through content. */
  raw: Uint8Array
  children: Asn1Node[]
}

function invalid(message: string): never {
  throw new CryptoError('INVALID_KEY', `Invalid DER: ${message}`)
}

function readNode(bytes: Uint8Array, offset: number): { node: Asn1Node; next: number } {
  if (offset + 2 > bytes.length) invalid('truncated')
  const tag = bytes[offset]
  if ((tag & 0x1f) === 0x1f) invalid('high tag numbers are not supported')
  let length = bytes[offset + 1]
  let header = 2
  if (length & 0x80) {
    const count = length & 0x7f
    if (count === 0 || count > 4) invalid('unsupported length encoding')
    if (offset + 2 + count > bytes.length) invalid('truncated length')
    length = 0
    for (let i = 0; i < count; i++) length = length * 256 + bytes[offset + 2 + i]
    header += count
  }
  const end = offset + header + length
  if (end > bytes.length) invalid('length exceeds data')
  const value = bytes.subarray(offset + header, end)
  const node: Asn1Node = { tag, value, raw: bytes.subarray(offset, end), children: [] }
  if (tag & 0x20) {
    let cursor = 0
    while (cursor < value.length) {
      const child = readNode(value, cursor)
      node.children.push(child.node)
      cursor = child.next
    }
  }
  return { node, next: end }
}

/** Parses one DER element that must span the entire input. */
export function parseDer(bytes: Uint8Array): Asn1Node {
  const { node, next } = readNode(bytes, 0)
  if (next !== bytes.length) invalid('trailing data')
  return node
}

export function expectTag(node: Asn1Node | undefined, tag: number, what: string): Asn1Node {
  if (!node || node.tag !== tag) invalid(`expected ${what}`)
  return node
}

export function encodeLength(length: number): Uint8Array {
  if (length < 0x80) return new Uint8Array([length])
  const bytes: number[] = []
  for (let n = length; n > 0; n = Math.floor(n / 256)) bytes.unshift(n & 0xff)
  return new Uint8Array([0x80 | bytes.length, ...bytes])
}

export function tlv(tag: number, ...contents: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const value = concatBytes(...contents)
  return concatBytes(new Uint8Array([tag]), encodeLength(value.length), value)
}

export const derSequence = (...items: Uint8Array[]) => tlv(TAG.SEQUENCE, ...items)
export const derNull = () => new Uint8Array([TAG.NULL, 0x00])
export const derOctetString = (bytes: Uint8Array) => tlv(TAG.OCTET_STRING, bytes)
export const derBitString = (bytes: Uint8Array) => tlv(TAG.BIT_STRING, new Uint8Array([0]), bytes)

/** Encodes an unsigned big-endian magnitude as a DER INTEGER. */
export function derUnsignedInteger(magnitude: Uint8Array): Uint8Array<ArrayBuffer> {
  let start = 0
  while (start < magnitude.length - 1 && magnitude[start] === 0) start++
  const trimmed = magnitude.subarray(start)
  const body = trimmed.length === 0 ? new Uint8Array([0]) : trimmed
  return body[0] & 0x80 ? tlv(TAG.INTEGER, new Uint8Array([0]), body) : tlv(TAG.INTEGER, body)
}

export function derSmallInteger(value: number): Uint8Array<ArrayBuffer> {
  if (!Number.isInteger(value) || value < 0) throw new RangeError('Only non-negative integers are supported')
  const bytes: number[] = []
  for (let n = value; n > 0; n = Math.floor(n / 256)) bytes.unshift(n & 0xff)
  return derUnsignedInteger(new Uint8Array(bytes.length ? bytes : [0]))
}

/** Unsigned magnitude of a non-negative INTEGER, without the sign padding byte. */
export function integerMagnitude(node: Asn1Node): Uint8Array {
  expectTag(node, TAG.INTEGER, 'INTEGER')
  if (node.value.length === 0) invalid('empty INTEGER')
  if (node.value[0] & 0x80) invalid('negative INTEGER')
  let start = 0
  while (start < node.value.length - 1 && node.value[start] === 0) start++
  return node.value.subarray(start)
}

export function integerToNumber(node: Asn1Node): number {
  const magnitude = integerMagnitude(node)
  if (magnitude.length > 6) invalid('INTEGER too large')
  return magnitude.reduce((acc, byte) => acc * 256 + byte, 0)
}

export function derOid(oid: string): Uint8Array<ArrayBuffer> {
  const parts = oid.split('.').map(Number)
  const bytes: number[] = [parts[0] * 40 + parts[1]]
  for (const part of parts.slice(2)) {
    const chunk: number[] = [part & 0x7f]
    for (let n = Math.floor(part / 128); n > 0; n = Math.floor(n / 128)) chunk.unshift((n & 0x7f) | 0x80)
    bytes.push(...chunk)
  }
  return tlv(TAG.OID, new Uint8Array(bytes))
}

export function decodeOid(node: Asn1Node): string {
  expectTag(node, TAG.OID, 'OBJECT IDENTIFIER')
  const { value } = node
  if (value.length === 0) invalid('empty OID')
  const parts: number[] = [Math.floor(value[0] / 40), value[0] % 40]
  let current = 0
  for (const byte of value.subarray(1)) {
    current = current * 128 + (byte & 0x7f)
    if (!(byte & 0x80)) {
      parts.push(current)
      current = 0
    }
  }
  return parts.join('.')
}

/** Content of a BIT STRING with zero unused bits. */
export function bitStringContent(node: Asn1Node): Uint8Array {
  expectTag(node, TAG.BIT_STRING, 'BIT STRING')
  if (node.value[0] !== 0) invalid('BIT STRING with unused bits')
  return node.value.subarray(1)
}
