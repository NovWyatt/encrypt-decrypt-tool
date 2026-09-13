import { CryptoError } from './errors'

const encoder = new TextEncoder()

export function utf8Encode(text: string): Uint8Array<ArrayBuffer> {
  return encoder.encode(text)
}

/** Decodes UTF-8, throwing INVALID_ENCODING when the bytes are not valid UTF-8 text. */
export function utf8Decode(bytes: Uint8Array): string {
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes)
  } catch {
    throw new CryptoError('INVALID_ENCODING', 'Data is not valid UTF-8 text')
  }
}

export function isValidUtf8(bytes: Uint8Array): boolean {
  try {
    new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    return true
  } catch {
    return false
  }
}

export function toHex(bytes: Uint8Array): string {
  let out = ''
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0')
  return out
}

/** Accepts upper/lower case, optional 0x prefix, and whitespace or colon separators. */
export function fromHex(text: string): Uint8Array<ArrayBuffer> {
  const clean = text.trim().replace(/^0x/i, '').replace(/[\s:]/g, '')
  if (clean.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(clean)) {
    throw new CryptoError('INVALID_ENCODING', 'Invalid hex string')
  }
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  return out
}

export function isHex(text: string): boolean {
  const clean = text.trim().replace(/^0x/i, '').replace(/[\s:]/g, '')
  return clean.length > 0 && clean.length % 2 === 0 && /^[0-9a-f]*$/i.test(clean)
}

const CHUNK = 0x8000

export function toBase64(bytes: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK))
  }
  return btoa(binary)
}

/** Accepts standard and URL-safe alphabets, missing padding and embedded whitespace. */
export function fromBase64(text: string): Uint8Array<ArrayBuffer> {
  let clean = text.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/')
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean)) {
    throw new CryptoError('INVALID_ENCODING', 'Invalid base64 string')
  }
  clean = clean.replace(/=+$/, '')
  if (clean.length % 4 === 1) throw new CryptoError('INVALID_ENCODING', 'Invalid base64 length')
  clean += '='.repeat((4 - (clean.length % 4)) % 4)
  let binary: string
  try {
    binary = atob(clean)
  } catch {
    throw new CryptoError('INVALID_ENCODING', 'Invalid base64 string')
  }
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i)
  return out
}

export function isBase64(text: string): boolean {
  const clean = text.replace(/\s+/g, '')
  return clean.length > 0 && /^[A-Za-z0-9+/_-]*={0,2}$/.test(clean) && clean.replace(/=+$/, '').length % 4 !== 1
}

export function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const total = parts.reduce((sum, part) => sum + part.length, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.length
  }
  return out
}

/** Constant-time comparison for MACs and key check values. */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

/** Copies into a fresh ArrayBuffer-backed array, which WebCrypto typings require. */
export function toBufferSource(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(bytes)
}

export function wrapLines(text: string, width = 64): string {
  const lines: string[] = []
  for (let i = 0; i < text.length; i += width) lines.push(text.slice(i, i + width))
  return lines.join('\n')
}

/** RFC 7468 textual encoding (the PEM layout), used for keys, messages and signatures. */
export function armor(label: string, data: Uint8Array): string {
  return `-----BEGIN ${label}-----\n${wrapLines(toBase64(data))}\n-----END ${label}-----\n`
}

export interface ArmoredBlock {
  label: string
  data: Uint8Array<ArrayBuffer>
  /** Header lines such as "Proc-Type: 4,ENCRYPTED" found before the base64 body. */
  headers: Record<string, string>
}

const ARMOR_RE = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g

export function dearmorAll(text: string): ArmoredBlock[] {
  const blocks: ArmoredBlock[] = []
  for (const match of text.matchAll(ARMOR_RE)) {
    const label = match[1]
    const headers: Record<string, string> = {}
    const bodyLines: string[] = []
    for (const rawLine of match[2].split(/\r?\n/)) {
      const line = rawLine.trim()
      if (!line) continue
      const header = /^([A-Za-z-]+):\s*(.*)$/.exec(line)
      if (header && bodyLines.length === 0) {
        headers[header[1]] = header[2]
      } else {
        bodyLines.push(line)
      }
    }
    blocks.push({ label, data: fromBase64(bodyLines.join('')), headers })
  }
  return blocks
}

export function dearmor(text: string): ArmoredBlock | null {
  return dearmorAll(text)[0] ?? null
}

export function readUint16BE(bytes: Uint8Array, offset: number): number {
  return (bytes[offset] << 8) | bytes[offset + 1]
}

export function uint16BE(value: number): Uint8Array<ArrayBuffer> {
  return new Uint8Array([(value >>> 8) & 0xff, value & 0xff])
}

export function formatBytes(size: number): string {
  if (size < 1024) return `${size} B`
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`
  return `${(size / (1024 * 1024)).toFixed(2)} MB`
}
