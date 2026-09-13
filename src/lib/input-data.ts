import { utf8Encode } from '@/lib/crypto/encoding'
import type { DataInput } from '@/lib/crypto/service'
import type { InputValue } from '@/lib/files'

/** Bytes to encrypt or sign. An untouched text file is used byte for byte, keeping its BOM and line endings. */
export function inputBytes(value: InputValue): Uint8Array<ArrayBuffer> {
  if (value.kind === 'binary') return value.file.bytes
  return value.file?.pristine ? value.file.bytes : utf8Encode(value.text)
}

/**
 * Ciphertext or signature for the crypto layer. Files go through byte detection, which also
 * recognizes binary containers that happen to be valid UTF-8.
 */
export function inputForDetection(value: InputValue): DataInput {
  if (value.kind === 'binary') return { bytes: value.file.bytes }
  return value.file?.pristine ? { bytes: value.file.bytes } : { text: value.text }
}

/** Text produced by a previous step, labeled with a file name derived from the source. */
export function textInput(text: string, fileName?: string): InputValue {
  if (!fileName) return { kind: 'text', text }
  const bytes = utf8Encode(text)
  return { kind: 'text', text, file: { name: fileName, size: bytes.length, bytes, pristine: false } }
}
