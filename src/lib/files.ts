import { isValidUtf8, utf8Decode } from '@/lib/crypto/encoding'

export const MAX_FILE_BYTES = 128 * 1024 * 1024

export interface LoadedFile {
  name: string
  size: number
  bytes: Uint8Array<ArrayBuffer>
  /** Decoded text when the file is valid UTF-8, otherwise null. */
  text: string | null
}

export class FileTooLargeError extends Error {
  constructor() {
    super('File too large')
    this.name = 'FileTooLargeError'
  }
}

export async function loadFile(file: File): Promise<LoadedFile> {
  if (file.size > MAX_FILE_BYTES) throw new FileTooLargeError()
  const bytes = new Uint8Array(await file.arrayBuffer())
  return { name: file.name, size: file.size, bytes, text: isValidUtf8(bytes) ? utf8Decode(bytes) : null }
}

/** What a data input currently holds: editable text (maybe from a file) or an opaque binary file. */
export type InputValue =
  | { kind: 'text'; text: string; file?: { name: string; size: number; bytes: Uint8Array<ArrayBuffer>; pristine: boolean } }
  | { kind: 'binary'; file: LoadedFile }

export const EMPTY_INPUT: InputValue = { kind: 'text', text: '' }

export function inputFromFile(file: LoadedFile): InputValue {
  return file.text === null
    ? { kind: 'binary', file }
    : { kind: 'text', text: file.text, file: { name: file.name, size: file.size, bytes: file.bytes, pristine: true } }
}

export function isInputEmpty(value: InputValue): boolean {
  return value.kind === 'text' ? value.text.length === 0 : false
}

export function inputFileName(value: InputValue): string | undefined {
  return value.kind === 'binary' ? value.file.name : value.file?.name
}

export function downloadBlob(data: BlobPart, fileName: string, type: string): void {
  const url = URL.createObjectURL(new Blob([data], { type }))
  const link = document.createElement('a')
  link.href = url
  link.download = fileName
  link.rel = 'noopener'
  document.body.appendChild(link)
  link.click()
  link.remove()
  setTimeout(() => URL.revokeObjectURL(url), 2000)
}

const ENCRYPTED_SUFFIXES = ['.edt', '.edt.bin', '.enc', '.bin', '.b64', '.txt.edt']

/** "notes.txt" -> "notes.txt.edt"; decrypting "notes.txt.edt" -> "notes.txt". */
export function encryptedFileName(source: string | undefined, extension: string, fallback = 'message'): string {
  return `${source ?? fallback}${extension}`
}

export function decryptedFileName(source: string | undefined, isText: boolean): string {
  if (source) {
    const suffix = ENCRYPTED_SUFFIXES.filter((s) => source.toLowerCase().endsWith(s)).sort((a, b) => b.length - a.length)[0]
    if (suffix && source.length > suffix.length) return source.slice(0, -suffix.length)
  }
  return isText ? 'decrypted.txt' : 'decrypted.bin'
}
