import { randomInt } from '@/lib/crypto/random'

export type StrengthScore = 0 | 1 | 2 | 3 | 4

const COMMON = new Set([
  '123456',
  '12345678',
  '123456789',
  '1234567890',
  'password',
  'password1',
  'qwerty',
  'qwerty123',
  'abc123',
  '111111',
  '000000',
  'iloveyou',
  'admin',
  'welcome',
  'matkhau',
  'matkhau123',
  'anhyeuem',
  'emyeuanh',
  'vietnam',
  'hanoi',
  'saigon',
])

function charsetSize(password: string): number {
  let size = 0
  if (/[a-z]/.test(password)) size += 26
  if (/[A-Z]/.test(password)) size += 26
  if (/[0-9]/.test(password)) size += 10
  if (/[^\p{L}\p{N}]/u.test(password)) size += 33
  // Vietnamese letters with diacritics and other non-ASCII letters widen the alphabet.
  if ([...password].some((char) => char.codePointAt(0)! > 0x7f)) size += 60
  return Math.max(size, 1)
}

/**
 * Rough, dependency-free estimate. It rewards length and variety and punishes the patterns
 * attackers try first (common passwords, repeats, keyboard or number sequences).
 */
export function estimateStrength(password: string): { score: StrengthScore; bits: number } {
  if (!password) return { score: 0, bits: 0 }
  const normalized = password.normalize('NFC')
  const lower = normalized.toLowerCase()
  const length = [...normalized].length
  let bits = length * Math.log2(charsetSize(normalized))

  if (COMMON.has(lower.replace(/[\s._-]/g, ''))) bits = Math.min(bits, 8)
  const uniqueRatio = new Set(normalized).size / length
  if (uniqueRatio < 0.4) bits *= 0.5
  if (/(.)\1{3,}/.test(normalized)) bits *= 0.7
  if (/(0123|1234|2345|3456|4567|5678|6789|abcd|qwer|asdf|zxcv)/.test(lower)) bits *= 0.75
  if (/^(19|20)\d{2}$/.test(normalized) || /^\d{1,8}$/.test(normalized)) bits = Math.min(bits, 20)

  const score: StrengthScore = bits < 28 ? 0 : bits < 40 ? 1 : bits < 60 ? 2 : bits < 90 ? 3 : 4
  return { score, bits: Math.round(bits) }
}

const ALPHABET = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'

/** Four groups of five unambiguous characters, about 116 bits of entropy, easy to read aloud. */
export function generatePassword(groups = 4, groupLength = 5): string {
  const parts: string[] = []
  for (let g = 0; g < groups; g++) {
    let part = ''
    for (let i = 0; i < groupLength; i++) part += ALPHABET[randomInt(ALPHABET.length)]
    parts.push(part)
  }
  return parts.join('-')
}
