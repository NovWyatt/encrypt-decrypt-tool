/**
 * A teaching implementation of the AES block cipher (FIPS-197) that records every intermediate
 * state. It is deliberately simple and slow, and is never used to protect real data: the tools
 * use WebCrypto and @noble/ciphers.
 */

export type AesStepKind = 'input' | 'addRoundKey' | 'subBytes' | 'shiftRows' | 'mixColumns'

export interface AesStep {
  round: number
  kind: AesStepKind
  /** State before this step. The state is 16 bytes in column order: row r, column c is `r + 4c`. */
  before: Uint8Array
  after: Uint8Array
  /** The round key mixed in by AddRoundKey. */
  roundKey?: Uint8Array
}

export interface KeyWord {
  index: number
  word: Uint8Array
  /** How the word was derived, for words that pass through the key schedule core. */
  rotated?: Uint8Array
  substituted?: Uint8Array
  rcon?: number
}

export interface AesTrace {
  rounds: number
  steps: AesStep[]
  roundKeys: Uint8Array[]
  keyWords: KeyWord[]
  output: Uint8Array
}

/** One byte as two hex digits. */
export const hex2 = (value: number) => value.toString(16).padStart(2, '0')

const rotl8 = (value: number, shift: number) => ((value << shift) | (value >> (8 - shift))) & 0xff

/** Multiplication by x (that is, by 2) in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1. */
export const xtime = (value: number) => ((value << 1) ^ (value & 0x80 ? 0x1b : 0)) & 0xff

export function gfMultiply(a: number, b: number): number {
  let result = 0
  for (let bit = 0; bit < 8; bit++) {
    if (b & (1 << bit)) result ^= a
    a = xtime(a)
  }
  return result
}

/**
 * The S-box is the multiplicative inverse in GF(2^8) followed by an affine transform. `p` walks
 * through all non-zero field elements as powers of 3 while `q` tracks its inverse.
 */
function buildSbox(): Uint8Array {
  const sbox = new Uint8Array(256)
  let p = 1
  let q = 1
  do {
    p = (p ^ (p << 1) ^ (p & 0x80 ? 0x1b : 0)) & 0xff
    q = (q ^ (q << 1)) & 0xff
    q = (q ^ (q << 2)) & 0xff
    q = (q ^ (q << 4)) & 0xff
    if (q & 0x80) q ^= 0x09
    const affine = q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4)
    sbox[p] = (affine ^ 0x63) & 0xff
  } while (p !== 1)
  sbox[0] = 0x63
  return sbox
}

export const SBOX = buildSbox()

export const MIX_MATRIX = [
  [2, 3, 1, 1],
  [1, 2, 3, 1],
  [1, 1, 2, 3],
  [3, 1, 1, 2],
] as const

export function subBytes(state: Uint8Array): Uint8Array {
  return state.map((value) => SBOX[value])
}

/** Row r moves r positions to the left. Returns, for each output position, its source position. */
export function shiftRowsSource(position: number): number {
  const row = position % 4
  const column = Math.floor(position / 4)
  return row + 4 * ((column + row) % 4)
}

export function shiftRows(state: Uint8Array): Uint8Array {
  return state.map((_, position) => state[shiftRowsSource(position)])
}

export function mixColumn(column: ArrayLike<number>): number[] {
  return MIX_MATRIX.map((row) => row.reduce((sum, factor, index) => sum ^ gfMultiply(factor, column[index]), 0))
}

export function mixColumns(state: Uint8Array): Uint8Array {
  const out = new Uint8Array(16)
  for (let column = 0; column < 4; column++) {
    out.set(mixColumn(state.subarray(4 * column, 4 * column + 4)), 4 * column)
  }
  return out
}

export function addRoundKey(state: Uint8Array, roundKey: Uint8Array): Uint8Array {
  return state.map((value, index) => value ^ roundKey[index])
}

export function expandKey(key: Uint8Array): { roundKeys: Uint8Array[]; words: KeyWord[] } {
  if (![16, 24, 32].includes(key.length)) throw new Error('AES keys are 16, 24 or 32 bytes')
  const nk = key.length / 4
  const rounds = nk + 6
  const words: KeyWord[] = []
  let rcon = 1
  for (let index = 0; index < 4 * (rounds + 1); index++) {
    if (index < nk) {
      words.push({ index, word: key.slice(4 * index, 4 * index + 4) })
      continue
    }
    let temp = words[index - 1].word
    const entry: KeyWord = { index, word: new Uint8Array(4) }
    if (index % nk === 0) {
      entry.rotated = new Uint8Array([temp[1], temp[2], temp[3], temp[0]])
      entry.substituted = entry.rotated.map((value) => SBOX[value])
      entry.rcon = rcon
      temp = entry.substituted.map((value, byte) => (byte === 0 ? value ^ rcon : value))
      rcon = xtime(rcon)
    } else if (nk > 6 && index % nk === 4) {
      entry.substituted = temp.map((value) => SBOX[value])
      temp = entry.substituted
    }
    entry.word = words[index - nk].word.map((value, byte) => value ^ temp[byte])
    words.push(entry)
  }
  const roundKeys = Array.from({ length: rounds + 1 }, (_, round) => {
    const roundKey = new Uint8Array(16)
    for (let word = 0; word < 4; word++) roundKey.set(words[4 * round + word].word, 4 * word)
    return roundKey
  })
  return { roundKeys, words }
}

export function traceEncrypt(block: Uint8Array, key: Uint8Array): AesTrace {
  if (block.length !== 16) throw new Error('AES blocks are 16 bytes')
  const { roundKeys, words } = expandKey(key)
  const rounds = roundKeys.length - 1
  const steps: AesStep[] = []
  let state: Uint8Array = block.slice()
  const apply = (round: number, kind: AesStepKind, next: Uint8Array, roundKey?: Uint8Array) => {
    steps.push({ round, kind, before: state, after: next, roundKey })
    state = next
  }

  steps.push({ round: 0, kind: 'input', before: state, after: state })
  apply(0, 'addRoundKey', addRoundKey(state, roundKeys[0]), roundKeys[0])
  for (let round = 1; round <= rounds; round++) {
    apply(round, 'subBytes', subBytes(state))
    apply(round, 'shiftRows', shiftRows(state))
    if (round < rounds) apply(round, 'mixColumns', mixColumns(state))
    apply(round, 'addRoundKey', addRoundKey(state, roundKeys[round]), roundKeys[round])
  }
  return { rounds, steps, roundKeys, keyWords: words, output: state }
}

export function hammingDistance(a: Uint8Array, b: Uint8Array): number {
  let bits = 0
  for (let index = 0; index < a.length; index++) {
    let diff = a[index] ^ b[index]
    while (diff) {
      bits += diff & 1
      diff >>= 1
    }
  }
  return bits
}

/** Bits that differ after each round when a single input bit is flipped. */
export function avalanche(block: Uint8Array, key: Uint8Array, bit: number): number[] {
  const flipped = block.slice()
  flipped[Math.floor(bit / 8)] ^= 0x80 >> (bit % 8)
  const roundStates = (trace: AesTrace) =>
    trace.steps.filter((step) => step.kind === 'addRoundKey').map((step) => step.after)
  const a = roundStates(traceEncrypt(block, key))
  const b = roundStates(traceEncrypt(flipped, key))
  return a.map((state, round) => hammingDistance(state, b[round]))
}
