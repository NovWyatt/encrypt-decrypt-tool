import { scrypt } from 'hash-wasm'
import { aesDecrypt, aesEncrypt } from './aes'
import {
  bitStringContent,
  decodeOid,
  derBitString,
  derNull,
  derOctetString,
  derOid,
  derSequence,
  derSmallInteger,
  derUnsignedInteger,
  expectTag,
  integerMagnitude,
  integerToNumber,
  OID,
  parseDer,
  TAG,
  type Asn1Node,
} from './asn1'
import {
  armor,
  concatBytes,
  dearmorAll,
  fromBase64,
  fromHex,
  toBase64,
  toBase64Url,
  toBufferSource,
  toHex,
  utf8Decode,
  utf8Encode,
} from './encoding'
import { CryptoError } from './errors'
import { evpBytesToKey } from './openssl'
import { randomBytes } from './random'

export type RsaHash = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512'
export type RsaAlgorithm = 'RSA-OAEP' | 'RSA-PSS' | 'RSASSA-PKCS1-v1_5'

export const HASH_BYTES: Record<RsaHash, number> = { 'SHA-1': 20, 'SHA-256': 32, 'SHA-384': 48, 'SHA-512': 64 }
export const RSA_KEY_SIZES = [1024, 2048, 3072, 4096] as const

export const PEM_LABELS = {
  spki: 'PUBLIC KEY',
  pkcs8: 'PRIVATE KEY',
  pkcs1Public: 'RSA PUBLIC KEY',
  pkcs1Private: 'RSA PRIVATE KEY',
  encryptedPkcs8: 'ENCRYPTED PRIVATE KEY',
} as const

export interface RsaPublicComponents {
  n: Uint8Array
  e: Uint8Array
}

export interface RsaPrivateComponents extends RsaPublicComponents {
  d: Uint8Array
  p: Uint8Array
  q: Uint8Array
  dp: Uint8Array
  dq: Uint8Array
  qi: Uint8Array
}

/** A key pair or public key held by the app, always in canonical DER. */
export interface RsaKeyMaterial {
  spki: Uint8Array<ArrayBuffer>
  pkcs8?: Uint8Array<ArrayBuffer>
}

const rsaAlgorithmIdentifier = () => derSequence(derOid(OID.rsaEncryption), derNull())

function assertRsaAlgorithm(node: Asn1Node | undefined): void {
  const alg = expectTag(node, TAG.SEQUENCE, 'AlgorithmIdentifier')
  const oid = decodeOid(alg.children[0])
  if (oid !== OID.rsaEncryption) throw new CryptoError('UNSUPPORTED', 'Only RSA keys are supported', { oid })
}

export function bitLength(magnitude: Uint8Array): number {
  let start = 0
  while (start < magnitude.length && magnitude[start] === 0) start++
  if (start === magnitude.length) return 0
  return (magnitude.length - start - 1) * 8 + (32 - Math.clz32(magnitude[start]))
}

// ---------------------------------------------------------------------------------------------
// PKCS#1 <-> SPKI / PKCS#8

export function parsePkcs1Public(der: Uint8Array): RsaPublicComponents {
  const root = expectTag(parseDer(der), TAG.SEQUENCE, 'RSAPublicKey')
  if (root.children.length !== 2) throw new CryptoError('INVALID_KEY', 'Invalid RSAPublicKey')
  return { n: integerMagnitude(root.children[0]), e: integerMagnitude(root.children[1]) }
}

export function encodePkcs1Public({ n, e }: RsaPublicComponents): Uint8Array<ArrayBuffer> {
  return derSequence(derUnsignedInteger(n), derUnsignedInteger(e))
}

export function parsePkcs1Private(der: Uint8Array): RsaPrivateComponents {
  const root = expectTag(parseDer(der), TAG.SEQUENCE, 'RSAPrivateKey')
  if (root.children.length !== 9 || integerToNumber(root.children[0]) !== 0) {
    throw new CryptoError('UNSUPPORTED', 'Only two-prime RSA private keys are supported')
  }
  const [, n, e, d, p, q, dp, dq, qi] = root.children.map((child, index) =>
    index === 0 ? new Uint8Array() : integerMagnitude(child),
  )
  return { n, e, d, p, q, dp, dq, qi }
}

export function encodePkcs1Private(c: RsaPrivateComponents): Uint8Array<ArrayBuffer> {
  return derSequence(
    derSmallInteger(0),
    ...[c.n, c.e, c.d, c.p, c.q, c.dp, c.dq, c.qi].map((value) => derUnsignedInteger(value)),
  )
}

export function spkiFromComponents(components: RsaPublicComponents): Uint8Array<ArrayBuffer> {
  return derSequence(rsaAlgorithmIdentifier(), derBitString(encodePkcs1Public(components)))
}

export function pkcs8FromComponents(components: RsaPrivateComponents): Uint8Array<ArrayBuffer> {
  return derSequence(derSmallInteger(0), rsaAlgorithmIdentifier(), derOctetString(encodePkcs1Private(components)))
}

export function publicComponentsFromSpki(spki: Uint8Array): RsaPublicComponents {
  const root = expectTag(parseDer(spki), TAG.SEQUENCE, 'SubjectPublicKeyInfo')
  assertRsaAlgorithm(root.children[0])
  return parsePkcs1Public(bitStringContent(root.children[1]))
}

export function privateComponentsFromPkcs8(pkcs8: Uint8Array): RsaPrivateComponents {
  const root = expectTag(parseDer(pkcs8), TAG.SEQUENCE, 'PrivateKeyInfo')
  if (root.children.length < 3) throw new CryptoError('INVALID_KEY', 'Invalid PrivateKeyInfo')
  const version = integerToNumber(root.children[0])
  if (version !== 0 && version !== 1) throw new CryptoError('UNSUPPORTED', 'Unsupported PKCS#8 version')
  assertRsaAlgorithm(root.children[1])
  return parsePkcs1Private(expectTag(root.children[2], TAG.OCTET_STRING, 'privateKey').value)
}

/** Re-encodes keys canonically so fingerprints stay stable whatever format they came from. */
export function normalizeSpki(spki: Uint8Array): Uint8Array<ArrayBuffer> {
  return spkiFromComponents(publicComponentsFromSpki(spki))
}

export function normalizePkcs8(pkcs8: Uint8Array): RsaKeyMaterial {
  const components = privateComponentsFromPkcs8(pkcs8)
  return { spki: spkiFromComponents(components), pkcs8: pkcs8FromComponents(components) }
}

export function pkcs1PublicFromSpki(spki: Uint8Array): Uint8Array<ArrayBuffer> {
  return encodePkcs1Public(publicComponentsFromSpki(spki))
}

export function pkcs1PrivateFromPkcs8(pkcs8: Uint8Array): Uint8Array<ArrayBuffer> {
  return encodePkcs1Private(privateComponentsFromPkcs8(pkcs8))
}

// ---------------------------------------------------------------------------------------------
// Generation, fingerprints, details

export async function generateRsaKeyPair(bits: number, publicExponent = 65537): Promise<RsaKeyMaterial> {
  if (!Number.isInteger(bits) || bits < 1024 || bits > 16384 || bits % 8 !== 0) {
    throw new CryptoError('PARAMS_OUT_OF_RANGE', 'Unsupported RSA modulus size', { field: 'bits' })
  }
  if (publicExponent !== 65537 && publicExponent !== 3) {
    throw new CryptoError('PARAMS_OUT_OF_RANGE', 'Public exponent must be 65537 or 3', { field: 'publicExponent' })
  }
  const exponent = publicExponent === 3 ? new Uint8Array([3]) : new Uint8Array([1, 0, 1])
  const pair = await crypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: bits, publicExponent: exponent, hash: 'SHA-256' },
    true,
    ['encrypt', 'decrypt'],
  )
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey))
  return normalizePkcs8(pkcs8)
}

export async function spkiFingerprint(spki: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', toBufferSource(spki)))
}

/** 16 hex characters identifying a public key inside message headers. */
export async function computeKeyId(spki: Uint8Array): Promise<string> {
  return toHex((await spkiFingerprint(spki)).subarray(0, 8))
}

export function formatFingerprint(fingerprint: Uint8Array): string {
  return `SHA256:${toBase64(fingerprint).replace(/=+$/, '')}`
}

export interface RsaKeyDetails {
  bits: number
  modulusHex: string
  publicExponent: number
  hasPrivate: boolean
  private?: { d: string; p: string; q: string; dp: string; dq: string; qi: string }
}

export function describeKey(material: RsaKeyMaterial): RsaKeyDetails {
  const pub = publicComponentsFromSpki(material.spki)
  const details: RsaKeyDetails = {
    bits: bitLength(pub.n),
    modulusHex: toHex(pub.n),
    publicExponent: pub.e.reduce((acc, byte) => acc * 256 + byte, 0),
    hasPrivate: Boolean(material.pkcs8),
  }
  if (material.pkcs8) {
    const c = privateComponentsFromPkcs8(material.pkcs8)
    details.private = { d: toHex(c.d), p: toHex(c.p), q: toHex(c.q), dp: toHex(c.dp), dq: toHex(c.dq), qi: toHex(c.qi) }
  }
  return details
}

export function modulusBits(spki: Uint8Array): number {
  return bitLength(publicComponentsFromSpki(spki).n)
}

// ---------------------------------------------------------------------------------------------
// WebCrypto handles

export function importPublicKey(spki: Uint8Array, algorithm: RsaAlgorithm, hash: RsaHash): Promise<CryptoKey> {
  const usages: KeyUsage[] = algorithm === 'RSA-OAEP' ? ['encrypt'] : ['verify']
  return crypto.subtle.importKey('spki', toBufferSource(spki), { name: algorithm, hash }, false, usages)
}

export function importPrivateKey(pkcs8: Uint8Array, algorithm: RsaAlgorithm, hash: RsaHash): Promise<CryptoKey> {
  const usages: KeyUsage[] = algorithm === 'RSA-OAEP' ? ['decrypt'] : ['sign']
  return crypto.subtle.importKey('pkcs8', toBufferSource(pkcs8), { name: algorithm, hash }, false, usages)
}

// ---------------------------------------------------------------------------------------------
// Text formats: PEM, JWK, OpenSSH

export function toPem(label: string, der: Uint8Array): string {
  return armor(label, der)
}

export function exportJwk(material: RsaKeyMaterial, includePrivate: boolean): JsonWebKey {
  if (includePrivate && material.pkcs8) {
    const c = privateComponentsFromPkcs8(material.pkcs8)
    return {
      kty: 'RSA',
      n: toBase64Url(c.n),
      e: toBase64Url(c.e),
      d: toBase64Url(c.d),
      p: toBase64Url(c.p),
      q: toBase64Url(c.q),
      dp: toBase64Url(c.dp),
      dq: toBase64Url(c.dq),
      qi: toBase64Url(c.qi),
    }
  }
  const pub = publicComponentsFromSpki(material.spki)
  return { kty: 'RSA', n: toBase64Url(pub.n), e: toBase64Url(pub.e) }
}

export function importJwk(jwk: JsonWebKey): RsaKeyMaterial {
  if (jwk.kty !== 'RSA' || !jwk.n || !jwk.e) throw new CryptoError('INVALID_KEY', 'JWK is not an RSA key')
  const n = fromBase64(jwk.n)
  const e = fromBase64(jwk.e)
  if (!jwk.d) return { spki: spkiFromComponents({ n, e }) }
  if (!jwk.p || !jwk.q || !jwk.dp || !jwk.dq || !jwk.qi) {
    throw new CryptoError('UNSUPPORTED', 'Private JWK must include CRT parameters (p, q, dp, dq, qi)')
  }
  const components: RsaPrivateComponents = {
    n,
    e,
    d: fromBase64(jwk.d),
    p: fromBase64(jwk.p),
    q: fromBase64(jwk.q),
    dp: fromBase64(jwk.dp),
    dq: fromBase64(jwk.dq),
    qi: fromBase64(jwk.qi),
  }
  return { spki: spkiFromComponents(components), pkcs8: pkcs8FromComponents(components) }
}

function sshString(bytes: Uint8Array): Uint8Array {
  const length = new Uint8Array(4)
  new DataView(length.buffer).setUint32(0, bytes.length)
  return concatBytes(length, bytes)
}

function sshMpint(magnitude: Uint8Array): Uint8Array {
  let start = 0
  while (start < magnitude.length && magnitude[start] === 0) start++
  const trimmed = magnitude.subarray(start)
  return sshString(trimmed.length && trimmed[0] & 0x80 ? concatBytes(new Uint8Array([0]), trimmed) : trimmed)
}

export function toOpenSshPublicKey(spki: Uint8Array, comment = ''): string {
  const { n, e } = publicComponentsFromSpki(spki)
  const blob = concatBytes(sshString(utf8Encode('ssh-rsa')), sshMpint(e), sshMpint(n))
  return `ssh-rsa ${toBase64(blob)}${comment ? ` ${comment}` : ''}`
}

export function fromOpenSshPublicKey(line: string): Uint8Array<ArrayBuffer> {
  const [type, body] = line.trim().split(/\s+/)
  if (type !== 'ssh-rsa' || !body) throw new CryptoError('UNSUPPORTED', 'Only ssh-rsa public keys are supported')
  const blob = fromBase64(body)
  const view = new DataView(blob.buffer, blob.byteOffset, blob.byteLength)
  let offset = 0
  const read = () => {
    if (offset + 4 > blob.length) throw new CryptoError('INVALID_KEY', 'Truncated OpenSSH key')
    const length = view.getUint32(offset)
    offset += 4
    if (offset + length > blob.length) throw new CryptoError('INVALID_KEY', 'Truncated OpenSSH key')
    const value = blob.subarray(offset, offset + length)
    offset += length
    return value
  }
  if (utf8Decode(read()) !== 'ssh-rsa') throw new CryptoError('INVALID_KEY', 'OpenSSH key type mismatch')
  const e = read()
  const n = read()
  return spkiFromComponents({ n, e })
}

// ---------------------------------------------------------------------------------------------
// Password-protected private keys

export interface Pkcs8EncryptOptions {
  iterations?: number
  hash?: 'SHA-256' | 'SHA-512'
}

const PRF_OIDS: Record<string, 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512'> = {
  [OID.hmacWithSHA1]: 'SHA-1',
  [OID.hmacWithSHA256]: 'SHA-256',
  [OID.hmacWithSHA384]: 'SHA-384',
  [OID.hmacWithSHA512]: 'SHA-512',
}

const CBC_OIDS: Record<string, number> = { [OID.aes128Cbc]: 16, [OID.aes192Cbc]: 24, [OID.aes256Cbc]: 32 }

async function pbkdf2Bytes(password: Uint8Array, salt: Uint8Array, iterations: number, hash: string, length: number) {
  const base = await crypto.subtle.importKey('raw', toBufferSource(password), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash, salt: toBufferSource(salt), iterations },
    base,
    length * 8,
  )
  return new Uint8Array(bits)
}

/** PKCS#8 EncryptedPrivateKeyInfo with PBES2 (PBKDF2-HMAC + AES-256-CBC), readable by OpenSSL. */
export async function encryptPkcs8(
  pkcs8: Uint8Array,
  passphrase: string,
  options: Pkcs8EncryptOptions = {},
): Promise<Uint8Array<ArrayBuffer>> {
  if (!passphrase) throw new CryptoError('INVALID_INPUT', 'Passphrase is empty')
  const iterations = options.iterations ?? 600_000
  const hash = options.hash ?? 'SHA-256'
  const salt = randomBytes(16)
  const iv = randomBytes(16)
  const key = await pbkdf2Bytes(utf8Encode(passphrase.normalize('NFC')), salt, iterations, hash, 32)
  const ciphertext = await aesEncrypt('CBC', key, iv, pkcs8)
  const prf = hash === 'SHA-512' ? OID.hmacWithSHA512 : OID.hmacWithSHA256
  const pbes2Params = derSequence(
    derSequence(
      derOid(OID.pbkdf2),
      derSequence(derOctetString(salt), derSmallInteger(iterations), derSequence(derOid(prf), derNull())),
    ),
    derSequence(derOid(OID.aes256Cbc), derOctetString(iv)),
  )
  return derSequence(derSequence(derOid(OID.pbes2), pbes2Params), derOctetString(ciphertext))
}

export async function decryptPkcs8(encrypted: Uint8Array, passphrase: string): Promise<RsaKeyMaterial> {
  const root = expectTag(parseDer(encrypted), TAG.SEQUENCE, 'EncryptedPrivateKeyInfo')
  const algorithm = expectTag(root.children[0], TAG.SEQUENCE, 'encryptionAlgorithm')
  if (decodeOid(algorithm.children[0]) !== OID.pbes2) {
    throw new CryptoError('UNSUPPORTED', 'Only PBES2-encrypted private keys are supported')
  }
  const params = expectTag(algorithm.children[1], TAG.SEQUENCE, 'PBES2-params')
  const kdf = expectTag(params.children[0], TAG.SEQUENCE, 'keyDerivationFunc')
  const scheme = expectTag(params.children[1], TAG.SEQUENCE, 'encryptionScheme')
  const keyLength = CBC_OIDS[decodeOid(scheme.children[0])]
  if (!keyLength) throw new CryptoError('UNSUPPORTED', 'Unsupported private key cipher (AES-CBC required)')
  const iv = expectTag(scheme.children[1], TAG.OCTET_STRING, 'IV').value
  const ciphertext = expectTag(root.children[1], TAG.OCTET_STRING, 'encryptedData').value

  const kdfOid = decodeOid(kdf.children[0])
  const kdfParams = expectTag(kdf.children[1], TAG.SEQUENCE, 'KDF params')
  const salt = expectTag(kdfParams.children[0], TAG.OCTET_STRING, 'salt').value

  const deriveFor = async (password: Uint8Array): Promise<Uint8Array> => {
    if (kdfOid === OID.pbkdf2) {
      const iterations = integerToNumber(kdfParams.children[1])
      if (iterations < 1 || iterations > 10_000_000)
        throw new CryptoError('PARAMS_OUT_OF_RANGE', 'Iterations out of range')
      const prfNode = kdfParams.children.find((child, index) => index >= 2 && child.tag === TAG.SEQUENCE)
      const hash = prfNode ? PRF_OIDS[decodeOid(prfNode.children[0])] : 'SHA-1'
      if (!hash) throw new CryptoError('UNSUPPORTED', 'Unsupported PBKDF2 PRF')
      return pbkdf2Bytes(password, salt, iterations, hash, keyLength)
    }
    if (kdfOid === OID.scrypt) {
      const [N, r, p] = kdfParams.children.slice(1, 4).map(integerToNumber)
      if (!N || (N & (N - 1)) !== 0 || N > 2 ** 20 || r > 32 || p > 16) {
        throw new CryptoError('PARAMS_OUT_OF_RANGE', 'scrypt parameters out of range')
      }
      return scrypt({
        password,
        salt,
        costFactor: N,
        blockSize: r,
        parallelism: p,
        hashLength: keyLength,
        outputType: 'binary',
      })
    }
    throw new CryptoError('UNSUPPORTED', 'Unsupported key derivation for private key')
  }

  const candidates = [utf8Encode(passphrase.normalize('NFC'))]
  if (passphrase.normalize('NFC') !== passphrase) candidates.push(utf8Encode(passphrase))
  for (const candidate of candidates) {
    try {
      const key = await deriveFor(candidate)
      return normalizePkcs8(await aesDecrypt('CBC', key, iv, ciphertext))
    } catch (error) {
      if (error instanceof CryptoError && (error.code === 'UNSUPPORTED' || error.code === 'PARAMS_OUT_OF_RANGE')) {
        throw error
      }
    }
  }
  throw new CryptoError('WRONG_PASSPHRASE', 'Wrong passphrase for the private key')
}

/** Traditional OpenSSL PEM encryption ("Proc-Type: 4,ENCRYPTED" + "DEK-Info: AES-256-CBC,<iv>"). */
async function decryptLegacyPem(data: Uint8Array, dekInfo: string, passphrase: string): Promise<RsaKeyMaterial> {
  const [cipher, ivHex] = dekInfo.split(',')
  const keyLength = { 'AES-128-CBC': 16, 'AES-192-CBC': 24, 'AES-256-CBC': 32 }[cipher?.trim().toUpperCase() ?? '']
  if (!keyLength || !ivHex)
    throw new CryptoError('UNSUPPORTED', 'Unsupported legacy PEM cipher', { cipher: cipher ?? '' })
  const iv = fromHex(ivHex.trim())
  const { key } = evpBytesToKey(utf8Encode(passphrase), iv.subarray(0, 8), keyLength, 0)
  try {
    const components = parsePkcs1Private(await aesDecrypt('CBC', key, iv, data))
    return { spki: spkiFromComponents(components), pkcs8: pkcs8FromComponents(components) }
  } catch {
    throw new CryptoError('WRONG_PASSPHRASE', 'Wrong passphrase for the private key')
  }
}

// ---------------------------------------------------------------------------------------------
// Import from any supported text

export type KeySource =
  | 'pem-spki'
  | 'pem-pkcs1-public'
  | 'pem-pkcs8'
  | 'pem-pkcs1-private'
  | 'pem-encrypted-pkcs8'
  | 'pem-legacy-encrypted'
  | 'pem-certificate'
  | 'jwk'
  | 'openssh'
  | 'der'

export interface ImportedKey extends RsaKeyMaterial {
  source: KeySource
}

function spkiFromCertificate(der: Uint8Array): Uint8Array<ArrayBuffer> {
  const cert = expectTag(parseDer(der), TAG.SEQUENCE, 'Certificate')
  const tbs = expectTag(cert.children[0], TAG.SEQUENCE, 'TBSCertificate')
  const index = tbs.children[0]?.tag === TAG.CONTEXT_0 ? 6 : 5
  return normalizeSpki(expectTag(tbs.children[index], TAG.SEQUENCE, 'SubjectPublicKeyInfo').raw)
}

function importDer(der: Uint8Array<ArrayBuffer>): ImportedKey {
  const attempts: Array<() => ImportedKey> = [
    () => ({ spki: normalizeSpki(der), source: 'der' }),
    () => ({ ...normalizePkcs8(der), source: 'der' }),
    () => {
      const components = parsePkcs1Private(der)
      return { spki: spkiFromComponents(components), pkcs8: pkcs8FromComponents(components), source: 'der' }
    },
    () => ({ spki: spkiFromComponents(parsePkcs1Public(der)), source: 'der' }),
  ]
  for (const attempt of attempts) {
    try {
      return attempt()
    } catch {
      // try the next structure
    }
  }
  throw new CryptoError('UNKNOWN_FORMAT', 'Not a recognized RSA key')
}

/**
 * Accepts PEM (SPKI, PKCS#1, PKCS#8, encrypted PKCS#8, legacy encrypted, X.509 certificate),
 * JWK / JWK Set, OpenSSH public keys and bare base64 DER. Blocks describing the same key
 * (for example a public and a private PEM pasted together) are merged.
 */
export async function importKeysFromText(text: string, passphrase?: string): Promise<ImportedKey[]> {
  const trimmed = text.trim()
  if (!trimmed) throw new CryptoError('INVALID_INPUT', 'No key data')
  const found: ImportedKey[] = []

  if (trimmed.startsWith('{')) {
    let json: unknown
    try {
      json = JSON.parse(trimmed)
    } catch {
      throw new CryptoError('INVALID_KEY', 'Invalid JSON')
    }
    const keys = (json as { keys?: JsonWebKey[] }).keys ?? [json as JsonWebKey]
    for (const jwk of keys) found.push({ ...importJwk(jwk), source: 'jwk' })
  } else if (trimmed.startsWith('ssh-rsa ')) {
    for (const line of trimmed.split(/\r?\n/).filter((l) => l.startsWith('ssh-rsa '))) {
      found.push({ spki: fromOpenSshPublicKey(line), source: 'openssh' })
    }
  } else if (trimmed.includes('-----BEGIN ')) {
    for (const block of dearmorAll(trimmed)) {
      switch (block.label) {
        case PEM_LABELS.spki:
          found.push({ spki: normalizeSpki(block.data), source: 'pem-spki' })
          break
        case PEM_LABELS.pkcs1Public:
          found.push({ spki: spkiFromComponents(parsePkcs1Public(block.data)), source: 'pem-pkcs1-public' })
          break
        case PEM_LABELS.pkcs8:
          found.push({ ...normalizePkcs8(block.data), source: 'pem-pkcs8' })
          break
        case PEM_LABELS.pkcs1Private: {
          if (block.headers['Proc-Type']?.includes('ENCRYPTED')) {
            if (!passphrase)
              throw new CryptoError('PASSPHRASE_REQUIRED', 'The private key is protected by a passphrase')
            found.push({
              ...(await decryptLegacyPem(block.data, block.headers['DEK-Info'] ?? '', passphrase)),
              source: 'pem-legacy-encrypted',
            })
          } else {
            const components = parsePkcs1Private(block.data)
            found.push({
              spki: spkiFromComponents(components),
              pkcs8: pkcs8FromComponents(components),
              source: 'pem-pkcs1-private',
            })
          }
          break
        }
        case PEM_LABELS.encryptedPkcs8:
          if (!passphrase) throw new CryptoError('PASSPHRASE_REQUIRED', 'The private key is protected by a passphrase')
          found.push({ ...(await decryptPkcs8(block.data, passphrase)), source: 'pem-encrypted-pkcs8' })
          break
        case 'CERTIFICATE':
          found.push({ spki: spkiFromCertificate(block.data), source: 'pem-certificate' })
          break
        default:
          break
      }
    }
  } else {
    found.push(importDer(fromBase64(trimmed)))
  }

  if (found.length === 0) throw new CryptoError('UNKNOWN_FORMAT', 'No RSA key found')
  const merged = new Map<string, ImportedKey>()
  for (const key of found) {
    const id = toHex(key.spki)
    const existing = merged.get(id)
    if (!existing) merged.set(id, key)
    else if (!existing.pkcs8 && key.pkcs8) merged.set(id, { ...key })
  }
  return [...merged.values()]
}
