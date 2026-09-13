/**
 * Interoperability with the real OpenSSL command line (and ssh-keygen when present).
 * Skipped automatically when the binaries are not installed; set OPENSSL_BIN to point at one.
 */
import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { utf8Decode, utf8Encode } from './encoding'
import { decryptOpenSsl, encryptOpenSsl, OPENSSL_DEFAULTS } from './openssl'
import { rsaOaepDecrypt, rsaOaepEncrypt } from './rsa'
import { encryptPkcs8, importKeysFromText, toOpenSshPublicKey, toPem, type RsaKeyMaterial } from './rsa-keys'
import { signData, verifyRawSignature } from './signature'

function findBinary(name: string, extra: string[]): string | null {
  const fromEnv = name === 'openssl' ? process.env.OPENSSL_BIN : undefined
  for (const candidate of [fromEnv, name, ...extra]) {
    if (!candidate) continue
    if (candidate.includes('\\') || candidate.includes('/')) {
      if (existsSync(candidate)) return candidate
      continue
    }
    const probe = spawnSync(candidate, ['version'], { encoding: 'utf8' })
    if (!probe.error) return candidate
  }
  return null
}

const OPENSSL = findBinary('openssl', [
  'C:\\Program Files\\Git\\usr\\bin\\openssl.exe',
  'C:\\Program Files\\Git\\mingw64\\bin\\openssl.exe',
])
const SSH_KEYGEN = ['C:\\Program Files\\Git\\usr\\bin\\ssh-keygen.exe', '/usr/bin/ssh-keygen'].find((p) =>
  existsSync(p),
)

const PASSWORD = 'mật khẩu 2026'
const TEXT = 'Văn bản tiếng Việt: Đồng ý chuyển nhượng.\n'

let dir = ''
const file = (name: string) => join(dir, name)

function run(bin: string, args: string[]): string {
  const result = spawnSync(bin, args, { encoding: 'utf8' })
  if (result.status !== 0) throw new Error(`${bin} ${args.join(' ')} failed:\n${result.stderr}`)
  return result.stdout
}

describe.runIf(Boolean(OPENSSL))('OpenSSL CLI interoperability', () => {
  const openssl = (...args: string[]) => run(OPENSSL!, args)
  let key: RsaKeyMaterial

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'edt-interop-'))
    writeFileSync(file('pw.txt'), `${PASSWORD}\n`, 'utf8')
    writeFileSync(file('plain.txt'), TEXT, 'utf8')
    openssl('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', file('key.pem'))
    openssl('pkey', '-in', file('key.pem'), '-pubout', '-out', file('pub.pem'))
    ;[key] = await importKeysFromText(readFileSync(file('key.pem'), 'utf8'))
  })

  afterAll(() => {
    if (dir) rmSync(dir, { recursive: true, force: true })
  })

  it('decrypts `openssl enc -aes-256-cbc -pbkdf2`', async () => {
    openssl(
      'enc',
      '-aes-256-cbc',
      '-pbkdf2',
      '-iter',
      '10000',
      '-salt',
      '-in',
      file('plain.txt'),
      '-out',
      file('enc.bin'),
      '-pass',
      `file:${file('pw.txt')}`,
    )
    const plaintext = await decryptOpenSsl(readFileSync(file('enc.bin')), PASSWORD, OPENSSL_DEFAULTS)
    expect(utf8Decode(plaintext)).toBe(TEXT)
  })

  it('produces data `openssl enc -d` can decrypt', async () => {
    writeFileSync(file('ours.bin'), await encryptOpenSsl(utf8Encode(TEXT), PASSWORD, OPENSSL_DEFAULTS))
    openssl(
      'enc',
      '-d',
      '-aes-256-cbc',
      '-pbkdf2',
      '-iter',
      '10000',
      '-in',
      file('ours.bin'),
      '-out',
      file('ours.txt'),
      '-pass',
      `file:${file('pw.txt')}`,
    )
    expect(readFileSync(file('ours.txt'), 'utf8')).toBe(TEXT)
  })

  it('decrypts legacy `openssl enc -md md5` output', async () => {
    openssl(
      'enc',
      '-aes-128-cbc',
      '-md',
      'md5',
      '-salt',
      '-in',
      file('plain.txt'),
      '-out',
      file('md5.bin'),
      '-pass',
      `file:${file('pw.txt')}`,
    )
    const plaintext = await decryptOpenSsl(readFileSync(file('md5.bin')), PASSWORD, {
      mode: 'CBC',
      keyBits: 128,
      kdf: { kind: 'md5' },
    })
    expect(utf8Decode(plaintext)).toBe(TEXT)
  })

  it('RSA-OAEP-SHA256 works with `openssl pkeyutl` both ways', async () => {
    const oaep = [
      '-pkeyopt',
      'rsa_padding_mode:oaep',
      '-pkeyopt',
      'rsa_oaep_md:sha256',
      '-pkeyopt',
      'rsa_mgf1_md:sha256',
    ]
    writeFileSync(file('oaep.bin'), await rsaOaepEncrypt(key.spki, 'SHA-256', utf8Encode('khóa phiên')))
    openssl(
      'pkeyutl',
      '-decrypt',
      '-inkey',
      file('key.pem'),
      '-in',
      file('oaep.bin'),
      '-out',
      file('oaep.txt'),
      ...oaep,
    )
    expect(readFileSync(file('oaep.txt'), 'utf8')).toBe('khóa phiên')

    writeFileSync(file('short.txt'), 'từ OpenSSL', 'utf8')
    openssl(
      'pkeyutl',
      '-encrypt',
      '-pubin',
      '-inkey',
      file('pub.pem'),
      '-in',
      file('short.txt'),
      '-out',
      file('from-openssl.bin'),
      ...oaep,
    )
    const plaintext = await rsaOaepDecrypt(key.pkcs8!, 'SHA-256', readFileSync(file('from-openssl.bin')))
    expect(utf8Decode(plaintext)).toBe('từ OpenSSL')
  })

  it('verifies `openssl dgst -sign` PSS signatures and produces verifiable ones', async () => {
    openssl(
      'dgst',
      '-sha256',
      '-sign',
      file('key.pem'),
      '-sigopt',
      'rsa_padding_mode:pss',
      '-out',
      file('sig.bin'),
      file('plain.txt'),
    )
    const outcome = await verifyRawSignature(
      utf8Encode(TEXT),
      readFileSync(file('sig.bin')),
      key.spki,
      'RSA-PSS',
      'SHA-256',
    )
    expect(outcome.valid).toBe(true)

    writeFileSync(file('our-sig.bin'), await signData(utf8Encode(TEXT), key.pkcs8!, 'RSA-PSS', 'SHA-256', 32))
    const out = openssl(
      'dgst',
      '-sha256',
      '-verify',
      file('pub.pem'),
      '-sigopt',
      'rsa_padding_mode:pss',
      '-sigopt',
      'rsa_pss_saltlen:32',
      '-signature',
      file('our-sig.bin'),
      file('plain.txt'),
    )
    expect(out).toContain('Verified OK')
  })

  it('opens OpenSSL passphrase-protected keys and writes ones OpenSSL opens', async () => {
    openssl(
      'genpkey',
      '-algorithm',
      'RSA',
      '-pkeyopt',
      'rsa_keygen_bits:1024',
      '-aes-256-cbc',
      '-pass',
      `file:${file('pw.txt')}`,
      '-out',
      file('enc-key.pem'),
    )
    const [opened] = await importKeysFromText(readFileSync(file('enc-key.pem'), 'utf8'), PASSWORD)
    expect(opened.pkcs8).toBeDefined()

    writeFileSync(
      file('our-enc.pem'),
      toPem('ENCRYPTED PRIVATE KEY', await encryptPkcs8(key.pkcs8!, PASSWORD, { iterations: 5000 })),
    )
    const pub = openssl('pkey', '-in', file('our-enc.pem'), '-passin', `file:${file('pw.txt')}`, '-pubout')
    expect(pub.replace(/\r/g, '')).toBe(readFileSync(file('pub.pem'), 'utf8').replace(/\r/g, ''))
  })

  it('extracts the public key from an X.509 certificate', async () => {
    openssl('req', '-x509', '-key', file('key.pem'), '-out', file('cert.pem'), '-subj', '/CN=edt-test', '-days', '1')
    const [fromCert] = await importKeysFromText(readFileSync(file('cert.pem'), 'utf8'))
    expect(toPem('PUBLIC KEY', fromCert.spki)).toBe(readFileSync(file('pub.pem'), 'utf8').replace(/\r/g, ''))
  })

  it.runIf(Boolean(SSH_KEYGEN))('matches ssh-keygen OpenSSH public key export', () => {
    const line = run(SSH_KEYGEN!, ['-i', '-m', 'PKCS8', '-f', file('pub.pem')]).trim()
    expect(toOpenSshPublicKey(key.spki)).toBe(line.split(/\s+/).slice(0, 2).join(' '))
  })
})
