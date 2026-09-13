import { describe, expect, it } from 'vitest'
import { estimateStrength, generatePassword } from './password'

describe('password strength', () => {
  it('rates common and short passwords as very weak', () => {
    expect(estimateStrength('123456').score).toBe(0)
    expect(estimateStrength('matkhau123').score).toBe(0)
    expect(estimateStrength('aaaaaaaa').score).toBe(0)
  })

  it('rewards long passphrases, including Vietnamese ones', () => {
    expect(estimateStrength('Con mèo đen ngủ trên mái nhà lúc 3 giờ').score).toBeGreaterThanOrEqual(3)
    expect(estimateStrength(generatePassword()).score).toBe(4)
  })
})

describe('password generator', () => {
  it('produces grouped, unambiguous passwords', () => {
    const password = generatePassword()
    expect(password).toMatch(/^[A-Za-z2-9]{5}(-[A-Za-z2-9]{5}){3}$/)
    expect(password).not.toMatch(/[01lIoO]/)
    expect(generatePassword()).not.toBe(password)
  })
})
