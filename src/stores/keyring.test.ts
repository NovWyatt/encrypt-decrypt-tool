import { describe, expect, it } from 'vitest'
import { mergeKeys, type RingKey } from './keyring'

function key(id: string, withPrivate = false, name = `key ${id}`): RingKey {
  return {
    id,
    name,
    spki: new Uint8Array([1, 2, 3]),
    pkcs8: withPrivate ? new Uint8Array([4, 5, 6]) : undefined,
    fingerprint: `SHA256:${id}`,
    bits: 2048,
    publicExponent: 65537,
    origin: 'imported',
    addedAt: 0,
    privateSaved: false,
  }
}

describe('mergeKeys', () => {
  it('adds unknown keys to the front', () => {
    const result = mergeKeys([key('a')], [key('b')])
    expect(result.keys.map((k) => k.id)).toEqual(['b', 'a'])
    expect(result.added.map((k) => k.id)).toEqual(['b'])
  })

  it('attaches a private part to a known public key and keeps its name', () => {
    const result = mergeKeys([key('a', false, 'Alice')], [key('a', true, 'imported name')])
    expect(result.upgraded).toHaveLength(1)
    expect(result.keys).toHaveLength(1)
    expect(result.keys[0].name).toBe('Alice')
    expect(result.keys[0].pkcs8).toBeDefined()
  })

  it('reports duplicates without changing the list', () => {
    const current = [key('a', true)]
    const result = mergeKeys(current, [key('a', false), key('a', true)])
    expect(result.duplicates).toHaveLength(2)
    expect(result.keys).toEqual(current)
  })
})
