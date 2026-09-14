import { cbc, ctr, ecb } from '@noble/ciphers/aes.js'

/**
 * Block cipher modes applied to raw RGBA pixels, the classic way to see why ECB leaks structure.
 * Every 16-byte AES block is four pixels, so equal runs of pixels produce equal ciphertext in ECB.
 */

export type DemoMode = 'ECB' | 'CBC' | 'CTR'

export const BLOCK_BYTES = 16

export interface DemoKey {
  key: Uint8Array
  iv: Uint8Array
}

export function randomDemoKey(): DemoKey {
  return { key: crypto.getRandomValues(new Uint8Array(16)), iv: crypto.getRandomValues(new Uint8Array(16)) }
}

/** Pads with zero bytes to a whole number of blocks; the demo only draws the original length back. */
export function zeroPad(data: Uint8Array): Uint8Array {
  const length = Math.ceil(data.length / BLOCK_BYTES) * BLOCK_BYTES
  if (length === data.length) return data
  const padded = new Uint8Array(length)
  padded.set(data)
  return padded
}

export function encryptBlocks(mode: DemoMode, { key, iv }: DemoKey, data: Uint8Array): Uint8Array {
  const padded = zeroPad(data)
  switch (mode) {
    case 'ECB':
      return ecb(key, { disablePadding: true }).encrypt(padded)
    case 'CBC':
      return cbc(key, iv, { disablePadding: true }).encrypt(padded)
    case 'CTR':
      return ctr(key, iv).encrypt(padded)
  }
}

/** Encrypts image pixels and keeps every pixel opaque, so the ciphertext can be shown as an image. */
export function encryptPixels(
  mode: DemoMode,
  demoKey: DemoKey,
  pixels: Uint8ClampedArray,
): Uint8ClampedArray<ArrayBuffer> {
  const cipher = encryptBlocks(mode, demoKey, new Uint8Array(pixels.buffer, pixels.byteOffset, pixels.length))
  const out = new Uint8ClampedArray(pixels.length)
  out.set(cipher.subarray(0, pixels.length))
  for (let alpha = 3; alpha < out.length; alpha += 4) out[alpha] = 255
  return out
}

type Rgb = readonly [number, number, number]
type Ridge = ReadonlyArray<readonly [number, number]>

const SCENE = {
  sky: [204, 224, 250],
  sun: [255, 236, 160],
  farHills: [150, 178, 222],
  nearHills: [96, 132, 196],
  ground: [58, 88, 150],
  shackle: [120, 130, 150],
  body: [28, 36, 64],
  keyhole: [255, 214, 102],
} as const satisfies Record<string, Rgb>

const FAR_RIDGE: Ridge = [
  [0, 100],
  [40, 70],
  [95, 100],
  [150, 60],
  [205, 95],
  [240, 85],
  [256, 95],
]
const NEAR_RIDGE: Ridge = [
  [0, 125],
  [60, 105],
  [130, 128],
  [200, 110],
  [256, 122],
]

function ridgeHeight(ridge: Ridge, x: number): number {
  for (let index = 1; index < ridge.length; index++) {
    const [x1, y1] = ridge[index]
    if (x <= x1) {
      const [x0, y0] = ridge[index - 1]
      return y0 + ((y1 - y0) * (x - x0)) / (x1 - x0)
    }
  }
  return ridge.at(-1)![1]
}

function sceneColor(x: number, y: number): Rgb {
  const inCircle = (cx: number, cy: number, radius: number) => (x - cx) ** 2 + (y - cy) ** 2 <= radius ** 2
  const keyhole = inCircle(128, 106, 7) || (x >= 125 && x < 132 && y >= 106 && y < 126)
  if (keyhole) return SCENE.keyhole
  const corner = (cx: number, cy: number) => (x - cx) ** 2 + (y - cy) ** 2 > 36
  const body =
    x >= 92 &&
    x < 164 &&
    y >= 86 &&
    y < 140 &&
    !(x < 98 && y < 92 && corner(98, 92)) &&
    !(x >= 158 && y < 92 && corner(157, 92)) &&
    !(x < 98 && y >= 134 && corner(98, 133)) &&
    !(x >= 158 && y >= 134 && corner(157, 133))
  if (body) return SCENE.body
  const distance = Math.hypot(x - 128, y - 70)
  const arch = y <= 70 && distance >= 17 && distance <= 27
  const legs = y > 70 && y < 86 && ((x >= 101 && x < 111) || (x >= 145 && x < 155))
  if (arch || legs) return SCENE.shackle
  if (y >= 140) return SCENE.ground
  if (y >= ridgeHeight(NEAR_RIDGE, x)) return SCENE.nearHills
  if (y >= ridgeHeight(FAR_RIDGE, x)) return SCENE.farHills
  if (inCircle(206, 38, 20)) return SCENE.sun
  return SCENE.sky
}

/** A flat-colour padlock landscape: large even areas make the ECB leak easy to see. */
export function sampleScene(width = 256, height = 160): Uint8ClampedArray<ArrayBuffer> {
  const pixels = new Uint8ClampedArray(width * height * 4)
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const [r, g, b] = sceneColor((x * 256) / width, (y * 160) / height)
      const offset = 4 * (y * width + x)
      pixels[offset] = r
      pixels[offset + 1] = g
      pixels[offset + 2] = b
      pixels[offset + 3] = 255
    }
  }
  return pixels
}

/** Splits bytes into blocks and, for each block, the index of the first identical block (or -1). */
export function repeatedBlocks(data: Uint8Array): { blocks: Uint8Array[]; firstSeen: number[] } {
  const blocks: Uint8Array[] = []
  const firstSeen: number[] = []
  const seen = new Map<string, number>()
  for (let offset = 0; offset < data.length; offset += BLOCK_BYTES) {
    const block = data.subarray(offset, offset + BLOCK_BYTES)
    const id = block.join(',')
    const index = blocks.length
    blocks.push(block)
    firstSeen.push(seen.get(id) ?? -1)
    if (!seen.has(id)) seen.set(id, index)
  }
  return { blocks, firstSeen }
}

/** Share of blocks that repeat an earlier block: high for ECB on images, near zero otherwise. */
export function repeatRatio(data: Uint8Array): number {
  const { firstSeen } = repeatedBlocks(data)
  return firstSeen.length === 0 ? 0 : firstSeen.filter((index) => index >= 0).length / firstSeen.length
}
