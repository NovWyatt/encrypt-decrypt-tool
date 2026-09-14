import { createHash } from 'node:crypto'
import type { Plugin } from 'vite'

/**
 * Content-Security-Policy for the built site. Inline scripts in index.html are allowed by hash, computed from the
 * emitted page so editing them cannot leave a stale hash behind.
 */
const POLICY: Record<string, string[]> = {
  'default-src': ["'self'"],
  // hash-wasm compiles Argon2id and scrypt from WebAssembly bytes.
  'script-src': ["'self'", "'wasm-unsafe-eval'"],
  // React, Radix, Sonner and Motion insert style elements at runtime.
  'style-src': ["'self'", "'unsafe-inline'"],
  'img-src': ["'self'"],
  // The stylesheet inlines one small font subset.
  'font-src': ["'self'", 'data:'],
  // Nothing leaves the page; the module preload polyfill is the only fetch, and only from this site.
  'connect-src': ["'self'"],
  'worker-src': ["'self'"],
  'object-src': ["'none'"],
  'base-uri': ["'none'"],
  'form-action': ["'none'"],
  'frame-ancestors': ["'none'"],
}

const HEADERS: Record<string, string> = {
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), geolocation=(), microphone=(), payment=(), usb=()',
  'Referrer-Policy': 'no-referrer',
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains',
  'X-Content-Type-Options': 'nosniff',
  // For browsers that predate frame-ancestors.
  'X-Frame-Options': 'DENY',
}

/**
 * File names under assets/ carry a content hash, so they never change and can be cached for good. A name that is not
 * in the build, such as a chunk an open tab still expects after a deploy, must not be cached like that. public/404.html
 * takes care of it: Cloudflare Pages then answers with a 404, and sends every 404 with `Cache-Control: no-store`.
 * Without that page, Pages would send index.html with status 200 under this rule.
 */
const ASSET_CACHE = 'public, max-age=31536000, immutable'

const INLINE_SCRIPT = /<script(?![^>]*\ssrc=)[^>]*>([\s\S]*?)<\/script>/g

export function contentSecurityPolicy(html: string): string {
  const hashes = [...html.matchAll(INLINE_SCRIPT)].map(
    ([, code]) => `'sha256-${createHash('sha256').update(code).digest('base64')}'`,
  )
  const directives = { ...POLICY, 'script-src': [...POLICY['script-src'], ...hashes] }
  return Object.entries(directives)
    .map(([name, sources]) => `${name} ${sources.join(' ')}`)
    .join('; ')
}

/** Emits a `_headers` file (Cloudflare Pages and Netlify format) with the security headers and asset caching. */
export function hostingHeaders(): Plugin {
  return {
    name: 'hosting-headers',
    apply: 'build',
    // After Vite has emitted index.html.
    enforce: 'post',
    generateBundle(_, bundle) {
      const page = bundle['index.html']
      if (page?.type !== 'asset') this.error('index.html was not emitted, so its inline scripts cannot be hashed')
      const html = typeof page.source === 'string' ? page.source : new TextDecoder().decode(page.source)
      const site = Object.entries({ 'Content-Security-Policy': contentSecurityPolicy(html), ...HEADERS })
      const lines = [
        '/*',
        ...site.map(([name, value]) => `  ${name}: ${value}`),
        '',
        '/assets/*',
        `  Cache-Control: ${ASSET_CACHE}`,
      ]
      this.emitFile({ type: 'asset', fileName: '_headers', source: `${lines.join('\n')}\n` })
    },
  }
}
