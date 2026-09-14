import { createReadStream, existsSync, readFileSync, statSync } from 'node:fs'
import { createServer } from 'node:http'
import { extname, join, normalize, resolve, sep } from 'node:path'

/**
 * Serves dist/ the way Cloudflare Pages does, so tests run the built app under its production Content-Security-Policy
 * and caching: with the headers from dist/_headers, and with Pages' answer to a path that is not in the build. Run
 * `npm run build` first.
 */
const root = resolve(import.meta.dirname, '..', 'dist')
const port = Number(process.env.PORT ?? 4173)

const TYPES: Record<string, string> = {
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.wasm': 'application/wasm',
  '.webmanifest': 'application/manifest+json',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
}

interface Rule {
  pattern: RegExp
  headers: [name: string, value: string][]
}

/** Parses `_headers`: an unindented URL pattern (`*` matches anything), then indented `Name: value` lines. */
function readRules(): Rule[] {
  const rules: Rule[] = []
  for (const line of readFileSync(join(root, '_headers'), 'utf8').split('\n')) {
    if (!line.trim() || line.trim().startsWith('#')) continue
    if (/^\s/.test(line)) {
      const colon = line.indexOf(':')
      rules.at(-1)?.headers.push([line.slice(0, colon).trim(), line.slice(colon + 1).trim()])
    } else {
      const source = line
        .trim()
        .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
        .replaceAll('*', '.*')
      rules.push({ pattern: new RegExp(`^${source}$`), headers: [] })
    }
  }
  return rules
}

const rules = readRules()

createServer((request, response) => {
  const path = decodeURIComponent(new URL(request.url ?? '/', 'http://localhost').pathname)
  let file = normalize(join(root, path))
  if (file !== root && !file.startsWith(root + sep)) return response.writeHead(403).end()
  if (existsSync(file) && statSync(file).isDirectory()) file = join(file, 'index.html')
  let status = 200
  if (path === '/_headers' || !existsSync(file)) {
    // Pages sends 404.html with status 404. A build without that page counts as a single-page app, and every missing
    // path, scripts included, gets index.html.
    const notFound = join(root, '404.html')
    status = existsSync(notFound) ? 404 : 200
    file = status === 404 ? notFound : join(root, 'index.html')
  }

  const headers: Record<string, string> = { 'Content-Type': TYPES[extname(file)] ?? 'application/octet-stream' }
  // Like Cloudflare, every matching rule applies, and a header set twice has its values joined with a comma.
  for (const rule of rules.filter(({ pattern }) => pattern.test(path))) {
    for (const [name, value] of rule.headers) headers[name] = headers[name] ? `${headers[name]}, ${value}` : value
  }
  // Pages replaces any Cache-Control from _headers on a 404, so a missing file is never cached.
  if (status === 404) headers['Cache-Control'] = 'no-store'
  response.writeHead(status, headers)
  createReadStream(file).pipe(response)
}).listen(port, () => console.log(`Serving dist/ with its _headers on http://localhost:${port}`))
