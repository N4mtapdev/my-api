// Dev-mode preview: one public URL that relays to the two dev servers the
// project already has, so everything runs in dev mode with live reload -
// edit a file, save, the browser updates itself (Vite HMR).
//
//   shell (bun run dev, PORT=3100) -> /device/*  and shell asset prefixes
//   website (vite dev, :3001)      -> everything else, incl. the HMR websocket
//
// The site embeds the simulator same-origin via VITE_SIMULATOR_URL=/device/,
// so it works both on localhost and through the managed preview URL.
//
// If an upstream dies (crash, killed relay leaving orphans behind), the next
// request revives it automatically instead of answering 502 forever.
//
// Start it with: bun ../duo-preview.mjs   (from duo/)

import { spawn } from 'node:child_process'
import { resolve } from 'node:path'

const ROOT = import.meta.dir
const DUO = resolve(ROOT, 'duo')
const SHELL_PORT = Number(process.env.SHELL_PORT ?? 3370)
const WEB_PORT = Number(process.env.WEB_PORT ?? 3371)
const port = Number(process.env.PORT ?? 3000)
const SHELL = `http://127.0.0.1:${SHELL_PORT}`
const WEB = `http://127.0.0.1:${WEB_PORT}`

// Child banners contain their own http://localhost:<port> URLs; forwarding
// those to the managed log makes the platform pick an upstream port as the
// preview port, which bypasses this relay. Strip them and keep the rest.
function log(name) {
  return (data) => {
    const lines = String(data).split('\n').filter((line) => !/https?:\/\//.test(line))
    if (lines.join('\n').trim()) process.stdout.write(lines.map((line) => `[${name}] ${line}`).join('\n') + '\n')
  }
}

const UPSTREAMS = {
  [SHELL]: { cwd: DUO, name: 'shell', args: [], env: () => ({ ...process.env, PORT: String(SHELL_PORT) }) },
  [WEB]: {
    cwd: resolve(DUO, 'packages', 'web'),
    name: 'web',
    args: ['--port', String(WEB_PORT), '--strictPort', '--host'],
    env: () => ({ ...process.env, VITE_SIMULATOR_URL: '/device/' }),
  },
}

// One spawn attempt per upstream at a time; the entry clears once it is up so
// a later crash can start a fresh one.
const starting = new Map()

async function alive(url) {
  try {
    await fetch(url, { signal: AbortSignal.timeout(1500) })
    return true
  } catch {
    return false
  }
}

async function ensure(url) {
  if (await alive(url)) return
  const u = UPSTREAMS[url]
  let run = starting.get(url)
  if (!run) {
    run = (async () => {
      console.log(`[${u.name}] starting`)
      const child = spawn('bun', ['run', 'dev', ...u.args], { cwd: u.cwd, env: u.env(), stdio: ['ignore', 'pipe', 'pipe'] })
      child.stdout.on('data', log(u.name))
      child.stderr.on('data', log(u.name))
      for (let i = 0; i < 240; i++) {
        if (await alive(url)) {
          console.log(`[${u.name}] ready`)
          return
        }
        if (child.exitCode !== null) throw new Error(`[${u.name}] dev server exited with code ${child.exitCode}`)
        await new Promise((r) => setTimeout(r, 500))
      }
      throw new Error(`[${u.name}] did not become ready`)
    })().finally(() => starting.delete(url))
    starting.set(url, run)
  }
  await run
}

// The shell dev server blocks unknown Host headers, so it must not inherit the
// managed preview's PORT (3000) - it gets its own. Upstreams sit outside the
// port range the platform probes so only the relay answers on the preview port.
// Revive both in the background right away; the first request never blocks on
// anything but a still-warming Vite.
for (const url of Object.keys(UPSTREAMS)) ensure(url).catch((err) => console.error(err.message))

// Where to forward a request. Shell paths mirror what the simulator loads;
// everything else belongs to the Vite dev server (site, docs, HMR, modules).
const SHELL_PREFIX = /^\/device(\/|$)|^\/(model|icons|covers|cdn|catalog|preinstalled)(\/|$)/

function targetOf(pathname) {
  return SHELL_PREFIX.test(pathname) ? SHELL : WEB
}

Bun.serve({
  port,
  hostname: '0.0.0.0',
  async fetch(req, server) {
    const url = new URL(req.url)
    // Websocket upgrades (Vite HMR) are relayed by the handlers below.
    if (req.headers.get('upgrade')?.toLowerCase() === 'websocket') {
      const upgraded = server.upgrade(req, { data: { path: url.pathname + url.search, queue: [] } })
      if (upgraded) return undefined
    }
    const target = targetOf(url.pathname)
    await ensure(target)
    const upstream = new URL(req.url)
    upstream.host = new URL(target).host
    upstream.port = new URL(target).port
    // /device/* maps to the shell server root, other shell prefixes pass as-is.
    upstream.pathname = url.pathname.replace(/^\/device/, '') || '/'
    const headers = new Headers(req.headers)
    headers.set('host', upstream.host)
    try {
      return await fetch(upstream, {
        method: req.method,
        headers,
        body: ['GET', 'HEAD'].includes(req.method) ? undefined : req.body,
        duplex: 'half',
      })
    } catch (err) {
      return new Response(`Upstream ${target} unavailable: ${err.message}`, { status: 502 })
    }
  },
  websocket: {
    open(ws) {
      const upstream = new WebSocket(`ws://127.0.0.1:${WEB_PORT}${ws.data.path}`)
      ws.data.upstream = upstream
      const queue = (ws.data.queue = [])
      upstream.onopen = () => queue.splice(0).forEach((m) => upstream.send(m))
      upstream.onmessage = (e) => ws.send(e.data)
      upstream.onclose = () => ws.close()
      upstream.onerror = () => ws.close()
    },
    message(ws, message) {
      const u = ws.data.upstream
      if (u && u.readyState === WebSocket.OPEN) u.send(message)
      else ws.data.queue.push(message)
    },
    close(ws) {
      try { ws.data.upstream?.close() } catch {}
    },
  },
})

console.log(`[duo-preview] relay ready on :${port}`)
console.log('[duo-preview] edit any file under duo/ and the browser updates itself (HMR)')
