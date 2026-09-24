// Static preview for the whole Duo product: the intro website with the
// interactive simulator embedded in it.
//
// packages/web builds to dist/client: every route is prerendered (TanStack
// Start), and scripts/simulator.ts copies the shell build under /device/
// along with /model, /icons, /covers, /cdn and /catalog. The result is fully
// static - the landing page drives the phone over postMessage from the same
// origin - so one file server serves the website AND the 3D simulator.
//
// For live code editing use the dev servers instead (see HUONG-DAN-SETUP.md):
//   cd duo && bun run dev                    # shell on :3000
//   cd duo/packages/web && bun run dev       # website on :3001, embeds :3000

import { spawnSync } from 'node:child_process'
import { existsSync, statSync } from 'node:fs'
import { resolve, sep } from 'node:path'

const ROOT = import.meta.dir
const MODEL = resolve(ROOT, 'duo', 'public', 'model', 'iPhone_Duo_Render.usdc')
const CLIENT = resolve(ROOT, 'duo', 'packages', 'web', 'dist', 'client')
// The classroom build: one plain HTML file at the repo root, served as-is.
const PLAIN = resolve(ROOT, 'index.html')
const port = Number(process.env.PORT ?? 3000)

// Cold start self-heal: a fresh workspace has neither the Apple model (gitignored)
// nor the build output. Prepare both so the preview serves the full site.
if (!existsSync(MODEL)) {
  const python = ['python3', 'python'].find((bin) => spawnSync(bin, ['--version'], { stdio: 'ignore' }).status === 0)
  if (python) {
    spawnSync(python, ['-m', 'pip', 'install', 'usd-core'], { cwd: ROOT, stdio: 'inherit' })
    spawnSync(python, ['scripts/prepare-model.py'], { cwd: resolve(ROOT, 'duo'), stdio: 'inherit' })
  } else {
    console.warn('[duo-preview] no python found; run scripts/prepare-model.py manually')
  }
}
if (!existsSync(resolve(CLIENT, 'index.html'))) {
  // The web build copies the freshly built shell under /device/ itself.
  spawnSync('bun', ['run', 'build'], { cwd: resolve(ROOT, 'duo', 'packages', 'web'), stdio: 'inherit' })
}

// Live reload for the plain HTML page: the browser polls the file's mtime and
// reloads when it changes, so editing index.html updates the page on save.
const RELOAD = `<script>
(function () {
  var seen = null;
  setInterval(function () {
    fetch('/__plain-stamp', { cache: 'no-store' })
      .then(function (r) { return r.text(); })
      .then(function (text) {
        text = text.trim();
        if (seen === null) { seen = text; return; }
        if (text !== seen) location.reload();
      })
      .catch(function () {});
  }, 800);
})();
</script>`

Bun.serve({
  port,
  hostname: '0.0.0.0',
  async fetch(req) {
    const path = decodeURIComponent(new URL(req.url).pathname)
    if (path.includes('..')) return new Response('Not found', { status: 404 })

    if (path === '/__plain-stamp') {
      return new Response(existsSync(PLAIN) ? String(statSync(PLAIN).mtimeMs) : '0')
    }
    // The plain build, straight from the repo root: no copy to keep in sync.
    if ((path === '/index-plain.html' || path === '/plain') && existsSync(PLAIN)) {
      const html = await Bun.file(PLAIN).text()
      return new Response(html.replace('</head>', `${RELOAD}</head>`), {
        headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }
      })
    }

    // Directory URLs and extensionless routes map to their prerendered index.
    const candidates = path.endsWith('/')
      ? [resolve(CLIENT, `.${path}`, 'index.html')]
      : [resolve(CLIENT, `.${path}`), resolve(CLIENT, `.${path}.html`), resolve(CLIENT, `.${path}`, 'index.html')]

    for (const file of candidates) {
      if (file !== CLIENT && !file.startsWith(CLIENT + sep)) continue
      const asset = Bun.file(file)
      if (await asset.exists()) return new Response(asset)
    }
    return new Response('Not found', { status: 404 })
  },
})

console.log(`[duo-preview] website + simulator on :${port} from duo/packages/web/dist/client`)
console.log(`[duo-preview] plain HTML build at /plain (live reload) from index.html`)
