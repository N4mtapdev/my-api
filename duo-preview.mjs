// Single-process preview for the Duo simulator behind a hosted preview domain.
//
// Why this exists: Bun's fullstack dev server (HTML-import routes) rejects
// requests whose Host header does not match its bind hostname ("Blocked: Host
// header does not match the dev server") as DNS-rebinding protection. Hosted
// previews arrive with the preview domain in Host, so the public server cannot
// serve the HTML route directly.
//
// Design (one process, two servers — nothing can be orphaned):
//   upstream : Bun.serve on 127.0.0.1:3999 — the real Duo dev server (HTML
//              route + static files), bound to loopback so its Host check
//              compares against 127.0.0.1 and passes for proxied requests.
//   public   : Bun.serve on 0.0.0.0:$PORT — rewrites Host to the loopback
//              upstream and forwards everything, bridging WebSockets for HMR.
//
// Run with cwd inside duo/ (see preview command) so duo's bunfig.toml with the
// StyleX plugin applies to the HTML bundling.

import duoIndex from "./duo/packages/shell/index.html";

const ROOT = import.meta.dir; // project root (this file lives there)
const UPSTREAM_PORT = 3999;
const UPSTREAM = `http://127.0.0.1:${UPSTREAM_PORT}`;

// duo's build scripts resolve repo-relative paths from the CWD; run from duo/.
process.chdir(`${ROOT}/duo`);
const { buildPreinstalled } = await import("./duo/scripts/build-preinstalled.ts");
await buildPreinstalled();

// ---- upstream: the Duo dev server, loopback-only --------------------------

Bun.serve({
  port: UPSTREAM_PORT,
  hostname: "127.0.0.1",
  routes: { "/": duoIndex },
  development: { hmr: true, console: true },
  async fetch(req) {
    const path = decodeURIComponent(new URL(req.url).pathname);
    const base = path.startsWith("/cdn/") || path.startsWith("/preinstalled/")
      ? `${ROOT}/duo/dist`
      : `${ROOT}/duo/public`;
    const file = Bun.file(`${base}${path}`);
    if (!path.includes("..") && (await file.exists())) return new Response(file);
    return new Response("Not found", { status: 404 });
  },
});

// ---- public: host-rewriting proxy ----------------------------------------

const HOP_BY_HOP = new Set([
  "connection", "keep-alive", "transfer-encoding", "upgrade",
  "proxy-authenticate", "proxy-authorization", "te", "trailer",
]);

function cleanHeaders(headers) {
  const out = new Headers();
  for (const [k, v] of headers) if (!HOP_BY_HOP.has(k.toLowerCase())) out.set(k, v);
  return out;
}

const server = Bun.serve({
  port: Number(process.env.PORT ?? 3000),
  hostname: "0.0.0.0",
  async fetch(req, srv) {
    const url = new URL(req.url);

    if ((req.headers.get("upgrade") ?? "").toLowerCase() === "websocket") {
      const upgraded = srv.upgrade(req, { data: { path: url.pathname + url.search, upstream: null } });
      if (upgraded) return;
      return new Response("WebSocket upgrade failed", { status: 400 });
    }

    const headers = cleanHeaders(req.headers);
    headers.set("host", `127.0.0.1:${UPSTREAM_PORT}`);
    headers.delete("content-length");

    let upstream = null;
    for (let attempt = 0; attempt < 120; attempt++) {
      try {
        upstream = await fetch(`${UPSTREAM}${url.pathname}${url.search}`, {
          method: req.method,
          headers,
          body: req.method === "GET" || req.method === "HEAD" ? undefined : req.body,
          redirect: "manual",
        });
        break;
      } catch (err) {
        if (attempt === 119) return new Response(`Duo dev server unreachable: ${err}`, { status: 502 });
        await Bun.sleep(250);
      }
    }

    const resHeaders = cleanHeaders(upstream.headers);
    // Bun's fetch may transparently decompress the body; drop stale framing headers.
    resHeaders.delete("content-length");
    resHeaders.delete("content-encoding");
    return new Response(upstream.body, { status: upstream.status, headers: resHeaders });
  },
  websocket: {
    open(ws) {
      const upstream = new WebSocket(`ws://127.0.0.1:${UPSTREAM_PORT}${ws.data.path}`);
      ws.data.upstream = upstream;
      upstream.addEventListener("message", event => {
        if (ws.readyState === 1) ws.send(event.data);
      });
      upstream.addEventListener("close", () => {
        try { ws.close(); } catch {}
      });
    },
    message(ws, message) {
      const upstream = ws.data?.upstream;
      if (upstream && upstream.readyState === WebSocket.OPEN) upstream.send(message);
    },
    close(ws) {
      try { ws.data?.upstream?.close(); } catch {}
    },
  },
});

console.log(`[duo-preview] public :${server.port} -> upstream 127.0.0.1:${UPSTREAM_PORT}`);
