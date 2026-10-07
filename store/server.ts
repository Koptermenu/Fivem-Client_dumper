// Central configuration store for the FiveM dumper.
// One JSON file per server, keyed by safeName("http://ip:port").
//
//   GET  /v1/servers/<key>   -> stored /client response (200) or 404
//   POST /v1/servers/<key>   -> store the request body as the configuration
//
// The dumper uploads the raw /client response after every successful live
// fetch and falls back to GET when the live server is unreachable or the
// token is rejected, so a server dumped once can be dumped again without
// anyone connecting to it.

import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";

const PORT = Number(process.env.PORT ?? 8920);
const DATA = path.resolve(import.meta.dir, "data");

mkdirSync(DATA, { recursive: true });

const validKey = (key: string): boolean => /^[A-Za-z0-9._-]{1,120}$/.test(key);

const fileOf = (key: string): string => path.join(DATA, `${key}.json`);

interface StoreMeta {
  savedAt: number;
  size: number;
}

const metaOf = (file: string): StoreMeta => {
  const st = statSync(file);
  return { savedAt: Math.round(st.mtimeMs), size: st.size };
};

Bun.serve({
  port: PORT,
  async fetch(req): Promise<Response> {
    const url = new URL(req.url);
    const match = url.pathname.match(/^\/v1\/servers\/([^/]+)$/);
    if (!match) return new Response("not found\n", { status: 404 });

    const key = decodeURIComponent(match[1]);
    if (!validKey(key)) return new Response("bad key\n", { status: 400 });
    const file = fileOf(key);

    if (req.method === "GET") {
      if (!existsSync(file)) return new Response("no stored configuration\n", { status: 404 });
      const meta = metaOf(file);
      const stored = JSON.parse(readFileSync(file, "utf8")) as Record<string, unknown>;
      stored.storeSavedAt = meta.savedAt;
      return new Response(JSON.stringify(stored), {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "X-Store-Saved-At": String(meta.savedAt),
        },
      });
    }

    if (req.method === "POST" || req.method === "PUT") {
      const body = await req.text();
      let config: unknown;
      try {
        config = JSON.parse(body);
      } catch {
        return new Response("body is not JSON\n", { status: 400 });
      }
      if (
        typeof config !== "object" ||
        config === null ||
        !Array.isArray((config as Record<string, unknown>).resources)
      ) {
        return new Response("body does not look like a /client configuration\n", { status: 400 });
      }
      writeFileSync(file, body);
      const meta = metaOf(file);
      console.log(`[store] ${req.method} ${key} (${meta.size} bytes)`);
      return new Response(JSON.stringify({ ok: true, key, savedAt: meta.savedAt }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }

    return new Response("method not allowed\n", { status: 405 });
  },
});

console.log(`[store] listening on http://0.0.0.0:${PORT} (data: ${DATA})`);
