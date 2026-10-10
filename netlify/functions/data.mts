import type { Config } from "@netlify/functions";
import { verifyToken, json } from "../lib/shared.mts";

// Keys the page uses: tp_<kind>_<carId> or tp_trips_<carId>_<YYYY-MM>
const KEY_RE = /^tp_([A-Za-z]+)_([A-Za-z0-9]+)(?:_(\d{4}-\d{2}))?$/;

export default async (req: Request) => {
  const s = await verifyToken(req);
  if (!s) return json({ error: "auth" }, 401);

  const key = new URL(req.url).searchParams.get("key") || "";
  const m = key.match(KEY_RE);
  if (!m) return json({ error: "key" }, 400);
  const [, kind, carId] = m;

  // Captains: only their own car. Salary is read-only for them.
  if (s.r === "c") {
    if (carId !== s.car) return json({ error: "forbidden" }, 403);
    if (req.method !== "GET" && kind === "salary") return json({ error: "forbidden" }, 403);
  }

  const base = Netlify.env.get("FIREBASE_URL");
  const secret = Netlify.env.get("FIREBASE_DB_SECRET");
  if (!base || !secret) return json({ error: "server_config" }, 500);
  const url = `${base}/tp/${encodeURIComponent(key)}.json?auth=${encodeURIComponent(secret)}`;

  if (req.method === "GET") {
    const r = await fetch(url);
    return new Response(await r.text(), { status: r.status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
  }
  if (req.method === "PUT") {
    const body = await req.text();
    if (body.length > 1_000_000) return json({ error: "too_big" }, 413);
    try { JSON.parse(body); } catch { return json({ error: "json" }, 400); }
    const r = await fetch(url, { method: "PUT", headers: { "content-type": "application/json" }, body });
    return new Response(await r.text(), { status: r.status, headers: { "content-type": "application/json" } });
  }
  return json({ error: "method" }, 405);
};

export const config: Config = { path: "/api/data", method: ["GET", "PUT"] };
