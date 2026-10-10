// Shared helpers for the login and data functions. Secrets live only in Netlify env vars.
const enc = new TextEncoder();

function b64url(bytes: Uint8Array): string {
  let s = "";
  bytes.forEach((b) => (s += String.fromCharCode(b)));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlToStr(s: string): string {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return atob(s);
}
async function hmac(data: string): Promise<string> {
  const secret = Netlify.env.get("TOKEN_SECRET");
  if (!secret || secret.length < 32) throw new Error("TOKEN_SECRET missing");
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(data))));
}
function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

export type Session = { r: "m" | "c"; car?: string; exp: number };

export async function signToken(s: Session): Promise<string> {
  const body = b64url(enc.encode(JSON.stringify(s)));
  return body + "." + (await hmac(body));
}
export async function verifyToken(req: Request): Promise<Session | null> {
  const h = req.headers.get("authorization") || "";
  const tok = h.startsWith("Bearer ") ? h.slice(7) : "";
  const [body, sig] = tok.split(".");
  if (!body || !sig) return null;
  if (!safeEqual(sig, await hmac(body))) return null;
  try {
    const s = JSON.parse(b64urlToStr(body)) as Session;
    if (!s.exp || s.exp < Date.now()) return null;
    return s;
  } catch {
    return null;
  }
}
export function codeMatches(entered: string, real: string | undefined): boolean {
  return !!real && safeEqual(String(entered || "").trim(), String(real));
}
export function jsonEnv(name: string): Record<string, string> {
  try { return JSON.parse(Netlify.env.get(name) || "{}"); } catch { return {}; }
}
export const json = (v: unknown, status = 200) =>
  new Response(JSON.stringify(v), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
