import type { Config } from "@netlify/functions";
import { signToken, codeMatches, jsonEnv, json } from "../lib/shared.mts";

const HOURS = 24;

export default async (req: Request) => {
  if (req.method !== "POST") return json({ error: "method" }, 405);
  let b: any = {};
  try { b = await req.json(); } catch {}
  const role = b.role, car = String(b.car || ""), code = String(b.code || "");
  const carCodes = jsonEnv("CAR_CODES");   // {"toyota2023":"....", ...}
  const links = jsonEnv("WA_LINKS");       // {"toyota2023":"https://chat.whatsapp.com/...", ...}
  const exp = Date.now() + HOURS * 3600 * 1000;

  if (role === "manager" && codeMatches(code, Netlify.env.get("MANAGER_CODE"))) {
    return json({ token: await signToken({ r: "m", exp }), role: "m", links });
  }
  if (role === "captain" && carCodes[car] && codeMatches(code, carCodes[car])) {
    return json({ token: await signToken({ r: "c", car, exp }), role: "c", car, links: { [car]: links[car] || "" } });
  }
  await new Promise((r) => setTimeout(r, 700)); // slow down guessing
  return json({ error: "bad_code" }, 401);
};

export const config: Config = {
  path: "/api/login",
  rateLimit: { action: "rate_limit", aggregateBy: ["ip", "domain"], windowSize: 60, windowLimit: 8 },
};
