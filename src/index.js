const TOKEN_TTL = 60;
const WINDOW_SECONDS = 1800;
const MAX_USERS_PER_IP = 5;
const key = (kind, value) => new Request(`https://login-cache.invalid/${kind}/${encodeURIComponent(value)}`);
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};
const notFound = () => new Response("Not Found", {
  status: 404,
  headers: { ...corsHeaders, "Content-Type": "text/plain; charset=UTF-8", "Cache-Control": "no-store" },
});
const json = (body, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { ...corsHeaders, "Content-Type": "application/json", "Cache-Control": "no-store" },
});
const read = async (request) => (await caches.default.match(request))?.json() || null;
const write = (request, value, ttl) => caches.default.put(request, new Response(JSON.stringify(value), {
  headers: { "Content-Type": "application/json", "Cache-Control": `max-age=${ttl}` },
}));
async function readSecret(env, name) {
  const binding = env[name];
  if (typeof binding === "string") return binding;
  if (binding && typeof binding.get === "function") {
    try {
      return await binding.get();
    } catch (error) {
      console.warn(`LOGIN_REJECTED:${name.toLowerCase()}_unavailable`);
      return null;
    }
  }
  return null;
}
function reject(reason) {
  console.warn(`LOGIN_REJECTED:${reason}`);
  return notFound();
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
    if (request.method !== "POST") return notFound();
    const url = new URL(request.url);
    const body = await request.json().catch(() => null);
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";

    if (url.pathname === "/api/verify") {
      if (!body?.username || !body.token) return notFound();
      const record = await read(key("token", body.token || ""));
      if (!record || record.username !== body.username || record.ip !== ip || record.expires < Date.now()) {
        return notFound();
      }
      await caches.default.delete(key("token", body.token));
      return json({ valid: true });
    }

    if (url.pathname !== "/api/login") return notFound();
    if (!body?.username || typeof body.password !== "string") return reject("invalid_payload");
    const ban = await read(key("ban", ip));
    if (ban?.until > Date.now()) return reject("ip_banned");

    // === DEBUG LOGS ===
    console.error("LOGIN_DEBUG: env keys:", Object.keys(env || {}));
    console.error("LOGIN_DEBUG: env.MAIN_USERNAME type:", typeof env?.MAIN_USERNAME);
    console.error("LOGIN_DEBUG: env.MAIN_PASSWORD type:", typeof env?.MAIN_PASSWORD);
    const debugUsername = await readSecret(env, "MAIN_USERNAME");
    const debugPassword = await readSecret(env, "MAIN_PASSWORD");
    console.error("LOGIN_DEBUG: readSecret(MAIN_USERNAME) =>", debugUsername ? "SET (hidden)" : "NULL/UNDEFINED");
    console.error("LOGIN_DEBUG: readSecret(MAIN_PASSWORD) =>", debugPassword ? "SET (hidden)" : "NULL/UNDEFINED");
    // === END DEBUG LOGS ===

    const expectedUsername = (await readSecret(env, "MAIN_USERNAME"))?.trim();
    if (!expectedUsername) {
      console.error("LOGIN_REJECTED:missing_main_username");
      return notFound();
    }
    if (body.username.trim() !== expectedUsername) return reject("username_mismatch");
    const expected = await readSecret(env, "MAIN_PASSWORD");
    if (!expected) {
      console.error("LOGIN_REJECTED:missing_main_password");
      return notFound();
    }
    const attemptsKey = key("attempts", ip);
    const attempts = await read(attemptsKey) || { count: 0 };
    if (body.password !== expected) {
      attempts.count += 1;
      await write(attemptsKey, attempts, WINDOW_SECONDS);
      if (attempts.count >= 10) await write(key("ban", ip), { until: Date.now() + 600000 }, 600);
      return reject("password_mismatch");
    }
    await caches.default.delete(attemptsKey);
    const usersKey = key("users", ip);
    const users = await read(usersKey) || { values: [] };
    users.values = users.values.filter((entry) => Date.now() - entry.at < WINDOW_SECONDS * 1000);
    if (!users.values.some((entry) => entry.username === body.username)) users.values.push({ username: body.username, at: Date.now() });
    if (users.values.length > MAX_USERS_PER_IP) {
      await fetch(`https://main-client-worker.${body.username}-cloudflare-account.workers.dev/api/auth/invalidate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason: "ip_user_limit" }),
      }).catch(() => {});
      return reject("ip_user_limit");
    }
    await write(usersKey, users, WINDOW_SECONDS);
    const token = `${crypto.randomUUID()}${crypto.randomUUID()}`;
    await write(key("token", token), { username: body.username, ip, expires: Date.now() + TOKEN_TTL * 1000 }, TOKEN_TTL);
    return json({ token });
  },
};
