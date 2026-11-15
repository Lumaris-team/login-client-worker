const TOKEN_TTL = 60;
const WINDOW_SECONDS = 1800;
const MAX_USERS_PER_IP = 5;
const key = (kind, value) => new Request(`https://login-cache.invalid/${kind}/${encodeURIComponent(value)}`);
const json = (body, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
});
const read = async (request) => (await caches.default.match(request))?.json() || null;
const write = (request, value, ttl) => caches.default.put(request, new Response(JSON.stringify(value), {
  headers: { "Content-Type": "application/json", "Cache-Control": `max-age=${ttl}` },
}));

export default {
  async fetch(request, env) {
    if (request.method !== "POST") return json({ error: "NOT_FOUND" }, 404);
    const url = new URL(request.url);
    const body = await request.json().catch(() => null);
    const ip = body?.ip || request.headers.get("CF-Connecting-IP") || "unknown";

    if (url.pathname === "/api/verify") {
      if (!body?.username || !body.token) return json({ error: "NOT_FOUND" }, 404);
      const record = await read(key("token", body.token || ""));
      if (!record || record.username !== body.username || record.ip !== ip || record.expires < Date.now()) {
        return json({ error: "NOT_FOUND" }, 404);
      }
      await caches.default.delete(key("token", body.token));
      return json({ valid: true });
    }

    if (url.pathname !== "/api/login") return json({ error: "NOT_FOUND" }, 404);
    if (!body?.username || typeof body.password !== "string") return json({ error: "NOT_FOUND" }, 404);
    const ban = await read(key("ban", ip));
    if (ban?.until > Date.now()) return json({ error: "NOT_FOUND" }, 404);
    const expected = await env.MAIN_PASSWORD?.get();
    const attemptsKey = key("attempts", ip);
    const attempts = await read(attemptsKey) || { count: 0 };
    if (!expected || body.password !== expected) {
      attempts.count += 1;
      await write(attemptsKey, attempts, WINDOW_SECONDS);
      if (attempts.count >= 10) await write(key("ban", ip), { until: Date.now() + 600000 }, 600);
      return json({ error: "NOT_FOUND" }, 404);
    }
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
      return json({ error: "NOT_FOUND" }, 404);
    }
    await write(usersKey, users, WINDOW_SECONDS);
    const token = `${crypto.randomUUID()}${crypto.randomUUID()}`;
    await write(key("token", token), { username: body.username, ip, expires: Date.now() + TOKEN_TTL * 1000 }, TOKEN_TTL);
    return json({ token });
  },
};
