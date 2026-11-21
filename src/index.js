const TOKEN_TTL = 60;
const JWT_TTL = 30 * 60; // 30 minutes
const WINDOW_SECONDS = 1800;
const MAX_USERS_PER_IP = 5;
const key = (kind, value) => new Request(`https://login-cache.invalid/${kind}/${encodeURIComponent(value)}`);
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};
const notFound = () => new Response(null, {
  status: 404,
  headers: { "Cache-Control": "no-store" },
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

// JWT helpers
async function hmacKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

async function signJWT(payload, secret) {
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const jwtPayload = { ...payload, iat: now, exp: now + JWT_TTL };
  
  const headerB64 = btoa(JSON.stringify(header)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const payloadB64 = btoa(JSON.stringify(jwtPayload)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const signingInput = `${headerB64}.${payloadB64}`;
  
  const key = await hmacKey(secret);
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(signingInput));
  const signatureB64 = btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  
  return `${signingInput}.${signatureB64}`;
}

async function verifyJWT(token, secret) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return { valid: false, reason: "malformed" };
    
    const [headerB64, payloadB64, signatureB64] = parts;
    const signingInput = `${headerB64}.${payloadB64}`;
    
    const key = await hmacKey(secret);
    const expectedSignature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(signingInput));
    const expectedB64 = btoa(String.fromCharCode(...new Uint8Array(expectedSignature))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    
    if (expectedB64 !== signatureB64) return { valid: false, reason: "bad_signature" };
    
    const payload = JSON.parse(atob(payloadB64.replace(/-/g, "+").replace(/_/g, "/")));
    const now = Math.floor(Date.now() / 1000);
    
    if (payload.exp < now) return { valid: false, reason: "expired" };
    
    return { valid: true, payload };
  } catch (e) {
    return { valid: false, reason: "error" };
  }
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
      // Delete the one-time token after verification
      await caches.default.delete(key("token", body.token));
      
      // Issue JWT
      const jwtSecret = await readSecret(env, "JWT_SECRET_KEY");
      if (!jwtSecret) {
        console.error("LOGIN_REJECTED:missing_jwt_secret");
        return notFound();
      }
      
      const jwt = await signJWT({ sub: body.username, ip }, jwtSecret);
      
      // Store JWT in cache for verification
      await write(key("jwt", jwt), { username: body.username, ip, expires: Date.now() + JWT_TTL * 1000 }, JWT_TTL);
      
      return json({ valid: true, jwt, expiresIn: JWT_TTL });
    }

    if (url.pathname === "/api/verify-jwt") {
      if (!body?.username || !body.token) return notFound();
      
      // Verify JWT signature and check cache
      const jwtSecret = await readSecret(env, "JWT_SECRET_KEY");
      if (!jwtSecret) {
        console.error("LOGIN_REJECTED:missing_jwt_secret");
        return notFound();
      }
      
      const verification = await verifyJWT(body.token, jwtSecret);
      if (!verification.valid) {
        return json({ valid: false, reason: verification.reason });
      }
      
      // Check if JWT is still in cache (not revoked)
      const cachedJwt = await read(key("jwt", body.token));
      if (!cachedJwt || cachedJwt.username !== body.username) {
        return json({ valid: false, reason: "revoked" });
      }
      
      if (cachedJwt.expires < Date.now()) {
        return json({ valid: false, reason: "expired" });
      }
      
      return json({ valid: true, payload: verification.payload });
    }

    if (url.pathname !== "/api/login") return notFound();
    if (!body?.username || typeof body.password !== "string") return reject("invalid_payload");
    const ban = await read(key("ban", ip));
    if (ban?.until > Date.now()) return reject("ip_banned");
    
    // Verify Turnstile token (required)
    const turnstileToken = body.turnstileToken;
    if (!turnstileToken) {
      console.warn("LOGIN_REJECTED:missing_turnstile_token");
      return notFound();
    }
    
    try {
      const turnstileSecret = await readSecret(env, "TURNSTILE_SECRET_KEY");
      if (!turnstileSecret) {
        console.error("LOGIN_REJECTED:missing_turnstile_secret");
        return notFound();
      }
      
      const verifyResponse = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          secret: turnstileSecret,
          response: turnstileToken,
          remoteip: ip,
        }),
      });
      const verifyResult = await verifyResponse.json();
      if (!verifyResult.success) {
        console.warn("LOGIN_REJECTED:turnstile_failed");
        return notFound();
      }
    } catch (error) {
      console.error("TURNSTILE_VERIFY_ERROR:", error.message);
      return notFound();
    }
    
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
    // Store IP + token for later verification
    await write(key("token", token), { username: body.username, ip, expires: Date.now() + TOKEN_TTL * 1000 }, TOKEN_TTL);
    return json({ token, username: body.username });
  },
};
