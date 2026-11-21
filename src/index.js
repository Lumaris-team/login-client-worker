const TOKEN_TTL = 60;
const WINDOW_SECONDS = 1800;
const MAX_USERS_PER_IP = 5;
const JWT_TTL = 1800; // 30 minutes
const JWT_RENEW_INTERVAL = 600; // 10 minutes
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

// Generate JWT
async function generateJWT(username, ip, secret) {
  const header = { alg: "HS256", typ: "JWT" };
  const payload = {
    sub: username,
    ip: ip,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + JWT_TTL,
    jti: crypto.randomUUID(),
  };
  
  const encodedHeader = btoa(JSON.stringify(header)).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  const encodedPayload = btoa(JSON.stringify(payload)).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  
  const data = `${encodedHeader}.${encodedPayload}`;
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(data));
  const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  
  return `${data}.${encodedSignature}`;
}

// Verify JWT
async function verifyJWT(token, secret) {
  try {
    const [header, payload, signature] = token.split(".");
    const data = `${header}.${payload}`;
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );
    
    const signatureBytes = Uint8Array.from(atob(signature.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
    const isValid = await crypto.subtle.verify("HMAC", key, signatureBytes, encoder.encode(data));
    
    if (!isValid) return null;
    
    const decodedPayload = JSON.parse(atob(payload.replace(/-/g, "+").replace(/_/g, "/")));
    if (decodedPayload.exp < Math.floor(Date.now() / 1000)) return null;
    
    return decodedPayload;
  } catch (e) {
    return null;
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
      await caches.default.delete(key("token", body.token));
      return json({ valid: true });
    }

    if (url.pathname === "/api/renew-jwt") {
      if (!body?.username || !body.oneTimeToken) return notFound();
      
      // Verify one-time token
      const tokenRecord = await read(key("one-time-token", body.oneTimeToken));
      if (!tokenRecord || tokenRecord.username !== body.username || tokenRecord.ip !== ip) {
        return notFound();
      }
      
      // Generate new JWT
      const jwtSecret = await readSecret(env, "JWT_SECRET_KEY");
      if (!jwtSecret) {
        console.error("JWT_SECRET_KEY not configured");
        return notFound();
      }
      
      const jwt = await generateJWT(body.username, ip, jwtSecret);
      
      // Store JWT in cache
      const jwtKey = key("jwt", jwt);
      await write(jwtKey, { username: body.username, ip, expires: Date.now() + JWT_TTL * 1000 }, JWT_TTL);
      
      // Delete one-time token (it can only be used once)
      await caches.default.delete(key("one-time-token", body.oneTimeToken));
      
      // Generate new one-time token for next renewal
      const newOneTimeToken = `${crypto.randomUUID()}${crypto.randomUUID()}`;
      await write(key("one-time-token", newOneTimeToken), { username: body.username, ip, expires: Date.now() + JWT_RENEW_INTERVAL * 1000 }, JWT_RENEW_INTERVAL);
      
      return json({ jwt, oneTimeToken: newOneTimeToken });
    }

    if (url.pathname !== "/api/login") return notFound();
    if (!body?.username || typeof body.password !== "string") return reject("invalid_payload");
    const ban = await read(key("ban", ip));
    if (ban?.until > Date.now()) return reject("ip_banned");
    
    // Verify Turnstile token (required)
    if (!body.turnstileToken) {
      console.warn("LOGIN_REJECTED:missing_turnstile");
      return notFound();
    }
    
    try {
      const turnstileSecret = await readSecret(env, "TURNSTILE_SECRET_KEY");
      if (!turnstileSecret) {
        console.error("TURNSTILE_SECRET_KEY not configured");
        return notFound();
      }
      
      const verifyResponse = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          secret: turnstileSecret,
          response: body.turnstileToken,
          remoteip: ip,
        }),
      });
      const verifyResult = await verifyResponse.json();
      if (!verifyResult.success) {
        console.warn("LOGIN_REJECTED:turnstile_failed");
        return notFound();
      }
    } catch (error) {
      console.warn("TURNSTILE_VERIFY_ERROR:", error.message);
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
    
    // Generate one-time token
    const oneTimeToken = `${crypto.randomUUID()}${crypto.randomUUID()}`;
    await write(key("one-time-token", oneTimeToken), { username: body.username, ip, expires: Date.now() + JWT_RENEW_INTERVAL * 1000 }, JWT_RENEW_INTERVAL);
    
    // Generate initial JWT
    const jwtSecret = await readSecret(env, "JWT_SECRET_KEY");
    if (!jwtSecret) {
      console.error("JWT_SECRET_KEY not configured");
      return notFound();
    }
    
    const jwt = await generateJWT(body.username, ip, jwtSecret);
    await write(key("jwt", jwt), { username: body.username, ip, expires: Date.now() + JWT_TTL * 1000 }, JWT_TTL);
    
    return json({ jwt, oneTimeToken });
  },
};
