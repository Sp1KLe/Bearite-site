/**
 * Аккаунты Bearite на Deno Deploy: регистрация, вход, проверка токена.
 * Данные лежат в встроенной базе Deno KV. Пароли хранятся как PBKDF2-SHA256, токены — JWT HS256.
 * Переменные окружения: JWT_SECRET (не короче 32 символов).
 */

const ITERATIONS = 210_000;
const TOKEN_TTL_SEC = 7 * 24 * 3600;
const encoder = new TextEncoder();
const kv = await Deno.openKv();

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(text: string): Uint8Array {
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(text.length / 4) * 4, "=");
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

function b64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function fromB64(text: string): Uint8Array {
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}

async function hmacKey(): Promise<CryptoKey> {
  const secret = Deno.env.get("JWT_SECRET") ?? "";
  if (secret.length < 32) throw new Error("JWT_SECRET must contain at least 32 characters");
  return crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

async function signToken(user: { id: string; email: string }): Promise<string> {
  const header = b64url(encoder.encode(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const now = Math.floor(Date.now() / 1000);
  const payload = b64url(encoder.encode(JSON.stringify({ sub: user.id, email: user.email, iat: now, exp: now + TOKEN_TTL_SEC })));
  const data = encoder.encode(`${header}.${payload}`);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", await hmacKey(), data));
  return `${header}.${payload}.${b64url(sig)}`;
}

async function verifyToken(token: string): Promise<{ sub: string; email: string } | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [header, payload, sig] = parts;
  const ok = await crypto.subtle.verify(
    "HMAC",
    await hmacKey(),
    b64urlDecode(sig),
    encoder.encode(`${header}.${payload}`),
  );
  if (!ok) return null;
  try {
    const data = JSON.parse(new TextDecoder().decode(b64urlDecode(payload)));
    if (typeof data.exp !== "number" || data.exp < Math.floor(Date.now() / 1000)) return null;
    return { sub: String(data.sub), email: String(data.email) };
  } catch {
    return null;
  }
}

async function hashPassword(password: string, salt?: Uint8Array): Promise<string> {
  const s = salt ?? crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: s, iterations: ITERATIONS, hash: "SHA-256" },
    key,
    256,
  );
  return `pbkdf2$${ITERATIONS}$${b64(s)}$${b64(new Uint8Array(bits))}`;
}

async function checkPassword(password: string, stored: string): Promise<boolean> {
  const [, iter, saltB64, hashB64] = stored.split("$");
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: fromB64(saltB64), iterations: Number(iter), hash: "SHA-256" },
    key,
    256,
  );
  const a = new Uint8Array(bits);
  const b = fromB64(hashB64);
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

interface User {
  id: string;
  email: string;
  displayName: string;
  passwordHash: string;
  createdAt: string;
}

function publicUser(u: User) {
  return { id: u.id, email: u.email, displayName: u.displayName, createdAt: u.createdAt };
}

async function readJson(req: Request): Promise<Record<string, unknown> | null> {
  try {
    const text = await req.text();
    if (text.length > 20_000) return null;
    const data = JSON.parse(text);
    return data && typeof data === "object" ? data as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

async function register(req: Request): Promise<Response> {
  const body = await readJson(req);
  if (!body) return json({ error: "Некорректный запрос" }, 400);
  const email = String(body.email ?? "").trim().toLowerCase();
  const password = String(body.password ?? "");
  const displayName = String(body.displayName ?? "").trim();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) return json({ error: "Неверный email" }, 400);
  if (password.length < 8 || password.length > 200) return json({ error: "Пароль: от 8 символов" }, 400);
  if (displayName.length < 2 || displayName.length > 24) return json({ error: "Имя: от 2 до 24 символов" }, 400);

  const existing = await kv.get<string>(["usersByEmail", email]);
  if (existing.value) return json({ error: "Этот email уже зарегистрирован" }, 409);

  const user: User = {
    id: crypto.randomUUID(),
    email,
    displayName,
    passwordHash: await hashPassword(password),
    createdAt: new Date().toISOString(),
  };
  // проверка и запись атомарно: если email заняли параллельно, запись не пройдёт
  const res = await kv.atomic()
    .check({ key: ["usersByEmail", email], versionstamp: null })
    .set(["users", user.id], user)
    .set(["usersByEmail", email], user.id)
    .commit();
  if (!res.ok) return json({ error: "Этот email уже зарегистрирован" }, 409);

  return json({ token: await signToken(user), user: publicUser(user) }, 201);
}

async function login(req: Request): Promise<Response> {
  const body = await readJson(req);
  if (!body) return json({ error: "Некорректный запрос" }, 400);
  const email = String(body.email ?? "").trim().toLowerCase();
  const password = String(body.password ?? "");
  const idEntry = await kv.get<string>(["usersByEmail", email]);
  const invalid = () => json({ error: "Неверный email или пароль" }, 401);
  if (!idEntry.value) return invalid();
  const userEntry = await kv.get<User>(["users", idEntry.value]);
  if (!userEntry.value) return invalid();
  if (!(await checkPassword(password, userEntry.value.passwordHash))) return invalid();
  return json({ token: await signToken(userEntry.value), user: publicUser(userEntry.value) });
}

async function me(req: Request): Promise<Response> {
  const auth = req.headers.get("authorization") ?? "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  const claims = token ? await verifyToken(token) : null;
  if (!claims) return json({ error: "Нужен вход" }, 401);
  const userEntry = await kv.get<User>(["users", claims.sub]);
  if (!userEntry.value) return json({ error: "Аккаунт не найден" }, 404);
  return json({ user: publicUser(userEntry.value) });
}

Deno.serve(async (req) => {
  const url = new URL(req.url);
  if (req.method === "GET" && url.pathname === "/health") return json({ ok: true });
  if (req.method === "POST" && url.pathname === "/api/auth/register") return register(req);
  if (req.method === "POST" && url.pathname === "/api/auth/login") return login(req);
  if (req.method === "GET" && url.pathname === "/api/auth/me") return me(req);
  return json({ error: "Не найдено" }, 404);
});
