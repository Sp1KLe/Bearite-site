import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import { OAuth2Client } from 'google-auth-library';

const { Pool } = pg;
const app = express();
const port = Number(process.env.PORT || 10000);
const required = ['DATABASE_URL', 'JWT_SECRET', 'GOOGLE_CLIENT_ID', 'FRONTEND_ORIGIN'];
for (const key of required) {
  if (!process.env[key]) console.warn(`Missing environment variable: ${key}`);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('localhost') ? false : { rejectUnauthorized: false }
});
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const allowedOrigins = (process.env.FRONTEND_ORIGIN || '')
  .split(',')
  .map(value => value.trim())
  .filter(Boolean);

app.set('trust proxy', 1);
app.use(helmet());
app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Origin is not allowed by CORS'));
  },
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '20kb' }));

const authLimiter = rateLimit({
  windowMs: 15 *  60 * 1000,
  limit: 12,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Слишком много попыток. Попробуй позже.' }
});

async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      display_name TEXT NOT NULL,
      password_hash TEXT,
      google_sub TEXT UNIQUE,
      avatar_url TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT users_auth_method CHECK (password_hash IS NOT NULL OR google_sub IS NOT NULL)
    )
  `);
}

function createToken(user) {
  if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
    throw new Error('JWT_SECRET must contain at least 32 characters');
  }
  return jwt.sign({ sub: String(user.id), email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
}

function publicUser(user) {
  return {
    id: String(user.id),
    email: user.email,
    displayName: user.display_name,
    avatarUrl: user.avatar_url || null,
    createdAt: user.created_at
  };
}

function sendSession(res, user, status = 200) {
  const token = createToken(user);
  return res.status(status).json({ token, user: publicUser(user) });
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'Нужно войти в аккаунт.' });
  try {
    req.auth = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Сессия истекла. Войди снова.' });
  }
}

app.get('/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, service: 'Bearite API', database: 'connected' });
  } catch {
    res.status(503).json({ ok: false, database: 'unavailable' });
  }
});

app.post('/api/auth/register', authLimiter, async (req, res, next) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const displayName = String(req.body.displayName || '').trim();
    if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Укажи корректную почту.' });
    if (password.length < 8 || password.length > 72) return res.status(400).json({ error: 'Пароль должен содержать от 8 до 72 символов.' });
    if (displayName.length < 3 || displayName.length > 24) return res.status(400).json({ error: 'Имя игрока должно содержать от 3 до 24 символов.' });
    const passwordHash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      'INSERT INTO users (email, display_name, password_hash) VALUES ($1, $2, $3) RETURNING *',
      [email, displayName, passwordHash]
    );
    return sendSession(res, result.rows[0], 201);
  } catch (error) {
    if (error.code === '23505') return res.status(409).json({ error: 'Этот адрес уже зарегистрирован. Попробуй войти.' });
    next(error);
  }
});

app.post('/api/auth/login', authLimiter, async (req, res, next) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user || !user.password_hash || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Неверная почта или пароль.' });
    }
    return sendSession(res, user);
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/google', authLimiter, async (req, res, next) => {
  try {
    const credential = String(req.body.credential || '');
    if (!credential) return res.status(400).json({ error: 'Google не передал токен авторизации.' });
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID
    });
    const payload = ticket.getPayload();
    if (!payload?.sub || !payload.email || payload.email_verified !== true) {
      return res.status(401).json({ error: 'Google-аккаунт не подтвердил адрес почты.' });
    }
    const email = payload.email.toLowerCase();
    const displayName = String(payload.name || email.split('@')[0]).slice(0, 24);
    const avatarUrl = payload.picture || null;

    let result = await pool.query('SELECT * FROM users WHERE google_sub = $1', [payload.sub]);
    let user = result.rows[0];
    if (!user) {
      result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
      user = result.rows[0];
      if (user) {
        if (user.google_sub && user.google_sub !== payload.sub) {
          return res.status(409).json({ error: 'Этот адрес уже связан с другим Google-аккаунтом.' });
        }
        result = await pool.query(
          'UPDATE users SET google_sub = $1, avatar_url = $2, updated_at = NOW() WHERE id = $3 RETURNING *',
          [payload.sub, avatarUrl, user.id]
        );
      } else {
        result = await pool.query(
          'INSERT INTO users (email, display_name, google_sub, avatar_url) VALUES ($1, $2, $3, $4) RETURNING *',
          [email, displayName, payload.sub, avatarUrl]
        );
      }
      user = result.rows[0];
    }
    return sendSession(res, user);
  } catch (error) {
    if (error.code === '23505') return res.status(409).json({ error: 'Аккаунт с этой почтой уже существует.' });
    next(error);
  }
});

app.get('/api/auth/me', requireAuth, async (req, res, next) => {
  try {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.auth.sub]);
    if (!result.rows[0]) return res.status(404).json({ error: 'Аккаунт не найден.' });
    res.json({ user: publicUser(result.rows[0]) });
  } catch (error) {
    next(error);
  }
});

app.use((error, _req, res, _next) => {
  console.error(error);
  if (error.message === 'Origin is not allowed by CORS') return res.status(403).json({ error: 'Запрос с этого сайта запрещён.' });
  res.status(500).json({ error: 'Внутренняя ошибка сервера. Попробуй позже.' });
});

ensureSchema()
  .then(() => app.listen(port, () => console.log(`Bearite API listening on ${port}`)))
  .catch(error => {
    console.error('Database initialization failed:', error);
    process.exit(1);
  });
