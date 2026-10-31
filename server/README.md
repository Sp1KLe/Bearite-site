# Bearite Auth API

Node.js API for Bearite ID. The static website stays on GitHub Pages; this service runs on Render.

## Endpoints
- GET /health
- POST /api/auth/register — { "email", "password", "displayName" }
- POST /api/auth/login — { "email", "password" }
- POST /api/auth/google — { "credential": "<Google ID token>" }
- GET /api/auth/me — Authorization: Bearer <token>

## Deploy on Render
1. Create a PostgreSQL database in Render.
2. Create a Web Service from the Bearite-site repository.
3. Set Root Directory to `server`, Build Command to `npm install`, Start Command to `npm start`.
4. Add environment variables:
   - DATABASE_URL: Internal Database URL from the Render PostgreSQL database (or External URL if required).
   - JWT_SECRET: a random secret of at least 32 characters.
   - GOOGLE_CLIENT_ID: OAuth 2.0 Web client ID from Google Cloud Console.
   - FRONTEND_ORIGIN: `https://sp1kle.github.io`
5. Deploy and check `/health`.

The database table is created automatically at server startup. Never commit real secrets to GitHub.
