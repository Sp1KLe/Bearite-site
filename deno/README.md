# Bearite аккаунты (Deno Deploy)

Сервер аккаунтов Bearite: регистрация, вход, проверка токена. Данные хранятся в Deno KV.

## Эндпоинты
- `GET /health`
- `POST /api/auth/register` — `{ "email", "password", "displayName" }` (пароль от 8 символов)
- `POST /api/auth/login` — `{ "email", "password" }`
- `GET /api/auth/me` — заголовок `Authorization: Bearer <token>`

Токен действует 7 дней.

## Деплой на Deno Deploy
1. Зайди на https://console.deno.com, войди через GitHub и создай проект.
2. Выбери «Git repository», репозиторий `Sp1KLe/bearite-site`.
3. Entrypoint: `deno/main.ts`.
4. В настройках проекта добавь переменную окружения `JWT_SECRET`: случайная строка не короче 32 символов.
5. Открой `https://<твой-проект>.deno.dev/health`. Должно вернуться `{"ok":true}`.

Секреты в репозиторий не коммить.
