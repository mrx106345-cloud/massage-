# Deployment

Aegis ships as a single backend process that serves the static client and
proxies its API and WebSocket paths. Web, desktop, and mobile clients connect
to the same backend; only the origin and WebSocket scheme differ.

## Requirements

- Node.js 20+
- SQLite (the app uses better-sqlite3)
- For email/verification: a mailer transport is optional; without it, password
  reset and email verification paths are no-ops or logged-only depending on
  configuration.
- For packaged desktop/mobile builds: the client is bundled inside the binary
  and shipped with a server address the user supplies at first launch.

## Environment

Copy `.env.example` to `.env` and review the values. The important ones:

- `NODE_ENV`
- `PORT`
- `HOST`
- `TRUST_PROXY`
- `RATE_LIMIT_*`
- `JWT_*`
- `SESSION_*`
- `TOTP_*`
- `CORS_ORIGINS` / `SOCKET_ALLOWED_ORIGINS`
- `MEDIA_*`

Do not commit `.env`. In production, inject secrets through your orchestrator
or secret manager, not the filesystem checkout.

## Run directly

```bash
npm install --production
npm run build
npm start
```

For development with auto-reload use `npm run dev`.

## Docker

```bash
docker compose -f docker-compose.prod.yml up -d
```

The production compose file exposes the API port and persists SQLite state via
a named volume. Review `docker-compose.prod.yml` for the exact image, command,
ports, and volume mounts before publishing. If you override `MEDIA_STORE`
to an external path, bind-mount that path into the container.

For local smoke testing against a running container, set
`TEST_SERVER_URL` to the container's public URL when running the Playwright
suite.

## Reverse proxy

If you front the app with nginx/Caddy/CDN:

- Terminate TLS at the proxy.
- Pass `X-Forwarded-For` / `X-Real-IP` and set `TRUST_PROXY` so rate limiting
  and logging see real client IPs.
- Keep `/api/*` and `/socket.io/*` pointing to the same backend so the client's
  fetch and WebSocket flows stay coherent.
- Do not cache authenticated JSON API responses or WebSocket upgrades.

## CORS and origins

The server's CORS and Socket.IO allowed origins must include every origin that
will connect: the web origin, the Electron `app://aegis` scheme, and the
Capacitor `capacitor://localhost` / `https://localhost` schemes. Defaults are
configured in `.env.example` and mirrored in the packaged shells. Update them
when you publish under a custom domain or custom-scheme desktop/mobile build.

## Mobile first launch

Packaged desktop and mobile clients show a server-connection screen on first
launch. The runtime validates reachability of the supplied server before
proceeding to the auth flow.

## Backups

SQLite data directory and media store are the only persistent state. Back up
both. If you rely on any mailer-delivered tokens for account recovery, also
treat mailer config as part of your operational backup story.

## Observability

Health and metrics endpoints exist under `/api/health*` and `/api/metrics`.
Do not expose `/api/metrics` publicly without auth or network restrictions.
