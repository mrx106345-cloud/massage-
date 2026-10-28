# Aegis — end-to-end encrypted messaging

Aegis is a server-relayed, client-encrypted chat system. Identity keys and
message keys live in the browser (or the native app's secure storage); the
server relays only ciphertext and metadata the clients already share. There is
no plaintext mailbox on the server.

## Targets

| Target | Runtime | Notes |
| --- | --- | --- |
| Web | Browser | Static `public/` served by the Node API process, or any static host with the `/api/*` and `/socket.io/*` proxies pointed at the same server. |
| Desktop | Electron | Windows (NSIS/zip), macOS (dmg/zip), Linux (AppImage/deb) built with `electron-builder`. |
| Mobile | Capacitor | Android (debug APK via `android/gradlew`) and iOS (scaffolded; archive needs macOS/Xcode). |

All three targets share the same client code in `public/` and the same server
API and WebSocket real-time path.

## Quick start

```bash
npm install
cp .env.example .env
npm run dev        # API + static client on one origin
```

Open `http://localhost:3000` (or whatever `PORT` you set). The first launch of
a packaged desktop or mobile build shows a server-connection screen so the
runtime can point at an existing Aegis server.

## Architecture

- `src/index.ts` — HTTP server bootstrap, shutdown, process-level error handlers.
- `src/app.ts` — Express app: middleware stack, routes, compression, security headers.
- `src/routes/*.ts` — REST endpoints under `/api/v1/*`.
- `src/sockets/server.ts` — Socket.IO namespace and presence/queue logic.
- `src/services/*.ts` — account, auth, crypto, media, threads, groups, mailer.
- `src/middleware/*.ts` — auth, rate limiting, async wrapper, error handling, security headers.
- `public/js/*` — Browser client (module + vendor libs).
- `desktop/` — Electron main + preload.
- `android/` and `ios/` — Capacitor native shells.

## Security model

- Client-side encryption with `libsodium` (X25519 + AES-256-GCM) via
  `nacl-fast`.
- Server auth is token-based with refresh rotation, TOTP, session revocation,
  and rate-limited auth endpoints.
- Media files are encrypted client-side; the server stores only ciphertext
  payloads and serves them back to authenticated clients.
- Security headers (CSP, X-Content-Type-Options, X-Frame-Options,
  Referrer-Policy, Permissions-Policy, X-DNS-Prefetch-Control) and
  response compression are enabled.
- Deny paths must never reflect client-supplied identity material back to the
  caller; this is asserted by the deny-response tests in
  `src/routes/threads.routes.test.ts`.

## Cross-platform notes

- Web uses `fetch` to the same origin by default and falls back to explicit
  endpoints when the page is authored with `?server=` or the packaged viewer
  supplies them.
- Desktop (Electron) serves the client from `app://aegis` with a preload that
  exposes a small, reviewed API to the renderer and applies security headers on
  protocol responses.
- Mobile (Capacitor) runs against `capacitor://localhost` / `https://localhost`
  and the server's CORS + socket allowed origins include those schemes.

## Tests

```bash
npm run test          # vitest suite
npm run typecheck     # tsc
npm run lint          # eslint
npm run format:check  # prettier
```

Web smoke tests use Playwright:

```bash
npx playwright test tests/web-smoke.spec.ts
```

Set `TEST_SERVER_URL` to point the browser tests at a running server instead of
the static `public/index.html` file.

## Packaging

- Web: build the server as usual; static assets are served from `public/`.
- Desktop: `npm run desktop:build` (or configure `electron-builder` via
  `package.json` and `desktop/`).
- Mobile: `npm run mobile:sync` then `cd android && ./gradlew.bat assembleDebug`
  for a debug APK; iOS requires a macOS host with Xcode.

## Deployment

See `DEPLOYMENT.md` for production startup, environment variables, and
docker-compose-based deployment. See `SECURITY.md` for the threat model and
operational security guidance.

## License

This project is provided as-is for internal evaluation and deployment.
