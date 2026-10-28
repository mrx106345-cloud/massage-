# Audit notes

## Dependency security

Run `npm audit --omit=dev` to check runtime dependencies only, and `npm audit`
to include dev dependencies.

Current status:

- Runtime dependencies: no known vulnerabilities reported by `npm audit
  --omit=dev`.
- Dev dependencies and build tooling: `npm audit` reports advisories under the
  test and packaging toolchain, including `vitest`, `electron`,
  `electron-builder`, `tar`, and a few other build dependencies.

That split matters for this project: the deployed server does not ship the
test runner or the Electron packager, so the meaningful question is whether the
advisories affect runtime behavior or only the developer machine and build
process.

### Known items from the current lockfile

- `vitest` depends on `tinypool`, which has had critical advisories. `vitest`
  is a test dependency, so this affects test execution, not the production
  server.
- `electron` and `electron-builder` advisories are part of the desktop build
  toolchain, not the packaged server runtime.
- `tar`, `node-gyp`, `cacache`, and related packages appear through the
  build/test toolchain in the dev dependency tree.

## Runtime attack surface

- The server process uses Express, Socket.IO, better-sqlite3, and a small set
  of application dependencies. Auth, rate limiting, security headers, and E2EE
  enforcement are handled in application code.
- Media access uses expiring HMAC-signed download keys rather than raw storage
  URLs.
- Configuration is validated at startup through the schema in
  `src/config/index.ts`.

## Recommended practice

- Before releasing or deploying, re-run `npm audit --omit=dev` and treat any
  new runtime advisory as a release blocker.
- Treat test- and build-time advisories as lower priority, but still track them
  and upgrade tooling on a schedule rather than only when a release is blocked.
- Keep dependency audits version-controlled. Record the date, command, and
  conclusion rather than silently re-locking.
