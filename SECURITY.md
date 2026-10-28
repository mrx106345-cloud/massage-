# Security

## Scope

Aegis is an end-to-end encrypted chat system. The provider server stores and
relays only ciphertext and minimal routing metadata. Secret key material is
generated and held in the client.

## Cryptographic model

- Keys and message encryption use libsodium primitives (X25519 and
  AES-256-GCM) on the client.
- Media files are encrypted client-side before upload; the server stores and
  serves ciphertext.
- Server-side auth uses short-lived tokens with refresh rotation, optional TOTP,
  and session revocation.

## Operational rules

- Secrets live only in the environment or a managed secret store. Never commit
  `.env`, `.env.local`, or `.env.development.local`.
- CORS and Socket.IO allowed origins must be restricted to the origins you
  control, including the Electron scheme and Capacitor schemes if you publish
  packaged clients.
- Authentication, password reset, 2FA, and session endpoints are rate-limited.
- The app sets security headers (CSP, X-Content-Type-Options, X-Frame-Options,
  Referrer-Policy, Permissions-Policy, X-DNS-Prefetch-Control) and compresses
  responses where appropriate.
- `/api/metrics` must not be exposed to the open internet without additional
  restriction.

## Deny-path hygiene

Server responses that refuse to match an identity must not echo client-supplied
identity material back to the caller. This repository has regression tests that
assert that invariant for authenticated lookups of nonexistent contacts. Treat
any new endpoint that accepts user-supplied identifiers the same way.

## Threats outside this model

- Compromise of a client device exposes that device's keys and stored messages.
- Social engineering, endpoint malware, and weak passphrases are outside the
  cryptographic model.
- Metadata (who talks to whom and when) is not hidden by this design; treat it
  accordingly for your deployment.

## Reporting

If you find a security issue, report it privately rather than opening a public
issue. Include a description, affected version, and reproduction steps if
available.
