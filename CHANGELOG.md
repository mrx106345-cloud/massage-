# Changelog

## Not yet released

- Added deny-response regression tests asserting that authenticated lookups of
  nonexistent contacts do not echo client-supplied identity material.
- Hardened packaging documentation and cross-platform setup instructions.
- Retained existing auth, E2EE, groups, media, and real-time behavior.

## Prior work (captured in repo history)

- Web, desktop (Electron), and mobile (Capacitor) targets wired to a shared
  client and server.
- CORS and Socket.IO allowed origins extended for packaged origins.
- Desktop first-launch server setup and mobile server-setup detection.
- Security headers, rate limiting, compression, and token/2FA flows.
