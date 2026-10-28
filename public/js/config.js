/**
 * Runtime endpoint resolution.
 *
 * The web build is served by the API, so it talks to its own origin. The desktop
 * and mobile shells bundle these assets and therefore must be told where the
 * server lives. Resolution order, highest first:
 *
 *   1. `?server=https://chat.example.com` — persists to localStorage, lets a
 *      support link or a deep link point a fresh install at a server.
 *   2. `window.__AEGIS_SERVER__` — injected by the desktop preload script.
 *   3. localStorage — the value chosen on the setup screen or by a previous link.
 *   4. same origin — the hosted web build.
 */

const STORAGE_KEY = 'aegis.server';

/** Normalise a user-entered endpoint into an origin with no trailing slash. */
export function normalizeServer(value) {
  const raw = typeof value === 'string' ? value.trim() : '';
  if (!raw) return '';
  let url;
  try {
    url = new URL(raw.includes('://') ? raw : `https://${raw}`);
  } catch {
    return '';
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return '';
  if (url.username || url.password) return '';
  // Keep only the origin: paths and query strings would silently break the
  // absolute API/media URLs built from this value.
  return url.origin;
}

function injectedServer() {
  return normalizeServer(globalThis.__AEGIS_SERVER__);
}

/** Read and persist the `?server=` parameter, if present. */
function consumeServerParam() {
  let params;
  try {
    params = new URLSearchParams(location.search);
  } catch {
    return '';
  }
  if (!params.has('server')) return '';
  const normalised = normalizeServer(params.get('server'));
  if (normalised) saveServer(normalised);
  params.delete('server');
  const query = params.toString();
  try {
    history.replaceState(
      null,
      '',
      `${location.pathname}${query ? `?${query}` : ''}${location.hash}`,
    );
  } catch {
    // History rewriting is cosmetic; the stored value is what matters.
  }
  return normalised;
}

export function saveServer(value) {
  const normalised = normalizeServer(value);
  try {
    if (normalised) localStorage.setItem(STORAGE_KEY, normalised);
    else localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Private mode with storage disabled: fall through to the same-origin build.
  }
  return normalised;
}

export function clearServer() {
  return saveServer('');
}

/** The configured server origin, or '' when this build is served by the API. */
export function serverBase() {
  return consumeServerParam() || injectedServer() || localStorage.getItem(STORAGE_KEY) || '';
}

/** Absolute URL for an API path such as `/api/v1/threads`. */
export function endpoint(path) {
  const base = serverBase();
  return base ? `${base}${path}` : path;
}

/**
 * Absolute form of a URL the server handed back (presigned upload/download).
 * Such URLs may already be absolute, in which case they are returned unchanged.
 */
export function absoluteUrl(value) {
  const raw = typeof value === 'string' ? value : '';
  if (!raw) return '';
  if (/^[a-z][a-z0-9+.-]*:/i.test(raw)) return raw;
  const base = serverBase();
  return base ? `${base}${raw.startsWith('/') ? '' : '/'}${raw}` : raw;
}

/** Undefined means "same origin" for socket.io. */
export function socketEndpoint() {
  return serverBase() || undefined;
}

/**
 * Bundled shells have no server to fall back on: their assets ship inside the
 * app, so a relative `/api` call would hit a local file. Detect that case so the
 * UI can ask for an endpoint instead of failing with a confusing 404.
 */
export function needsServerSetup() {
  if (serverBase()) return false;
  const protocol = location.protocol;
  // Custom schemes: Electron (app:), iOS Capacitor (capacitor:)
  if (protocol !== 'http:' && protocol !== 'https:') return true;
  // Android Capacitor uses https://localhost as the app origin but still needs
  // to connect to a remote server
  if (protocol === 'https:' && location.hostname === 'localhost') {
    // If Capacitor is present, it's likely Android Capacitor
    if (globalThis.Capacitor) return true;
    // Also check for common Capacitor indicators
    if (navigator.userAgent?.includes('Capacitor')) return true;
  }
  return false;
}
