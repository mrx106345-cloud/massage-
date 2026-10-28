/**
 * Thin API client: bearer auth, transparent refresh-token rotation, typed errors.
 * Tokens live in localStorage because the app must also work when the server is
 * opened directly (no cookie session). XSS is mitigated by a strict CSP and by
 * never interpolating server strings into HTML.
 */

import { endpoint } from './config.js?v=5';

const SESSION_KEY = 'aegis.session';

export class ApiError extends Error {
  constructor(status, body) {
    const message = typeof body?.error === 'string' ? body.error : `request failed (${status})`;
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
  }

  get code() {
    return typeof this.body?.code === 'string' ? this.body.code : null;
  }
}

export function loadSession() {
  try {
    const raw = localStorage.getItem(SESSION_KEY);
    const parsed = raw ? JSON.parse(raw) : null;
    return parsed && typeof parsed.token === 'string' ? parsed : null;
  } catch {
    return null;
  }
}

export function saveSession(session) {
  localStorage.setItem(SESSION_KEY, JSON.stringify(session));
}

export function clearSession() {
  localStorage.removeItem(SESSION_KEY);
}

async function rawFetch(path, { method = 'GET', body, token } = {}) {
  const res = await fetch(endpoint(path), {
    method,
    headers: {
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  const text = await res.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }
  return { res, data };
}

let refreshInFlight = null;

async function refreshSession() {
  const session = loadSession();
  if (!session?.refreshToken) throw new ApiError(401, { error: 'signed out' });

  if (!refreshInFlight) {
    refreshInFlight = (async () => {
      const { res, data } = await rawFetch('/api/v1/auth/refresh', {
        method: 'POST',
        body: { refreshToken: session.refreshToken },
      });
      if (!res.ok || typeof data?.token !== 'string') {
        clearSession();
        throw new ApiError(res.status, data);
      }
      const next = {
        ...session,
        token: data.token,
        refreshToken:
          typeof data.refreshToken === 'string' ? data.refreshToken : session.refreshToken,
      };
      saveSession(next);
      return next;
    })().finally(() => {
      refreshInFlight = null;
    });
  }
  return refreshInFlight;
}

export async function request(path, options = {}) {
  const session = loadSession();
  let result = await rawFetch(path, { ...options, token: session?.token });

  // Access tokens are short lived; rotate once and replay the request. A second
  // 401 means the session itself is gone.
  if (result.res.status === 401 && session?.refreshToken && !options.noRetry) {
    const next = await refreshSession().catch((error) => {
      throw error instanceof ApiError ? error : new ApiError(401, { error: 'session expired' });
    });
    result = await rawFetch(path, { ...options, token: next.token });
  }

  if (!result.res.ok) throw new ApiError(result.res.status, result.data);
  return result.data;
}

export const api = {
  signup: (input) => request('/api/v1/auth/signup', { method: 'POST', body: input }),
  login: (input) => request('/api/v1/auth/login', { method: 'POST', body: input }),
  logout: (refreshToken) =>
    request('/api/v1/auth/logout', { method: 'POST', body: { refreshToken } }).catch(() => null),

  threads: () => request('/api/v1/threads'),
  messages: (threadId, { before, limit = 50 } = {}) => {
    const params = new URLSearchParams({ limit: String(limit) });
    if (before) params.set('before', before);
    return request(`/api/v1/threads/${encodeURIComponent(threadId)}/messages?${params.toString()}`);
  },
  markRead: (threadId) =>
    request(`/api/v1/threads/${encodeURIComponent(threadId)}/read`, {
      method: 'POST',
      body: {},
    }).catch(() => null),

  searchUsers: (query) => request(`/api/v1/users/search?q=${encodeURIComponent(query)}`),
  publicKey: (userId) => request(`/api/v1/users/${encodeURIComponent(userId)}/public-key`),
  selfKeys: () => request('/api/v1/crypto/keys/self'),

  createGroup: ({ groupName, memberIds }) =>
    request('/api/v1/groups', { method: 'POST', body: { groupName, memberIds } }),
  group: (groupId) => request(`/api/v1/groups/${encodeURIComponent(groupId)}`),
  addGroupMembers: (groupId, memberIds) =>
    request(`/api/v1/groups/${encodeURIComponent(groupId)}/members`, {
      method: 'POST',
      body: { memberIds },
    }),
  removeGroupMember: (groupId, memberId) =>
    request(
      `/api/v1/groups/${encodeURIComponent(groupId)}/members/${encodeURIComponent(memberId)}`,
      { method: 'DELETE' },
    ),
  leaveGroup: (groupId) =>
    request(`/api/v1/groups/${encodeURIComponent(groupId)}/leave`, {
      method: 'POST',
      body: {},
    }),

  presignMedia: ({ fileType, fileName, sizeBytes }) =>
    request('/api/v1/media/presign', {
      method: 'POST',
      body: { fileType, fileName, sizeBytes },
    }),
  mediaInfo: (mediaId) => request(`/api/v1/media/${encodeURIComponent(mediaId)}`),
};
