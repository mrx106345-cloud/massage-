/**
 * Aegis Chat client.
 *
 * Everything that touches message contents runs here: plaintext is sealed with
 * X25519 + HKDF-SHA256 + AES-256-GCM before it reaches the socket, and incoming
 * envelopes are opened locally. The server only stores and routes ciphertext.
 */

import * as ce from './crypto.js?v=5';
import { api, ApiError, clearSession, loadSession, saveSession, request } from './api.js?v=5';
import { absoluteUrl, needsServerSetup, saveServer, socketEndpoint } from './config.js?v=5';

const $ = (id) => document.getElementById(id);

const dom = {
  serverView: $('server-view'),
  serverForm: $('server-form'),
  serverError: $('server-error'),
  authView: $('auth-view'),
  appView: $('app-view'),
  loginForm: $('login-form'),
  signupForm: $('signup-form'),
  totpRow: $('totp-row'),
  loginError: $('login-error'),
  signupError: $('signup-error'),
  meName: $('me-name'),
  meAvatar: $('me-avatar'),
  logout: $('logout-button'),
  newChat: $('new-chat-button'),
  newGroup: $('new-group-button'),
  filter: $('thread-filter'),
  threadList: $('thread-list'),
  relayState: $('relay-state'),
  emptyState: $('empty-state'),
  chatView: $('chat-view'),
  chatAvatar: $('chat-avatar'),
  chatName: $('chat-name'),
  chatMeta: $('chat-meta'),
  chatNotice: $('chat-notice'),
  chatNoticeText: $('chat-notice-text'),
  requestKey: $('request-key'),
  groupInfo: $('group-info-button'),
  verifyButton: $('verify-button'),
  back: $('back-button'),
  messages: $('message-list'),
  composer: $('composer'),
  input: $('composer-input'),
  send: $('send-button'),
  attach: $('attach-button'),
  fileInput: $('file-input'),
  attachmentPreview: $('attachment-preview'),
  modalHost: $('modal-host'),
  toastHost: $('toast-host'),
};

const MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024;
const ATTACHMENT_TYPES = new Set([
  'image/png',
  'image/jpeg',
  'image/gif',
  'image/webp',
  'video/mp4',
  'video/webm',
  'audio/mpeg',
  'audio/wav',
  'audio/ogg',
  'audio/webm',
  'audio/m4a',
  'application/pdf',
  'application/zip',
  'application/json',
  'text/plain',
]);

const state = {
  me: null,
  identity: null,
  socket: null,
  connected: false,
  threads: [],
  filter: '',
  activeId: null,
  messages: new Map(),
  online: new Set(),
  keyCache: new Map(),
  groupMembers: new Map(),
  pendingSends: new Map(),
  pendingAttachment: null,
  mediaCache: new Map(),
  requestedKeys: new Set(),
  socketRefreshTried: false,
  identityPublishPromise: null,
  verifiedKeys: new Map(),
  keyChanges: new Map(),
  rotatingGroups: new Set(),
};

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

const identityStorageKey = (userId) => `aegis.identity.${userId}`;
const groupKeyStorageKey = (groupId) => `aegis.gmk.${groupId}`;

function loadIdentity(userId) {
  try {
    const raw = localStorage.getItem(identityStorageKey(userId));
    const parsed = raw ? JSON.parse(raw) : null;
    if (!parsed?.secretKeyHex) return null;
    return ce.identityFromSecret(parsed.secretKeyHex);
  } catch {
    return null;
  }
}

function verifiedStorageKey() {
  return `aegis.verified.${state.me?.id ?? ''}`;
}

function loadVerifiedKeys() {
  try {
    const raw = localStorage.getItem(verifiedStorageKey());
    const parsed = raw ? JSON.parse(raw) : null;
    if (!parsed || typeof parsed !== 'object') return new Map();
    return new Map(
      Object.entries(parsed).map(([userId, value]) => [
        userId,
        {
          signingPublicKeyHex: String(value.signingPublicKeyHex ?? ''),
          safetyNumber: String(value.safetyNumber ?? ''),
          verifiedAt: value.verifiedAt ?? null,
        },
      ]),
    );
  } catch {
    return new Map();
  }
}

function persistVerifiedKeys() {
  try {
    const payload = {};
    for (const [userId, value] of state.verifiedKeys) {
      payload[userId] = {
        signingPublicKeyHex: value.signingPublicKeyHex,
        safetyNumber: value.safetyNumber,
        verifiedAt: value.verifiedAt,
      };
    }
    localStorage.setItem(verifiedStorageKey(), JSON.stringify(payload));
  } catch {
    // Storage full or unavailable; verification is non-critical.
  }
}

function ensureIdentity(userId) {
  const existing = loadIdentity(userId);
  if (existing) return existing;
  const identity = ce.generateIdentity();
  localStorage.setItem(identityStorageKey(userId), JSON.stringify(identity));
  return identity;
}

/**
 * Group keys are stored by version so rotating a key when membership changes
 * does not make older messages undecryptable. The legacy single-key shape is
 * migrated transparently on read.
 */
function readGroupKeyStore(groupId) {
  try {
    const raw = localStorage.getItem(groupKeyStorageKey(groupId));
    if (!raw) return { latest: 0, keys: {} };
    const parsed = JSON.parse(raw);
    if (parsed?.keys && typeof parsed.keys === 'object') {
      return { latest: Number(parsed.latest) || 0, keys: parsed.keys };
    }
    if (parsed?.gmk) {
      const version = Number(parsed.version) || 1;
      return {
        latest: version,
        keys: { [String(version)]: { gmk: parsed.gmk, gmkId: parsed.gmkId } },
      };
    }
  } catch {
    // Corrupt storage is treated as empty; the key can be requested again.
  }
  return { latest: 0, keys: {} };
}

function saveGroupKey(groupId, { version, gmk, gmkId }) {
  const numericVersion = Number(version) || 1;
  const store = readGroupKeyStore(groupId);
  store.keys[String(numericVersion)] = { gmk: ce.toBase64(gmk), gmkId };
  store.latest = Math.max(Number(store.latest) || 0, numericVersion);
  localStorage.setItem(groupKeyStorageKey(groupId), JSON.stringify(store));
}

function loadGroupKey(groupId, version) {
  const store = readGroupKeyStore(groupId);
  const requested =
    version === undefined || version === null || Number(version) <= 0
      ? Number(store.latest) || 0
      : Number(version);
  if (!requested) return null;
  const entry = store.keys[String(requested)];
  if (!entry?.gmk) return null;
  try {
    return { version: requested, gmk: ce.fromBase64(entry.gmk), gmkId: entry.gmkId };
  } catch {
    return null;
  }
}

function latestGroupKeyVersion(groupId) {
  return Number(readGroupKeyStore(groupId).latest) || 0;
}

function groupKeyForThread(thread) {
  if (!thread) return null;
  const version = Number(thread.group?.gmVersion) || latestGroupKeyVersion(thread.id);
  return loadGroupKey(thread.id, version || undefined);
}

// ---------------------------------------------------------------------------
// Small UI utilities
// ---------------------------------------------------------------------------

function toast(message, kind = 'info') {
  const node = document.createElement('div');
  node.className = `toast${kind === 'error' ? ' error' : ''}`;
  node.textContent = message;
  dom.toastHost.append(node);
  setTimeout(() => node.remove(), 5200);
}

function initial(name) {
  return (name ?? '?').trim().charAt(0) || '?';
}

function setAvatar(node, name, isGroup = false) {
  node.textContent = initial(name);
  node.classList.toggle('group', Boolean(isGroup));
}

function formatClock(iso) {
  const date = iso ? new Date(iso) : new Date();
  if (Number.isNaN(date.getTime())) return '';
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function formatRelative(iso) {
  if (!iso) return '';
  const time = new Date(iso).getTime();
  if (Number.isNaN(time)) return '';
  const diff = Date.now() - time;
  if (diff < 60_000) return 'now';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h`;
  if (diff < 7 * 86_400_000) return `${Math.floor(diff / 86_400_000)}d`;
  return new Date(iso).toLocaleDateString([], { month: 'short', day: 'numeric' });
}

function formatBytes(value) {
  const bytes = Number(value) || 0;
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function mediaKind(type) {
  if (typeof type !== 'string') return 'file';
  if (type.startsWith('image/')) return 'image';
  if (type.startsWith('video/')) return 'video';
  if (type.startsWith('audio/')) return 'audio';
  return 'file';
}

function attachmentLabel(attachment) {
  const icon = { image: '📷', video: '🎬', audio: '🎧', file: '📎' }[mediaKind(attachment.type)];
  return `${icon} ${attachment.name || 'Attachment'}`;
}

function setRelayState(connected) {
  state.connected = connected;
  dom.relayState.textContent = connected ? 'connected' : 'offline';
  dom.relayState.classList.toggle('on', connected);
}

function directThreadId(a, b) {
  return `thread_direct_${[a, b].sort().join('__')}`;
}

function activeThread() {
  return state.threads.find((thread) => thread.id === state.activeId) ?? null;
}

function isGroupThread(thread) {
  return thread?.type === 'group';
}

function threadTitle(thread) {
  if (!thread) return '';
  return isGroupThread(thread)
    ? (thread.group?.name ?? 'Group')
    : (thread.participant?.username ?? 'Unknown');
}

// ---------------------------------------------------------------------------
// Crypto helpers around the relay
// ---------------------------------------------------------------------------

function myKeyObject() {
  return {
    keyId: state.identity.keyId,
    publicKeyHex: state.identity.publicKeyHex,
  };
}

async function peerKey(userId, { refresh = false } = {}) {
  if (!refresh && state.keyCache.has(userId)) return state.keyCache.get(userId);

  const data = await api.publicKey(userId);
  const hex =
    typeof data.x25519_public === 'string' && /^[0-9a-f]{64}$/i.test(data.x25519_public)
      ? data.x25519_public
      : typeof data.publicKey === 'string' && /^[0-9a-f]{64}$/i.test(data.publicKey)
        ? data.publicKey
        : null;
  if (!hex) throw new Error('peer has no usable X25519 key');

  const signing =
    typeof data.signingPublicKey === 'string' && /^[0-9a-f]{64}$/i.test(data.signingPublicKey)
      ? data.signingPublicKey
      : typeof data.ed25519_public === 'string' && /^[0-9a-f]{64}$/i.test(data.ed25519_public)
        ? data.ed25519_public
        : null;

  const key = { keyId: String(data.keyId), publicKeyHex: hex, signingPublicKeyHex: signing };
  state.keyCache.set(userId, key);
  return key;
}

/**
 * A decrypted payload is either plain text (legacy messages) or a versioned
 * envelope carrying an attachment descriptor. Attachment keys only ever exist
 * inside the ciphertext, never in server-visible metadata.
 */
function parsePayload(plaintext) {
  const value = typeof plaintext === 'string' ? plaintext : String(plaintext ?? '');
  if (value.startsWith('{')) {
    try {
      const parsed = JSON.parse(value);
      const attachment = parsed?.attachment;
      if (
        parsed?.__aegis === 'media-v1' &&
        attachment &&
        typeof attachment.mediaId === 'string' &&
        typeof attachment.key === 'string' &&
        typeof attachment.iv === 'string'
      ) {
        return {
          text: typeof parsed.caption === 'string' ? parsed.caption : '',
          attachment: {
            mediaId: attachment.mediaId,
            key: attachment.key,
            iv: attachment.iv,
            name: typeof attachment.name === 'string' ? attachment.name : 'Attachment',
            type:
              typeof attachment.type === 'string' ? attachment.type : 'application/octet-stream',
            size: Number(attachment.size) || 0,
          },
        };
      }
    } catch {
      // A normal text message may legitimately start with `{`.
    }
  }
  return { text: value, attachment: null };
}

/**
 * Verify a stored message first, then decrypt it. History arrives without
 * signatures (pre-security implementation), so those are marked unsigned but
 * still displayed. Live network messages without a valid signature are never
 * decrypted or displayed as their sender's content.
 */
async function decodeMessage(message) {
  const verification = await verifyIncoming(message);
  if (verification.status === 'invalid') {
    return {
      text: 'Message signature verification failed',
      error: true,
      verification,
      attachment: null,
    };
  }

  const decoded = await decryptEntry(message);
  return { ...decoded, verification };
}
async function verifyIncoming(message) {
  if (!message?.signature) return { status: 'unsigned' };
  if (!message.senderId || !message.threadId)
    return { status: 'unverified', reason: 'missing identity' };

  let signingKey;
  if (message.senderId === state.me.id) {
    signingKey = state.identity.signingPublicKeyHex;
  } else {
    const peer = await peerKey(message.senderId).catch(() => null);
    signingKey = peer?.signingPublicKeyHex ?? null;
  }
  if (!signingKey) return { status: 'unverified', reason: 'no signing key' };

  const valid = ce.verifyMessageSignature(message, message.signature, signingKey);
  if (!valid) return { status: 'invalid' };

  const pin = state.verifiedKeys.get(message.senderId);
  if (pin?.signingPublicKeyHex && pin.signingPublicKeyHex !== signingKey) {
    return { status: 'changed', signingKey };
  }
  return { status: 'valid', signingKey };
}

async function decryptEntry(message) {
  try {
    const fromGroup = !String(message.threadId ?? '').startsWith('thread_direct_');
    if (fromGroup) {
      const bundle = message.cipherBundle ?? {};
      const version =
        Number(
          message.metadata?.gmkVersion ??
            bundle.gmkVersion ??
            String(bundle.gmkId ?? '').replace(/\D/g, ''),
        ) || undefined;
      const groupKey = loadGroupKey(message.threadId, version);
      if (!groupKey) {
        return {
          text: version ? `Waiting for group key v${version}…` : 'Waiting for the group key…',
          locked: true,
        };
      }
      const plaintext = await ce.decryptForGroup(
        { ...bundle, gmkVersion: version ?? groupKey.version },
        groupKey.gmk,
        { groupId: message.threadId },
      );
      return parsePayload(plaintext);
    }

    if (message.senderId === state.me.id) {
      const selfEnvelope = message.metadata?.selfEnvelope;
      if (!selfEnvelope) return { text: 'Sent from another device', locked: true };
      const plaintext = await ce.decryptForRecipient(selfEnvelope, state.identity.secretKeyHex);
      return parsePayload(plaintext);
    }

    if (!message.cipherBundle) return { text: 'No ciphertext in this message', error: true };
    const plaintext = await ce.decryptForRecipient(
      message.cipherBundle,
      state.identity.secretKeyHex,
    );
    return parsePayload(plaintext);
  } catch (error) {
    return { text: 'Unable to decrypt with this identity', error: true };
  }
}

// ---------------------------------------------------------------------------
// Socket relay
// ---------------------------------------------------------------------------

function connectSocket() {
  if (!state.session || typeof globalThis.io !== 'function') return;

  const options = {
    auth: (cb) => cb({ token: loadSession()?.token ?? '' }),
    transports: ['websocket', 'polling'],
    reconnectionDelayMax: 8000,
  };
  const endpointUrl = socketEndpoint();
  const socket = endpointUrl ? globalThis.io(endpointUrl, options) : globalThis.io(options);
  state.socket = socket;

  socket.on('connect', () => {
    state.socketRefreshTried = false;
    setRelayState(true);
    void publishIdentity();
    requestMissingGroupKeys();
    void loadThreads();
  });

  socket.on('disconnect', () => setRelayState(false));

  socket.on('connect_error', async (error) => {
    setRelayState(false);
    if (state.socketRefreshTried) {
      toast(error?.message ?? 'Connection failed', 'error');
      return;
    }
    state.socketRefreshTried = true;
    try {
      // Forces the API client to rotate the access token if it expired.
      await request('/api/v1/account/sessions');
      socket.connect();
    } catch {
      signOut('Your session expired; please sign in again.');
    }
  });

  socket.on('receive_message', (raw) => {
    void onRelayMessage(raw);
  });
  socket.on('message_sent', onMessageSent);
  socket.on('user_status', onUserStatus);
  socket.on('group_key_requested', () => toast('Group key requested.'));
}

async function publishIdentity() {
  if (state.identityPublishPromise) return state.identityPublishPromise;
  state.identityPublishPromise = (async () => {
    try {
      const existing = await api.selfKeys().catch(() => null);
      const published = Array.isArray(existing?.keys) ? existing.keys : [];
      const mine = published.find((key) => key.keyId === state.identity.keyId);
      if (mine && (mine.signingPublicKey || mine.ed25519_public)) return true;
      if (!state.socket?.connected) return false;
      return await new Promise((resolve) => {
        const timer = setTimeout(() => {
          state.socket?.off('public_key_published', onPublished);
          state.identityPublishPromise = null;
          resolve(false);
        }, 3000);
        const onPublished = (payload) => {
          if (payload?.keyId === state.identity.keyId) {
            clearTimeout(timer);
            state.socket?.off('public_key_published', onPublished);
            state.identityPublishPromise = null;
            resolve(true);
          }
        };
        state.socket?.on('public_key_published', onPublished);
        state.socket?.emit('publish_public_key', {
          keyId: state.identity.keyId,
          x25519: state.identity.publicKeyHex,
          ed25519: state.identity.signingPublicKeyHex,
        });
      });
    } catch {
      state.identityPublishPromise = null;
      return false;
    }
  })();
  return state.identityPublishPromise;
}

function joinRoom(thread) {
  if (!state.socket?.connected) return;
  if (isGroupThread(thread)) state.socket.emit('join_room', { groupId: thread.id });
  else state.socket.emit('join_room', { threadId: thread.id });
}

async function onRelayMessage(raw) {
  let payload;
  try {
    payload = typeof raw === 'string' ? JSON.parse(raw) : raw;
  } catch {
    return;
  }
  if (!payload || typeof payload !== 'object') return;

  if (payload.error) {
    toast(String(payload.error), 'error');
    // The relay rejects messages until an Ed25519 key is registered. Retrying
    // publication once makes the next send succeed without a reload.
    if (payload.code === 'signing_key_required') {
      state.identityPublishPromise = null;
      void publishIdentity();
    }
    return;
  }
  if (payload.event === 'group_key_distribution') {
    await handleGroupKeyDistribution(payload);
    return;
  }
  if (payload.event === 'group_key_request') {
    await handleGroupKeyRequest(payload);
    return;
  }
  if (payload.event === 'group_key_rotation_needed') {
    await handleGroupKeyRotationNeeded(payload);
    return;
  }

  await handleIncomingMessage(payload);
}

async function handleIncomingMessage(payload) {
  if (!payload.threadId || !payload.senderId) return;

  // A relay may echo our own message back (other devices, or an overlapping
  // send). If this device is still awaiting the ack, the optimistic bubble is
  // already on screen — adding the echo would duplicate it.
  if (
    payload.senderId === state.me.id &&
    (state.pendingSends.get(payload.threadId)?.length ?? 0) > 0
  ) {
    return;
  }

  const decoded = await decodeMessage(payload);
  const entry = {
    id: payload.messageId ?? `in-${Date.now()}`,
    threadId: payload.threadId,
    senderId: payload.senderId,
    text: decoded.text,
    attachment: decoded.attachment ?? null,
    createdAt: payload.createdAt ?? new Date().toISOString(),
    mine: payload.senderId === state.me.id,
    locked: Boolean(decoded.locked),
    error: Boolean(decoded.error),
    verification: decoded.verification,
    state: 'sent',
  };

  const thread = state.threads.find((item) => item.id === payload.threadId);
  if (thread) {
    thread.lastMessage = payload;
    thread.lastUpdatedAt = entry.createdAt;
    if (state.activeId === thread.id) {
      void api.markRead(thread.id);
    } else if (!entry.mine) {
      thread.unreadCount = Number(thread.unreadCount ?? 0) + 1;
    }
    renderThreads();
  } else {
    // A conversation opened by someone else: refresh the list to pick it up.
    await loadThreads();
  }

  if (state.activeId === entry.threadId && pushMessage(entry.threadId, entry)) {
    appendMessage(entry);
    scrollMessages();
  }
}

function onMessageSent(payload) {
  const queue = state.pendingSends.get(payload.threadId);
  const pending = queue?.shift();
  if (!pending) return;
  clearTimeout(pending.timer);
  pending.entry.id = payload.messageId;
  pending.entry.createdAt = payload.createdAt ?? pending.entry.createdAt;
  pending.entry.state = 'sent';
  if (state.activeId === pending.entry.threadId) renderMessages();
}

function onUserStatus({ userId, isOnline }) {
  if (typeof userId !== 'string') return;
  if (isOnline) state.online.add(userId);
  else state.online.delete(userId);

  for (const thread of state.threads) {
    if (thread.type === 'direct' && thread.participant?.id === userId) {
      thread.participant.isOnline = Boolean(isOnline);
    }
  }

  const thread = activeThread();
  if (thread?.type === 'direct' && thread.participant?.id === userId) {
    renderChatHeader(thread);
  }
  renderThreads();
}

// ---------------------------------------------------------------------------
// Thread list
// ---------------------------------------------------------------------------

function normalizeThread(thread) {
  if (thread.type === 'direct' && thread.participant) {
    thread.participant.isOnline = state.online.has(thread.participant.id)
      ? true
      : Boolean(thread.participant.isOnline);
  }
  return thread;
}

async function loadThreads() {
  const data = await api.threads();
  const incoming = Array.isArray(data.threads) ? data.threads : [];
  const known = new Map(state.threads.map((thread) => [thread.id, thread]));

  state.threads = incoming.map((thread) => {
    const normalized = normalizeThread(thread);
    const previous = known.get(thread.id);
    if (previous && previous.unreadCount === 0 && state.activeId === thread.id) {
      normalized.unreadCount = 0;
    }
    return normalized;
  });

  renderThreads();
  void requestMissingGroupKeys();
}

async function updateThreadPreview(thread, node) {
  if (!thread.lastMessage) {
    node.textContent = isGroupThread(thread) ? 'No messages yet' : 'Say hello 👋';
    return;
  }
  const decoded = await decodeMessage(thread.lastMessage);
  const prefix = thread.lastMessage.senderId === state.me.id ? 'You: ' : '';
  const preview = decoded.attachment ? attachmentLabel(decoded.attachment) : decoded.text;
  const text = preview.length > 64 ? `${preview.slice(0, 64)}…` : preview;
  if (node.isConnected) node.textContent = `${prefix}${text}`;
}

function renderThreads() {
  const list = dom.threadList;
  list.textContent = '';

  const filter = state.filter.trim().toLowerCase();
  const threads = [...state.threads]
    .filter((thread) => {
      if (!filter) return true;
      return threadTitle(thread).toLowerCase().includes(filter);
    })
    .sort((a, b) => String(b.lastUpdatedAt ?? '').localeCompare(String(a.lastUpdatedAt ?? '')));

  if (threads.length === 0) {
    const empty = document.createElement('p');
    empty.className = 'thread-preview';
    empty.style.padding = '10px';
    empty.textContent = filter
      ? 'No conversations match that search.'
      : 'No conversations yet — start one with “New chat”.';
    list.append(empty);
    return;
  }

  for (const thread of threads) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = `thread${thread.id === state.activeId ? ' active' : ''}`;
    button.dataset.threadId = thread.id;

    const avatar = document.createElement('span');
    avatar.className = 'avatar';
    setAvatar(avatar, threadTitle(thread), isGroupThread(thread));

    const main = document.createElement('div');
    main.className = 'thread-main';

    const nameRow = document.createElement('div');
    nameRow.className = 'thread-name';
    if (thread.type === 'direct' && thread.participant?.isOnline) {
      const dot = document.createElement('span');
      dot.className = 'dot online';
      nameRow.append(dot);
    }
    const name = document.createElement('span');
    name.textContent = threadTitle(thread);
    nameRow.append(name);

    const preview = document.createElement('div');
    preview.className = 'thread-preview';
    preview.textContent = 'Encrypted message';

    main.append(nameRow, preview);

    const side = document.createElement('div');
    side.className = 'thread-side';
    const time = document.createElement('span');
    time.className = 'thread-time';
    time.textContent = formatRelative(thread.lastUpdatedAt);
    side.append(time);
    if (Number(thread.unreadCount) > 0) {
      const badge = document.createElement('span');
      badge.className = 'badge';
      badge.textContent = String(thread.unreadCount);
      side.append(badge);
    }

    button.append(avatar, main, side);
    button.addEventListener('click', () => {
      void openThread(thread);
    });
    list.append(button);

    void updateThreadPreview(thread, preview);
  }
}

// ---------------------------------------------------------------------------
// Conversation view
// ---------------------------------------------------------------------------

function renderChatHeader(thread) {
  setAvatar(dom.chatAvatar, threadTitle(thread), isGroupThread(thread));
  dom.chatName.textContent = threadTitle(thread);
  dom.groupInfo.classList.toggle('hidden', !isGroupThread(thread));
  dom.verifyButton.classList.toggle(
    'hidden',
    Boolean(isGroupThread(thread)) || !thread.participant,
  );
  const changed = state.keyChanges.has(thread.participant?.id);
  dom.verifyButton.textContent = changed
    ? 'Verify new key'
    : state.verifiedKeys.has(String(thread.participant?.id))
      ? 'Verified'
      : 'Verify';
  dom.verifyButton.classList.toggle(
    'verify-verified',
    state.verifiedKeys.has(String(thread.participant?.id)) && !changed,
  );
  dom.verifyButton.classList.toggle(
    'verify-new',
    changed && !state.verifiedKeys.has(String(thread.participant?.id)),
  );
  dom.chatMeta.classList.toggle('changed', changed);
  const online = Boolean(thread.participant?.isOnline) || state.online.has(thread.participant?.id);
  dom.chatMeta.textContent = changed
    ? 'Security key changed — verify code'
    : online
      ? 'Online'
      : 'Offline';
  if (changed && !state.verifiedKeys.has(String(thread.participant?.id))) {
    showNotice(
      "This contact's security key changed. Verify the new code before trusting new messages.",
    );
  }
}

function showNotice(text, { request = false } = {}) {
  dom.chatNoticeText.textContent = text;
  dom.chatNotice.classList.remove('hidden');
  dom.requestKey.classList.toggle('hidden', !request);
}

function hideNotice() {
  dom.chatNotice.classList.add('hidden');
}

async function openThread(thread) {
  state.activeId = thread.id;
  dom.appView.classList.add('chat-open');
  dom.emptyState.classList.add('hidden');
  dom.chatView.classList.remove('hidden');
  hideNotice();

  thread.unreadCount = 0;
  renderThreads();
  renderChatHeader(thread);
  joinRoom(thread);

  if (isGroupThread(thread)) {
    await ensureGroupMembers(thread.id);
    renderChatHeader(thread);
    if (!groupKeyForThread(thread)) {
      showNotice('This group is encrypted with a shared key you do not have yet.', {
        request: true,
      });
      requestGroupKey(thread.id);
    }
  }

  // History is fetched after the group-key check so entries render as locked
  // placeholders when the key is still missing; the distribution handler
  // reloads them once the key arrives.
  await loadMessages(thread.id);
}

async function ensureGroupMembers(groupId) {
  if (state.groupMembers.has(groupId)) return state.groupMembers.get(groupId);
  try {
    const data = await api.group(groupId);
    const members = new Map();
    for (const member of data.members ?? []) {
      if (member.user) {
        members.set(member.user.id, member.user);
        if (member.user.is_online) state.online.add(member.user.id);
      }
    }
    state.groupMembers.set(groupId, members);
    return members;
  } catch {
    return new Map();
  }
}

async function loadMessages(threadId) {
  let entries = state.messages.get(threadId);
  if (!entries) {
    const data = await api.messages(threadId, { limit: 50 });
    const rows = Array.isArray(data.messages) ? [...data.messages].reverse() : [];
    entries = [];
    for (const row of rows) {
      const decoded = await decodeMessage(row);
      entries.push({
        id: row.id,
        threadId,
        senderId: row.senderId,
        text: decoded.text,
        attachment: decoded.attachment ?? null,
        createdAt: row.createdAt,
        mine: row.senderId === state.me.id,
        locked: Boolean(decoded.locked),
        error: Boolean(decoded.error),
        verification: decoded.verification,
        state: 'sent',
      });
    }
    state.messages.set(threadId, entries);
  }
  renderMessages();
  scrollMessages();
}

function pushMessage(threadId, entry) {
  const list = state.messages.get(threadId);
  if (!list) {
    state.messages.set(threadId, [entry]);
    return true;
  }
  if (entry.id && list.some((item) => item.id === entry.id)) return false;
  list.push(entry);
  return true;
}

function renderMessages() {
  dom.messages.textContent = '';
  const thread = activeThread();
  if (!thread) return;
  const entries = state.messages.get(thread.id) ?? [];

  if (entries.length === 0) {
    const empty = document.createElement('p');
    empty.className = 'plaintext';
    empty.textContent = isGroupThread(thread)
      ? 'No messages yet. Messages you send are encrypted with the group key.'
      : 'No messages yet. Messages are end-to-end encrypted.';
    dom.messages.append(empty);
    return;
  }

  for (const entry of entries) appendMessage(entry);
}

function appendMessage(entry) {
  const thread = activeThread();
  const isGroup = thread
    ? isGroupThread(thread)
    : !String(entry.threadId).startsWith('thread_direct_');

  const wrapper = document.createElement('div');
  wrapper.className = `message ${entry.mine ? 'mine' : 'theirs'}${
    entry.state === 'pending' ? ' pending' : entry.state === 'failed' ? ' failed' : ''
  }`;
  wrapper.dataset.messageId = entry.id;

  if (!entry.mine && isGroup) {
    const sender = document.createElement('span');
    sender.className = 'sender';
    const member = state.groupMembers.get(entry.threadId)?.get(entry.senderId);
    sender.textContent = member?.username ?? 'Member';
    wrapper.append(sender);
  }

  const bubble = document.createElement('div');
  bubble.className = `bubble${entry.error ? ' plaintext' : ''}${entry.attachment ? ' has-attachment' : ''}`;
  if (entry.attachment) {
    const attachmentNode = document.createElement('div');
    attachmentNode.className = 'attachment';
    attachmentNode.dataset.mediaId = entry.attachment.mediaId;
    bubble.append(attachmentNode);
    paintAttachment(attachmentNode, entry);
    if (entry.text) {
      const caption = document.createElement('p');
      caption.className = 'attachment-caption';
      caption.textContent = entry.text;
      bubble.append(caption);
    }
  } else {
    bubble.textContent = entry.text;
  }
  wrapper.append(bubble);

  const meta = document.createElement('div');
  meta.className = 'message-meta';
  const time = document.createElement('span');
  time.textContent = formatClock(entry.createdAt);
  meta.append(time);
  if (entry.state === 'pending') {
    const status = document.createElement('span');
    status.textContent = 'sending…';
    meta.append(status);
  }
  if (entry.state === 'failed') {
    const status = document.createElement('span');
    status.textContent = 'not delivered';
    meta.append(status);
  }

  // Signature state is shown per message: history written before signing was
  // enforced is marked unsigned, and anything unverifiable is flagged loudly.
  const verification = entry.verification;
  if (verification) {
    const badge = document.createElement('span');
    if (verification.status === 'valid') {
      badge.textContent = 'signed';
      badge.title = "Signature verified with the sender's published key";
    } else if (verification.status === 'unsigned') {
      badge.className = 'unsigned';
      badge.textContent = 'unsigned';
      badge.title = 'This message carries no signature';
    } else {
      badge.className = 'changed';
      badge.textContent = 'check key';
      badge.title =
        verification.status === 'changed'
          ? "The sender's key changed since you verified it"
          : 'This signature could not be verified';
    }
    meta.append(badge);
  }
  wrapper.append(meta);

  dom.messages.append(wrapper);
}

/**
 * Download, verify and decrypt one attachment. Records live in `mediaCache` so
 * re-rendering a conversation does not re-download the same encrypted bytes.
 */
function ensureMedia(entry) {
  const attachment = entry.attachment;
  if (!attachment) return Promise.reject(new Error('message has no attachment'));
  if (entry.localUrl) return Promise.resolve({ url: entry.localUrl, info: null, local: true });

  const existing = state.mediaCache.get(attachment.mediaId);
  if (existing?.url) return Promise.resolve(existing);
  if (existing?.promise) return existing.promise;

  const record = { status: 'loading', url: null, info: null };
  record.promise = (async () => {
    const info = await api.mediaInfo(attachment.mediaId);
    const response = await fetch(absoluteUrl(info.downloadUrl));
    if (!response.ok) throw new Error(`attachment download failed (${response.status})`);
    const ciphertext = new Uint8Array(await response.arrayBuffer());
    const bytes = await ce.decryptFileBytes(
      ciphertext,
      attachment.key,
      attachment.iv,
      attachment.mediaId,
    );
    const blob = new Blob([bytes], {
      type: attachment.type || info.contentType || 'application/octet-stream',
    });
    record.url = URL.createObjectURL(blob);
    record.info = info;
    record.status = 'ready';
    return record;
  })().catch((error) => {
    record.status = 'error';
    record.error = error;
    state.mediaCache.delete(attachment.mediaId);
    throw error;
  });

  state.mediaCache.set(attachment.mediaId, record);
  return record.promise;
}

function renderMedia(container, url, attachment) {
  container.textContent = '';
  const kind = mediaKind(attachment.type);
  const media = document.createElement('div');
  media.className = `attachment-media ${kind}`;

  if (kind === 'image') {
    const link = document.createElement('a');
    link.href = url;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    const image = document.createElement('img');
    image.src = url;
    image.alt = attachment.name || 'Encrypted image';
    image.loading = 'lazy';
    link.append(image);
    media.append(link);
  } else if (kind === 'video') {
    const video = document.createElement('video');
    video.src = url;
    video.controls = true;
    video.preload = 'metadata';
    media.append(video);
  } else if (kind === 'audio') {
    const audio = document.createElement('audio');
    audio.src = url;
    audio.controls = true;
    audio.preload = 'metadata';
    media.append(audio);
  }

  const download = document.createElement('a');
  download.className = 'attachment-download';
  download.href = url;
  download.download = attachment.name || 'attachment';
  download.textContent = `Download${attachment.size ? ` (${formatBytes(attachment.size)})` : ''}`;
  media.append(download);
  container.append(media);
}

function renderFileCard(container, entry) {
  const attachment = entry.attachment;
  container.textContent = '';
  const card = document.createElement('div');
  card.className = 'file-card';

  const icon = document.createElement('span');
  icon.className = 'file-icon';
  icon.textContent = '📎';

  const meta = document.createElement('div');
  meta.className = 'file-meta';
  const name = document.createElement('strong');
  name.textContent = attachment.name;
  const size = document.createElement('span');
  size.textContent = attachment.size ? formatBytes(attachment.size) : 'Encrypted file';
  meta.append(name, size);

  const action = document.createElement('button');
  action.type = 'button';
  action.className = 'ghost sm';
  action.textContent = 'Download';
  action.addEventListener('click', async () => {
    action.disabled = true;
    action.textContent = 'Decrypting…';
    try {
      const { url } = await ensureMedia(entry);
      const link = document.createElement('a');
      link.href = url;
      link.download = attachment.name || 'attachment';
      link.click();
      action.textContent = 'Download';
    } catch {
      action.textContent = 'Failed';
    } finally {
      action.disabled = false;
    }
  });

  card.append(icon, meta, action);
  container.append(card);
}

function paintAttachment(container, entry) {
  const attachment = entry.attachment;
  if (!attachment) return;
  if (mediaKind(attachment.type) === 'file') {
    renderFileCard(container, entry);
    return;
  }

  const loading = document.createElement('span');
  loading.className = 'attachment-loading';
  loading.textContent = 'Decrypting attachment…';
  container.append(loading);

  ensureMedia(entry)
    .then(({ url }) => {
      if (!container.isConnected) return;
      renderMedia(container, url, attachment);
    })
    .catch(() => {
      if (!container.isConnected) return;
      container.textContent = 'This attachment could not be decrypted.';
      container.classList.add('error');
    });
}

function scrollMessages() {
  dom.messages.scrollTop = dom.messages.scrollHeight;
}

// ---------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------

function composerHeight() {
  dom.input.style.height = 'auto';
  dom.input.style.height = `${Math.min(dom.input.scrollHeight, 160)}px`;
}

function renderAttachmentPreview() {
  const file = state.pendingAttachment;
  dom.attachmentPreview.textContent = '';
  if (!file) {
    dom.attachmentPreview.classList.add('hidden');
    return;
  }
  dom.attachmentPreview.classList.remove('hidden');

  const icon = document.createElement('span');
  icon.className = 'attachment-icon';
  icon.textContent = { image: '🖼️', video: '🎬', audio: '🎧', file: '📎' }[mediaKind(file.type)];

  const meta = document.createElement('div');
  meta.className = 'attachment-meta';
  const name = document.createElement('strong');
  name.textContent = file.name;
  const size = document.createElement('span');
  size.textContent = `${formatBytes(file.size)} · encrypted before upload`;
  meta.append(name, size);

  const remove = document.createElement('button');
  remove.type = 'button';
  remove.className = 'ghost sm';
  remove.textContent = 'Remove';
  remove.addEventListener('click', () => {
    state.pendingAttachment = null;
    dom.fileInput.value = '';
    renderAttachmentPreview();
  });

  dom.attachmentPreview.append(icon, meta, remove);
}

function selectAttachment(file) {
  if (!file) return;
  const type = file.type || 'application/octet-stream';
  if (!ATTACHMENT_TYPES.has(type)) {
    toast(
      'Unsupported file type. Choose an image, video, audio file, PDF, ZIP, JSON or text file.',
      'error',
    );
    dom.fileInput.value = '';
    return;
  }
  if (file.size > MAX_ATTACHMENT_BYTES) {
    toast(`Attachment is too large (max ${formatBytes(MAX_ATTACHMENT_BYTES)})`, 'error');
    dom.fileInput.value = '';
    return;
  }
  state.pendingAttachment = file;
  renderAttachmentPreview();
  dom.input.focus();
}

async function sendCurrentMessage() {
  const text = dom.input.value.trim();
  const file = state.pendingAttachment;
  const thread = activeThread();
  if ((!text && !file) || !thread) return;
  if (!state.socket?.connected) {
    toast('Not connected to the relay yet', 'error');
    return;
  }

  const groupKey = isGroupThread(thread) ? groupKeyForThread(thread) : null;
  if (isGroupThread(thread) && !groupKey) {
    toast('No group key yet — request it from an admin', 'error');
    return;
  }
  const peer = isGroupThread(thread) ? null : thread.participant;
  if (!isGroupThread(thread) && !peer?.id) {
    toast('This conversation has no recipient', 'error');
    return;
  }

  dom.send.disabled = true;
  try {
    // The relay only accepts signed envelopes, so this device's Ed25519 key has
    // to be registered before the first send after a reload.
    if (!(await publishIdentity())) {
      toast('Still registering your signing key — try sending again in a moment', 'error');
      return;
    }

    // Resolve the recipient key before uploading anything, so a missing key
    // does not leave an orphaned encrypted blob in storage.
    const peerCryptoKey = peer
      ? await peerKey(peer.id).catch(async () => peerKey(peer.id, { refresh: true }))
      : null;

    let envelope;
    let attachment = null;
    let localUrl = null;
    let contentType = 'text';
    const metadata = {};

    if (file) {
      contentType = mediaKind(file.type);
      const presigned = await api.presignMedia({
        fileType: file.type,
        fileName: file.name,
        sizeBytes: file.size,
      });
      const bytes = new Uint8Array(await file.arrayBuffer());
      const sealed = await ce.encryptFileBytes(bytes, presigned.mediaId);
      const upload = await fetch(absoluteUrl(presigned.uploadUrl), {
        method: 'PUT',
        body: sealed.ciphertext,
      });
      if (!upload.ok) {
        const body = await upload.json().catch(() => null);
        throw new Error(body?.error ?? `attachment upload failed (${upload.status})`);
      }
      attachment = {
        mediaId: presigned.mediaId,
        key: sealed.key,
        iv: sealed.iv,
        name: file.name,
        type: file.type,
        size: file.size,
      };
      // Only the opaque media id goes into server-visible metadata; the key
      // stays inside the encrypted message payload.
      metadata.mediaId = presigned.mediaId;
      localUrl = URL.createObjectURL(file);
    }

    const plaintext = attachment
      ? JSON.stringify({ __aegis: 'media-v1', caption: text, attachment })
      : text;

    if (isGroupThread(thread)) {
      envelope = await ce.encryptForGroup(plaintext, groupKey.gmk, {
        groupId: thread.id,
        version: groupKey.version,
      });
      metadata.gmkVersion = groupKey.version;
    } else {
      envelope = await ce.encryptForRecipient(plaintext, peerCryptoKey, {
        senderKeyId: state.identity.keyId,
      });
      const selfEnvelope = await ce.encryptForRecipient(plaintext, myKeyObject(), {
        senderKeyId: state.identity.keyId,
      });
      metadata.selfEnvelope = selfEnvelope;
    }

    // Every envelope is signed with the device's Ed25519 identity key. The
    // canonical payload must carry the same thread id the relay computes, so
    // direct chats use the sorted-id form and groups use the group id.
    const messageId = ce.newMessageKeyId();
    const createdAt = new Date().toISOString();
    const outgoing = {
      ...(isGroupThread(thread) ? { groupId: thread.id } : { recipientId: peer.id }),
      messageId,
      threadId: isGroupThread(thread) ? thread.id : directThreadId(state.me.id, peer.id),
      senderId: state.me.id,
      type: contentType,
      createdAt,
      cipherBundle: envelope,
      metadata,
    };
    outgoing.signature = ce.signMessage(outgoing, state.identity.signingSecretKeyHex);
    state.socket.emit('send_message', outgoing);

    const entry = {
      id: messageId,
      threadId: thread.id,
      senderId: state.me.id,
      text,
      attachment,
      localUrl,
      contentType,
      createdAt,
      mine: true,
      state: 'pending',
    };
    pushMessage(thread.id, entry);
    if (state.activeId === thread.id) {
      appendMessage(entry);
      scrollMessages();
    }

    thread.lastMessage = {
      messageId: entry.id,
      threadId: thread.id,
      senderId: state.me.id,
      cipherBundle: envelope,
      metadata,
      createdAt: entry.createdAt,
    };
    thread.lastUpdatedAt = entry.createdAt;
    renderThreads();

    const queue = state.pendingSends.get(thread.id) ?? [];
    queue.push({
      entry,
      timer: setTimeout(() => {
        if (entry.state === 'pending') {
          entry.state = 'failed';
          if (state.activeId === thread.id) renderMessages();
        }
      }, 10_000),
    });
    state.pendingSends.set(thread.id, queue);

    dom.input.value = '';
    state.pendingAttachment = null;
    dom.fileInput.value = '';
    renderAttachmentPreview();
    composerHeight();
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Message could not be sent';
    toast(
      /published a key|no usable X25519/i.test(message)
        ? 'This person has not opened Aegis yet, so they have no key to encrypt to.'
        : message,
      'error',
    );
  } finally {
    dom.send.disabled = false;
  }
}

// ---------------------------------------------------------------------------
// Group keys
// ---------------------------------------------------------------------------

async function requestGroupKey(groupId) {
  if (!state.socket?.connected || state.requestedKeys.has(groupId)) return;
  state.requestedKeys.add(groupId);
  state.socket.emit('request_group_key', { groupId });
  if (state.activeId === groupId) {
    showNotice('Waiting for the group key from an admin…', { request: true });
  }
}

function requestMissingGroupKeys() {
  for (const thread of state.threads) {
    if (thread.type !== 'group') continue;
    // The server's gmVersion is authoritative: an offline member may hold an
    // older key after an admin rotated it, and must ask for the new one.
    if (groupKeyForThread(thread)) continue;
    void requestGroupKey(thread.id);
  }
}

async function handleGroupKeyRequest(payload) {
  const groupId = payload.groupId;
  const requesterId = payload.requesterId;
  if (!groupId || !requesterId || requesterId === state.me.id) return;
  const groupKey = loadGroupKey(groupId, payload.gmkVersion) ?? loadGroupKey(groupId);
  if (!groupKey) return;

  try {
    const key = await peerKey(requesterId, { refresh: true });
    const wrapped = await ce.wrapGroupKey(groupKey.gmk, key, groupKey.version);
    // The admin signs its own distribution; the requester's request is not a
    // signature and must never be forwarded as if it authenticated the keys.
    const distribution = {
      groupId,
      gmkVersion: groupKey.version,
      groupMasterKeyId: groupKey.gmkId,
      encryptedGMKByMember: [wrapped],
      createdAt: new Date().toISOString(),
    };
    distribution.signature = ce.signGroupKeyDistribution(
      distribution,
      state.identity.signingSecretKeyHex,
    );
    state.socket?.emit('group_key_distribution', distribution);
  } catch {
    toast('A member requested the group key but has no published key yet', 'error');
  }
}

async function handleGroupKeyDistribution(payload) {
  const wrapped = Array.isArray(payload.encryptedGMKByMember) ? payload.encryptedGMKByMember : [];
  const mine = wrapped.find((entry) => entry.memberKeyId === state.identity.keyId);
  if (!mine) return;

  try {
    const signer =
      payload.distributedBy === state.me.id
        ? state.identity
        : await peerKey(payload.distributedBy).catch(() => null);
    if (
      !signer?.signingPublicKeyHex ||
      !ce.verifyGroupKeyDistribution(payload, payload.signature, signer.signingPublicKeyHex)
    ) {
      toast('Could not verify the group key distribution signature', 'error');
      return;
    }

    const version = Number(payload.gmkVersion) || 1;
    const gmk = await ce.unwrapGroupKey(mine, state.identity.secretKeyHex);
    saveGroupKey(payload.groupId, {
      version,
      gmk,
      gmkId: payload.groupMasterKeyId ?? `gmk_v${version}`,
    });
    state.requestedKeys.delete(payload.groupId);
    hideNotice();

    const thread = state.threads.find((item) => item.id === payload.groupId);
    if (thread) {
      thread.group.gmVersion = Math.max(Number(thread.group.gmVersion) || 0, version);
      if (
        state.activeId === payload.groupId &&
        (state.pendingSends.get(payload.groupId)?.length ?? 0) === 0
      ) {
        state.messages.delete(payload.groupId);
        await loadMessages(payload.groupId);
        hideNotice();
      }
      renderThreads();
    }
    toast(`Group key v${version} received`);
  } catch {
    toast('Could not unwrap the group key', 'error');
  }
}

async function handleGroupKeyRotationNeeded(payload) {
  if (state.rotatingGroups.has(payload.groupId)) return;
  state.rotatingGroups.add(payload.groupId);
  try {
    const data = await api.group(payload.groupId).catch(() => null);
    if (!data || !data.members) return;
    const meMember = (data.members ?? []).find((member) => String(member.user_id) === state.me.id);
    if (!meMember || !Number(meMember.is_admin)) return;
    const memberIds = (data.members ?? []).map((m) => String(m.user_id));
    await rotateGroupKey(payload.groupId, memberIds, data.group);
    toast('Rotated the group key');
    await loadThreads();
    const thread = state.threads.find((item) => item.id === payload.groupId);
    if (thread) {
      thread.group.gmVersion = Math.max(
        Number(thread.group.gmVersion) || 0,
        latestGroupKeyVersion(payload.groupId),
      );
      renderChatHeader(thread);
    }
  } catch {
    // An admin may have left before we rotated.
  } finally {
    state.rotatingGroups.delete(payload.groupId);
  }
}

async function distributeNewGroupKey(groupId, memberIds, { version = 1 } = {}) {
  const numericVersion = Number(version) || 1;
  const gmk = ce.generateGroupMasterKey();
  const gmkId = `gmk_${ce.toHex(ce.randomBytes(16))}`;
  const wrapped = [];

  for (const memberId of [...new Set([state.me.id, ...memberIds])]) {
    try {
      const key = memberId === state.me.id ? myKeyObject() : await peerKey(memberId);
      wrapped.push(await ce.wrapGroupKey(gmk, key, numericVersion));
    } catch {
      // The member has not opened the app yet; they will request the key later.
    }
  }

  saveGroupKey(groupId, { version: numericVersion, gmk, gmkId });

  const distribution = {
    groupId,
    gmkVersion: numericVersion,
    groupMasterKeyId: gmkId,
    encryptedGMKByMember: wrapped,
    createdAt: new Date().toISOString(),
  };
  distribution.signature = ce.signGroupKeyDistribution(
    distribution,
    state.identity.signingSecretKeyHex,
  );
  state.socket?.emit('group_key_distribution', distribution);
}

// ---------------------------------------------------------------------------
// Modals
// ---------------------------------------------------------------------------

function closeModal() {
  dom.modalHost.textContent = '';
}

function openModal(title, buildBody) {
  closeModal();
  const backdrop = document.createElement('div');
  backdrop.className = 'modal-backdrop';
  backdrop.addEventListener('click', (event) => {
    if (event.target === backdrop) closeModal();
  });

  const modal = document.createElement('div');
  modal.className = 'modal';
  modal.setAttribute('role', 'dialog');
  modal.setAttribute('aria-modal', 'true');

  const heading = document.createElement('h2');
  heading.textContent = title;

  const body = document.createElement('div');
  const built = buildBody(body) ?? null;

  const actions = document.createElement('div');
  actions.className = 'modal-actions';
  const cancel = document.createElement('button');
  cancel.type = 'button';
  cancel.className = 'ghost';
  cancel.textContent = 'Cancel';
  cancel.addEventListener('click', closeModal);
  actions.append(cancel);

  modal.append(heading, body, actions);
  backdrop.append(modal);
  dom.modalHost.append(backdrop);

  return { modal, body, actions, built };
}

function renderSearchResults(container, users, onPick) {
  container.textContent = '';
  if (users.length === 0) {
    const empty = document.createElement('p');
    empty.className = 'thread-preview';
    empty.textContent = 'No users found.';
    container.append(empty);
    return;
  }
  for (const user of users) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'result';
    const avatar = document.createElement('span');
    avatar.className = 'avatar';
    setAvatar(avatar, user.username);
    const label = document.createElement('span');
    label.textContent = user.username;
    button.append(avatar, label);
    button.addEventListener('click', () => onPick(user, button));
    container.append(button);
  }
}

function openNewChatModal() {
  openModal('Start a conversation', (container) => {
    const input = document.createElement('input');
    input.className = 'filter';
    input.placeholder = 'Search by username';
    input.setAttribute('aria-label', 'Search users');
    const results = document.createElement('div');
    results.className = 'search-results';
    container.append(input, results);

    let timer = null;
    input.addEventListener('input', () => {
      clearTimeout(timer);
      const query = input.value.trim();
      if (query.length < 2) {
        results.textContent = '';
        return;
      }
      timer = setTimeout(async () => {
        try {
          const data = await api.searchUsers(query);
          renderSearchResults(results, data.users ?? [], (user) => {
            closeModal();
            openDirectThread(user);
          });
        } catch (error) {
          toast(error.message, 'error');
        }
      }, 220);
    });
    input.focus();
  });
}

function openNewGroupModal() {
  const selected = new Map();
  const { actions, built } = openModal('Create a group', (container) => {
    const name = document.createElement('input');
    name.className = 'filter';
    name.placeholder = 'Group name';
    name.setAttribute('aria-label', 'Group name');
    name.maxLength = 128;

    const search = document.createElement('input');
    search.className = 'filter';
    search.placeholder = 'Add members by username';
    search.setAttribute('aria-label', 'Search members');

    const chips = document.createElement('div');
    chips.className = 'chips';

    const results = document.createElement('div');
    results.className = 'search-results';

    container.append(name, search, chips, results);

    let timer = null;
    search.addEventListener('input', () => {
      clearTimeout(timer);
      const query = search.value.trim();
      if (query.length < 2) {
        results.textContent = '';
        return;
      }
      timer = setTimeout(async () => {
        try {
          const data = await api.searchUsers(query);
          const users = (data.users ?? []).filter((user) => user.id !== state.me.id);
          renderSearchResults(results, users, (user) => {
            if (selected.has(user.id)) {
              selected.delete(user.id);
            } else {
              selected.set(user.id, user);
            }
            renderChips();
          });
        } catch (error) {
          toast(error.message, 'error');
        }
      }, 220);
    });

    function renderChips() {
      chips.textContent = '';
      for (const user of selected.values()) {
        const chip = document.createElement('span');
        chip.className = 'chip';
        const label = document.createElement('span');
        label.textContent = user.username;
        const remove = document.createElement('button');
        remove.type = 'button';
        remove.textContent = '×';
        remove.setAttribute('aria-label', `Remove ${user.username}`);
        remove.addEventListener('click', () => {
          selected.delete(user.id);
          renderChips();
        });
        chip.append(label, remove);
        chips.append(chip);
      }
    }

    return { getGroupName: () => name.value.trim() };
  });

  const create = document.createElement('button');
  create.type = 'button';
  create.className = 'primary';
  create.textContent = 'Create group';
  create.addEventListener('click', async () => {
    const groupName = built.getGroupName();
    if (!groupName) {
      toast('Give the group a name', 'error');
      return;
    }
    create.disabled = true;
    try {
      const created = await api.createGroup({
        groupName,
        memberIds: [...selected.keys()],
      });
      await distributeNewGroupKey(created.id, [...selected.keys()]);
      closeModal();
      await loadThreads();
      const thread = state.threads.find((item) => item.id === created.id);
      if (thread) await openThread(thread);
    } catch (error) {
      toast(error.message, 'error');
    } finally {
      create.disabled = false;
    }
  });
  actions.append(create);
}

/**
 * Remove a member and immediately re-key the group for everyone who remains, so
 * the removed member cannot read anything sent afterwards.
 */
async function removeMemberAndRotate(thread, member, button) {
  const username = member.user?.username ?? 'this member';
  if (!window.confirm(`Remove ${username} from the group? This starts a new key rotation.`)) return;
  button.disabled = true;
  try {
    const result = await api.removeGroupMember(thread.id, member.user_id);
    if (!result?.ok) throw new Error(result?.error ?? 'Could not remove member');
    const refreshed = await api.group(thread.id);
    const remaining = (refreshed.members ?? [])
      .map((row) => String(row.user_id))
      .filter((id) => id !== String(member.user_id));
    const nextVersion =
      Math.max(Number(refreshed.group?.gm_version) || 0, latestGroupKeyVersion(thread.id)) + 1;
    await distributeNewGroupKey(thread.id, remaining, { version: nextVersion });
    thread.group = { ...(thread.group ?? {}), ...(refreshed.group ?? {}), gmVersion: nextVersion };
    state.groupMembers.delete(thread.id);
    closeModal();
    await loadThreads();
    const current = state.threads.find((item) => item.id === thread.id);
    if (current) {
      current.group.gmVersion = nextVersion;
      renderChatHeader(current);
      if (state.activeId === thread.id) renderMessages();
    }
    toast(`Removed ${username} and rotated the group key`);
  } catch (error) {
    toast(error.message ?? 'Could not remove member', 'error');
  } finally {
    button.disabled = false;
  }
}

async function openGroupInfo(thread) {
  let data;
  try {
    data = await api.group(thread.id);
  } catch (error) {
    toast(error.message ?? 'Could not load group members', 'error');
    return;
  }

  const members = new Map();
  for (const member of data.members ?? []) {
    if (member.user) members.set(member.user.id, member.user);
  }
  state.groupMembers.set(thread.id, members);
  if (data.group) thread.group = { ...(thread.group ?? {}), ...data.group };
  renderChatHeader(thread);

  const meMember = (data.members ?? []).find((member) => String(member.user_id) === state.me.id);
  const isAdmin = Boolean(Number(meMember?.is_admin));
  const existing = new Set((data.members ?? []).map((member) => String(member.user_id)));
  const selected = new Map();

  const { actions, built } = openModal(
    `Group · ${data.group?.name ?? threadTitle(thread)}`,
    (container) => {
      const list = document.createElement('div');
      list.className = 'member-list';
      for (const member of data.members ?? []) {
        const row = document.createElement('div');
        row.className = 'member-row';

        const avatar = document.createElement('span');
        avatar.className = 'avatar';
        const username = member.user?.username ?? 'Member';
        setAvatar(avatar, username);

        const name = document.createElement('span');
        name.className = 'member-name';
        name.textContent = String(member.user_id) === state.me.id ? `${username} (you)` : username;

        row.append(avatar, name);
        if (Number(member.is_admin)) {
          const badge = document.createElement('span');
          badge.className = 'member-badge';
          badge.textContent = 'Admin';
          row.append(badge);
        }

        const isSelf = String(member.user_id) === state.me.id;
        if (member.user && !isSelf) {
          const verify = document.createElement('button');
          verify.type = 'button';
          verify.className = 'ghost sm';
          verify.textContent = 'Verify';
          verify.addEventListener('click', () => openVerifyModal(member.user.id, username));
          row.append(verify);

          if (isAdmin) {
            const remove = document.createElement('button');
            remove.type = 'button';
            remove.className = 'ghost sm';
            remove.textContent = 'Remove';
            remove.addEventListener('click', () => removeMemberAndRotate(thread, member, remove));
            row.append(remove);
          }
        }
        list.append(row);
      }
      container.append(list);

      if (!isAdmin) {
        const note = document.createElement('p');
        note.className = 'thread-preview';
        note.textContent = 'Only group admins can add members.';
        container.append(note);
        return { getSelected: () => [] };
      }

      const heading = document.createElement('h3');
      heading.textContent = 'Members';
      const search = document.createElement('input');
      search.className = 'filter';
      search.placeholder = 'Search by username';
      search.setAttribute('aria-label', 'Search users');
      const chips = document.createElement('div');
      chips.className = 'chips';
      const results = document.createElement('div');
      results.className = 'search-results';
      container.append(heading, search, chips, results);

      const renderChips = () => {
        chips.textContent = '';
        for (const user of selected.values()) {
          const chip = document.createElement('span');
          chip.className = 'chip';
          const label = document.createElement('span');
          label.textContent = user.username;
          const remove = document.createElement('button');
          remove.type = 'button';
          remove.textContent = '×';
          remove.setAttribute('aria-label', `Remove ${user.username}`);
          remove.addEventListener('click', () => {
            selected.delete(user.id);
            renderChips();
          });
          chip.append(label, remove);
          chips.append(chip);
        }
      };

      let timer = null;
      search.addEventListener('input', () => {
        clearTimeout(timer);
        const query = search.value.trim();
        if (query.length < 2) {
          results.textContent = '';
          return;
        }
        timer = setTimeout(async () => {
          try {
            const found = await api.searchUsers(query);
            const users = (found.users ?? []).filter(
              (user) => !existing.has(user.id) && user.id !== state.me.id,
            );
            renderSearchResults(results, users, (user, button) => {
              if (selected.has(user.id)) selected.delete(user.id);
              else selected.set(user.id, user);
              button.classList.toggle('selected', selected.has(user.id));
              renderChips();
            });
          } catch (error) {
            toast(error.message, 'error');
          }
        }, 220);
      });

      return { getSelected: () => [...selected.keys()] };
    },
  );

  // The action row is shown to every member: admins get key rotation and member
  // management, everyone can verify keys and leave the group.
  actions.append(buildGroupActions(thread, data, isAdmin, state));
}

async function openDirectThread(user) {
  const id = directThreadId(state.me.id, user.id);
  let thread = state.threads.find((item) => item.id === id);
  if (!thread) {
    thread = {
      id,
      type: 'direct',
      participant: {
        id: user.id,
        username: user.username,
        avatarUrl: user.avatar_url ?? null,
        isOnline: state.online.has(user.id) || Boolean(user.is_online),
      },
      lastMessage: null,
      unreadCount: 0,
      lastUpdatedAt: null,
    };
    state.threads.push(thread);
    renderThreads();
  }
  await openThread(thread);
}

// ---------------------------------------------------------------------------
// Session lifecycle
// ---------------------------------------------------------------------------

function buildGroupActions(thread, data, isAdmin, state) {
  const actions = document.createElement('div');
  actions.className = 'modal-actions';

  const meMember = (data.members ?? []).find((member) => String(member.user_id) === state.me.id);
  const isCurrentAdmin = Boolean(meMember?.is_admin);
  const allMemberIds = (data.members ?? []).map((member) => String(member.user_id));

  if (isCurrentAdmin) {
    const rotate = document.createElement('button');
    rotate.type = 'button';
    rotate.className = 'primary';
    rotate.textContent = 'Rotate group key';
    rotate.addEventListener('click', async () => {
      rotate.disabled = true;
      rotate.textContent = 'Rotating…';
      try {
        await rotateGroupKey(thread.id, allMemberIds, data.group);
        toast('Group key rotated');
        closeModal();
        await loadThreads();
        const current = state.threads.find((item) => item.id === thread.id);
        if (current) {
          current.group.gmVersion = Math.max(
            Number(current.group.gmVersion) || 0,
            latestGroupKeyVersion(thread.id),
          );
          renderChatHeader(current);
          if (state.activeId === thread.id) {
            renderMessages();
          }
        }
      } catch (error) {
        toast(error.message ?? 'Could not rotate group key', 'error');
      } finally {
        rotate.disabled = false;
        rotate.textContent = 'Rotate group key';
      }
    });
    actions.append(rotate);
  }

  const leave = document.createElement('button');
  leave.type = 'button';
  leave.className = 'ghost';
  leave.textContent = 'Leave group';
  leave.addEventListener('click', async () => {
    if (!window.confirm(`Leave ${thread.group?.name ?? 'this group'}?`)) return;
    leave.disabled = true;
    try {
      await api.leaveGroup(thread.id);
      // Remaining admins must re-key the group without this member, so ask the
      // relay to hand a rotation request to one of them.
      state.socket?.emit('group_key_rotation_needed', { groupId: thread.id });
      state.threads = state.threads.filter((item) => item.id !== thread.id);
      state.messages.delete(thread.id);
      state.groupMembers.delete(thread.id);
      state.activeId = null;
      closeModal();
      renderThreads();
      dom.chatView.classList.add('hidden');
      dom.emptyState.classList.remove('hidden');
      toast('You left the group');
      await loadThreads();
    } catch (error) {
      toast(error.message ?? 'Could not leave the group', 'error');
    } finally {
      leave.disabled = false;
    }
  });
  actions.append(leave);
  return actions;
}

function openVerifyModal(userId, username) {
  let badge = null;

  const { modal, body, actions } = openModal(`Verify ${username}`, (container) => {
    const note = document.createElement('p');
    note.className = 'verify-note';
    note.textContent =
      'Compare this code with the contact over a channel you already trust. If it matches, mark the key as verified.';
    container.append(note);

    badge = document.createElement('div');
    badge.className = 'verify-badge';
    const loading = document.createElement('span');
    loading.className = 'hint';
    loading.textContent = 'Loading…';
    badge.append(loading);
    container.append(badge);

    return null;
  });

  const mark = document.createElement('button');
  mark.type = 'button';
  mark.className = 'primary';
  mark.textContent = 'Mark as verified';
  mark.disabled = true;

  const close = document.createElement('button');
  close.type = 'button';
  close.className = 'ghost';
  close.textContent = 'Close';
  close.addEventListener('click', closeModal);

  actions.append(mark, close);

  let pending = null;

  void (async () => {
    try {
      const peer = await peerKey(userId, { refresh: true });
      if (!peer.signingPublicKeyHex) {
        badge.textContent = 'This contact has not published a signing key yet.';
        return;
      }

      const number = await ce.safetyNumber(state.identity, {
        keyId: peer.keyId,
        publicKeyHex: peer.publicKeyHex,
        signingPublicKeyHex: peer.signingPublicKeyHex,
      });

      badge.textContent = '';
      const code = document.createElement('span');
      code.className = 'fingerprint';
      code.textContent = number;
      badge.append(code);

      const current = state.verifiedKeys.get(String(userId));
      if (current?.signingPublicKeyHex === peer.signingPublicKeyHex) {
        const ok = document.createElement('p');
        ok.className = 'hint';
        ok.textContent = 'Already verified for this key.';
        badge.append(ok);
      }

      pending = { signingPublicKeyHex: peer.signingPublicKeyHex, safetyNumber: number };
      mark.disabled = false;
    } catch (error) {
      badge.textContent = error.message ?? 'Could not load this contact’s key';
    }
  })();

  mark.addEventListener('click', () => {
    if (!pending) return;
    state.verifiedKeys.set(String(userId), {
      signingPublicKeyHex: pending.signingPublicKeyHex,
      safetyNumber: pending.safetyNumber,
      verifiedAt: new Date().toISOString(),
    });
    persistVerifiedKeys();
    state.keyChanges.delete(String(userId));
    closeModal();
    const thread = activeThread();
    if (thread) {
      renderChatHeader(thread);
      renderMessages();
    }
    toast(`${username} verified`);
  });

  return { modal, body, actions };
}

/**
 * Bundled shells (desktop, mobile) ship the client without a server, so the
 * first launch asks for one instead of failing every request with a 404.
 */
function showServerSetup(message = '') {
  dom.serverView.classList.remove('hidden');
  dom.authView.classList.add('hidden');
  dom.appView.classList.add('hidden');
  dom.serverError.textContent = message;
  dom.serverForm.querySelector('input[name="server"]')?.focus();
}

function showAuth(message = '') {
  state.me = null;
  state.identity = null;
  state.socket?.disconnect();
  state.socket = null;
  state.threads = [];
  state.messages.clear();
  state.pendingSends.clear();
  state.activeId = null;
  state.keyCache.clear();
  state.groupMembers.clear();
  state.requestedKeys.clear();
  state.pendingAttachment = null;
  for (const record of state.mediaCache.values()) {
    if (record.url) URL.revokeObjectURL(record.url);
  }
  state.mediaCache.clear();
  dom.fileInput.value = '';
  renderAttachmentPreview();

  dom.threadList.textContent = '';
  dom.appView.classList.add('hidden');
  dom.authView.classList.remove('hidden');
  dom.loginError.textContent = message;
  dom.signupError.textContent = '';
  setRelayState(false);
}

function signOut(message = '') {
  const session = loadSession();
  if (session?.refreshToken) void api.logout(session.refreshToken);
  clearSession();
  showAuth(message);
}

async function startSession(session) {
  state.session = session;
  state.me = session.user;
  state.identity = ensureIdentity(session.user.id);
  state.verifiedKeys = loadVerifiedKeys();

  dom.authView.classList.add('hidden');
  dom.appView.classList.remove('hidden');
  dom.meName.textContent = session.user.username;
  setAvatar(dom.meAvatar, session.user.username);
  dom.emptyState.classList.remove('hidden');
  dom.chatView.classList.add('hidden');
  dom.appView.classList.remove('chat-open');

  connectSocket();

  try {
    await loadThreads();
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      signOut('Your session expired; please sign in again.');
      return;
    }
    toast(error.message ?? 'Could not load conversations', 'error');
  }
}

async function handleAuthSuccess(data) {
  if (!data?.token || !data?.user) throw new Error('unexpected response from the server');
  saveSession({ token: data.token, refreshToken: data.refreshToken, user: data.user });
  await startSession(loadSession());
}

function setAuthMode(mode) {
  for (const tab of document.querySelectorAll('.tab')) {
    const active = tab.dataset.mode === mode;
    tab.classList.toggle('active', active);
    tab.setAttribute('aria-selected', String(active));
  }
  dom.loginForm.classList.toggle('hidden', mode !== 'login');
  dom.signupForm.classList.toggle('hidden', mode !== 'signup');
  dom.loginError.textContent = '';
  dom.signupError.textContent = '';
}

// ---------------------------------------------------------------------------
// Rotation

async function rotateGroupKey(groupId, memberIds, group) {
  const data = await api.group(groupId);
  const remaining = (data.members ?? [])
    .filter((m) => String(m.user_id) !== state.me.id)
    .map((m) => String(m.user_id));
  const nextVersion =
    Math.max(Number(data.group?.gm_version) || 0, latestGroupKeyVersion(groupId)) + 1;
  await distributeNewGroupKey(groupId, remaining, { version: nextVersion });
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

for (const tab of document.querySelectorAll('.tab')) {
  tab.addEventListener('click', () => setAuthMode(tab.dataset.mode));
}

dom.serverForm.addEventListener('submit', (event) => {
  event.preventDefault();
  dom.serverError.textContent = '';
  const value = String(new FormData(dom.serverForm).get('server') ?? '');
  if (!saveServer(value)) {
    dom.serverError.textContent = 'Enter a full address, for example https://chat.example.com';
    return;
  }
  location.reload();
});

dom.loginForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  dom.loginError.textContent = '';
  const form = new FormData(dom.loginForm);
  const email = String(form.get('email') ?? '').trim();
  const password = String(form.get('password') ?? '');
  const totpCode = String(form.get('totpCode') ?? '').trim();

  const submit = dom.loginForm.querySelector('button[type="submit"]');
  submit.disabled = true;
  try {
    const data = await api.login({
      email,
      password,
      ...(totpCode ? { totpCode } : {}),
    });
    await handleAuthSuccess(data);
  } catch (error) {
    if (error instanceof ApiError && error.code === 'totp_required') {
      dom.totpRow.classList.remove('hidden');
      dom.loginForm.querySelector('input[name="totpCode"]')?.focus();
      dom.loginError.textContent = 'Enter your two-factor code to continue.';
    } else {
      dom.loginError.textContent = error.message ?? 'Sign in failed';
    }
  } finally {
    submit.disabled = false;
  }
});

dom.signupForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  dom.signupError.textContent = '';
  const form = new FormData(dom.signupForm);
  const username = String(form.get('username') ?? '').trim();
  const email = String(form.get('email') ?? '').trim();
  const password = String(form.get('password') ?? '');

  const submit = dom.signupForm.querySelector('button[type="submit"]');
  submit.disabled = true;
  try {
    const data = await api.signup({ username, email, password });
    await handleAuthSuccess(data);
  } catch (error) {
    dom.signupError.textContent = error.message ?? 'Could not create the account';
  } finally {
    submit.disabled = false;
  }
});

dom.logout.addEventListener('click', () => signOut());
dom.newChat.addEventListener('click', openNewChatModal);
dom.newGroup.addEventListener('click', openNewGroupModal);

dom.filter.addEventListener('input', () => {
  state.filter = dom.filter.value;
  renderThreads();
});

dom.groupInfo.addEventListener('click', () => {
  const thread = activeThread();
  if (thread) void openGroupInfo(thread);
});

dom.verifyButton.addEventListener('click', () => {
  const thread = activeThread();
  if (!thread || !thread.participant || isGroupThread(thread)) return;
  openVerifyModal(thread.participant.id, thread.participant.username);
});

dom.back.addEventListener('click', () => {
  dom.appView.classList.remove('chat-open');
  state.activeId = null;
  dom.chatView.classList.add('hidden');
  dom.emptyState.classList.remove('hidden');
  renderThreads();
});

dom.requestKey.addEventListener('click', () => {
  const thread = activeThread();
  if (!thread) return;
  state.requestedKeys.delete(thread.id);
  void requestGroupKey(thread.id);
});

dom.composer.addEventListener('submit', (event) => {
  event.preventDefault();
  void sendCurrentMessage();
});

dom.attach.addEventListener('click', () => dom.fileInput.click());
dom.fileInput.addEventListener('change', () => selectAttachment(dom.fileInput.files?.[0]));

dom.input.addEventListener('keydown', (event) => {
  if (event.key === 'Enter' && !event.shiftKey) {
    event.preventDefault();
    void sendCurrentMessage();
  }
});

dom.input.addEventListener('input', composerHeight);

document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') closeModal();
});

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

if (needsServerSetup()) {
  showServerSetup();
} else {
  const existing = loadSession();
  if (existing?.user && existing?.token) {
    void startSession(existing);
  } else {
    showAuth();
  }
}
