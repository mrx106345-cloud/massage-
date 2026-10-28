import { randomUUID, createHash, createHmac, timingSafeEqual } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Request, Response } from 'express';
import { deleteRows, insertRow, selectAll, selectOne, updateRows } from '../db/index.js';
import { cfg } from '../config/index.js';

// Content-type guard for rich media.
const ALLOWED_MEDIA = [
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
];

const LOCAL_MEDIA_ROOT = path.resolve(process.cwd(), 'data', 'media');

/** Ceiling for the credential-free local upload endpoint (encrypted bytes). */
const MAX_LOCAL_UPLOAD_BYTES = 25 * 1024 * 1024;

type LocalUrlKind = 'upload' | 'download';

export interface MediaPresignRequest extends Request {
  userId?: string;
}
export interface MediaPresignResponse {
  uploadUrl: string;
  downloadUrl: string;
  mediaId: string;
  expiresAt: string;
}

export interface MediaReadResponse {
  id: string;
  ownerId: string;
  originalName: string;
  contentType: string;
  sizeBytes: number;
  storageKey: string;
  uploadUrl: string;
  downloadUrl: string;
  uploadStatus: string;
  uploadError: string | null;
  mediaType: string;
  durationSeconds: number | null;
  width: number | null;
  height: number | null;
  thumbUrl: string | null;
  createdAt: string;
}

/**
 * Media pipeline (RFC Phase 4):
 *
 *   User selects a file  ->  Client encrypts it locally (AES-256-GCM)  ->
 *   App asks backend for a TEMP signed upload URL  ->
 *   Client uploads the ENCRYPTED bytes to cloud storage directly (S3) or local endpoint ->
 *   Client sends { mediaId, uploadUrl, downloadUrl, keys, metadata } over WS
 */
export async function presignMediaUpload(req: MediaPresignRequest, res: Response) {
  const { fileType, fileName, sizeBytes } = req.body ?? {};

  if (!fileType || !ALLOWED_MEDIA.includes(fileType)) {
    return res
      .status(400)
      .json({ error: 'unsupported file type; allowed: ' + ALLOWED_MEDIA.join(', ') });
  }
  if (typeof fileName !== 'string' || fileName.length > 255) {
    return res.status(400).json({ error: 'fileName must be a string <= 255 chars' });
  }
  const opts =
    typeof sizeBytes === 'number' && Number.isFinite(sizeBytes) && sizeBytes >= 0 ? sizeBytes : 0;

  const userId = (req as MediaPresignRequest).userId;
  if (!userId) return res.status(401).json({ error: 'missing authenticated user' });

  const mediaId = randomUUID();
  const now = () => new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');

  const storageKey = `media/${userId}/${mediaId}/${createHash('sha256')
    .update(mediaId + now())
    .digest('hex')}.bin`;

  // Short-lived pre-signed URL (15 min default, RFC 001 guardrail).
  const expiresIn = cfg.S3_OBJECT_URL_EXPIRES_IN;
  const expiresAt = new Date(Date.now() + expiresIn * 1000).toISOString();

  const uploadUrl = buildUploadUrl(storageKey, expiresIn);
  const downloadUrl = buildDownloadUrl(storageKey, expiresIn);

  await insertRow('media_file', {
    id: mediaId,
    message_id: null,
    owner_id: userId,
    original_name: fileName,
    content_type: fileType,
    size_bytes: opts,
    storage_key: storageKey,
    upload_url: uploadUrl,
    download_url: downloadUrl,
    upload_status: 'pending',
    upload_error: null,
    media_type: classifyMediaType(fileType),
    duration_seconds: null,
    width: null,
    height: null,
    thumb_url: null,
    created_at: now(),
    updated_at: now(),
  });

  res.json({
    uploadUrl,
    downloadUrl,
    mediaId,
    expiresAt,
  });
}

export async function getMedia(req: MediaPresignRequest, res: Response) {
  const { mediaId } = req.params as { mediaId: string };
  const userId = (req as MediaPresignRequest).userId;
  if (!userId) return res.status(401).json({ error: 'missing authenticated user' });

  const row = await selectOne('media_file', { id: mediaId });
  if (!row) return res.status(404).json({ error: 'media not found' });

  const isOwner = String(row.owner_id) === userId;
  if (!isOwner) {
    // Check if the user is a participant or group member for any message attached to this media
    let hasAccess = false;
    const messages = await selectAll(
      'message',
      { metadata: { _like: `%"mediaId":"${mediaId}"%` } },
      10,
    );
    for (const msg of messages) {
      const threadId = String(msg.thread_id);
      if (threadId.startsWith('thread_direct_')) {
        const parts = threadId.replace('thread_direct_', '').split('__');
        if (parts.includes(userId)) {
          hasAccess = true;
          break;
        }
      } else {
        const member = await selectOne('group_member', {
          group_id: threadId,
          user_id: userId,
          status: 'active',
        });
        if (member) {
          hasAccess = true;
          break;
        }
      }
    }

    if (!hasAccess) {
      return res.status(403).json({ error: 'not your media' });
    }
  }

  // URLs are minted on read: the ones issued at presign time have usually
  // expired by the time a recipient opens the conversation.
  const storageKey = String(row.storage_key);
  const expiresIn = cfg.S3_OBJECT_URL_EXPIRES_IN;

  res.json({
    id: row.id,
    ownerId: row.owner_id,
    originalName: row.original_name,
    contentType: row.content_type,
    sizeBytes: row.size_bytes,
    storageKey,
    uploadUrl: row.upload_status === 'completed' ? null : buildUploadUrl(storageKey, expiresIn),
    downloadUrl: buildDownloadUrl(storageKey, expiresIn),
    uploadStatus: row.upload_status,
    uploadError: row.upload_error,
    mediaType: row.media_type,
    durationSeconds: row.duration_seconds,
    width: row.width,
    height: row.height,
    thumbUrl: row.thumb_url,
    createdAt: row.created_at,
  });
}

// ---------------------------------------------------------------------------
// Deletion
// ---------------------------------------------------------------------------
//
// Media rows are not enough: the encrypted object itself must go away too.
// Local files are removed directly; S3-compatible buckets get a short-lived
// signed DELETE. Both paths are best-effort so one missing object cannot block
// account or group deletion.

function parseMediaId(metadata: unknown): string | null {
  if (typeof metadata !== 'string' || metadata.length === 0) return null;
  try {
    const parsed = JSON.parse(metadata) as Record<string, unknown>;
    return typeof parsed.mediaId === 'string' && parsed.mediaId.length > 0 ? parsed.mediaId : null;
  } catch {
    return null;
  }
}

async function deleteStoredObject(row: Record<string, unknown>): Promise<void> {
  const storageKey = typeof row.storage_key === 'string' ? row.storage_key : '';
  if (!storageKey) return;

  const localPath = resolveStoragePath(storageKey);
  if (localPath) {
    await fs.promises.rm(localPath, { force: true }).catch(() => undefined);
  }

  const endpoint = process.env.S3_ENDPOINT?.trim();
  const accessKey = process.env.S3_ACCESS_KEY_ID?.trim();
  const secret = process.env.S3_SECRET_ACCESS_KEY?.trim();
  if (!endpoint || !accessKey || !secret) return;

  try {
    const bucket = process.env.S3_BUCKET?.trim() || 'aegis-media';
    const region = process.env.S3_REGION ?? 'us-east-1';
    const url = presignS3DeleteUrl(
      endpoint,
      region,
      accessKey,
      secret,
      `${bucket}/${storageKey}`,
      cfg.S3_OBJECT_URL_EXPIRES_IN,
    );
    await fetch(url, { method: 'DELETE', signal: AbortSignal.timeout(5000) });
  } catch {
    // The database row is still removed; an operator can reconcile a failed
    // bucket deletion from the storage provider's audit trail.
  }
}

async function deleteMediaRows(ids: string[]): Promise<number> {
  const unique = [...new Set(ids.filter((id) => typeof id === 'string' && id.length > 0))];
  if (unique.length === 0) return 0;

  const rows = await selectAll('media_file', { id: { _in: unique } }, unique.length);
  for (const row of rows) {
    await deleteStoredObject(row);
  }
  await deleteRows('media_file', { id: { _in: unique } });
  return unique.length;
}

/** Delete every media object a user owns or attached to one of their messages. */
export async function deleteMediaObjectsForAccount(userId: string): Promise<number> {
  const owned = await selectAll('media_file', { owner_id: userId }, 5000, ['id']);
  const messages = await selectAll('message', { sender_id: userId }, 5000, ['metadata']);
  const ids = owned.map((row) => String(row.id));
  for (const message of messages) {
    const mediaId = parseMediaId(message.metadata);
    if (mediaId) ids.push(mediaId);
  }
  return deleteMediaRows(ids);
}

/** Delete media referenced by any message in a group thread. */
export async function deleteMediaObjectsForThread(threadId: string): Promise<number> {
  const messages = await selectAll('message', { thread_id: threadId }, 5000, ['id', 'metadata']);
  const ids: string[] = [];
  const messageIds: string[] = [];
  for (const message of messages) {
    messageIds.push(String(message.id));
    const mediaId = parseMediaId(message.metadata);
    if (mediaId) ids.push(mediaId);
  }
  if (messageIds.length > 0) {
    const attached = await selectAll('media_file', { message_id: { _in: messageIds } }, 5000, [
      'id',
    ]);
    for (const row of attached) ids.push(String(row.id));
  }
  return deleteMediaRows(ids);
}

/** Delete media referenced by one message (used when a message is deleted). */
export async function deleteMediaObjectsForMessage(messageId: string): Promise<number> {
  const message = await selectOne('message', { id: messageId }, ['metadata']);
  const ids: string[] = [];
  const mediaId = parseMediaId(message?.metadata);
  if (mediaId) ids.push(mediaId);
  const attached = await selectAll('media_file', { message_id: messageId }, 100, ['id']);
  for (const row of attached) ids.push(String(row.id));
  return deleteMediaRows(ids);
}

// ---------------------------------------------------------------------------
// Local (credential-free) storage fallback
// ---------------------------------------------------------------------------
//
// Without S3 credentials the presign endpoints hand out URLs that point back at
// this process. They are still "presigned": the key, the operation and the
// expiry are covered by an HMAC signature derived from JWT_SECRET, so a leaked
// or guessed storage key is not enough to upload or read an object, and no
// bearer token has to be shipped to a storage host.

function localSignature(kind: LocalUrlKind, storageKey: string, expiresAt: number): string {
  return createHmac('sha256', cfg.JWT_SECRET)
    .update(`${kind}\n${storageKey}\n${expiresAt}`)
    .digest('hex');
}

function safeSignatureMatches(expected: string, provided: string): boolean {
  const a = Buffer.from(expected, 'utf8');
  const b = Buffer.from(provided, 'utf8');
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

function buildLocalUrl(kind: LocalUrlKind, storageKey: string, expiresIn: number): string {
  const expiresAt = Math.floor(Date.now() / 1000) + expiresIn;
  const signature = localSignature(kind, storageKey, expiresAt);
  const query = new URLSearchParams({
    key: storageKey,
    exp: String(expiresAt),
    sig: signature,
  });
  return `/api/v1/media/${kind}/local?${query.toString()}`;
}

/** Resolve a storage key inside the media root, or null when it escapes it. */
function resolveStoragePath(storageKey: string): string | null {
  const resolved = path.resolve(LOCAL_MEDIA_ROOT, storageKey);
  if (resolved === LOCAL_MEDIA_ROOT) return null;
  if (!resolved.startsWith(`${LOCAL_MEDIA_ROOT}${path.sep}`)) return null;
  return resolved;
}

function readSignedKey(
  req: Request,
  kind: LocalUrlKind,
): { ok: true; storageKey: string } | { ok: false; status: number; error: string } {
  const storageKey = typeof req.query.key === 'string' ? req.query.key : '';
  const expiresAt = Number(req.query.exp);
  const provided = typeof req.query.sig === 'string' ? req.query.sig : '';

  if (!storageKey || !Number.isFinite(expiresAt) || !provided) {
    return { ok: false, status: 400, error: 'key, exp and sig are required' };
  }
  if (expiresAt * 1000 <= Date.now()) {
    return { ok: false, status: 403, error: 'url has expired' };
  }
  const expected = localSignature(kind, storageKey, Math.floor(expiresAt));
  if (!safeSignatureMatches(expected, provided)) {
    return { ok: false, status: 403, error: 'invalid signature' };
  }
  if (!resolveStoragePath(storageKey)) {
    return { ok: false, status: 400, error: 'invalid storage path' };
  }
  return { ok: true, storageKey };
}

/**
 * Local upload endpoint used when S3 is not configured. The body is streamed
 * straight to disk (the bytes are already encrypted by the client), with a hard
 * size ceiling and cleanup on failure.
 */
export async function handleLocalUpload(req: Request, res: Response) {
  const signed = readSignedKey(req, 'upload');
  if (signed.ok === false) return res.status(signed.status).json({ error: signed.error });

  const storageKey = signed.storageKey;
  const media = await selectOne('media_file', { storage_key: storageKey });
  if (!media) return res.status(404).json({ error: 'unknown media key' });
  if (media.upload_status === 'completed') {
    return res.status(409).json({ error: 'media already uploaded' });
  }

  const declared = Number(req.headers['content-length']);
  if (Number.isFinite(declared) && declared > MAX_LOCAL_UPLOAD_BYTES) {
    return res.status(413).json({ error: `upload exceeds ${MAX_LOCAL_UPLOAD_BYTES} bytes` });
  }

  const target = resolveStoragePath(storageKey);
  if (!target) return res.status(400).json({ error: 'invalid storage path' });
  await fs.promises.mkdir(path.dirname(target), { recursive: true });

  await new Promise<void>((resolve) => {
    let settled = false;
    let received = 0;
    const writeStream = fs.createWriteStream(target);

    const fail = (status: number, error: string) => {
      if (settled) return;
      settled = true;
      writeStream.destroy();
      void fs.promises.rm(target, { force: true }).catch(() => undefined);
      if (!res.headersSent) res.status(status).json({ error });
      resolve();
    };

    req.on('data', (chunk: Buffer) => {
      received += chunk.length;
      if (received > MAX_LOCAL_UPLOAD_BYTES) {
        fail(413, `upload exceeds ${MAX_LOCAL_UPLOAD_BYTES} bytes`);
      }
    });
    req.on('aborted', () => fail(400, 'upload aborted'));
    req.on('error', () => fail(400, 'upload failed'));

    writeStream.on('error', () => fail(500, 'upload write failed'));
    writeStream.on('finish', () => {
      if (settled) return;
      settled = true;
      void (async () => {
        try {
          await updateRows(
            'media_file',
            { id: String(media.id) },
            {
              upload_status: 'completed',
              size_bytes: received,
              upload_error: null,
              updated_at: new Date().toISOString(),
            },
          );
          if (!res.headersSent) res.json({ ok: true, storageKey, sizeBytes: received });
        } catch {
          if (!res.headersSent) res.status(500).json({ error: 'upload could not be recorded' });
        }
        resolve();
      })();
    });

    req.pipe(writeStream);
  });
}

/**
 * Local download endpoint used when S3 is not configured. Access is granted by
 * the signed query string; the stored MIME type is echoed so clients can render
 * the (still encrypted) payload correctly.
 */
export async function handleLocalDownload(req: Request, res: Response) {
  const signed = readSignedKey(req, 'download');
  if (signed.ok === false) return res.status(signed.status).json({ error: signed.error });

  const storageKey = signed.storageKey;
  const media = await selectOne('media_file', { storage_key: storageKey });
  if (!media) return res.status(404).json({ error: 'unknown media key' });

  const source = resolveStoragePath(storageKey);
  if (!source) return res.status(400).json({ error: 'invalid storage path' });

  let stats: fs.Stats;
  try {
    stats = await fs.promises.stat(source);
  } catch {
    return res.status(404).json({ error: 'file not found' });
  }

  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Length', String(stats.size));
  res.setHeader('Cache-Control', 'private, no-store');
  res.setHeader(
    'Content-Disposition',
    `attachment; filename="${String(media.original_name ?? 'download').replace(/["\\\r\n]/g, '_')}"`,
  );

  const readStream = fs.createReadStream(source);
  readStream.on('error', () => {
    if (!res.headersSent) res.status(500).json({ error: 'download failed' });
    else res.destroy();
  });
  readStream.pipe(res);
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function buildUploadUrl(storageKey: string, expiresIn: number): string {
  const endpoint = process.env.S3_ENDPOINT?.trim();
  const accessKey = process.env.S3_ACCESS_KEY_ID?.trim();
  const secret = process.env.S3_SECRET_ACCESS_KEY?.trim();
  const bucket = process.env.S3_BUCKET?.trim() || 'aegis-media';
  const region = process.env.S3_REGION ?? 'us-east-1';
  // Object URL expires in 900s (15 min) - see .env.example.
  const objectKey = `${bucket}/${storageKey}`;

  if (endpoint && accessKey && secret) {
    // Real S3-compatible presigned PUT URL.  We use a tiny, dependency-free
    // implementation here so the project has no extra runtime deps.
    return presignS3PutUrl(endpoint, region, accessKey, secret, objectKey, expiresIn);
  }

  // No cloud credentials -> return a signed local URL. The client sends the
  // encrypted bytes there and this process stores them on disk.
  return buildLocalUrl('upload', storageKey, expiresIn);
}

function buildDownloadUrl(storageKey: string, expiresIn: number): string {
  const endpoint = process.env.S3_ENDPOINT?.trim();
  const accessKey = process.env.S3_ACCESS_KEY_ID?.trim();
  const secret = process.env.S3_SECRET_ACCESS_KEY?.trim();
  const bucket = process.env.S3_BUCKET?.trim() || 'aegis-media';
  const region = process.env.S3_REGION ?? 'us-east-1';
  const objectKey = `${bucket}/${storageKey}`;

  if (endpoint && accessKey && secret) {
    return presignS3GetUrl(endpoint, region, accessKey, secret, objectKey, expiresIn);
  }

  return buildLocalUrl('download', storageKey, expiresIn);
}

function rfc3986(value: string): string {
  return encodeURIComponent(value).replace(
    /[!'()*]/g,
    (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

/**
 * Build an AWS Signature Version 4 presigned PUT URL so the client can upload
 * the *encrypted* bytes straight to S3 without routing them through the API.
 *
 * Implemented with node:crypto (HMAC-SHA256) to avoid pulling in the AWS SDK
 * just for presigning.
 */
function presignS3PutUrl(
  endpoint: string,
  region: string,
  accessKey: string,
  secret: string,
  objectKey: string,
  expiresIn: number,
): string {
  const base = new URL(endpoint.replace(/\/+$/, ''));
  const canonicalUri = `/${objectKey.split('/').map(rfc3986).join('/')}`;

  const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);
  const scope = `${dateStamp}/${region}/s3/aws4_request`;

  const params: Record<string, string> = {
    'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
    'X-Amz-Credential': `${accessKey}/${scope}`,
    'X-Amz-Date': amzDate,
    'X-Amz-Expires': String(expiresIn),
    'X-Amz-SignedHeaders': 'host',
  };
  const canonicalQuery = Object.keys(params)
    .sort()
    .map((key) => `${rfc3986(key)}=${rfc3986(params[key])}`)
    .join('&');

  const canonicalRequest = [
    'PUT',
    canonicalUri,
    canonicalQuery,
    `host:${base.host}\n`,
    'host',
    'UNSIGNED-PAYLOAD',
  ].join('\n');

  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    scope,
    createHash('sha256').update(canonicalRequest).digest('hex'),
  ].join('\n');

  const hmac = (key: Buffer | string, data: string) =>
    createHmac('sha256', key).update(data).digest();
  const signingKey = hmac(
    hmac(hmac(hmac(`AWS4${secret}`, dateStamp), region), 's3'),
    'aws4_request',
  );
  const signature = createHmac('sha256', signingKey).update(stringToSign).digest('hex');

  return `${base.origin}${canonicalUri}?${canonicalQuery}&X-Amz-Signature=${signature}`;
}

function presignS3DeleteUrl(
  endpoint: string,
  region: string,
  accessKey: string,
  secret: string,
  objectKey: string,
  expiresIn: number,
): string {
  const base = new URL(endpoint.replace(/\/+$/, ''));
  const canonicalUri = `/${objectKey.split('/').map(rfc3986).join('/')}`;

  const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);
  const scope = `${dateStamp}/${region}/s3/aws4_request`;

  const params: Record<string, string> = {
    'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
    'X-Amz-Credential': `${accessKey}/${scope}`,
    'X-Amz-Date': amzDate,
    'X-Amz-Expires': String(expiresIn),
    'X-Amz-SignedHeaders': 'host',
  };
  const canonicalQuery = Object.keys(params)
    .sort()
    .map((key) => `${rfc3986(key)}=${rfc3986(params[key])}`)
    .join('&');

  const canonicalRequest = [
    'DELETE',
    canonicalUri,
    canonicalQuery,
    `host:${base.host}\n`,
    'host',
    'UNSIGNED-PAYLOAD',
  ].join('\n');

  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    scope,
    createHash('sha256').update(canonicalRequest).digest('hex'),
  ].join('\n');

  const hmac = (key: Buffer | string, data: string) =>
    createHmac('sha256', key).update(data).digest();
  const signingKey = hmac(
    hmac(hmac(hmac(`AWS4${secret}`, dateStamp), region), 's3'),
    'aws4_request',
  );
  const signature = createHmac('sha256', signingKey).update(stringToSign).digest('hex');

  return `${base.origin}${canonicalUri}?${canonicalQuery}&X-Amz-Signature=${signature}`;
}

function presignS3GetUrl(
  endpoint: string,
  region: string,
  accessKey: string,
  secret: string,
  objectKey: string,
  expiresIn: number,
): string {
  const base = new URL(endpoint.replace(/\/+$/, ''));
  const canonicalUri = `/${objectKey.split('/').map(rfc3986).join('/')}`;

  const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);
  const scope = `${dateStamp}/${region}/s3/aws4_request`;

  const params: Record<string, string> = {
    'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
    'X-Amz-Credential': `${accessKey}/${scope}`,
    'X-Amz-Date': amzDate,
    'X-Amz-Expires': String(expiresIn),
    'X-Amz-SignedHeaders': 'host',
  };
  const canonicalQuery = Object.keys(params)
    .sort()
    .map((key) => `${rfc3986(key)}=${rfc3986(params[key])}`)
    .join('&');

  const canonicalRequest = [
    'GET',
    canonicalUri,
    canonicalQuery,
    `host:${base.host}\n`,
    'host',
    'UNSIGNED-PAYLOAD',
  ].join('\n');

  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    scope,
    createHash('sha256').update(canonicalRequest).digest('hex'),
  ].join('\n');

  const hmac = (key: Buffer | string, data: string) =>
    createHmac('sha256', key).update(data).digest();
  const signingKey = hmac(
    hmac(hmac(hmac(`AWS4${secret}`, dateStamp), region), 's3'),
    'aws4_request',
  );
  const signature = createHmac('sha256', signingKey).update(stringToSign).digest('hex');

  return `${base.origin}${canonicalUri}?${canonicalQuery}&X-Amz-Signature=${signature}`;
}

function classifyMediaType(fileType: string): string {
  if (fileType.startsWith('image/')) return 'image';
  if (fileType.startsWith('video/')) return 'video';
  if (fileType.startsWith('audio/')) return 'audio';
  return 'file';
}
