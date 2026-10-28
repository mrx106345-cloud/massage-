// Auto-generated Kysely typescript types for the Aegis Secure Chat database.
// Regenerate with: npx kysely-codegen --outFile src/db/types.ts
// NOTE: this file is checked in so the IDE can resolve types; it is an
// implementation detail and should not be edited by hand.

import { type ColumnType } from 'kysely';

export type Json = string | number | boolean | null | { [key: string]: Json } | Json[];

export type PublicUser = {
  id: string;
  username: string;
  email: string;
  avatar_url: string | null;
  is_online: boolean;
  token_version: number;
  email_verified: boolean;
  created_at: string;
  updated_at: string;
};

export type User = PublicUser & {
  password_hash: string;
  totp_secret?: string | null;
  totp_enabled?: boolean;
};

export type AuthToken = {
  id: string;
  user_id: string;
  type: string;
  token_hash: string;
  expires_at: string;
  consumed_at: string | null;
  created_at: string;
};

export type AuditLog = {
  id: string;
  actor_id: string | null;
  action: string;
  target_type: string | null;
  target_id: string | null;
  ip_address: string | null;
  user_agent: string | null;
  metadata: string | null;
  created_at: string;
};

export type Group_ = {
  id: string;
  name: string | null;
  admin_id: string;
  is_private: boolean;
  gm_locked: boolean | null;
  gm_version: number | null;
  created_at: string;
  updated_at: string;
};

export type GroupMember = {
  id: string;
  group_id: string;
  user_id: string;
  joined_at: string;
  is_admin: boolean;
  joined_via_invite: boolean | null;
  invite_token: string | null;
  last_read_message_id: string | null;
  last_read_at: string | null;
  status: string;
};

export type DirectMessageThread = {
  id: string;
  user_a_id: string;
  user_b_id: string;
  last_message_id: string | null;
  last_read_message_id: string | null;
  last_read_at: string | null;
  last_updated_at: string | null;
  unread_count_a: number;
  unread_count_b: number;
  created_at: string;
  updated_at: string;
};

export type Message = {
  id: string;
  thread_id: string;
  sender_id: string;
  parent_id: string | null;
  content_type: string;
  content: string | null;
  encrypted_content: string | null;
  encryption_alg: string | null;
  encryption_key_id: string | null;
  gmk_id: string | null;
  metadata: Json | null;
  signature: string | null;
  signature_key_id: string | null;
  status: string;
  delivery_receipts: string[] | null;
  created_at: string;
  updated_at: string;
};

export type MediaFile = {
  id: string;
  message_id: string | null;
  owner_id: string;
  original_name: string;
  content_type: string;
  size_bytes: number;
  storage_key: string;
  upload_url: string;
  download_url: string;
  upload_status: string;
  upload_error: string | null;
  media_type: string;
  duration_seconds: number | null;
  width: number | null;
  height: number | null;
  thumb_url: string | null;
  created_at: string;
  updated_at: string;
};

export type CryptoKey = {
  id: string;
  owner_id: string;
  key_type: string;
  key_id: string;
  public_key_pem: string | null;
  private_key_pem: string | null;
  x25519_public: string | null;
  curve25519_public: string | null;
  ed25519_public: string | null;
  usage: string;
  expires_at: string | null;
  status: string;
  created_at: string;
  updated_at: string;
};

export type Session = {
  id: string;
  user_id: string;
  token: string;
  token_version: number;
  ip_address: string | null;
  user_agent: string | null;
  is_anonymous: boolean | null;
  created_at: string;
  updated_at: string;
  expires_at: string;
};

export type Invite = {
  id: string;
  group_id: string;
  token: string;
  inviter_id: string;
  invited_email: string | null;
  invited_username: string | null;
  status: string;
  expires_at: string | null;
  created_at: string;
};

export type Report = {
  id: string;
  reported_by_id: string;
  reported_user_id: string;
  group_id: string | null;
  message_id: string | null;
  reason: string;
  details: string | null;
  status: string;
  created_at: string;
};

export type OfflineQueueItem = {
  id: string;
  user_id: string;
  channel_type: string;
  channel_id: string;
  message_id: string;
  payload: string;
  enqueued_at: string;
  delivered_at: string | null;
  status: string;
};

export type Maintenance = {
  id: string;
  key: string;
  value: string | null;
  updated_at: string;
};

export type Migration = {
  id: string;
  name: string;
  batch: number;
  migration_time: ColumnType<string, string, unknown>;
  executed_at: ColumnType<string, string, unknown>;
};

export type Database = Record<string, Record<string, unknown>>;
