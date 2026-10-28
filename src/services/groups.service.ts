import { randomUUID as uid } from 'node:crypto';
import { countRows, deleteRows, insertRow, selectAll, selectOne, updateRows } from '../db/index.js';
import { deleteMediaObjectsForThread } from './media.service.js';
import type { Request, Response } from 'express';
import type { Group_, GroupMember } from '../db/types.js';
import type { Socket } from 'socket.io';

export interface GroupRequest extends Request {
  userId?: string;
}

export interface GroupListResponse {
  groups: Array<Pick<Group_, 'id' | 'name' | 'is_private' | 'gm_version'>>;
}

export interface GroupMemberProfile {
  id: string;
  username: string;
  avatar_url: string | null;
  is_online: boolean;
  crypto?: {
    keyId: string;
    x25519Public: string | null;
    signingPublicKey: string | null;
  } | null;
}

export interface GroupDetailResponse {
  group: Pick<Group_, 'id' | 'name' | 'is_private' | 'gm_version' | 'created_at'>;
  members: Array<
    Pick<GroupMember, 'id' | 'user_id' | 'is_admin' | 'joined_at' | 'status'> & {
      user: GroupMemberProfile | null;
    }
  >;
}

export interface GroupInviteResponse {
  inviteToken: string;
  inviteExpiresAt: string;
}

const now = () => new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');

function asStringArray(value: unknown): string[] {
  if (typeof value === 'string') return value.length > 0 ? [value] : [];
  if (!Array.isArray(value)) return [];
  return value.filter((entry): entry is string => typeof entry === 'string' && entry.length > 0);
}

async function membership(
  groupId: string,
  userId: string,
): Promise<Record<string, unknown> | null> {
  return selectOne('group_member', { group_id: groupId, user_id: userId });
}

// ---------------------------------------------------------------------------
// Group CRUD
// ---------------------------------------------------------------------------

export async function createGroup(req: GroupRequest, res: Response) {
  const { groupName, memberIds, isPrivate } = (req.body ?? {}) as Record<string, unknown>;
  const userId = req.userId;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });

  if (typeof groupName !== 'string' || groupName.length < 1 || groupName.length > 128) {
    return res.status(400).json({ error: 'groupName must be 1-128 chars' });
  }

  // Only add members that actually exist (and de-duplicate).
  const requested = [...new Set(asStringArray(memberIds))].filter((id) => id !== userId);
  const validMembers: string[] = [];
  for (const id of requested) {
    const user = await selectOne('user', { id });
    if (user) validMembers.push(id);
  }

  const groupId = uid();
  const createdAt = now();

  await insertRow('group', {
    id: groupId,
    name: groupName,
    admin_id: userId,
    is_private: Boolean(isPrivate),
    gm_locked: false,
    gm_version: 1,
    created_at: createdAt,
    updated_at: createdAt,
  });

  // The creator is always the first member and an admin.
  await insertRow('group_member', {
    id: uid(),
    group_id: groupId,
    user_id: userId,
    joined_at: createdAt,
    is_admin: true,
    joined_via_invite: false,
    invite_token: null,
    last_read_message_id: null,
    last_read_at: null,
    status: 'active',
  });

  for (const memberId of validMembers) {
    await insertRow('group_member', {
      id: uid(),
      group_id: groupId,
      user_id: memberId,
      joined_at: createdAt,
      is_admin: false,
      joined_via_invite: false,
      invite_token: null,
      last_read_message_id: null,
      last_read_at: null,
      status: 'active',
    });
  }

  res
    .status(201)
    .json({ id: groupId, name: groupName, isPrivate: Boolean(isPrivate), gmVersion: 1 });
}

export async function listGroups(req: GroupRequest, res: Response) {
  const userId = req.userId;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });

  const memberships = await selectAll('group_member', { user_id: userId }, 1000, ['group_id']);
  const groupIds = [...new Set(memberships.map((row) => String(row.group_id)))];
  if (groupIds.length === 0) return res.json({ groups: [] });

  const groups = await selectAll('group', { id: { _in: groupIds } }, 1000, [
    'id',
    'name',
    'is_private',
    'gm_version',
    'created_at',
  ]);
  res.json({ groups });
}

export async function getGroup(req: GroupRequest, res: Response) {
  const { groupId } = req.params as { groupId: string };
  const userId = req.userId;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });

  if (!(await membership(groupId, userId))) {
    // Do not leak whether the group exists to non-members.
    return res.status(404).json({ error: 'group not found' });
  }

  const group = await selectOne('group', { id: groupId }, [
    'id',
    'name',
    'is_private',
    'gm_version',
    'created_at',
    'admin_id',
  ]);
  if (!group) return res.status(404).json({ error: 'group not found' });

  const members = await selectAll('group_member', { group_id: groupId }, 1000, [
    'id',
    'user_id',
    'is_admin',
    'joined_at',
    'status',
  ]);

  // The chat UI needs display names for senders in a group; members are always
  // visible to each other, so return the safe public profile only.
  const memberIds = [...new Set(members.map((member) => String(member.user_id)))];
  const profiles = memberIds.length
    ? await selectAll('user', { id: { _in: memberIds } }, 1000, [
        'id',
        'username',
        'avatar_url',
        'is_online',
      ])
    : [];
  const byId = new Map(profiles.map((profile) => [String(profile.id), profile]));

  // Members need each other's public halves to wrap rotated group keys and to
  // display the safety number for manual verification. Private material never
  // appears in this table, so returning the public halves is safe.
  const cryptoRows = memberIds.length
    ? await selectAll(
        'crypto_key',
        { owner_id: { _in: memberIds }, status: 'active' },
        2000,
        ['owner_id', 'key_id', 'x25519_public', 'ed25519_public', 'created_at'],
        { column: 'created_at', direction: 'desc' },
      )
    : [];
  const cryptoByOwner = new Map<string, Record<string, unknown>>();
  for (const row of cryptoRows) {
    const ownerId = String(row.owner_id);
    if (!cryptoByOwner.has(ownerId)) cryptoByOwner.set(ownerId, row);
  }

  res.json({
    group,
    members: members.map((member) => {
      const profile = byId.get(String(member.user_id));
      return {
        ...member,
        user: profile
          ? {
              id: String(profile.id),
              username: String(profile.username),
              avatar_url: profile.avatar_url === null ? null : String(profile.avatar_url),
              is_online: Boolean(profile.is_online),
              crypto: (() => {
                const key = cryptoByOwner.get(String(profile.id));
                if (!key) return null;
                return {
                  keyId: String(key.key_id),
                  x25519Public: key.x25519_public === null ? null : String(key.x25519_public),
                  signingPublicKey: key.ed25519_public === null ? null : String(key.ed25519_public),
                };
              })(),
            }
          : null,
      };
    }),
  });
}

export async function updateGroup(req: GroupRequest, res: Response) {
  const { groupId } = req.params as { groupId: string };
  const { name, isPrivate } = (req.body ?? {}) as Record<string, unknown>;
  const userId = req.userId;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });

  const member = await membership(groupId, userId);
  if (!member || !Number(member.is_admin)) {
    return res.status(403).json({ error: 'only group admins can modify metadata' });
  }

  const updates: Record<string, unknown> = {};
  if (typeof name === 'string' && name.length > 0 && name.length <= 128) updates.name = name;
  if (typeof isPrivate === 'boolean') updates.is_private = isPrivate;
  if (Object.keys(updates).length === 0) {
    return res.status(400).json({ error: 'nothing to update' });
  }
  updates.updated_at = now();

  await updateRows('group', { id: groupId }, updates);
  res.json({ ok: true });
}

export async function deleteGroup(req: GroupRequest, res: Response) {
  const { groupId } = req.params as { groupId: string };
  const userId = req.userId;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });

  const member = await membership(groupId, userId);
  if (!member || !Number(member.is_admin)) {
    return res.status(403).json({ error: 'only admins can delete groups' });
  }

  // Delete referenced encrypted objects before their rows disappear, then
  // remove messages, queue entries, memberships and pending invites.
  await deleteMediaObjectsForThread(groupId);
  await deleteRows('message', { thread_id: groupId });
  await deleteRows('offline_queue_item', { channel_id: groupId });
  await deleteRows('group_member', { group_id: groupId });
  await deleteRows('invite', { group_id: groupId });
  await deleteRows('group', { id: groupId });
  res.json({ ok: true });
}

// ---------------------------------------------------------------------------
// Membership
// ---------------------------------------------------------------------------

export async function addMembers(req: GroupRequest, res: Response) {
  const { groupId } = req.params as { groupId: string };
  const { memberIds } = (req.body ?? {}) as Record<string, unknown>;
  const userId = req.userId;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });

  const member = await membership(groupId, userId);
  if (!member || !Number(member.is_admin)) {
    return res.status(403).json({ error: 'only admins can add members' });
  }

  const ids = [...new Set(asStringArray(memberIds))];
  if (ids.length === 0) return res.status(400).json({ error: 'memberIds is required' });

  const existing = await selectAll('group_member', { group_id: groupId }, 1000, ['user_id']);
  const alreadyIn = new Set(existing.map((row) => String(row.user_id)));

  let added = 0;
  for (const id of ids) {
    if (alreadyIn.has(id)) continue;
    const exists = await selectOne('user', { id });
    if (!exists) continue;
    await insertRow('group_member', {
      id: uid(),
      group_id: groupId,
      user_id: id,
      joined_at: now(),
      is_admin: false,
      joined_via_invite: false,
      invite_token: null,
      last_read_message_id: null,
      last_read_at: null,
      status: 'active',
    });
    alreadyIn.add(id);
    added += 1;
  }

  res.json({ ok: true, added });
}

/** Remove another member. Admins cannot remove themselves through this route. */
export async function removeMember(req: GroupRequest, res: Response) {
  const { groupId, memberId } = req.params as { groupId: string; memberId: string };
  const userId = req.userId;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });

  const actor = await membership(groupId, userId);
  if (!actor || !Number(actor.is_admin)) {
    return res.status(403).json({ error: 'only group admins can remove members' });
  }
  if (memberId === userId) {
    return res.status(400).json({ error: 'use the leave endpoint to leave a group' });
  }

  const target = await membership(groupId, memberId);
  if (!target) return res.status(404).json({ error: 'member not found' });

  if (Number(target.is_admin)) {
    const admins = await countRows('group_member', {
      group_id: groupId,
      is_admin: true,
      status: 'active',
    });
    if (admins <= 1) {
      return res.status(409).json({ error: 'the last admin cannot be removed' });
    }
  }

  await deleteRows('group_member', { group_id: groupId, user_id: memberId });
  // A removed member must not receive queued group ciphertext after removal.
  await deleteRows('offline_queue_item', { user_id: memberId, channel_id: groupId });

  res.json({ ok: true, removedUserId: memberId, rotationRequired: true });
}

/** Leave a group. The caller cannot be the last admin of a non-empty group. */
export async function leaveGroup(req: GroupRequest, res: Response) {
  const { groupId } = req.params as { groupId: string };
  const userId = req.userId;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });

  const member = await membership(groupId, userId);
  if (!member) return res.status(404).json({ error: 'group not found' });

  if (Number(member.is_admin)) {
    const admins = await countRows('group_member', {
      group_id: groupId,
      is_admin: true,
      status: 'active',
    });
    const activeMembers = await countRows('group_member', {
      group_id: groupId,
      status: 'active',
    });
    if (admins <= 1 && activeMembers > 1) {
      return res
        .status(409)
        .json({ error: 'promote another admin before leaving, or delete the group' });
    }
    if (admins <= 1 && activeMembers <= 1) {
      return res.status(409).json({ error: 'the last member must delete the group instead' });
    }
  }

  await deleteRows('group_member', { group_id: groupId, user_id: userId });
  await deleteRows('offline_queue_item', { user_id: userId, channel_id: groupId });

  res.json({ ok: true, groupId, rotationRequired: true });
}

// ---------------------------------------------------------------------------
// Offline queue
// ---------------------------------------------------------------------------

export interface OfflineQueueEnqueueInput {
  userId: string;
  channelType: 'direct' | 'group';
  channelId: string;
  messageId: string;
  payload: string;
  createdAt: string;
}

export async function enqueueOffline(input: OfflineQueueEnqueueInput): Promise<void> {
  await insertRow('offline_queue_item', {
    id: uid(),
    user_id: input.userId,
    channel_type: input.channelType,
    channel_id: input.channelId,
    message_id: input.messageId,
    payload: input.payload,
    enqueued_at: input.createdAt,
    delivered_at: null,
    status: 'queued',
  });
}

export function claimOfflineQueue(userIds: string[]) {
  return selectOne('offline_queue_item', { user_id: { _in: userIds }, status: 'queued' }, [
    'id',
    'user_id',
    'channel_type',
    'channel_id',
    'message_id',
    'payload',
    'enqueued_at',
  ]);
}

// ---------------------------------------------------------------------------
// Group broadcast helpers (used by the socket service)
// ---------------------------------------------------------------------------

export interface BroadcastContext {
  io: unknown;
  users: Map<string, Set<Socket>>;
}

export async function broadcastToGroup(ctx: BroadcastContext, groupId: string, payload: string) {
  const rows = await selectAll('group_member', { group_id: groupId }, 1000, ['user_id']);
  if (rows.length === 0) return;

  for (const row of rows) {
    const sockets = ctx.users.get(String(row.user_id));
    if (sockets && sockets.size > 0) {
      for (const socket of sockets) {
        socket.emit('receive_message', JSON.parse(payload));
      }
    } else {
      await enqueueOffline({
        userId: String(row.user_id),
        channelType: 'group',
        channelId: groupId,
        messageId: '',
        payload,
        createdAt: now(),
      });
    }
  }
}
