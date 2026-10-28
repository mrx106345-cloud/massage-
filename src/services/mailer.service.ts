/**
 * Transactional email.
 *
 * The app only needs to deliver verification and password-reset links, so the
 * transport is deliberately provider-agnostic:
 *
 *  - `MAIL_WEBHOOK_URL` set  -> POST the message as JSON to that endpoint
 *                               (Resend/Postmark/SES-over-HTTP/your own relay).
 *  - otherwise               -> append to an in-process outbox and log it, so
 *                               local development and tests can read the link
 *                               from `/__dev__/outbox` (dev only) or
 *                               `getOutbox()`.
 *
 * Sending never throws: a mail outage must not turn a password reset into a 500
 * or leak whether an address exists.
 */

import { randomUUID } from 'node:crypto';
import { cfg } from '../config/index.js';
import { logger } from '../utils/logger.js';

export interface MailMessage {
  to: string;
  subject: string;
  text: string;
  html?: string;
}

export interface SentMail extends MailMessage {
  id: string;
  from: string;
  sentAt: string;
  transport: 'webhook' | 'outbox';
}

const MAX_OUTBOX = 100;
const outbox: SentMail[] = [];

export function getOutbox(): SentMail[] {
  return [...outbox];
}

/** Most recently delivered message for an address, useful in tests. */
export function findLastMailTo(address: string): SentMail | undefined {
  return [...outbox].reverse().find((m) => m.to.toLowerCase() === address.toLowerCase());
}

export function clearOutbox(): void {
  outbox.length = 0;
}

function record(message: MailMessage, transport: SentMail['transport']): SentMail {
  const from =
    cfg.EMAIL_FROM && cfg.EMAIL_FROM.trim().length > 0
      ? cfg.EMAIL_FROM
      : 'Aegis Chat <no-reply@aegis.local>';

  const sent: SentMail = {
    ...message,
    id: randomUUID(),
    from,
    sentAt: new Date().toISOString(),
    transport,
  };
  outbox.push(sent);
  if (outbox.length > MAX_OUTBOX) outbox.splice(0, outbox.length - MAX_OUTBOX);
  return sent;
}

export async function sendMail(message: MailMessage): Promise<SentMail> {
  if (!cfg.MAIL_WEBHOOK_URL) {
    const sent = record(message, 'outbox');
    logger.info(
      { mailId: sent.id, to: message.to, subject: message.subject },
      'mail queued (no transport configured)',
    );
    return sent;
  }

  const sent = record(message, 'webhook');
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch(cfg.MAIL_WEBHOOK_URL, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(cfg.MAIL_WEBHOOK_TOKEN ? { authorization: `Bearer ${cfg.MAIL_WEBHOOK_TOKEN}` } : {}),
      },
      body: JSON.stringify({
        from: cfg.EMAIL_FROM,
        to: message.to,
        subject: message.subject,
        text: message.text,
        html: message.html,
      }),
      signal: controller.signal,
    });
    if (!response.ok) {
      logger.error(
        { mailId: sent.id, status: response.status },
        'mail webhook rejected the message',
      );
    }
  } catch (error) {
    logger.error(
      { mailId: sent.id, err: error instanceof Error ? error.message : String(error) },
      'mail webhook request failed',
    );
  } finally {
    clearTimeout(timeout);
  }
  return sent;
}

export function verificationEmail(to: string, username: string, token: string): MailMessage {
  const link = `${cfg.APP_ORIGIN.replace(/\/$/, '')}/verify-email?token=${encodeURIComponent(token)}`;
  return {
    to,
    subject: 'Verify your Aegis Chat email',
    text: `Hi ${username},\n\nConfirm your email address to finish setting up your account:\n${link}\n\nThis link expires in ${cfg.EMAIL_VERIFICATION_TTL_HOURS} hours. If you did not sign up, ignore this email.`,
    html: `<p>Hi ${escapeHtml(username)},</p><p>Confirm your email address to finish setting up your account:</p><p><a href="${link}">Verify email</a></p><p>This link expires in ${cfg.EMAIL_VERIFICATION_TTL_HOURS} hours.</p>`,
  };
}

export function passwordResetEmail(to: string, username: string, token: string): MailMessage {
  const link = `${cfg.APP_ORIGIN.replace(/\/$/, '')}/reset-password?token=${encodeURIComponent(token)}`;
  return {
    to,
    subject: 'Reset your Aegis Chat password',
    text: `Hi ${username},\n\nUse this link to choose a new password:\n${link}\n\nThis link expires in ${cfg.PASSWORD_RESET_TTL_MINUTES} minutes. If you did not request a reset, you can ignore this email — your password is unchanged.`,
    html: `<p>Hi ${escapeHtml(username)},</p><p>Use the link below to choose a new password:</p><p><a href="${link}">Reset password</a></p><p>This link expires in ${cfg.PASSWORD_RESET_TTL_MINUTES} minutes.</p>`,
  };
}

export function passwordChangedEmail(to: string, username: string): MailMessage {
  return {
    to,
    subject: 'Your Aegis Chat password was changed',
    text: `Hi ${username},\n\nThe password for your account was just changed and all other sessions were signed out. If this was not you, reset your password immediately.`,
  };
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
