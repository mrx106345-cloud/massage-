import { Router } from 'express';
import { requireAuth, changePassword, logout } from '../services/auth.service.js';
import {
  deleteAccount,
  disableTotp,
  enableTotp,
  exportAccount,
  listAuditTrail,
  listUserSessions,
  logoutAllSessions,
  requestEmailVerification,
  requestPasswordReset,
  resetPassword,
  revokeUserSession,
  setupTotp,
  totpStatus,
  verifyEmail,
} from '../services/account.service.js';
import { authLimiter, sensitiveLimiter } from '../middleware/rateLimiter.js';
import { asyncRoute } from '../middleware/async.js';

const auth = asyncRoute(requireAuth);

/**
 * Auth flows that extend the core signup/login/refresh endpoints. Mounted at
 * `/api/v1/auth`.
 */
export const authFlowRouter = Router();

authFlowRouter.post(
  '/verify-email',
  authLimiter,
  asyncRoute((req, res) => verifyEmail(req, res)),
);
authFlowRouter.post(
  '/verify-email/resend',
  auth,
  authLimiter,
  asyncRoute((req, res) => requestEmailVerification(req, res)),
);
authFlowRouter.post(
  '/forgot-password',
  sensitiveLimiter,
  asyncRoute((req, res) => requestPasswordReset(req, res)),
);
authFlowRouter.post(
  '/reset-password',
  sensitiveLimiter,
  asyncRoute((req, res) => resetPassword(req, res)),
);
authFlowRouter.post(
  '/logout',
  asyncRoute((req, res) => logout(req, res)),
);
authFlowRouter.post(
  '/logout-all',
  auth,
  asyncRoute((req, res) => logoutAllSessions(req, res)),
);
authFlowRouter.post(
  '/change-password',
  auth,
  sensitiveLimiter,
  asyncRoute((req, res) => changePassword(req, res)),
);

authFlowRouter.get(
  '/2fa/status',
  auth,
  asyncRoute((req, res) => totpStatus(req, res)),
);
authFlowRouter.post(
  '/2fa/setup',
  auth,
  asyncRoute((req, res) => setupTotp(req, res)),
);
authFlowRouter.post(
  '/2fa/enable',
  auth,
  authLimiter,
  asyncRoute((req, res) => enableTotp(req, res)),
);
authFlowRouter.post(
  '/2fa/disable',
  auth,
  sensitiveLimiter,
  asyncRoute((req, res) => disableTotp(req, res)),
);

/**
 * Account management. Mounted at `/api/v1/account`; every route requires a
 * valid access token.
 */
export const accountRouter = Router();

accountRouter.use(auth);

accountRouter.get(
  '/sessions',
  asyncRoute((req, res) => listUserSessions(req, res)),
);
accountRouter.delete(
  '/sessions/:sessionId',
  asyncRoute((req, res) => revokeUserSession(req, res)),
);
accountRouter.get(
  '/audit',
  asyncRoute((req, res) => listAuditTrail(req, res)),
);
accountRouter.get(
  '/export',
  asyncRoute((req, res) => exportAccount(req, res)),
);
accountRouter.delete(
  '/',
  sensitiveLimiter,
  asyncRoute((req, res) => deleteAccount(req, res)),
);
