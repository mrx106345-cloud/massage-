/**
 * OpenAPI 3.1 description of the Aegis Chat HTTP API.
 *
 * Kept as a plain object (no code generation) so it can be served at
 * `/api/openapi.json` and rendered by the built-in reference page at
 * `/api/docs`. Update it alongside route changes.
 */

const bearer = [{ bearerAuth: [] }];

const errorResponse = {
  description: 'Error',
  content: {
    'application/json': {
      schema: {
        type: 'object',
        properties: {
          error: { type: 'string' },
          code: { type: 'string' },
          requestId: { type: 'string' },
        },
        required: ['error'],
      },
    },
  },
};

const jsonBody = (schema: Record<string, unknown>) => ({
  required: true,
  content: { 'application/json': { schema } },
});

export const openApiDocument = {
  openapi: '3.1.0',
  info: {
    title: 'Aegis Secure Chat API',
    version: '1.0.0',
    description:
      'End-to-end encrypted messenger. Message contents are encrypted client-side; the server routes opaque envelopes and never holds plaintext or private keys.',
    license: { name: 'MIT' },
  },
  servers: [{ url: '/', description: 'Current host' }],
  tags: [
    { name: 'Health' },
    { name: 'Auth' },
    { name: 'Account' },
    { name: 'Users' },
    { name: 'Groups' },
    { name: 'Threads' },
    { name: 'Media' },
  ],
  components: {
    securitySchemes: {
      bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
    },
    schemas: {
      User: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
          username: { type: 'string' },
          email: { type: 'string', format: 'email' },
          avatar_url: { type: ['string', 'null'] },
          is_online: { type: 'boolean' },
          email_verified: { type: 'boolean' },
          token_version: { type: 'integer' },
          created_at: { type: 'string', format: 'date-time' },
          updated_at: { type: 'string', format: 'date-time' },
        },
      },
      AuthTokens: {
        type: 'object',
        properties: {
          token: { type: 'string', description: 'Short-lived access token (JWT)' },
          refreshToken: { type: 'string', description: 'Rotating refresh token (JWT)' },
          user: { $ref: '#/components/schemas/User' },
          emailVerificationRequired: { type: 'boolean' },
        },
      },
      Group: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
          name: { type: 'string' },
          is_private: { type: 'boolean' },
          gm_version: { type: 'integer' },
          created_at: { type: 'string', format: 'date-time' },
        },
      },
      Error: {
        type: 'object',
        properties: { error: { type: 'string' }, code: { type: 'string' } },
        required: ['error'],
      },
    },
  },
  paths: {
    '/api/health': {
      get: {
        tags: ['Health'],
        summary: 'Liveness probe',
        responses: { '200': { description: 'Process is running' } },
      },
    },
    '/api/health/ready': {
      get: {
        tags: ['Health'],
        summary: 'Readiness probe (checks the database)',
        responses: {
          '200': { description: 'Ready' },
          '503': { description: 'A dependency is unavailable' },
        },
      },
    },
    '/api/health/detailed': {
      get: {
        tags: ['Health'],
        summary: 'Detailed dependency health and latency',
        responses: { '200': { description: 'Health report' } },
      },
    },
    '/api/metrics': {
      get: {
        tags: ['Health'],
        summary: 'Process/runtime metrics',
        description: 'Requires `Authorization: Bearer $METRICS_TOKEN` when that variable is set.',
        responses: { '200': { description: 'Metrics' }, '401': errorResponse },
      },
    },
    '/api/v1/auth/signup': {
      post: {
        tags: ['Auth'],
        summary: 'Create an account',
        requestBody: jsonBody({
          type: 'object',
          required: ['email', 'password', 'username'],
          properties: {
            email: { type: 'string', format: 'email' },
            password: { type: 'string', minLength: 8, maxLength: 128 },
            username: { type: 'string', minLength: 3, maxLength: 64 },
          },
        }),
        responses: {
          '201': {
            description: 'Account created',
            content: {
              'application/json': { schema: { $ref: '#/components/schemas/AuthTokens' } },
            },
          },
          '400': errorResponse,
          '409': errorResponse,
          '429': errorResponse,
        },
      },
    },
    '/api/v1/auth/login': {
      post: {
        tags: ['Auth'],
        summary: 'Exchange credentials (and a 2FA code when enabled) for tokens',
        requestBody: jsonBody({
          type: 'object',
          required: ['email', 'password'],
          properties: {
            email: { type: 'string', format: 'email' },
            password: { type: 'string' },
            totpCode: { type: 'string', description: '6-digit TOTP code' },
            backupCode: { type: 'string', description: 'One-time recovery code' },
          },
        }),
        responses: {
          '200': {
            description: 'Authenticated',
            content: {
              'application/json': { schema: { $ref: '#/components/schemas/AuthTokens' } },
            },
          },
          '401': errorResponse,
          '403': errorResponse,
          '429': errorResponse,
        },
      },
    },
    '/api/v1/auth/refresh': {
      post: {
        tags: ['Auth'],
        summary: 'Rotate a refresh token',
        requestBody: jsonBody({
          type: 'object',
          required: ['refreshToken'],
          properties: { refreshToken: { type: 'string' } },
        }),
        responses: {
          '200': { description: 'New access + refresh tokens' },
          '401': errorResponse,
        },
      },
    },
    '/api/v1/auth/logout': {
      post: {
        tags: ['Auth'],
        summary: 'Revoke the presented refresh token',
        requestBody: jsonBody({
          type: 'object',
          properties: { refreshToken: { type: 'string' } },
        }),
        responses: { '204': { description: 'Logged out' } },
      },
    },
    '/api/v1/auth/logout-all': {
      post: {
        tags: ['Auth'],
        summary: 'Sign out everywhere (bumps the token version)',
        security: bearer,
        responses: { '204': { description: 'All sessions revoked' } },
      },
    },
    '/api/v1/auth/change-password': {
      post: {
        tags: ['Auth'],
        summary: 'Change the password and revoke every session',
        security: bearer,
        requestBody: jsonBody({
          type: 'object',
          required: ['currentPassword', 'newPassword'],
          properties: {
            currentPassword: { type: 'string' },
            newPassword: { type: 'string', minLength: 8, maxLength: 128 },
          },
        }),
        responses: {
          '200': { description: 'Password changed; re-authenticate' },
          '400': errorResponse,
          '401': errorResponse,
          '429': errorResponse,
        },
      },
    },
    '/api/v1/auth/forgot-password': {
      post: {
        tags: ['Auth'],
        summary: 'Request a password-reset email',
        description: 'Always returns 200 so the endpoint cannot enumerate accounts.',
        requestBody: jsonBody({
          type: 'object',
          required: ['email'],
          properties: { email: { type: 'string', format: 'email' } },
        }),
        responses: { '200': { description: 'Request accepted' }, '429': errorResponse },
      },
    },
    '/api/v1/auth/reset-password': {
      post: {
        tags: ['Auth'],
        summary: 'Redeem a password-reset token',
        requestBody: jsonBody({
          type: 'object',
          required: ['token', 'newPassword'],
          properties: {
            token: { type: 'string' },
            newPassword: { type: 'string', minLength: 8, maxLength: 128 },
          },
        }),
        responses: {
          '200': { description: 'Password reset; all sessions revoked' },
          '400': errorResponse,
        },
      },
    },
    '/api/v1/auth/verify-email': {
      post: {
        tags: ['Auth'],
        summary: 'Verify an email address with a token',
        requestBody: jsonBody({
          type: 'object',
          required: ['token'],
          properties: { token: { type: 'string' } },
        }),
        responses: {
          '200': { description: 'Email verified' },
          '400': errorResponse,
          '429': errorResponse,
        },
      },
    },
    '/api/v1/auth/verify-email/resend': {
      post: {
        tags: ['Auth'],
        summary: 'Send a fresh verification email',
        security: bearer,
        responses: { '202': { description: 'Email queued' }, '401': errorResponse },
      },
    },
    '/api/v1/auth/2fa/status': {
      get: {
        tags: ['Auth'],
        summary: 'Two-factor status for the current user',
        security: bearer,
        responses: { '200': { description: 'Status' }, '401': errorResponse },
      },
    },
    '/api/v1/auth/2fa/setup': {
      post: {
        tags: ['Auth'],
        summary: 'Start TOTP enrolment (returns the otpauth:// URL)',
        security: bearer,
        responses: { '200': { description: 'Secret + otpauth URL' }, '409': errorResponse },
      },
    },
    '/api/v1/auth/2fa/enable': {
      post: {
        tags: ['Auth'],
        summary: 'Confirm TOTP enrolment and receive recovery codes',
        security: bearer,
        requestBody: jsonBody({
          type: 'object',
          required: ['code'],
          properties: { code: { type: 'string' } },
        }),
        responses: {
          '200': { description: 'Enabled; recovery codes returned once' },
          '400': errorResponse,
        },
      },
    },
    '/api/v1/auth/2fa/disable': {
      post: {
        tags: ['Auth'],
        summary: 'Disable TOTP (requires the account password)',
        security: bearer,
        requestBody: jsonBody({
          type: 'object',
          required: ['password'],
          properties: { password: { type: 'string' } },
        }),
        responses: { '200': { description: 'Disabled' }, '401': errorResponse },
      },
    },
    '/api/v1/account/sessions': {
      get: {
        tags: ['Account'],
        summary: 'List active sessions',
        security: bearer,
        parameters: [
          {
            name: 'x-refresh-token',
            in: 'header',
            required: false,
            schema: { type: 'string' },
            description: 'Marks the matching session as `current`',
          },
        ],
        responses: { '200': { description: 'Sessions' }, '401': errorResponse },
      },
    },
    '/api/v1/account/sessions/{sessionId}': {
      delete: {
        tags: ['Account'],
        summary: 'Revoke one session',
        security: bearer,
        parameters: [{ name: 'sessionId', in: 'path', required: true, schema: { type: 'string' } }],
        responses: { '200': { description: 'Revoked' }, '404': errorResponse },
      },
    },
    '/api/v1/account/audit': {
      get: {
        tags: ['Account'],
        summary: 'Security audit trail for the current user',
        security: bearer,
        responses: { '200': { description: 'Audit entries' }, '401': errorResponse },
      },
    },
    '/api/v1/account/export': {
      get: {
        tags: ['Account'],
        summary: 'GDPR data export (JSON download)',
        security: bearer,
        responses: { '200': { description: 'Account archive' }, '401': errorResponse },
      },
    },
    '/api/v1/account': {
      delete: {
        tags: ['Account'],
        summary: 'Permanently delete the account and personal data',
        security: bearer,
        requestBody: jsonBody({
          type: 'object',
          required: ['password'],
          properties: { password: { type: 'string' } },
        }),
        responses: { '204': { description: 'Deleted' }, '401': errorResponse },
      },
    },
    '/api/v1/users/search': {
      get: {
        tags: ['Users'],
        summary: 'Search users by username',
        security: bearer,
        parameters: [{ name: 'q', in: 'query', required: true, schema: { type: 'string' } }],
        responses: { '200': { description: 'Matching users' }, '400': errorResponse },
      },
    },
    '/api/v1/users/{id}/public-key': {
      get: {
        tags: ['Users'],
        summary: "Fetch a user's published X25519 public key",
        security: bearer,
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        responses: { '200': { description: 'Public key bundle' }, '401': errorResponse },
      },
    },
    '/api/v1/groups': {
      get: {
        tags: ['Groups'],
        summary: "List the caller's groups",
        security: bearer,
        responses: { '200': { description: 'Groups' } },
      },
      post: {
        tags: ['Groups'],
        summary: 'Create a group',
        security: bearer,
        requestBody: jsonBody({
          type: 'object',
          required: ['groupName'],
          properties: {
            groupName: { type: 'string', maxLength: 128 },
            memberIds: { type: 'array', items: { type: 'string' } },
            isPrivate: { type: 'boolean' },
          },
        }),
        responses: {
          '201': { description: 'Created' },
          '400': errorResponse,
          '401': errorResponse,
        },
      },
    },
    '/api/v1/groups/{groupId}': {
      get: {
        tags: ['Groups'],
        summary: 'Group details and members',
        security: bearer,
        parameters: [{ name: 'groupId', in: 'path', required: true, schema: { type: 'string' } }],
        responses: { '200': { description: 'Group' }, '404': errorResponse },
      },
      put: {
        tags: ['Groups'],
        summary: 'Update group metadata (admin only)',
        security: bearer,
        parameters: [{ name: 'groupId', in: 'path', required: true, schema: { type: 'string' } }],
        responses: { '200': { description: 'Updated' }, '403': errorResponse },
      },
      delete: {
        tags: ['Groups'],
        summary: 'Delete a group (admin only)',
        security: bearer,
        parameters: [{ name: 'groupId', in: 'path', required: true, schema: { type: 'string' } }],
        responses: { '200': { description: 'Deleted' }, '403': errorResponse },
      },
    },
    '/api/v1/groups/{groupId}/members': {
      post: {
        tags: ['Groups'],
        summary: 'Add members (admin only)',
        security: bearer,
        parameters: [{ name: 'groupId', in: 'path', required: true, schema: { type: 'string' } }],
        requestBody: jsonBody({
          type: 'object',
          required: ['memberIds'],
          properties: { memberIds: { type: 'array', items: { type: 'string' } } },
        }),
        responses: { '200': { description: 'Members added' }, '403': errorResponse },
      },
    },
    '/api/v1/threads': {
      get: {
        tags: ['Threads'],
        summary: "List the caller's conversations, newest activity first",
        description:
          'Covers both 1-to-1 threads and joined groups. Unread counts are tracked per participant and per group member.',
        security: bearer,
        responses: { '200': { description: 'Threads' }, '401': errorResponse },
      },
    },
    '/api/v1/threads/{threadId}/messages': {
      get: {
        tags: ['Threads'],
        summary: 'Paginated ciphertext history for one thread',
        description:
          'Returns opaque ciphertext bundles only; the server never holds plaintext or private keys. Newest first, cursor-paginated with `before`.',
        security: bearer,
        parameters: [
          { name: 'threadId', in: 'path', required: true, schema: { type: 'string' } },
          {
            name: 'limit',
            in: 'query',
            required: false,
            schema: { type: 'integer', minimum: 1, maximum: 100, default: 50 },
          },
          {
            name: 'before',
            in: 'query',
            required: false,
            schema: { type: 'string', format: 'date-time' },
            description: 'Return messages older than this ISO-8601 timestamp',
          },
        ],
        responses: {
          '200': { description: 'Messages and the next cursor' },
          '400': errorResponse,
          '403': errorResponse,
        },
      },
    },
    '/api/v1/threads/{threadId}/read': {
      post: {
        tags: ['Threads'],
        summary: "Clear the caller's unread counter for a thread",
        security: bearer,
        parameters: [{ name: 'threadId', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          '200': { description: 'Read state recorded' },
          '403': errorResponse,
          '404': errorResponse,
        },
      },
    },
    '/api/v1/media/presign': {
      post: {
        tags: ['Media'],
        summary: 'Request a short-lived upload URL for encrypted media',
        security: bearer,
        requestBody: jsonBody({
          type: 'object',
          required: ['fileType', 'fileName'],
          properties: {
            fileType: { type: 'string' },
            fileName: { type: 'string', maxLength: 255 },
            sizeBytes: { type: 'integer', minimum: 0 },
          },
        }),
        responses: { '200': { description: 'Presigned URL' }, '400': errorResponse },
      },
    },
    '/api/v1/media/upload/local': {
      put: {
        tags: ['Media'],
        summary: 'Local storage fallback: upload encrypted bytes',
        description:
          'Only used when no S3 credentials are configured. The presigned URL carries an HMAC-signed, expiring key; no bearer token is required. Uploads are capped at 25 MiB and accepted once.',
        parameters: [
          { name: 'key', in: 'query', required: true, schema: { type: 'string' } },
          { name: 'exp', in: 'query', required: true, schema: { type: 'integer' } },
          { name: 'sig', in: 'query', required: true, schema: { type: 'string' } },
        ],
        requestBody: {
          required: true,
          content: { 'application/octet-stream': { schema: { type: 'string', format: 'binary' } } },
        },
        responses: {
          '200': { description: 'Stored' },
          '403': errorResponse,
          '404': errorResponse,
          '409': errorResponse,
          '413': errorResponse,
        },
      },
    },
    '/api/v1/media/download/local': {
      get: {
        tags: ['Media'],
        summary: 'Local storage fallback: download encrypted bytes',
        description:
          'Only used when no S3 credentials are configured. Access is granted by the HMAC-signed, expiring query string issued at presign time.',
        parameters: [
          { name: 'key', in: 'query', required: true, schema: { type: 'string' } },
          { name: 'exp', in: 'query', required: true, schema: { type: 'integer' } },
          { name: 'sig', in: 'query', required: true, schema: { type: 'string' } },
        ],
        responses: {
          '200': {
            description: 'Ciphertext bytes',
            content: {
              'application/octet-stream': { schema: { type: 'string', format: 'binary' } },
            },
          },
          '403': errorResponse,
          '404': errorResponse,
        },
      },
    },
    '/api/v1/media/{mediaId}': {
      get: {
        tags: ['Media'],
        summary: 'Metadata and short-lived download URL for owned media',
        security: bearer,
        parameters: [{ name: 'mediaId', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          '200': { description: 'Media metadata' },
          '403': errorResponse,
          '404': errorResponse,
        },
      },
    },
  },
} as const;

export type OpenApiDocument = typeof openApiDocument;
