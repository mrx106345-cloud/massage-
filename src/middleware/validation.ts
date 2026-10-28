/**
 * Input validation middleware.
 *
 * Provides:
 * - Schema-based validation using express-validator
 * - Consistent error formatting
 * - Type-safe validated data access
 */

import { body, param, query, validationResult, type ValidationChain } from 'express-validator';
import { type Response, type NextFunction, type Request } from 'express';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ValidationError {
  field: string;
  message: string;
  value: unknown;
}

// ---------------------------------------------------------------------------
// Validation middleware factory
// ---------------------------------------------------------------------------

export function validate(...validators: ValidationChain[]) {
  return async (req: Request, res: Response, next: NextFunction) => {
    // Run all validators
    await Promise.all(validators.map((v) => v.run(req)));

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const formattedErrors: ValidationError[] = (
        errors.array() as Array<{
          path: string;
          msg: string;
          value: unknown;
        }>
      ).map((err) => ({
        field: err.path,
        message: err.msg,
        value: err.value,
      }));

      return res.status(400).json({
        error: 'validation failed',
        errors: formattedErrors,
      });
    }

    // Attach validated data to request

    const mapped = errors.mapped();
    if (mapped && typeof mapped === 'object' && !Array.isArray(mapped)) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (req as any).validatedData = mapped;
    }
    next();
  };
}

// ---------------------------------------------------------------------------
// Convenience validators
// ---------------------------------------------------------------------------

export const validator = {
  body: body,
  param: param,
  query: query,

  email: body('email').isEmail().withMessage('must be a valid email address').normalizeEmail(),

  username: body('username')
    .trim()
    .isLength({ min: 1, max: 64 })
    .withMessage('must be 1-64 characters')
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('can only contain letters, numbers, underscores, and hyphens'),

  password: body('password')
    .trim()
    .isLength({ min: 8, max: 128 })
    .withMessage('must be 8-128 characters'),

  groupName: body('groupName')
    .trim()
    .isLength({ min: 1, max: 128 })
    .withMessage('must be 1-128 characters'),

  uuid: body('id').optional().isUUID().withMessage('must be a valid UUID'),

  requiredFields: (...fields: string[]) => {
    return fields.map((field) => body(field).trim().notEmpty().withMessage(`${field} is required`));
  },
};

// ---------------------------------------------------------------------------
// Sanitization helpers
// ---------------------------------------------------------------------------

/**
 * Trim whitespace from input.
 * Note: This is basic sanitization. Use a proper library for XSS prevention.
 */
export function sanitizeInput(input: string): string {
  return input.trim();
}

/**
 * Limit ID length for safety.
 */
export function sanitizeId(id: string): string {
  return id.trim().slice(0, 36);
}

/**
 * Sanitize search query by removing dangerous characters.
 */
export function sanitizeSearchQuery(q: string): string {
  return q
    .trim()
    .slice(0, 100)
    .replace(/['";\\]/g, '');
}
