import type { NextFunction, Request, RequestHandler, Response } from 'express';

/**
 * Express 4 does not forward rejected promises to the error handler, so an
 * async handler that throws leaves the request hanging until the client times
 * out. Wrap every async handler with this helper.
 *
 * Generic over the request type so handlers that rely on an augmented request
 * (e.g. `Request & AuthRequest`) can be wrapped without casts.
 */
export function asyncRoute<R extends Request = Request>(
  handler: (req: R, res: Response, next: NextFunction) => Promise<unknown> | unknown,
): RequestHandler {
  return (req, res, next) => {
    Promise.resolve(handler(req as R, res, next)).catch(next);
  };
}
