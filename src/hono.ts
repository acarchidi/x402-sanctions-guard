/**
 * Hono middleware (Node, Bun, Deno, Cloudflare Workers). Register it BEFORE the
 * x402 payment middleware:
 *
 *   app.use('*', sanctionsGuard({ privateKey: c.env.SCREENING_KEY }));
 */
import type { MiddlewareHandler } from 'hono';
import { createSanctionsGuard, refusalBody, type SanctionsGuardOptions } from './guard.js';

export function sanctionsGuard(opts: SanctionsGuardOptions = {}): MiddlewareHandler {
  const guard = createSanctionsGuard(opts);
  return async (c, next) => {
    const d = await guard.check(c.req.raw.headers);
    if (!d.allowed) return c.json(refusalBody(d), 403);
    await next();
  };
}
