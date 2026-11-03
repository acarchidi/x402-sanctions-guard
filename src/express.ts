/**
 * Express middleware. Mount it BEFORE the x402 payment middleware so a refused
 * payer is turned away before their payment is verified or settled:
 *
 *   app.use(sanctionsGuard({ privateKey: process.env.SCREENING_KEY as `0x${string}` }));
 *   app.use(paymentMiddleware(...));
 */
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { createSanctionsGuard, refusalBody, type SanctionsGuardOptions } from './guard.js';

export function sanctionsGuard(opts: SanctionsGuardOptions = {}): RequestHandler {
  const guard = createSanctionsGuard(opts);
  return async (req: Request, res: Response, next: NextFunction) => {
    const d = await guard.check(req.headers);
    if (d.allowed) return next();
    res.status(403).json(refusalBody(d));
  };
}
