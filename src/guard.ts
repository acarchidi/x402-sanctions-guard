/**
 * Decide whether to accept a payer, using AgentForge's address screening
 * (OFAC SDN sanctions + known scam/phishing wallets), with a per-payer cache
 * so each wallet is screened at most once per TTL.
 */

import { AgentForge, type AgentForgeOptions } from 'agentforge-tools';
import { payerFromPaymentHeader, paymentHeaderFrom, type Payer } from './payer.js';

export type Verdict = 'block' | 'caution' | 'no_known_issues';

export interface Decision {
  allowed: boolean;
  payer: Payer | null;
  verdict?: Verdict;
  reasons: string[];
  /** 'cache' | 'agentforge' | 'allowlist' | 'no-payment' | 'error' */
  source: string;
}

export interface SanctionsGuardOptions extends AgentForgeOptions {
  /** Use an existing client instead of building one from privateKey/fetch. */
  client?: AgentForge;
  /**
   * Verdicts to refuse. Default ['block'] (sanctioned or known scam wallets).
   * Adding 'caution' also refuses brand-new wallets — note that many x402
   * payers are legitimately new, since x402 payments are gasless signatures.
   */
  refuse?: Verdict[];
  /** Re-screen a payer after this long. Default 24h. */
  cacheTtlMs?: number;
  /** If AgentForge can't be reached: true = let the payment through (default), false = refuse it. */
  failOpen?: boolean;
  /** Addresses that are always allowed (case-insensitive for EVM). */
  allowlist?: string[];
  /** Observe every decision (logging, metrics). */
  onDecision?: (d: Decision) => void;
}

const key = (p: Payer) => (p.chain === 'solana' ? p.address : p.address.toLowerCase());

export function createSanctionsGuard(opts: SanctionsGuardOptions = {}) {
  const client = opts.client ?? new AgentForge(opts);
  const refuse = new Set<Verdict>(opts.refuse ?? ['block']);
  const ttl = opts.cacheTtlMs ?? 24 * 3600_000;
  const failOpen = opts.failOpen ?? true;
  const allow = new Set((opts.allowlist ?? []).map((a) => (a.startsWith('0x') ? a.toLowerCase() : a)));
  const cache = new Map<string, { at: number; verdict: Verdict; reasons: string[] }>();
  const inflight = new Map<string, Promise<{ verdict: Verdict; reasons: string[] }>>();

  const done = (d: Decision) => {
    opts.onDecision?.(d);
    return d;
  };

  async function screen(payer: Payer): Promise<{ verdict: Verdict; reasons: string[] }> {
    const res = (await client.checkAddresses({ addresses: [{ address: payer.address, chain: payer.chain }], chain: payer.chain })) as {
      results?: Array<{ verdict: Verdict; reasons: string[] }>;
    };
    const r = res.results?.[0];
    if (!r) throw new Error('AgentForge returned no result');
    return { verdict: r.verdict, reasons: r.reasons };
  }

  /** Screen the payer of a request. Requests without an x402 payment header pass through untouched. */
  async function check(headers: Headers | Record<string, string | string[] | undefined>): Promise<Decision> {
    const payer = payerFromPaymentHeader(paymentHeaderFrom(headers));
    if (!payer) return done({ allowed: true, payer: null, reasons: [], source: 'no-payment' });
    const k = key(payer);
    if (allow.has(k)) return done({ allowed: true, payer, reasons: ['allowlisted'], source: 'allowlist' });

    const hit = cache.get(k);
    if (hit && Date.now() - hit.at < ttl) {
      return done({ allowed: !refuse.has(hit.verdict), payer, verdict: hit.verdict, reasons: hit.reasons, source: 'cache' });
    }
    try {
      let p = inflight.get(k);
      if (!p) {
        p = screen(payer).finally(() => inflight.delete(k));
        inflight.set(k, p);
      }
      const r = await p;
      cache.set(k, { at: Date.now(), ...r });
      return done({ allowed: !refuse.has(r.verdict), payer, verdict: r.verdict, reasons: r.reasons, source: 'agentforge' });
    } catch (e) {
      const reason = `screening unavailable: ${e instanceof Error ? e.message : String(e)}`;
      return done({ allowed: failOpen, payer, reasons: [reason], source: 'error' });
    }
  }

  return { check, clearCache: () => cache.clear() };
}

export type SanctionsGuard = ReturnType<typeof createSanctionsGuard>;

/** JSON body returned to a refused payer (HTTP 403, before any settlement). */
export function refusalBody(d: Decision) {
  return {
    error: 'PAYER_REFUSED',
    message: 'This payment cannot be accepted from this wallet. No funds were taken.',
    verdict: d.verdict,
    reasons: d.reasons,
  };
}
