import { describe, it, expect, vi } from 'vitest';
import express from 'express';
import request from 'supertest';
import { Hono } from 'hono';
import { createSanctionsGuard, payerFromPaymentHeader } from '../src/index.js';
import { sanctionsGuard as expressGuard } from '../src/express.js';
import { sanctionsGuard as honoGuard } from '../src/hono.js';

const b64 = (o: unknown) => btoa(JSON.stringify(o));
const evmHeader = (from: string, network = 'eip155:8453') =>
  b64({ x402Version: 2, accepted: { scheme: 'exact', network }, payload: { authorization: { from, to: '0xseller' }, signature: '0x' } });

const BAD = '0x0330070fd38ec3bb94f58fa55d40368271e9e54a';
const GOOD = '0x1111111111111111111111111111111111111111';

function fakeClient(verdicts: Record<string, string>) {
  return {
    checkAddresses: vi.fn(async ({ addresses }: { addresses: Array<{ address: string }> }) => ({
      results: addresses.map((a) => ({ verdict: verdicts[a.address.toLowerCase()] ?? 'no_known_issues', reasons: ['r'] })),
    })),
  } as any;
}

describe('payerFromPaymentHeader', () => {
  it('reads EIP-3009 and Permit2 payers and maps the chain', () => {
    expect(payerFromPaymentHeader(evmHeader(GOOD))).toMatchObject({ address: GOOD, chain: 'base' });
    expect(payerFromPaymentHeader(evmHeader(GOOD, 'eip155:1'))?.chain).toBe('ethereum');
    const permit2 = b64({ accepted: { network: 'eip155:8453' }, payload: { permit2Authorization: { from: GOOD } } });
    expect(payerFromPaymentHeader(permit2)?.address).toBe(GOOD);
  });

  it('reads the Solana payer, skipping the facilitator fee payer', () => {
    // legacy tx: 2 signatures, header [2,0,1], 3 keys: fee payer (all 0x00), payer (all 0xff), program
    const bytes = new Uint8Array(1 + 128 + 3 + 1 + 96);
    let o = 0;
    bytes[o++] = 2;
    o += 128;
    bytes.set([2, 0, 1], o);
    o += 3;
    bytes[o++] = 3;
    o += 32; // fee payer: zeros
    bytes.fill(0xff, o, o + 32);
    const tx = btoa(String.fromCharCode(...bytes));
    const header = b64({ accepted: { network: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp', extra: { feePayer: '11111111111111111111111111111111' } }, payload: { transaction: tx } });
    expect(payerFromPaymentHeader(header)).toMatchObject({ chain: 'solana', address: 'JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFG' });
  });

  it('returns null for missing or malformed headers', () => {
    expect(payerFromPaymentHeader(undefined)).toBeNull();
    expect(payerFromPaymentHeader('not base64 json')).toBeNull();
    expect(payerFromPaymentHeader(b64({ payload: {} }))).toBeNull();
  });
});

describe('createSanctionsGuard', () => {
  it('refuses block verdicts, allows caution by default, and caches per payer', async () => {
    const client = fakeClient({ [BAD]: 'block', [GOOD]: 'caution' });
    const guard = createSanctionsGuard({ client });
    expect(await guard.check({ 'payment-signature': evmHeader(BAD) })).toMatchObject({ allowed: false, verdict: 'block', source: 'agentforge' });
    expect(await guard.check({ 'payment-signature': evmHeader(GOOD) })).toMatchObject({ allowed: true, verdict: 'caution' });
    expect(await guard.check({ 'payment-signature': evmHeader(BAD.toUpperCase().replace('0X', '0x')) })).toMatchObject({ allowed: false, source: 'cache' });
    expect(client.checkAddresses).toHaveBeenCalledTimes(2);
  });

  it('can also refuse caution, and dedupes concurrent checks for one payer', async () => {
    const client = fakeClient({ [GOOD]: 'caution' });
    const guard = createSanctionsGuard({ client, refuse: ['block', 'caution'] });
    const [a, b] = await Promise.all([guard.check({ 'x-payment': evmHeader(GOOD) }), guard.check({ 'x-payment': evmHeader(GOOD) })]);
    expect(a.allowed).toBe(false);
    expect(b.allowed).toBe(false);
    expect(client.checkAddresses).toHaveBeenCalledTimes(1);
  });

  it('passes requests without a payment, honors the allowlist, and fails open or closed', async () => {
    const broken = { checkAddresses: vi.fn(async () => { throw new Error('down'); }) } as any;
    expect((await createSanctionsGuard({ client: broken }).check({})).source).toBe('no-payment');
    expect((await createSanctionsGuard({ client: broken, allowlist: [BAD.toUpperCase().replace('0X', '0x')] }).check({ 'x-payment': evmHeader(BAD) })).allowed).toBe(true);
    expect((await createSanctionsGuard({ client: broken }).check({ 'x-payment': evmHeader(GOOD) }))).toMatchObject({ allowed: true, source: 'error' });
    expect((await createSanctionsGuard({ client: broken, failOpen: false }).check({ 'x-payment': evmHeader(GOOD) })).allowed).toBe(false);
  });
});

describe('middleware', () => {
  it('Express: refuses a sanctioned payer with 403 before the paid handler runs', async () => {
    const handler = vi.fn((_req, res) => res.json({ ok: true }));
    const app = express();
    app.use(expressGuard({ client: fakeClient({ [BAD]: 'block' }) }));
    app.get('/paid', handler);
    const refused = await request(app).get('/paid').set('PAYMENT-SIGNATURE', evmHeader(BAD));
    expect(refused.status).toBe(403);
    expect(refused.body.error).toBe('PAYER_REFUSED');
    expect(handler).not.toHaveBeenCalled();
    expect((await request(app).get('/paid').set('PAYMENT-SIGNATURE', evmHeader(GOOD))).status).toBe(200);
    expect((await request(app).get('/paid')).status).toBe(200);
  });

  it('Hono: same behavior with Fetch headers', async () => {
    const app = new Hono();
    app.use('*', honoGuard({ client: fakeClient({ [BAD]: 'block' }) }));
    app.get('/paid', (c) => c.json({ ok: true }));
    expect((await app.request('/paid', { headers: { 'PAYMENT-SIGNATURE': evmHeader(BAD) } })).status).toBe(403);
    expect((await app.request('/paid', { headers: { 'PAYMENT-SIGNATURE': evmHeader(GOOD) } })).status).toBe(200);
  });
});
