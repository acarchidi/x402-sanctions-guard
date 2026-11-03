# x402-sanctions-guard

**Know who's paying before you take the money.** Drop-in Express / Hono middleware for x402 sellers that screens every payer wallet against OFAC sanctions and known scam/phishing wallets — and refuses them **before** their payment is verified or settled.

Selling an API over x402 means accepting USDC from wallets you know nothing about. Receiving funds from an OFAC-sanctioned address can be illegal for US persons, and scam wallets launder stolen funds through exactly these kinds of pay-per-call services. This middleware reads the payer straight from the x402 payment header and asks [AgentForge](https://agentforge-taupe.vercel.app) about it, once per wallet per day.

```bash
npm install x402-sanctions-guard
```

## Express

```ts
import express from 'express';
import { paymentMiddleware } from '@x402/express';
import { sanctionsGuard } from 'x402-sanctions-guard/express';

const app = express();
app.use(sanctionsGuard({ privateKey: process.env.SCREENING_KEY as `0x${string}` })); // 1. screen the payer
app.use(paymentMiddleware(/* your routes */));                                          // 2. then take payment
```

## Hono (Node, Bun, Deno, Cloudflare Workers)

```ts
import { sanctionsGuard } from 'x402-sanctions-guard/hono';

app.use('*', sanctionsGuard({ privateKey: env.SCREENING_KEY }));
```

A refused payer gets `403` with `{ "error": "PAYER_REFUSED", "verdict": "block", "reasons": [...] }` and is never charged. Requests without an x402 payment header (including the initial unpaid request that receives your `402`) pass straight through.

## What it costs

Each **new** payer wallet is screened once per day via AgentForge's `/v1/address-check`: **$0.003 USDC**, paid over x402 from `SCREENING_KEY` (any Base wallet holding a little USDC — gasless). Repeat payers within the TTL are served from an in-memory cache at no cost, and concurrent requests from one wallet share a single check.

## Options

| Option | Default | |
|---|---|---|
| `privateKey` / `fetch` / `client` | — | How screening calls are paid: a Base key, your own x402-paying fetch, or an `AgentForge` client |
| `refuse` | `['block']` | Verdicts to refuse. `block` = on a sanctions or scam list. Adding `'caution'` also refuses brand-new wallets — **not recommended**: x402 payments are gasless signatures, so many legitimate agent wallets have never sent a transaction |
| `cacheTtlMs` | 24h | Re-screen a payer after this long |
| `failOpen` | `true` | If screening is unreachable, let the payment through (`false` refuses it) |
| `allowlist` | `[]` | Wallets always allowed |
| `maxPaymentUsd` | 0.5 | Cap on any single screening payment |
| `onDecision` | — | Callback for logging/metrics: `{ allowed, payer, verdict, reasons, source }` |

## Framework-agnostic

```ts
import { createSanctionsGuard } from 'x402-sanctions-guard';

const guard = createSanctionsGuard({ privateKey });
const decision = await guard.check(request.headers); // Fetch Headers or a Node headers object
if (!decision.allowed) return new Response('Payer refused', { status: 403 });
```

`payerFromPaymentHeader()` is exported too: it extracts the payer from x402 v1/v2 headers for EVM (EIP-3009 and Permit2) and Solana payments, without verifying anything.

## Data sources

OFAC SDN digital-currency addresses and the MyEtherWallet scam/phishing darklist, refreshed monthly, plus AgentForge's labeled-contract registry. A `no_known_issues` verdict is not a guarantee; this is a screening layer, not legal advice.

MIT licensed.
