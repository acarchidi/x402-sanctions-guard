/**
 * Who is paying? Read the payer address straight from an x402 payment header,
 * before the payment is verified or settled.
 *
 * v2 clients send `PAYMENT-SIGNATURE`, v1 clients send `X-PAYMENT`; both are
 * base64 JSON. EVM exact payments (EIP-3009 or Permit2) carry the signer in the
 * payload; Solana exact payments carry a serialized transaction whose required
 * signers include the payer (the facilitator's fee payer is skipped).
 *
 * Portable: no Buffer, so it runs on Node, Bun, Deno, and Cloudflare Workers.
 */

export interface Payer {
  address: string;
  /** CAIP-2 network from the payment, e.g. "eip155:8453" or "solana:5eykt4…". */
  network?: string;
  /** AgentForge chain name for the network: "base", "ethereum", "solana", … */
  chain: 'ethereum' | 'base' | 'arbitrum' | 'optimism' | 'polygon' | 'solana';
}

const EVM_CHAINS: Record<string, Payer['chain']> = {
  'eip155:1': 'ethereum',
  'eip155:8453': 'base',
  'eip155:42161': 'arbitrum',
  'eip155:10': 'optimism',
  'eip155:137': 'polygon',
};

function decodeBase64(value: string): Uint8Array {
  const bin = atob(value);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function decodeBase64Json(value: string): Record<string, unknown> | null {
  try {
    return JSON.parse(new TextDecoder().decode(decodeBase64(value)));
  } catch {
    return null;
  }
}

/** Header lookup that works for Node (lowercase keys), Fetch `Headers`, and plain objects. */
export function paymentHeaderFrom(headers: Headers | Record<string, string | string[] | undefined>): string | undefined {
  if (typeof (headers as Headers).get === 'function') {
    const h = headers as Headers;
    return h.get('payment-signature') ?? h.get('x-payment') ?? undefined;
  }
  const h = headers as Record<string, string | string[] | undefined>;
  const v = h['payment-signature'] ?? h['PAYMENT-SIGNATURE'] ?? h['x-payment'] ?? h['X-PAYMENT'];
  return Array.isArray(v) ? v[0] : v;
}

export function payerFromPaymentHeader(header: string | undefined): Payer | null {
  if (!header) return null;
  const payload = decodeBase64Json(header);
  if (!payload) return null;

  const accepted = (payload.accepted ?? {}) as Record<string, unknown>;
  const network = (accepted.network ?? payload.network) as string | undefined;
  const inner = (payload.payload ?? {}) as Record<string, unknown>;
  const extra = (accepted.extra ?? {}) as Record<string, unknown>;

  const auth = inner.authorization as Record<string, unknown> | undefined;
  const permit2 = inner.permit2Authorization as Record<string, unknown> | undefined;
  const evm = (typeof auth?.from === 'string' && auth.from)
    || (typeof permit2?.from === 'string' && permit2.from)
    || (typeof permit2?.owner === 'string' && permit2.owner)
    || undefined;
  if (evm) return { address: evm, network, chain: (network && EVM_CHAINS[network]) || 'base' };

  if (typeof inner.transaction === 'string') {
    const sol = solanaPayer(inner.transaction, extra.feePayer as string | undefined);
    if (sol) return { address: sol, network, chain: 'solana' };
  }
  return null;
}

/** Required signer keys of a legacy or v0 Solana transaction, minus the fee payer. */
function solanaPayer(txBase64: string, feePayer?: string): string | undefined {
  try {
    const bytes = decodeBase64(txBase64);
    let offset = 0;
    const readShortVec = () => {
      let len = 0;
      let size = 0;
      for (;;) {
        const b = bytes[offset++];
        len |= (b & 0x7f) << (size * 7);
        size += 1;
        if ((b & 0x80) === 0) break;
      }
      return len;
    };
    // Read the count first: `offset += readShortVec() * 64` would use the stale offset.
    const signatureCount = readShortVec();
    offset += signatureCount * 64;
    if ((bytes[offset] & 0x80) !== 0) offset += 1; // versioned message prefix
    const required = bytes[offset];
    offset += 3;
    const keyCount = readShortVec();
    const keys: string[] = [];
    for (let i = 0; i < keyCount && i < required; i++) keys.push(base58(bytes.subarray(offset + i * 32, offset + (i + 1) * 32)));
    return keys.find((k) => k !== feePayer) ?? keys[0];
  } catch {
    return undefined;
  }
}

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58(buf: Uint8Array): string {
  let num = 0n;
  for (const b of buf) num = (num << 8n) + BigInt(b);
  let out = '';
  while (num > 0n) {
    out = ALPHABET[Number(num % 58n)] + out;
    num /= 58n;
  }
  for (const b of buf) {
    if (b !== 0) break;
    out = `1${out}`;
  }
  return out;
}
