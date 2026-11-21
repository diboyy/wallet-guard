// Wallet Guard — browser-compatible audit core (static demo).
// A port of the audit logic in server.js (same file's audit core, kept
// identical: same SELECTORS, scoring, reasons, verdict thresholds and
// recommendation text). No Node APIs, no server, no dependencies, no keys.
// The audit runs entirely in the browser: it calls public BSC RPCs,
// Sourcify and BscScan directly from the page, and signs nothing.
//
// External checks degrade to "unavailable" on any failure (timeout,
// network error, CORS block, non-JSON) — never a crash, and never alone
// a reason to BLOCK. Bad input (missing/malformed "to", non-hex calldata,
// unparsable value) is a BLOCK, exactly as in server.js.
//
// Exposes window.WalletGuard = { audit }.

'use strict';

const FETCH_TIMEOUT_MS = 6000;

// Public BSC JSON-RPC endpoints (no key). Tried in parallel; first success wins.
const BSC_RPCS = [
  'https://bsc-dataseed.binance.org/',
  'https://bsc-dataseed1.ninicoin.io/',
];

const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';
const MAX_UINT256 = BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');

const SELECTORS = {
  '0x095ea7b3': { name: 'approve', params: ['address', 'uint256'] },
  '0xa22cb465': { name: 'setApprovalForAll', params: ['address', 'bool'] },
  '0xa9059cbb': { name: 'transfer', params: ['address', 'uint256'] },
  '0x23b872dd': { name: 'transferFrom', params: ['address', 'address', 'uint256'] },
  '0xa0712d68': { name: 'mint', params: ['uint256'] },
  '0x6a627842': { name: 'mint', params: ['address'] },
  '0x40c10f19': { name: 'mint', params: ['address', 'uint256'] },
  '0x4e71d92d': { name: 'claim', params: [] },
  '0x1249c58b': { name: 'mint', params: [] },
  '0x9b9b9d12': { name: 'claimFree', params: [] },
  '0x5c19a95c': { name: 'mint', params: ['address', 'uint256', 'uint256'] },
  '0x84bbeb12': { name: 'mint', params: ['address', 'uint256', 'uint256', 'bytes'] },
  '0x8f3b57f0': { name: 'safeMint', params: ['address'] },
  '0x2db9d1a3': { name: 'buy', params: [] },
};

// ---------------------------------------------------------------- helpers

function isAddress(v) {
  return typeof v === 'string' && /^0x[0-9a-fA-F]{40}$/.test(v);
}

function isHex(v) {
  return typeof v === 'string' && /^0x([0-9a-fA-F]*)$/.test(v);
}

function checksumLoose(addr) {
  return addr.toLowerCase();
}

function parseWei(value) {
  if (value === undefined || value === null || value === '') return 0n;
  try {
    if (typeof value === 'string' && value.startsWith('0x')) return BigInt(value);
    return BigInt(String(value));
  } catch (_) {
    return null; // unparsable
  }
}

function weiToBnb(wei) {
  // human-readable BNB with up to 6 decimals, no floating point
  const whole = wei / 1000000000000000000n;
  const frac = wei % 1000000000000000000n;
  const fracStr = frac.toString().padStart(18, '0').slice(0, 6).replace(/0+$/, '');
  return fracStr ? `${whole}.${fracStr}` : `${whole}`;
}

async function httpsJson(url, { method = 'GET', body = null, timeoutMs = FETCH_TIMEOUT_MS } = {}) {
  // Browser fetch. No User-Agent header: browsers forbid setting it, and
  // none of these endpoints needs it. Anything that fails — timeout,
  // network error, CORS block, non-JSON — resolves as {ok:false} so the
  // caller can report the check "unavailable" instead of crashing.
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method,
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    const text = await res.text();
    try {
      return { ok: res.status >= 200 && res.status < 300, status: res.status, json: JSON.parse(text) };
    } catch (_) {
      return { ok: false, status: res.status, error: 'non-json response' };
    }
  } catch (e) {
    return { ok: false, error: e.name === 'AbortError' ? 'timeout' : (e.message || 'fetch failed') };
  } finally {
    clearTimeout(timer);
  }
}

// ------------------------------------------------------- external checks

async function getCode(chainId, address) {
  // Only BSC (56) has a configured public RPC here; other chains are reported
  // as "code check unavailable" rather than guessed.
  if (chainId !== 56) return { available: false, reason: `no public RPC configured for chain ${chainId}` };
  // Query the public RPCs in parallel and take the FIRST success — waiting
  // for the slowest one would make every audit as slow as the worst endpoint.
  return new Promise((resolve) => {
    let done = false;
    let pending = BSC_RPCS.length;
    const timer = setTimeout(() => {
      if (!done) { done = true; resolve({ available: false, reason: 'public RPC unreachable' }); }
    }, FETCH_TIMEOUT_MS + 1000);
    const finish = (v) => { if (!done) { done = true; clearTimeout(timer); resolve(v); } };
    for (const rpc of BSC_RPCS) {
      httpsJson(rpc, {
        method: 'POST',
        body: { jsonrpc: '2.0', id: 1, method: 'eth_getCode', params: [address, 'latest'] },
      }).then((r) => {
        if (done) return;
        if (r.ok && r.json && typeof r.json.result === 'string') {
          const code = r.json.result;
          finish({ available: true, isContract: code !== '0x' && code.length > 2, codeLength: code.length > 2 ? (code.length - 2) / 2 : 0 });
        } else if (--pending === 0) {
          finish({ available: false, reason: 'public RPC unreachable' });
        }
      });
    }
  });
}

async function checkSourcify(chainId, address) {
  // Sourcify API v2 (v1 was removed): GET /v2/contract/{chainId}/{address}
  // 200 + a match  -> verified; 404 + match null -> unverified; anything
  // else (timeout, 4xx/5xx) -> unavailable, reported as such.
  const url = `https://sourcify.dev/server/v2/contract/${chainId}/${address}`;
  const r = await httpsJson(url);
  if (r.json && typeof r.json === 'object' && 'match' in r.json) {
    if (r.json.match) {
      return { available: true, verified: true, status: String(r.json.match) };
    }
    return { available: true, verified: false, status: 'unverified' };
  }
  return { available: false, reason: r.error || `sourcify http ${r.status || '?'}` };
}

async function checkBscScan(address) {
  // BscScan's public API without a key: usually rate-limited / key-gated.
  // We try it as a secondary signal only; failure is "unavailable", not a risk.
  const url = `https://api.bscscan.com/api?module=contract&action=getsourcecode&address=${address}`;
  const r = await httpsJson(url);
  if (!r.ok || !r.json || !Array.isArray(r.json.result) || r.json.result.length === 0) {
    return { available: false, reason: 'bscscan unreachable or key-gated' };
  }
  const src = r.json.result[0];
  const verified = src && src.SourceCode && src.SourceCode !== '';
  return { available: true, verified: !!verified };
}

// ------------------------------------------------------- calldata decode

function decodeCalldata(data) {
  if (!data || data === '0x' || data.length < 10) return { kind: 'no-data' };
  const selector = data.slice(0, 10).toLowerCase();
  const spec = SELECTORS[selector];
  if (!spec) return { kind: 'unknown', selector };
  const words = [];
  const body = data.slice(10);
  for (let i = 0; i + 64 <= body.length; i += 64) words.push(body.slice(i, i + 64));
  const args = {};
  const decoded = [];
  spec.params.forEach((type, i) => {
    const w = words[i];
    if (w === undefined) return;
    if (type === 'address') {
      const a = '0x' + w.slice(24);
      decoded.push(a);
      args[`arg${i}`] = a;
    } else if (type === 'uint256') {
      let v = null;
      try { v = BigInt('0x' + w); } catch (_) { v = null; }
      decoded.push(v);
      args[`arg${i}`] = v === null ? null : v.toString();
    } else if (type === 'bool') {
      const b = w.slice(-1) === '1';
      decoded.push(b);
      args[`arg${i}`] = b;
    }
  });
  return { kind: 'known', selector, name: spec.name, params: spec.params, args: decoded, rawArgs: args };
}

// ------------------------------------------------------- audit core

async function audit(input) {
  const reasons = []; // {level: 'high'|'medium'|'low'|'info', message}
  const checks = {};
  let score = 0;
  const add = (points, level, message) => {
    score += points;
    reasons.push({ level, message });
  };

  const chainId = Number(input.chainId) || 56;
  const to = typeof input.to === 'string' ? input.to : '';
  const from = typeof input.from === 'string' ? input.from : '';
  const data = typeof input.data === 'string' ? input.data : '0x';
  const valueWei = parseWei(input.value);

  checks.chainId = chainId;
  checks.target = to || null;

  // --- input validation
  if (!isAddress(to)) {
    return {
      verdict: 'BLOCK', score: 100,
      reasons: [{ level: 'high', message: 'Missing or invalid "to" address — cannot audit a transaction without a destination.' }],
      checks, recommendation: 'Do not sign: the destination address is missing or malformed.',
    };
  }
  if (data !== '0x' && !isHex(data)) {
    return {
      verdict: 'BLOCK', score: 100,
      reasons: [{ level: 'high', message: 'Calldata is not valid hex — cannot decode what this transaction does.' }],
      checks, recommendation: 'Do not sign: the calldata cannot be read.',
    };
  }
  if (valueWei === null) {
    return {
      verdict: 'BLOCK', score: 100,
      reasons: [{ level: 'high', message: 'Value is not a valid wei amount — cannot judge how much native currency this sends.' }],
      checks, recommendation: 'Do not sign: the value field is malformed.',
    };
  }
  checks.valueWei = valueWei.toString();
  checks.valueBnb = weiToBnb(valueWei);

  // --- decode the call
  const call = decodeCalldata(data);
  checks.call = call.kind === 'no-data'
    ? { kind: 'plain-transfer' }
    : call.kind === 'unknown'
      ? { kind: 'unknown', selector: call.selector }
      : { kind: call.name, selector: call.selector, args: call.rawArgs };

  // --- on-chain code: contract vs EOA
  const code = await getCode(chainId, to);
  checks.targetIsContract = code.available ? code.isContract : null;
  checks.codeCheck = code.available ? 'ok' : `unavailable (${code.reason})`;
  if (!code.available) {
    add(5, 'low', `Could not read the target's on-chain code (${code.reason}); contract-vs-EOA check skipped.`);
  } else if (!code.isContract) {
    checks.targetType = 'EOA';
    if (call.kind !== 'no-data') {
      add(30, 'medium', 'Calldata targets an externally-owned account (no code). A contract call to an EOA does nothing useful and is a common spoof pattern.');
    } else {
      reasons.push({ level: 'info', message: 'Plain native transfer to an externally-owned account (no contract involved).' });
    }
  } else {
    checks.targetType = 'contract';
  }

  // --- verification (Sourcify primary, BscScan secondary)
  let verified = null;
  let verificationNote = null;
  if (checks.targetType === 'contract') {
    const [s, b] = await Promise.all([checkSourcify(chainId, to), checkBscScan(to)]);
    checks.sourcify = s.available ? (s.verified ? `verified (${s.status})` : 'unverified') : `unavailable (${s.reason})`;
    if (s.available) verified = s.verified;
    checks.bscscan = b.available ? (b.verified ? 'verified' : 'unverified') : `unavailable (${b.reason})`;
    if (b.available && verified === null) verified = b.verified;
    if (verified === true) {
      reasons.push({ level: 'info', message: 'Target contract source is verified (Sourcify/BscScan) — its code matches what is deployed.' });
    } else if (verified === false) {
      add(20, 'medium', 'Target contract is UNVERIFIED — its source code is not public, so what it does cannot be checked by reading it.');
    } else {
      verificationNote = 'Contract verification status could not be checked (Sourcify/BscScan unreachable) — treated as unknown, not as safe.';
      add(5, 'low', verificationNote);
    }
    checks.verified = verified;
  }

  // --- value attached
  if (valueWei > 0n) {
    if (call.kind === 'no-data') {
      reasons.push({ level: 'info', message: `Sends ${checks.valueBnb} BNB with no calldata (plain transfer).` });
    } else {
      add(25, 'medium', `Sends ${checks.valueBnb} BNB along with a contract call — value attached to a call is how paid mints and purchase traps move money.`);
      if (valueWei > 1000000000000000000n) add(10, 'medium', 'Value is over 1 BNB — a large amount to attach to a contract call.');
    }
  }

  // --- per-call analysis
  if (call.kind === 'known') {
    if (call.name === 'approve') {
      const spender = call.args[0];
      const amount = call.args[1];
      checks.spender = spender;
      checks.approvalAmount = amount === null ? null : amount.toString();
      if (spender && checksumLoose(spender) === ZERO_ADDRESS) {
        add(25, 'high', 'Spender is the zero address — approving 0x0 is never useful and usually a mistake or a trap.');
      }
      if (from && spender && checksumLoose(spender) === checksumLoose(from)) {
        add(10, 'low', 'Spender is your own address — an approval to yourself is pointless.');
      }
      if (spender && checksumLoose(spender) === checksumLoose(to)) {
        add(10, 'low', 'Spender is the token contract itself — unusual; normally you approve a marketplace or router, not the token.');
      }
      if (amount === null) {
        add(10, 'low', 'Approval amount could not be decoded.');
      } else if (amount === MAX_UINT256) {
        add(75, 'high', `UNLIMITED approval: spender ${spender} would be allowed to move ALL of this token from your wallet, forever, until you revoke it.`);
      } else if (amount > 10n ** 30n) {
        add(40, 'high', `Approval amount is extremely large (${amount.toString()} units) — effectively unlimited for any realistic balance.`);
      } else {
        add(5, 'low', `Limited approval of ${amount.toString()} units to ${spender} — bounded, but still check that you trust the spender.`);
      }
    } else if (call.name === 'setApprovalForAll') {
      const operator = call.args[0];
      const approved = call.args[1];
      checks.operator = operator;
      checks.approved = approved;
      if (approved === true) {
        add(55, 'high', `setApprovalForAll(true) gives operator ${operator} control over ALL of your NFTs in this collection — the single most dangerous approval.`);
        if (operator && checksumLoose(operator) === ZERO_ADDRESS) {
          add(25, 'high', 'Operator is the zero address.');
        }
        if (from && operator && checksumLoose(operator) === checksumLoose(from)) {
          add(10, 'low', 'Operator is your own address — pointless.');
        }
      } else if (approved === false) {
        reasons.push({ level: 'info', message: 'setApprovalForAll(false) REVOKES an operator — this makes your wallet safer, not riskier.' });
      } else {
        add(10, 'low', 'setApprovalForAll flag could not be decoded.');
      }
    } else if (call.name === 'transfer') {
      const recipient = call.args[0];
      const amount = call.args[1];
      checks.recipient = recipient;
      checks.transferAmount = amount === null ? null : amount.toString();
      if (recipient && checksumLoose(recipient) === ZERO_ADDRESS) {
        add(40, 'high', 'Transfer recipient is the zero address — those tokens would be burned/lost.');
      } else {
        reasons.push({ level: 'info', message: `Plain token transfer of ${amount === null ? '?' : amount.toString()} units to ${recipient}.` });
      }
    } else if (call.name === 'transferFrom') {
      const sender = call.args[0];
      const recipient = call.args[1];
      const amount = call.args[2];
      checks.transferFrom = { from: sender, to: recipient, amount: amount === null ? null : amount.toString() };
      add(10, 'medium', `transferFrom moves ${amount === null ? '?' : amount.toString()} units from ${sender} to ${recipient} — only safe if you intended that exact movement.`);
      if (recipient && checksumLoose(recipient) === ZERO_ADDRESS) {
        add(40, 'high', 'transferFrom recipient is the zero address — those tokens would be burned/lost.');
      }
    } else if (call.name === 'mint' || call.name === 'safeMint' || call.name === 'claim' || call.name === 'claimFree' || call.name === 'buy') {
      add(15, 'medium', `This is a ${call.name}() call — mints and claims are where fake-mint contracts hide. Check the contract is the real one before signing.`);
      if (checks.targetType === 'contract' && verified === false) {
        add(15, 'medium', 'Mint/claim on an UNVERIFIED contract — the highest-risk combination for a fake mint.');
      }
    }
  } else if (call.kind === 'unknown') {
    add(15, 'medium', `Unknown function selector ${call.selector} — Wallet Guard cannot decode what this call does. Treat it as opaque.`);
  }

  // --- verdict
  score = Math.max(0, Math.min(100, score));
  const verdict = score >= 70 ? 'BLOCK' : score >= 30 ? 'CAUTION' : 'SAFE';
  const recommendation =
    verdict === 'BLOCK'
      ? 'Do not sign this transaction. It hands over unlimited or collection-wide control, or moves money to an unverified contract.'
      : verdict === 'CAUTION'
        ? 'Pause before signing: check the spender/operator and the contract address against the official source, and prefer a limited approval.'
        : 'Nothing dangerous detected in this call. Still confirm the address matches the official contract before signing.';
  return { verdict, score, reasons, checks, recommendation };
}

// Expose for the static demo page. In Node (parity test) `window` is
// stubbed as a plain object; fall back to globalThis otherwise.
(function expose(root) {
  root.WalletGuard = { audit };
})(typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : {}));
