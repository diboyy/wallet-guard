# Wallet Guard — pre-signing transaction auditor

**Agent Games (zkVerify) — Wildcard track entry.**

## What it is

Wallet Guard audits an EVM transaction **before you sign it** and tells you
whether it is safe. You paste the destination address, the calldata and the
value; it decodes the call, checks the target contract, and returns a verdict
— **SAFE**, **CAUTION** or **BLOCK** — with a 0–100 risk score and
plain-language reasons.

## Who it helps

Anyone who signs EVM transactions — especially BSC users claiming free mints,
approving tokens for marketplaces, or interacting with new contracts. The
classic wallet drains all start the same way: an unlimited `approve()` or a
`setApprovalForAll(true)` signed without reading the calldata. Wallet Guard
reads it for you, in seconds, before anything is signed.

## How to run

```bash
node server.js            # listens on http://0.0.0.0:8000
PORT=3000 node server.js  # or pick your own port
```

Requirements: Node.js 18+. **No dependencies to install, no API keys, no
accounts, no secrets.** Outbound checks use only public endpoints
(Sourcify, BscScan, public BSC RPCs).

Endpoints:

- `GET /` — demo page: a form to paste a transaction and see the verdict.
- `GET /health` — `{"status":"ok"}`.
- `POST /audit` — JSON in, JSON out.

### `POST /audit`

Request:

```json
{
  "chainId": 56,
  "to": "0x55d398326f99059fF775485246999027B3197955",
  "from": "0xD5Dd6810f25fd329Ffc0530Ef09a0a66d3E7D682",
  "value": "0",
  "data": "0x095ea7b3..."
}
```

Response:

```json
{
  "verdict": "BLOCK",
  "score": 75,
  "reasons": [
    { "level": "info", "message": "Target contract source is verified ..." },
    { "level": "high", "message": "UNLIMITED approval: spender 0x1111... would be allowed to move ALL of this token ..." }
  ],
  "checks": { "chainId": 56, "target": "0x55d3...", "call": { "kind": "approve", "...": "..." }, "...": "..." },
  "recommendation": "Do not sign this transaction. ..."
}
```

## What it checks

1. **Call decoding** — the 4-byte selector is matched against the common
   dangerous calls: `approve`, `setApprovalForAll`, `transfer`,
   `transferFrom`, and common `mint`/`claim`/`buy` shapes. Unknown selectors
   are reported as opaque, never guessed.
2. **Approval scope** — unlimited (`type(uint256).max`) and extremely large
   approvals, `setApprovalForAll(true)`, zero-address spenders/operators,
   self-approvals.
3. **Contract vs EOA** — a public BSC RPC (`eth_getCode`) tells whether the
   target holds code. Calldata aimed at an EOA is flagged; a plain transfer
   to an EOA is normal.
4. **Verification** — the target's source verification is checked on
   Sourcify (public API v2, no key) with BscScan's public endpoint as a
   secondary signal. Unverified contracts raise the risk.
5. **Value** — native value attached to a contract call is flagged; a plain
   transfer with no calldata is not.

Scoring: 0–29 **SAFE**, 30–69 **CAUTION**, 70–100 **BLOCK**.

## Example audits (actually run, 2026-11-16)

Target contracts: BSC USDT `0x55d3…7955` (verified), Agent Cards NFT
`0x19f1…FACd` (verified), Pokechain market `0x3399…1a7` (unverified).
Spender/operator addresses are illustrative (`0x1111…`, `0x2222…`).

**1. Unlimited approve — BLOCK (75/100), ~2.4s**

```bash
curl -X POST http://localhost:8000/audit -H 'Content-Type: application/json' -d '{
  "chainId": 56, "to": "0x55d398326f99059fF775485246999027B3197955",
  "from": "0xD5Dd6810f25fd329Ffc0530Ef09a0a66d3E7D682", "value": "0",
  "data": "0x095ea7b30000000000000000000000001111111111111111111111111111111111111111ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
}'
```

**2. Limited approve (1,000 units) — SAFE (5/100), ~0.6s**

Same call, amount `...00000000000000000000000000000000000000000000000000000000000003e8`.

**3. setApprovalForAll(true) — CAUTION (55/100), ~1.2s**

```bash
curl -X POST http://localhost:8000/audit -H 'Content-Type: application/json' -d '{
  "chainId": 56, "to": "0x19f125dA1985033f102CA7746Cbd1F6f512CFACd",
  "from": "0xD5Dd6810f25fd329Ffc0530Ef09a0a66d3E7D682", "value": "0",
  "data": "0xa22cb46500000000000000000000000022222222222222222222222222222222222222220000000000000000000000000000000000000000000000000000000000000001"
}'
```

(On an *unverified* contract the same call scores 75 — BLOCK.)

**4. Plain transfer, 0.01 BNB to an EOA — SAFE (0/100), ~0.1s**

```bash
curl -X POST http://localhost:8000/audit -H 'Content-Type: application/json' -d '{
  "chainId": 56, "to": "0x4444444444444444444444444444444444444444",
  "from": "0xD5Dd6810f25fd329Ffc0530Ef09a0a66d3E7D682",
  "value": "10000000000000000", "data": "0x"
}'
```

**5. Limited approve on an UNVERIFIED contract — SAFE (25/100), ~1.2s**

Target `0x3399E3AC0D6aA973a00D47Ff52072906841ee1a7`, approve 1,000,000 units.
Flagged "Target contract is UNVERIFIED" (+20) but bounded, so it stays SAFE
with a clear warning.

**6. Unknown selector on a verified contract — SAFE (15/100), ~0.7s**

Data `0xdeadbeef...` on USDT: "Unknown function selector — Wallet Guard
cannot decode what this call does. Treat it as opaque."

## What it can and cannot do

Can: decode the common approval/transfer/mint calls; tell a contract from an
EOA; check source verification; flag unlimited and collection-wide approvals,
zero-address recipients, value attached to calls, and opaque selectors.

Cannot: read the intent of an unknown contract; detect a verified contract
that is nonetheless malicious (verification proves the code matches the
source, not that the source is honest); replace checking that an address is
the official one. On-chain code checks currently cover BSC (chain 56) only —
other chains report the code check as unavailable rather than guessing.

## Notes on the external checks

- **Sourcify** is the primary verification source (API v2, no key). In the
  test runs above it correctly reported USDT and Agent Cards as verified and
  the Pokechain market contract as unverified.
- **BscScan** is a secondary signal only: without an API key its public
  endpoint is usually rate-limited or key-gated, so it often reports
  "unavailable". That never blocks a transaction on its own.
- **Public RPCs** (`bsc-dataseed.binance.org`, `bsc-dataseed1.ninicoin.io`)
  are queried in parallel and the first success wins.
- **If an external check fails** (timeout, unreachable, bad response) the
  audit reports it as "unavailable" and adds only a small risk penalty. A
  network error alone never produces a BLOCK. Bad input, on the other hand —
  a missing/malformed `to`, non-hex calldata, an unparsable value — is a
  BLOCK, because the auditor cannot do its job at all.

## Files

- `server.js` — the whole service (one file, Node stdlib + global fetch).
- `WRITEUP.md` — use case, build context, key decisions, limitations.
- `LICENSE` — MIT.

## About this entry

Built for the Agent Games Season 01 Wildcard track (zkVerify). It does not
use zkVerify proofs (optional for Wildcard) and it never signs, holds keys,
or broadcasts anything — it only advises the human who decides. The public
HTTPS endpoint is deployed separately from this repo.
