# Wallet Guard — build write-up

## The problem

Every day, EVM users sign transactions they do not fully understand: token
approvals, NFT operator approvals, "free mint" calls. A single unlimited
`approve()` hands a contract the right to drain a whole token balance; a
single `setApprovalForAll(true)` hands an operator every NFT in a collection.
Fake mint contracts and phishing sites rely on the fact that the wallet's
sign screen shows an opaque hex blob. By the time the user realises what
happened, the funds are gone and the approval is already on-chain.

## What Wallet Guard does

Wallet Guard is a small HTTP service that audits a proposed transaction
**before** the user signs it. Send it the destination, the calldata and the
value; it returns a verdict — SAFE, CAUTION or BLOCK — a 0–100 risk score,
and a plain-language list of reasons.

The audit pipeline, in order:

1. **Decode.** The 4-byte selector is matched against the common dangerous
   calls (`approve`, `setApprovalForAll`, `transfer`, `transferFrom`, and
   common `mint`/`claim`/`buy` shapes). Parameters are decoded from the
   calldata words. Unknown selectors are reported as opaque, never guessed.
2. **Contract vs EOA.** A public BSC JSON-RPC endpoint (`eth_getCode`) tells
   whether the target holds code. A plain transfer to an EOA is normal;
   calldata aimed at an EOA is a spoof pattern.
3. **Verification.** The target's source verification is checked on Sourcify
   (public API, no key) with BscScan's public endpoint as a secondary signal.
   Unverified contracts raise the risk; if both sources are unreachable the
   check is reported "unavailable" and adds only a small penalty — a network
   error alone never blocks a transaction.
4. **Value.** Native value attached to a contract call is flagged (that is
   how paid mints and purchase traps move money); a plain transfer with no
   calldata is not.
5. **Approval scope.** Unlimited (`type(uint256).max`) and extremely large
   approvals, `setApprovalForAll(true)`, zero-address spenders/operators,
   and self-approvals are each scored. The score maps to the verdict:
   0–29 SAFE, 30–69 CAUTION, 70–100 BLOCK.

## Key decisions

- **No dependencies, no keys, no accounts.** Node.js standard library only,
  public endpoints only. Anyone can run it with one command and nothing to
  configure. This also keeps the entry honest: there is no hidden data source.
- **Fail open on network errors, fail closed on bad input.** A missing or
  malformed `to`, bad calldata hex, or an unparsable value is a BLOCK — the
  auditor cannot do its job, so it says so. But a Sourcify or RPC timeout is
  only "unavailable": punishing the user for our network problem would make
  the tool unusable and teach people to ignore it.
- **No blocklist.** The agent never claims an address is "known bad" unless
  it can verify that from a public source at audit time. Invented reputation
  data would be worse than none — it creates false confidence.
- **The verdict is advice, not a signature gate.** Wallet Guard never signs,
  never holds keys, never broadcasts. It informs the human who still decides.

## What it can and cannot do

Can: decode the common approval/transfer/mint calls; tell a contract from an
EOA; check source verification; flag unlimited and collection-wide approvals,
zero-address recipients, value attached to calls, and opaque selectors.

Cannot: read the intent of an unknown contract (an unknown selector is
flagged, not understood); detect a verified contract that is nonetheless
malicious (verification proves the code matches the source, not that the
source is honest); replace the user checking that the address is the official
one; audit chains other than BSC 56 for on-chain code (other chains report
the code check as unavailable rather than guessing).

## Stack

Node.js 18+ (standard library only: `http` server plus global `fetch` for the
outbound checks). One file, `server.js`. `GET /` demo page, `GET /health`,
`POST /audit`.
