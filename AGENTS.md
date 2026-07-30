# AGENTS.md — memora-protocol

Guidance for AI coding agents working in this repository. This repo contains only the
signing/verification schema — no hosted service, no infrastructure, no secrets. It is the public
half of a larger system; the hosted counterpart (indexer, key broker, console) lives in a
separate, closed-source repository and consumes this package the same way any other consumer
does, from the published npm version.

## What this is

`@smritheon/memora-protocol` — canonical types, deterministic JSON canonicalization, signing
digest computation, Merkle batch proofs, and TEE attestation quote handling. Pure functions and
type declarations. No `fetch`, no filesystem writes beyond build output, no environment
variables read at runtime.

## Invariants — get these wrong and verification silently breaks

### 1. `agentId` has two different encodings

Off-chain (this package, SDK, indexer) uses the raw UTF-8 string. On-chain (EVM contract calls)
uses:

```typescript
ethers.keccak256(ethers.toUtf8Bytes(agentId));
```

Never pass a raw agent string where a contract expects `bytes32`.

### 2. Sign raw digest bytes, not their hex string

EIP-191 signing of a `bytes32` digest must receive bytes, not the digest's UTF-8 hex
representation:

```typescript
wallet.signMessage(getBytes(digestHex)); // correct
wallet.signMessage(digestHex); // wrong — signs the string "0xabc123...", not the bytes
```

Use `getOperatorSigningDigestBytes` / `getAgentSigningDigestBytes` from
`packages/protocol/src/envelope.ts` — they already return the correct `Buffer`.

### 3. `event_id` is computed with `signature: null`, before the operator signs

Write order: canonicalize → hash → upload → compute `event_id` from the canonical commit with
`signature: null` → sign (the signature covers `event_id`). Reversing this order produces an
`event_id` that doesn't match what was signed — a real, historically-seen bug class.

### 4. Parent event IDs are sorted before signing

`getOperatorSigningDigestBytes` / `getAgentSigningDigestBytes` sort `parent_event_ids`
internally. Any independent implementation (a verifier in another language, say) must do the
same or digests won't match.

### 5. Signing JSON is canonical and version-sensitive

`sortedJson` (`packages/protocol/src/canonicalize.ts`) sorts keys alphabetically. Adding, removing, or renaming a
signed field changes every previously-signed digest unless the domain separator version bumps
(`memora:event:v1` → `v2`). This is the single most consequential invariant in this package —
see the Versioning section of `README.md`.

### 6. Cryptographic claims must stay precise

On-chain `ecrecover` proves a key signed a digest. It does not by itself prove: digest
correctness, trusted-signer registration, honest runtime execution, plaintext integrity, or
provider/model identity. Anything this package's outputs get described as proving — in code
comments, README prose, or downstream docs — must stay within what `ecrecover` and a hash
comparison actually establish.

## Working with the conformance vectors

`packages/protocol/vectors/` is append-only, the same rule as database migrations — a vector
that changes value is a format change in disguise, not a fix. All three consumer repos
(`memora-sdk`, `memora-local`, and the private hosted repo) execute these vectors in CI. If you
change anything in `packages/protocol/src/`, run `pnpm test` here first; if a vector fails, the
question is whether you just made a breaking protocol change (see Versioning in `README.md`),
not whether the vector is wrong.

## What does NOT belong in this repo

Nothing about: write authorization policy, key custody, Supabase/database schemas, service-to-service
authentication, rate limiting, or any hosted-service operational concern. If a change requires
touching any of those, it belongs in the private hosted repository, not here.
