# @memora-hq/memora-protocol

The signing and verification primitives behind [Memora](https://github.com/memora-hq) — canonical
record types, deterministic JSON canonicalization, the signing digests that get `ecrecover`'d
on-chain, Merkle batch proofs, and TEE attestation quote handling.

This package answers one question precisely: **given a signed Memora record, how do you check
it's real?** It contains no network calls, no storage, no service logic — just the schema and the
math. Everything needed to *produce or verify* a record lives here; everything needed to
*operate* the hosted service does not.

Most people never install this directly — it arrives automatically as a dependency of
[`@memora-hq/memora-core`](https://github.com/memora-hq/memora-sdk) (the SDK) or
[`memora-local`](https://github.com/memora-hq/memora-local) (the desktop app). Install it
yourself only if you're writing your own verifier or tooling directly against the schema:

```bash
npm install @memora-hq/memora-protocol
```

## What's in here

| Module | Purpose |
|---|---|
| `types.ts` | Canonical record shapes (`MemoryCommit`, `MemoryPayload`, and related types) |
| `canonicalize.ts` | Deterministic JSON serialization — the same data always hashes the same way |
| `crypto.ts` | Hashing and signing primitives |
| `envelope.ts` | Computes the operator and agent signing digests — the exact bytes signed and `ecrecover`'d |
| `merkle.ts` | Builds and verifies Merkle proofs for batched records |
| `tee.ts` | TEE attestation quote handling (verification of quote *content* — anchoring the quote *hash* on-chain is a separate, consuming concern) |
| `phaseTimer.ts` | Small timing utility used by verifiers |

## Who uses this

- [`memora-sdk`](https://github.com/memora-hq/memora-sdk) — the client library and CLI, which sign
  and verify records using these primitives.
- [`memora-local`](https://github.com/memora-hq/memora-local) — the desktop app and evidence engine,
  which produces `.memora` bundles built on this schema.
- Memora Cloud (hosted, closed-source) — the indexer, key broker, and console consume the exact
  same package, from the exact same published version, as everything above. There is no private
  fork of this code.

## The spec

[`EVIDENCE_BUNDLE_SPEC.md`](./EVIDENCE_BUNDLE_SPEC.md) is the normative format description for
the `.memora` evidence bundle this package's types and digests underpin. If you're writing a
verifier in another language, start there — the conformance vectors in
[`vectors/`](./vectors) are the executable version of the same guarantee: signed records, their
expected digests, and expected verification outcomes, covering every signing domain
(`memora:event:v1`, `memora:agent:v1`, `memora:agent:tee:v1`) and the Merkle leaf format.

## Versioning

Strict semver, with one rule stricter than it looks: **any change to a signing digest domain,
wire format, or Merkle proof structure is a major version**, even if the TypeScript type change
looks additive — because it requires a new domain separator string (`memora:event:v1` →
`memora:event:v2`) so old and new digests never collide. Records signed under an old domain stay
verifiable forever; this package only ever grows.

Every tagged release is gated on the conformance vectors passing.

## License

Apache-2.0

## Explicit event-ID verification profiles (Foundation v1, Slice 06)

`EVENT_ID_PROFILES.shared` (`shared-protocol-json-stringify-v1`) freezes the
existing shared/Local constructor. `EVENT_ID_PROFILES.hosted`
(`hosted-indexer-json-stringify-v1`) freezes the hosted writer's historical
insertion order: task immediately follows agent, and legacy TEE fields precede
lineage summaries. The shared constructor appends task after `signature:null`
and TEE fields after lineage. Task-bearing bytes/IDs differ. Absent-task records
without TEE ordering differences can match; that coincidence is not profile detection.

New hosted writes retain **the hosted profile, schema 1, and existing v1 signing
domains**. This makes no signed-semantic change and requires no v2 format. Neither
profile is a new claim about agent identity, tenant scope or hardware authenticity.
The original `computeEventId` / `verifyEventId` stay shared-only with their existing
behavior. No function guesses a recipe or retries with another profile.

Use `getEventIdPreimage` / `computeProfiledEventId` for explicit construction.
`verifyProfiledEventId` checks integrity only. `verifyProfiledEvent` also requires
an external `expectedOperatorSigner`. `verifyOriginalEvent` accepts exact
`commit_bytes_b64` and `event_id_preimage_b64`, strictly decodes them, and verifies
that the saved preimage equals the selected constructor's bytes for the actual
commit before verifying its ID and operator signature. Supply policy independently
of the evidence; do not copy `profiles.producer` or `commit.signer` into trust policy.
Unknown profiles, noncanonical base64, invalid UTF-8/JSON, altered tasks, inconsistent
preimages and signature failures cannot trigger a fallback. Historical records
without saved preimages can use the frozen explicit constructor with their original
commit and an external operator pin; index-only rows cannot recreate missing proof.

`vectors/hosted-event-id-v1.json` freezes actual hosted handler task/empty/no-task
outputs, signatures and digests with deterministic synthetic test keys. `vectors/event-id-metadata-v1.json` additionally freezes shared and historical hosted
agent/mission/TEE bytes and signatures (synthetic quotes do not prove hardware).
Existing signature and Merkle vector files are unchanged. Original IDs, preimages, signatures,
domains and Merkle roots are never rewritten. Parent/reference namespace resolution
and raw/index/contract identity joins remain Foundation Slice 07 work.
