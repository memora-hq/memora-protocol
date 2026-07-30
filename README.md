# @smritheon/memora-protocol

The signing and verification primitives behind [Memora](https://github.com/memora-hq) — canonical
record types, deterministic JSON canonicalization, the signing digests that get `ecrecover`'d
on-chain, Merkle batch proofs, and TEE attestation quote handling.

This package answers one question precisely: **given a signed Memora record, how do you check
it's real?** It contains no network calls, no storage, no service logic — just the schema and the
math. Everything needed to *produce or verify* a record lives here; everything needed to
*operate* the hosted service does not.

Most people never install this directly — it arrives automatically as a dependency of
[`@smritheon/memora-core`](https://github.com/memora-hq/memora-sdk) (the SDK) or
[`memora-local`](https://github.com/memora-hq/memora-local) (the desktop app). Install it
yourself only if you're writing your own verifier or tooling directly against the schema:

```bash
npm install @smritheon/memora-protocol
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
