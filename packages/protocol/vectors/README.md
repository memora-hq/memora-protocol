# Golden conformance vectors

Frozen, machine-checkable ground truth for every cryptographic primitive
`@smritheon/memora-protocol` exposes to the outside world.

## Why these exist

Memora's verifiers live in **separate repositories** — the public SDK/CLI (`memora-sdk`), the
public desktop app (`memora-local`), and the private hosted console — with nothing structurally
forcing them to agree beyond depending on the same published version of this package. The hosted
console's own replay verifier independently reimplements Merkle proof verification rather than
importing this package directly, so the drift risk is live, not hypothetical.

These vectors are the shared pin. Every implementation of the Memora protocol — in any of these
repos, in any language — must reproduce these exact bytes. A change that breaks agreement fails a
test wherever it drifted, immediately.

## Append-only rule

**Once a vector file is committed, its content never changes.** Same rule as an append-only
database migration.

A frozen vector changing would mean a previously-shipped signing domain now produces a different
output for the same input — which must never happen. If a vector file's content and the current
code disagree, the *code* is what regressed (or the change requires a new domain separator);
"just update the vector" is never the fix.

New coverage = **a new file**, never an edit to an existing one. `generate.mjs` enforces this
mechanically: it refuses to overwrite any file that already exists.

## Keys

| Role | Key | Address |
|------|-----|---------|
| Operator | `0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80` | `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266` |
| Agent | `0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d` | `0x70997970C51812dc3A010C7d01b50e0d17dc79C8` |

These are the **well-known Hardhat dev accounts #0 and #1**, published in Hardhat's own
documentation. They are public by design and hold nothing. They are never used for production
value, and their presence in this directory is not a secret leak. Reusing them (rather than
minting a fresh keypair) keeps the vectors reproducible by inspection.

## Files

| File | Covers |
|------|--------|
| `event-v1.json` | `memora:event:v1` operator envelope — `computeSigningDigest()`, `extractSigningFields()`, `signEventEnvelope()`. Two cases: a parentless commit, and a commit carrying `agent_signer` whose `parent_event_ids` are supplied **out of sorted order** (the frozen digest is the sorted-parent digest — see `AGENTS.md` invariant 4). |
| `agent-v1.json` | `memora:agent:v1` agent countersignature — `computeAgentSigningDigest()`, `signAgentEvent()`. Same two shapes. Note `computeAgentSigningDigest()` does **not** sort parents itself; `signAgentEvent()`/`verifyAgentSignature()` do, so the vector carries both `fields_input` (unsorted) and `fields_sorted`. |
| `agent-tee-v1.json` | `memora:agent:tee:v1` TEE-domain agent signature — `computeAgentTeeSigningDigest()`, `signAgentTeeEvent()`. Quote bytes come from `buildMockTeeQuote("memora-conformance-vector-v1")`; `quote_hash` is `sha256(raw quote bytes)` in lowercase hex with no `0x`. |
| `merkle-v1.json` | `memora:leaf:v1` leaf hashing plus tree/proof/verification — `computeEventLeafHash()`, `buildMerkleTree()`, `getMerkleProof()`, `verifyMerkleProof()`. A 5-leaf (odd) tree, so duplicate-last-node padding is exercised at two levels. Cases: a valid proof for interior index 2 (contains both a `right` and a `left` step), a valid proof for the padded last index 4, and one **negative** case — `tampered-proof-index-2`, identical to the valid index-2 proof except one character of the first step's sibling hash is flipped. The tampered hash is still well-formed 64-char hex, so a verifier must reject it on the *root comparison*, not on an input-shape guard. Expected result: `false`. |
| `merkle-v2-edge-cases.json` | Additional Merkle edge cases pinning path reconstruction against the caller's root (not a proof's self-reported root field) and `0x`-prefix stripping, across both this package's implementation and the hosted console's independent reimplementation. |
| `bundle-v2-sealed.memora` | A real, sealed v2 `.memora` evidence bundle produced end-to-end by `memora-local`'s `LocalSession` (`session.record()` ×2 → `session.finish("complete")` → `exportLocalBundle()`), signed by the agent key above. Four events (`session_started`, `prompt_submitted`, `tool_completed`, `session_completed`). This is a **forward-compatibility pin**, not a byte-reproducibility pin: the test asserts `verifyLocalBundle(await readLocalBundle(path)).valid === true` forever, proving future protocol/local changes never silently break the ability to read and verify a bundle produced under today's format. Payload ciphertext is encrypted under a key derived from the public test key, so it is readable by anyone — the content is inert fixture data. |
| `generate.mjs` | The one-off generator that produced the digest/Merkle vectors above by calling the real implementations (dogfooding, never hand-computed). Kept for future append-only additions; it refuses to overwrite existing files. **Note:** it cannot regenerate `bundle-v2-sealed.memora` on its own — that fixture requires `memora-local`'s `LocalSession`, which lives in a different repo. Generating a *new* bundle vector means running the equivalent steps from within `memora-local` against a local-linked `packages/protocol`, then copying the result here. |

## Who consumes them

Executed in CI in every repo that has a verifier: this package's own suite (the reference
implementation — recomputes every digest/leaf/root and re-verifies every signature and proof),
`memora-local`'s bundle verifier suite (reads and verifies the frozen `.memora` artifact), and the
private hosted console's replay-verification suite (its independent inline Merkle reimplementation
must return the same true/false as this package's `verifyMerkleProof()` on the identical frozen
inputs — the actual multi-verifier-agreement pin).

## Regenerating (only ever to ADD)

```bash
pnpm --filter @smritheon/memora-protocol build
node packages/protocol/vectors/generate.mjs
```

Existing files are skipped, not rewritten. See the note on `bundle-v2-sealed.memora` above for
the one fixture this can't produce standalone.
