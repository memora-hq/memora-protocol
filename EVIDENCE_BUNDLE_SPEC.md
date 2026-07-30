# Memora Evidence Bundle — `memora.local.bundle`

A single file that carries one agent execution and everything needed to verify it: no account, no
network, no Memora software required beyond a JSON parser, a SHA-256, and secp256k1 signature
recovery.

This is the portable form of a Memora Local session. Reference implementation:
`packages/local/src/bundle.ts` in the [`memora-local`](https://github.com/memora-hq/memora-local)
repository — this repository defines the schema and signing digests the format is built on, but
the bundle-writer itself lives there. File extension: `.memora`. Media type (provisional):
`application/vnd.memora.bundle+json`.

---

## 1. Structure

```jsonc
{
  "format":  "memora.local.bundle",
  "version": 2,
  "manifest": { /* LocalExecutionManifestV1 — signed */ },
  "events":   [ /* LocalEventRecordV1[]     — each commit signed */ ],
  "payloads": { "<objectId>": { /* EncryptedPayloadBundle */ } },
  "disclosed": { "<objectId>": { /* MemoryPayload, plaintext */ } }   // v2, optional
}
```

Canonical type definitions live in `packages/protocol/src/types.ts` (this repository).

| Field | Version | Signed? | Meaning |
|---|---|---|---|
| `format` | 1, 2 | no | Always `"memora.local.bundle"`. |
| `version` | 1, 2 | no | `1` = sealed only. `2` = sealed, optionally with disclosure. |
| `manifest` | 1, 2 | **yes** | The session index: identity, ordered `event_ids`, capture status and warnings, `signer`, `signature`. |
| `events` | 1, 2 | **yes** (each `commit`) | The journal. Every entry holds a canonical `MemoryCommit` with `event_id`, `payload_hash`, `cid_ciphertext`, `parent_event_ids`, `signer`, `signature`. |
| `payloads` | 1, 2 | no (content-addressed) | AES-256-GCM ciphertext for **every** event, keyed by object ID. |
| `disclosed` | 2 | no (hash-bound) | Plaintext `MemoryPayload` for the subset the exporter chose to reveal, keyed by the same object ID. Absent means nothing was revealed. |

The bundle envelope itself is **not signed** — it is a container. Every trust-bearing claim comes
from the manifest signature, the per-event signatures, and the hashes those signatures cover. A
verifier must never trust a field for which it cannot trace that path; `disclosed` is trusted only
because §3.5 binds it to `payload_hash`.

**Object ID.** `objectId = sha256(JSON.stringify(payloads[objectId]))`, and each event's
`cid_ciphertext` is `"local:sha256:" + objectId`.

**Signature scheme.** EIP-191 `personal_sign` over a raw 32-byte digest. Manifest digest domain:
`memora:local:manifest:v1\n`. Event envelope digests come from this package's `envelope.ts`. Both
recover to `manifest.signer`, a secp256k1 address.

**Encryption.** `payloads` values are AES-256-GCM under a key derived from the recording device's
private key. There is deliberately no key-escrow path: a recipient can never decrypt `payloads`.
Readability comes only from `disclosed`.

---

## 2. Versioning

- A reader MUST accept `version` 1 and 2, and MUST reject anything else.
- Version 2 without `disclosed` is semantically identical to version 1.
- Writers emit version 2.
- New fields require a new `version`. Fields inside `manifest`, `events[].commit`, or `MemoryPayload`
  are covered by signatures and can never be added in place — doing so invalidates every previously
  signed record.

---

## 3. Verification algorithm

Given a parsed bundle, with no key and no network:

1. **Envelope.** `format === "memora.local.bundle"`, `version ∈ {1, 2}`, `manifest.event_ids` is an
   array, `events` is an array, `payloads` is an object. Cap the file size before parsing
   (reference implementation: 64 MB) — a bundle is untrusted input.
2. **Manifest signature.** Recover the signer from `manifest.signature` over the manifest digest
   with `signature: null`; it MUST equal `manifest.signer`.
3. **Event set.** Every ID in `manifest.event_ids` MUST be present in `events`, and `events` MUST
   contain no entries outside that list.
4. **Per event**, for each ID in `manifest.event_ids`:
   - recomputed `event_id` matches the stored one;
   - the envelope signature recovers to `manifest.signer`;
   - every `parent_event_ids` entry exists in the bundle;
   - `payloads[objectId]` exists and `sha256` of its serialization equals `objectId`.
5. **Disclosure**, for each entry in `disclosed`:
   - the object ID matches an event in the bundle;
   - `hashPayload(canonicalizePayload(payload)) === event.commit.payload_hash`.

   A mismatch is a **verification failure**, not a warning: the exporter published content that
   contradicts what they signed.
6. **Capture warnings** in `manifest.capture_warnings` surface as warnings, never failures. They
   describe capture completeness, which is independent of cryptographic integrity.

The bundle is valid only if steps 2–5 all pass.

---

## 4. What a valid bundle proves — and what it does not

**Proves**

- The manifest and every event were sealed by one key and have not been altered since.
- The events form the exact set and lineage the manifest committed to.
- The stored ciphertext is byte-identical to what was sealed.
- For every disclosed record: the plaintext you are reading is precisely what that signature covers.
- Across bundles: two files signed by the same key came from the same device (*continuity*).

**Does not prove**

- **Who** the signer is. The key is self-issued and self-signed. Continuity is the strongest identity
  claim available; naming a key is a local, personal annotation with no cryptographic weight.
- That capture was **complete**. Capture is hook-based; `capture_status` and `capture_warnings` state
  what is known, and an agent action that emitted no hook leaves no trace to be missing from.
- That undisclosed records say anything in particular. Sealed content is proof-of-existence only.
- Anything about **when** in absolute terms. Timestamps come from the recording device's clock and
  are signed, not attested — order is chain-derived, wall-clock time is not.
- That the agent's runtime behaved correctly. Memora records what happened; it does not judge it.

---

## 5. Producing and consuming

```bash
memora local export <session-id> --out evidence.memora              # sealed
memora local export <session-id> --out evidence.memora --disclose   # readable copy
memora local verify-bundle evidence.memora                          # offline verification
memora local receipt <session-id> --out receipt.html                # human-readable page
```

In Memora Local: **Share evidence** on any session, and **Verify a receipt** in the sidebar for a
file from someone else. A verified foreign bundle is displayed and discarded — it is never written
into the verifier's own evidence store.
