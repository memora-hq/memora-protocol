/**
 * Merkle tree utilities for Memora batch provenance.
 *
 * Provides deterministic leaf hashing, tree construction, proof generation,
 * and verification. Used by the batcher service (anchor side) and the replay
 * verifier (verification side).
 *
 * Tree rules:
 *  - Leaves are 64-char lowercase hex sha256 hashes (no 0x prefix).
 *  - Internal nodes: sha256(left_bytes ‖ right_bytes), positional order.
 *  - Odd-length levels: last node is duplicated (Bitcoin-style padding).
 *  - Single-leaf batch: root === leaf.
 *
 * Proof format:
 *  Array of {hash, side} steps from leaf level up to the root.
 *  Verifier reconstructs root by applying each step in order.
 *
 * Pair ordering rule:
 *  At every level, left child is at even index i and right child is at i+1.
 *  The index determines pairing — NOT the hash values (so proofs are index-stable).
 */

import { createHash } from "crypto";

// ── Domain separator (same style as envelope.ts) ─────────────────────────────

const LEAF_DOMAIN = "memora:leaf:v1\n";

// ── Canonical leaf fields ─────────────────────────────────────────────────────

/**
 * Canonical input for computing a Merkle leaf hash.
 *
 * Includes only stable, immutable fields from the execution event.
 * Mutable fields are explicitly excluded:
 *  - hcs_sequence, hcs_timestamp  (set by subscriber, not writer)
 *  - contract_tx_hash             (set by contract listener, async)
 *  - created_at, updated_at       (DB timestamps, not event data)
 *  - batch_id                     (set by the batcher, circular)
 */
export interface EventLeafInput {
  event_id:              string;
  payload_hash:          string;   // 64-char hex, no 0x
  agent_id:              string;
  /** EVM address of the agent signing key. Absent fields normalise to "". */
  agent_signer?:         string | null;
  /** EVM address of the operator (the `signer` field in MemoryRef / MemoryCommit). */
  operator_signer?:      string | null;
  /** Parent event IDs; sorted before hashing. Absent normalises to []. */
  parent_event_ids?:     string[] | null;
  /** 32-byte operator signing digest (hex). Absent normalises to "". */
  event_digest?:         string | null;
  /** 32-byte agent commit digest (hex). Absent normalises to "". */
  agent_commit_digest?:  string | null;
}

function sortedJson(obj: Record<string, unknown>): string {
  const sorted: Record<string, unknown> = {};
  for (const k of Object.keys(obj).sort()) sorted[k] = obj[k];
  return JSON.stringify(sorted);
}

function canonicalLeafFields(input: EventLeafInput): Record<string, unknown> {
  return {
    agent_commit_digest: input.agent_commit_digest  ?? "",
    agent_id:            input.agent_id,
    agent_signer:        input.agent_signer          ?? "",
    event_digest:        input.event_digest           ?? "",
    event_id:            input.event_id,
    operator_signer:     input.operator_signer        ?? "",
    parent_event_ids:    [...(input.parent_event_ids ?? [])].sort(),
    payload_hash:        (input.payload_hash ?? "").replace(/^0x/, ""),
  };
}

/**
 * Compute the deterministic Merkle leaf hash for an execution event.
 * sha256("memora:leaf:v1\n" + sortedJson(canonicalFields))
 * Returns 64-char lowercase hex (no 0x prefix).
 */
export function computeEventLeafHash(input: EventLeafInput): string {
  const fields = canonicalLeafFields(input);
  return createHash("sha256")
    .update(LEAF_DOMAIN + sortedJson(fields), "utf8")
    .digest("hex");
}

// ── Proof types ───────────────────────────────────────────────────────────────

export interface MerkleProofStep {
  hash: string;              // 64-char hex sibling hash (no 0x)
  side: "left" | "right";   // position of the sibling relative to the current node
}

export interface MerkleProof {
  index:  number;            // leaf index in the original leaves array
  leaf:   string;            // 64-char hex leaf hash (no 0x)
  proof:  MerkleProofStep[]; // steps from leaf to root
  root:   string;            // 64-char hex Merkle root (no 0x)
}

export interface MerkleTree {
  leaves:  string[];    // original leaf hashes
  levels:  string[][];  // levels[0] = leaves, levels[N] = [root]
  root:    string;      // 64-char hex
}

// ── Internal helpers ──────────────────────────────────────────────────────────

function assertHex64(hash: string, label: string): void {
  if (!/^[0-9a-f]{64}$/i.test(hash)) {
    throw new Error(`${label}: expected 64-char hex hash, got "${hash.slice(0, 20)}…" (len=${hash.length})`);
  }
}

function pairHash(left: string, right: string): string {
  const buf = Buffer.concat([
    Buffer.from(left,  "hex"),
    Buffer.from(right, "hex"),
  ]);
  return createHash("sha256").update(buf).digest("hex");
}

function buildLevels(leaves: string[]): string[][] {
  if (leaves.length === 0) throw new Error("Cannot build Merkle tree from empty leaves array");
  leaves.forEach((h, i) => assertHex64(h, `leaf[${i}]`));

  const levels: string[][] = [leaves.map(h => h.toLowerCase())];
  let current = leaves.map(h => h.toLowerCase());

  while (current.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < current.length; i += 2) {
      const left  = current[i];
      const right = current[i + 1] ?? current[i]; // duplicate last node if odd count
      next.push(pairHash(left, right));
    }
    levels.push(next);
    current = next;
  }

  return levels;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Compute the Merkle root for a list of leaf hashes.
 * Single-leaf batch: root equals the leaf itself.
 */
export function getMerkleRoot(leaves: string[]): string {
  const levels = buildLevels(leaves);
  return levels[levels.length - 1][0];
}

/**
 * Build the complete Merkle tree and return all levels.
 */
export function buildMerkleTree(leaves: string[]): MerkleTree {
  const levels = buildLevels(leaves);
  return {
    leaves:  leaves.slice(),
    levels,
    root:    levels[levels.length - 1][0],
  };
}

/**
 * Generate a Merkle inclusion proof for the leaf at `index`.
 * The proof path lets a verifier reconstruct the root bottom-up.
 */
export function getMerkleProof(leaves: string[], index: number): MerkleProof {
  if (index < 0 || index >= leaves.length) {
    throw new Error(
      `getMerkleProof: index ${index} out of range [0, ${leaves.length - 1}]`
    );
  }

  const levels = buildLevels(leaves);
  const leaf   = leaves[index].toLowerCase();
  const proof: MerkleProofStep[] = [];

  let i = index;
  for (let level = 0; level < levels.length - 1; level++) {
    const current      = levels[level];
    const isLeft       = i % 2 === 0;
    const siblingIndex = isLeft ? i + 1 : i - 1;
    // If sibling is absent (odd-length level), the last node pairs with itself
    const sibling = (current[siblingIndex] ?? current[i]).toLowerCase();
    proof.push({ hash: sibling, side: isLeft ? "right" : "left" });
    i = Math.floor(i / 2);
  }

  return {
    index,
    leaf,
    proof,
    root: levels[levels.length - 1][0],
  };
}

function strip0x(value: string): string {
  return value.startsWith("0x") || value.startsWith("0X") ? value.slice(2) : value;
}

/**
 * Verify a Merkle inclusion proof.
 * Returns true iff the proof is cryptographically valid and the reconstructed
 * root matches the provided root.
 *
 * Ground truth is the reconstruction, not `proof.root` — a proof's self-reported
 * root field can go stale (e.g. after a batch is re-anchored) without affecting
 * whether the leaf actually reconstructs to the root the caller is asking about.
 * `proof.leaf` is still checked against the supplied `leaf`, since that's an
 * input to the reconstruction, not just descriptive metadata.
 */
export function verifyMerkleProof(
  leaf:  string,
  proof: MerkleProof,
  root:  string
): boolean {
  if (!leaf || !proof || !root) return false;

  const normLeaf = strip0x(leaf).toLowerCase();
  const normRoot = strip0x(root).toLowerCase();

  if (normLeaf !== strip0x(proof.leaf).toLowerCase()) return false;

  let current = normLeaf;
  for (const step of proof.proof) {
    const sibling = strip0x(step.hash).toLowerCase();
    current =
      step.side === "left"
        ? pairHash(sibling, current)
        : pairHash(current, sibling);
  }

  return current === normRoot;
}
