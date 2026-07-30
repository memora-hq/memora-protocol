import { describe, it, expect } from "vitest";
import {
  computeEventLeafHash,
  buildMerkleTree,
  getMerkleRoot,
  getMerkleProof,
  verifyMerkleProof,
  type EventLeafInput,
  type MerkleProof,
} from "./merkle.js";

// ── Test fixtures ─────────────────────────────────────────────────────────────

const BASE_EVENT: EventLeafInput = {
  event_id:     "a".repeat(64),
  payload_hash: "b".repeat(64),
  agent_id:     "test-agent",
  agent_signer: "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
  operator_signer: "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
  parent_event_ids: ["c".repeat(64), "d".repeat(64)],
  event_digest:        "e".repeat(64),
  agent_commit_digest: "f".repeat(64),
};

// helper: fabricate a deterministic leaf hash from a seed string
function leafFrom(seed: string): string {
  const { createHash } = require("crypto") as typeof import("crypto");
  return createHash("sha256").update(seed).digest("hex");
}

// ── computeEventLeafHash ──────────────────────────────────────────────────────

describe("computeEventLeafHash", () => {
  it("produces a 64-char hex hash", () => {
    const h = computeEventLeafHash(BASE_EVENT);
    expect(h).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is deterministic for identical inputs", () => {
    const a = computeEventLeafHash(BASE_EVENT);
    const b = computeEventLeafHash({ ...BASE_EVENT });
    expect(a).toBe(b);
  });

  it("changes when event_id changes", () => {
    const mutated = { ...BASE_EVENT, event_id: "0".repeat(64) };
    expect(computeEventLeafHash(mutated)).not.toBe(computeEventLeafHash(BASE_EVENT));
  });

  it("changes when payload_hash changes", () => {
    const mutated = { ...BASE_EVENT, payload_hash: "9".repeat(64) };
    expect(computeEventLeafHash(mutated)).not.toBe(computeEventLeafHash(BASE_EVENT));
  });

  it("changes when agent_id changes", () => {
    const mutated = { ...BASE_EVENT, agent_id: "other-agent" };
    expect(computeEventLeafHash(mutated)).not.toBe(computeEventLeafHash(BASE_EVENT));
  });

  it("changes when agent_signer changes", () => {
    const mutated = { ...BASE_EVENT, agent_signer: "0x1111111111111111111111111111111111111111" };
    expect(computeEventLeafHash(mutated)).not.toBe(computeEventLeafHash(BASE_EVENT));
  });

  it("normalises parent_event_ids order — [A,B] === [B,A]", () => {
    const fwd = computeEventLeafHash({ ...BASE_EVENT, parent_event_ids: ["1".repeat(64), "2".repeat(64)] });
    const rev = computeEventLeafHash({ ...BASE_EVENT, parent_event_ids: ["2".repeat(64), "1".repeat(64)] });
    expect(fwd).toBe(rev);
  });

  it("normalises absent optional fields to empty string", () => {
    const full = computeEventLeafHash({
      ...BASE_EVENT,
      agent_signer: "",
      operator_signer: "",
      event_digest: "",
      agent_commit_digest: "",
      parent_event_ids: [],
    });
    const absent = computeEventLeafHash({
      event_id:     BASE_EVENT.event_id,
      payload_hash: BASE_EVENT.payload_hash,
      agent_id:     BASE_EVENT.agent_id,
    });
    expect(full).toBe(absent);
  });

  it("strips 0x prefix from payload_hash before hashing", () => {
    const withPrefix    = computeEventLeafHash({ ...BASE_EVENT, payload_hash: "0x" + "b".repeat(64) });
    const withoutPrefix = computeEventLeafHash({ ...BASE_EVENT, payload_hash: "b".repeat(64) });
    expect(withPrefix).toBe(withoutPrefix);
  });

  it("mutable fields (hcs_sequence, etc.) are not in the input type — compile-time exclusion", () => {
    // EventLeafInput has no hcs_sequence field — this is a type-level guarantee
    const input: EventLeafInput = BASE_EVENT;
    expect("hcs_sequence"    in input).toBe(false);
    expect("hcs_timestamp"   in input).toBe(false);
    expect("contract_tx_hash" in input).toBe(false);
    expect("created_at"      in input).toBe(false);
  });
});

// ── getMerkleRoot ─────────────────────────────────────────────────────────────

describe("getMerkleRoot", () => {
  it("single leaf: root === leaf", () => {
    const leaf = leafFrom("solo");
    expect(getMerkleRoot([leaf])).toBe(leaf);
  });

  it("two leaves: deterministic pair hash", () => {
    const a = leafFrom("a");
    const b = leafFrom("b");
    const root = getMerkleRoot([a, b]);
    expect(root).toMatch(/^[0-9a-f]{64}$/);
    expect(root).not.toBe(a);
    expect(root).not.toBe(b);
  });

  it("root changes when leaf changes", () => {
    const leaves = [leafFrom("x"), leafFrom("y"), leafFrom("z")];
    const mutated = [leafFrom("X"), leafFrom("y"), leafFrom("z")];
    expect(getMerkleRoot(leaves)).not.toBe(getMerkleRoot(mutated));
  });

  it("rejects empty leaves array", () => {
    expect(() => getMerkleRoot([])).toThrow();
  });

  it("rejects malformed leaf hash", () => {
    expect(() => getMerkleRoot(["not-a-hash"])).toThrow();
  });
});

// ── buildMerkleTree ───────────────────────────────────────────────────────────

describe("buildMerkleTree", () => {
  it("levels[0] equals input leaves", () => {
    const leaves = [leafFrom("a"), leafFrom("b"), leafFrom("c")];
    const tree = buildMerkleTree(leaves);
    expect(tree.levels[0]).toEqual(leaves.map(h => h.toLowerCase()));
  });

  it("levels[last] is a single-element array containing the root", () => {
    const leaves = [leafFrom("a"), leafFrom("b"), leafFrom("c"), leafFrom("d")];
    const tree = buildMerkleTree(leaves);
    expect(tree.levels[tree.levels.length - 1]).toHaveLength(1);
    expect(tree.levels[tree.levels.length - 1][0]).toBe(tree.root);
  });

  it("odd number of leaves: last leaf duplicated at each level", () => {
    const leaves = [leafFrom("a"), leafFrom("b"), leafFrom("c")];
    const tree = buildMerkleTree(leaves);
    expect(tree.levels[1]).toHaveLength(2); // ceil(3/2) = 2 nodes at level 1
    expect(tree.root).toMatch(/^[0-9a-f]{64}$/);
  });
});

// ── getMerkleProof / verifyMerkleProof ────────────────────────────────────────

describe("getMerkleProof + verifyMerkleProof", () => {
  const LEAVES_4 = [leafFrom("a"), leafFrom("b"), leafFrom("c"), leafFrom("d")];
  const LEAVES_5 = [leafFrom("p"), leafFrom("q"), leafFrom("r"), leafFrom("s"), leafFrom("t")];
  const LEAVES_1 = [leafFrom("solo")];

  function roundTrip(leaves: string[], index: number): boolean {
    const proof = getMerkleProof(leaves, index);
    const root  = getMerkleRoot(leaves);
    return verifyMerkleProof(leaves[index], proof, root);
  }

  it("verifies proof for every index in a 4-leaf tree", () => {
    for (let i = 0; i < 4; i++) expect(roundTrip(LEAVES_4, i)).toBe(true);
  });

  it("verifies proof for every index in a 5-leaf (odd) tree", () => {
    for (let i = 0; i < 5; i++) expect(roundTrip(LEAVES_5, i)).toBe(true);
  });

  it("verifies proof for a single-leaf tree", () => {
    expect(roundTrip(LEAVES_1, 0)).toBe(true);
  });

  it("rejects tampered leaf hash", () => {
    const proof = getMerkleProof(LEAVES_4, 0);
    const root  = getMerkleRoot(LEAVES_4);
    const wrong = leafFrom("tampered");
    expect(verifyMerkleProof(wrong, proof, root)).toBe(false);
  });

  it("rejects tampered sibling in proof path", () => {
    const proof = getMerkleProof(LEAVES_4, 0);
    const root  = getMerkleRoot(LEAVES_4);
    const tampered: MerkleProof = {
      ...proof,
      proof: [{ hash: leafFrom("evil"), side: proof.proof[0].side }, ...proof.proof.slice(1)],
    };
    expect(verifyMerkleProof(LEAVES_4[0], tampered, root)).toBe(false);
  });

  it("rejects wrong root", () => {
    const proof    = getMerkleProof(LEAVES_4, 0);
    const wrongRoot = leafFrom("wrong-root");
    expect(verifyMerkleProof(LEAVES_4[0], proof, wrongRoot)).toBe(false);
  });

  it("rejects proof from a different tree", () => {
    const proofFor4 = getMerkleProof(LEAVES_4, 0);
    const rootOf5   = getMerkleRoot(LEAVES_5);
    expect(verifyMerkleProof(LEAVES_4[0], proofFor4, rootOf5)).toBe(false);
  });

  it("getMerkleProof throws on out-of-range index", () => {
    expect(() => getMerkleProof(LEAVES_4, 4)).toThrow();
    expect(() => getMerkleProof(LEAVES_4, -1)).toThrow();
  });

  it("proof root matches getMerkleRoot output", () => {
    const root  = getMerkleRoot(LEAVES_5);
    const proof = getMerkleProof(LEAVES_5, 2);
    expect(proof.root).toBe(root);
  });

  it("verifyMerkleProof returns false for missing args", () => {
    expect(verifyMerkleProof("", {} as MerkleProof, "")).toBe(false);
  });
});

// ── Determinism across leaf orderings ─────────────────────────────────────────

describe("Merkle determinism", () => {
  it("same leaves in same order → same root every time", () => {
    const leaves = [leafFrom("1"), leafFrom("2"), leafFrom("3")];
    const r1 = getMerkleRoot(leaves);
    const r2 = getMerkleRoot(leaves);
    const r3 = getMerkleRoot([...leaves]);
    expect(r1).toBe(r2);
    expect(r1).toBe(r3);
  });

  it("different leaf order → different root (order matters)", () => {
    const a = [leafFrom("x"), leafFrom("y")];
    const b = [leafFrom("y"), leafFrom("x")];
    expect(getMerkleRoot(a)).not.toBe(getMerkleRoot(b));
  });
});
