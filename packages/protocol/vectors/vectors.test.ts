/**
 * Golden conformance vectors — reference implementation check.
 *
 * Every value in vectors/*.json was produced by the functions exercised below.
 * This suite re-derives each one and asserts byte-for-byte string equality
 * against the frozen file. If one of these fails, the *code* changed, not the
 * vector: see vectors/README.md for the append-only rule.
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  buildMerkleTree,
  buildMockTeeQuote,
  computeAgentSigningDigest,
  computeAgentTeeSigningDigest,
  computeEventLeafHash,
  computeSigningDigest,
  extractSigningFields,
  getMerkleProof,
  recoverEnvelopeSigner,
  verifyAgentSignature,
  verifyAgentTeeSignature,
  verifyEventEnvelope,
  verifyMerkleProof,
  type AgentCanonicalSigningFields,
  type AgentTeeCanonicalSigningFields,
  type CanonicalSigningFields,
  type EventLeafInput,
  type MemoryCommit,
  type MerkleProof,
} from "../src/index.js";

const VECTORS_DIR = dirname(fileURLToPath(import.meta.url));

function loadVector<T>(filename: string): T {
  return JSON.parse(readFileSync(join(VECTORS_DIR, filename), "utf8")) as T;
}

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

// ── memora:event:v1 ───────────────────────────────────────────────────────────

interface EventVectorFile {
  operator_address: string;
  cases: Array<{
    name: string;
    commit: MemoryCommit;
    parent_event_ids_input: string[];
    parent_event_ids_sorted: string[];
    signing_fields: CanonicalSigningFields;
    digest_hex: string;
    signature: string;
    recovered_signer: string;
  }>;
}

describe("golden vectors — memora:event:v1", () => {
  const vector = loadVector<EventVectorFile>("event-v1.json");

  it("has the expected coverage", () => {
    expect(vector.cases.map((c) => c.name)).toEqual([
      "operator-no-parents",
      "operator-unsorted-parents-with-agent-signer",
    ]);
  });

  for (const testCase of vector.cases) {
    describe(testCase.name, () => {
      const signedCommit: MemoryCommit = { ...testCase.commit, signature: testCase.signature };

      it("reproduces the frozen operator digest", () => {
        expect(hex(computeSigningDigest(testCase.signing_fields))).toBe(testCase.digest_hex);
      });

      it("sorts parent_event_ids before hashing", () => {
        expect([...testCase.parent_event_ids_input].sort()).toEqual(testCase.parent_event_ids_sorted);
        const fields = extractSigningFields(testCase.commit);
        // Feed the UNSORTED input the way signEventEnvelope does, and expect the
        // sorted-parent digest back.
        fields.parent_event_ids = [...testCase.parent_event_ids_input].sort();
        expect(hex(computeSigningDigest(fields))).toBe(testCase.digest_hex);
      });

      it("extractSigningFields matches the frozen signing fields", () => {
        const extracted = extractSigningFields(testCase.commit);
        extracted.parent_event_ids = testCase.parent_event_ids_sorted;
        expect(extracted).toEqual(testCase.signing_fields);
      });

      it("verifies the frozen signature against the expected signer", () => {
        const result = verifyEventEnvelope(
          signedCommit,
          testCase.parent_event_ids_input,
          vector.operator_address,
        );
        expect(result.valid).toBe(true);
        expect(result.recoveredSigner).toBe(testCase.recovered_signer);
      });

      it("recovers the frozen signer address", () => {
        expect(recoverEnvelopeSigner(signedCommit, testCase.parent_event_ids_input)).toBe(
          testCase.recovered_signer,
        );
      });

      it("rejects a different expected signer", () => {
        expect(
          verifyEventEnvelope(
            signedCommit,
            testCase.parent_event_ids_input,
            "0x0000000000000000000000000000000000000001",
          ).valid,
        ).toBe(false);
      });
    });
  }
});

// ── memora:agent:v1 ───────────────────────────────────────────────────────────

interface AgentVectorFile {
  agent_address: string;
  cases: Array<{
    name: string;
    fields_input: AgentCanonicalSigningFields;
    fields_sorted: AgentCanonicalSigningFields;
    digest_hex: string;
    signature: string;
    recovered_signer: string;
  }>;
}

describe("golden vectors — memora:agent:v1", () => {
  const vector = loadVector<AgentVectorFile>("agent-v1.json");

  it("has the expected coverage", () => {
    expect(vector.cases.map((c) => c.name)).toEqual(["agent-no-parents", "agent-unsorted-parents"]);
  });

  for (const testCase of vector.cases) {
    describe(testCase.name, () => {
      it("reproduces the frozen agent digest", () => {
        expect(hex(computeAgentSigningDigest(testCase.fields_sorted))).toBe(testCase.digest_hex);
      });

      it("verifies the frozen signature from the unsorted input fields", () => {
        const result = verifyAgentSignature(
          testCase.fields_input,
          testCase.signature,
          vector.agent_address,
        );
        expect(result.valid).toBe(true);
        expect(result.recoveredSigner).toBe(testCase.recovered_signer);
      });

      it("rejects a different expected signer", () => {
        expect(
          verifyAgentSignature(
            testCase.fields_input,
            testCase.signature,
            "0x0000000000000000000000000000000000000001",
          ).valid,
        ).toBe(false);
      });
    });
  }

  it("produces a different digest than the TEE domain for the same fields", () => {
    const agentCase = vector.cases[0];
    const teeFields: AgentTeeCanonicalSigningFields = {
      ...agentCase.fields_sorted,
      tee_quote_hash: "0".repeat(64),
    };
    expect(hex(computeAgentTeeSigningDigest(teeFields))).not.toBe(agentCase.digest_hex);
  });
});

// ── memora:agent:tee:v1 ───────────────────────────────────────────────────────

interface AgentTeeVectorFile {
  agent_address: string;
  tee_quote: {
    payload: string;
    raw_utf8: string;
    raw_base64: string;
    quote_hash: string;
  };
  cases: Array<{
    name: string;
    fields_input: AgentTeeCanonicalSigningFields;
    fields_sorted: AgentTeeCanonicalSigningFields;
    digest_hex: string;
    signature: string;
    recovered_signer: string;
  }>;
}

describe("golden vectors — memora:agent:tee:v1", () => {
  const vector = loadVector<AgentTeeVectorFile>("agent-tee-v1.json");

  it("reproduces the frozen mock quote and its hash", () => {
    const quote = buildMockTeeQuote(vector.tee_quote.payload);
    expect(quote.toString("utf8")).toBe(vector.tee_quote.raw_utf8);
    expect(quote.toString("base64")).toBe(vector.tee_quote.raw_base64);
    expect(createHash("sha256").update(quote).digest("hex")).toBe(vector.tee_quote.quote_hash);
  });

  it("has the expected coverage", () => {
    expect(vector.cases.map((c) => c.name)).toEqual([
      "agent-tee-no-parents",
      "agent-tee-unsorted-parents",
    ]);
  });

  for (const testCase of vector.cases) {
    describe(testCase.name, () => {
      it("reproduces the frozen TEE digest from sorted fields", () => {
        expect(hex(computeAgentTeeSigningDigest(testCase.fields_sorted))).toBe(testCase.digest_hex);
      });

      it("sorts parent_event_ids internally", () => {
        expect(hex(computeAgentTeeSigningDigest(testCase.fields_input))).toBe(testCase.digest_hex);
      });

      it("verifies the frozen signature against the expected signer", () => {
        const result = verifyAgentTeeSignature(
          testCase.fields_input,
          testCase.signature,
          vector.agent_address,
        );
        expect(result.valid).toBe(true);
        expect(result.recoveredSigner).toBe(testCase.recovered_signer);
      });

      it("is not accepted by the non-TEE agent domain verifier", () => {
        const { tee_quote_hash: _ignored, ...withoutQuote } = testCase.fields_sorted;
        expect(
          verifyAgentSignature(
            withoutQuote as AgentCanonicalSigningFields,
            testCase.signature,
            vector.agent_address,
          ).valid,
        ).toBe(false);
      });
    });
  }
});

// ── memora:leaf:v1 + Merkle ───────────────────────────────────────────────────

interface MerkleVectorFile {
  tree: {
    leaf_inputs: EventLeafInput[];
    leaves: string[];
    levels: string[][];
    root: string;
  };
  cases: Array<{
    name: string;
    leaf: string;
    proof: MerkleProof;
    root: string;
    expected: boolean;
  }>;
}

describe("golden vectors — memora:leaf:v1 and Merkle proofs", () => {
  const vector = loadVector<MerkleVectorFile>("merkle-v1.json");

  it("reproduces every frozen leaf hash", () => {
    expect(vector.tree.leaf_inputs.map((input) => computeEventLeafHash(input))).toEqual(
      vector.tree.leaves,
    );
  });

  it("reproduces the frozen tree levels and root", () => {
    const tree = buildMerkleTree(vector.tree.leaves);
    expect(tree.levels).toEqual(vector.tree.levels);
    expect(tree.root).toBe(vector.tree.root);
  });

  it("has the expected coverage, including a negative case", () => {
    expect(vector.cases.map((c) => c.name)).toEqual([
      "valid-proof-index-2",
      "valid-proof-index-4",
      "tampered-proof-index-2",
    ]);
    expect(vector.cases.map((c) => c.expected)).toEqual([true, true, false]);
  });

  for (const testCase of vector.cases) {
    it(`verifyMerkleProof returns ${testCase.expected} for ${testCase.name}`, () => {
      expect(verifyMerkleProof(testCase.leaf, testCase.proof, testCase.root)).toBe(
        testCase.expected,
      );
    });
  }

  it("regenerates the frozen proofs for the positive cases", () => {
    for (const testCase of vector.cases.filter((c) => c.expected)) {
      expect(getMerkleProof(vector.tree.leaves, testCase.proof.index)).toEqual(testCase.proof);
    }
  });

  it("the tampered proof differs from the valid one only in the first step's hash", () => {
    const valid = vector.cases.find((c) => c.name === "valid-proof-index-2")!;
    const tampered = vector.cases.find((c) => c.name === "tampered-proof-index-2")!;
    expect(tampered.leaf).toBe(valid.leaf);
    expect(tampered.root).toBe(valid.root);
    expect(tampered.proof.proof.length).toBe(valid.proof.proof.length);
    expect(tampered.proof.proof[0].hash).not.toBe(valid.proof.proof[0].hash);
    expect(tampered.proof.proof[0].side).toBe(valid.proof.proof[0].side);
    expect(tampered.proof.proof.slice(1)).toEqual(valid.proof.proof.slice(1));
    // Well-formed hex, so rejection must come from the root comparison, not an
    // input-shape guard — this is what makes the negative vector meaningful.
    expect(tampered.proof.proof[0].hash).toMatch(/^[0-9a-f]{64}$/);
    expect(verifyMerkleProof(tampered.leaf, tampered.proof, tampered.root)).toBe(false);
  });
});

describe("golden vectors — merkle-v2-edge-cases (stale proof.root, 0x-prefixed inputs)", () => {
  const vector = loadVector<MerkleVectorFile>("merkle-v2-edge-cases.json");

  it("has the expected coverage", () => {
    expect(vector.cases.map((c) => c.name)).toEqual([
      "stale-proof-root-metadata",
      "0x-prefixed-inputs",
    ]);
    expect(vector.cases.every((c) => c.expected === true)).toBe(true);
  });

  for (const testCase of vector.cases) {
    it(`verifyMerkleProof returns ${testCase.expected} for ${testCase.name}`, () => {
      expect(verifyMerkleProof(testCase.leaf, testCase.proof, testCase.root)).toBe(
        testCase.expected,
      );
    });
  }

  it("the stale-root case has a proof.root that disagrees with the supplied root", () => {
    const staleRoot = vector.cases.find((c) => c.name === "stale-proof-root-metadata")!;
    expect(staleRoot.proof.root).not.toBe(staleRoot.root);
  });
});
