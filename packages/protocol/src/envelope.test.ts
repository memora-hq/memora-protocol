import { describe, it, expect } from "vitest";
import { Wallet } from "ethers";
import { createHash } from "crypto";
import {
  computeSigningDigest,
  extractSigningFields,
  signEventEnvelope,
  verifyEventEnvelope,
  recoverEnvelopeSigner,
  verifyEventId,
  computeAgentSigningDigest,
  signAgentEvent,
  verifyAgentSignature,
  computeAgentTeeSigningDigest,
  signAgentTeeEvent,
  verifyAgentTeeSignature,
  getAgentTeeSigningDigestBytes,
  getOperatorSigningDigestBytes,
  getAgentSigningDigestBytes,
  type CanonicalSigningFields,
  type AgentCanonicalSigningFields,
  type AgentTeeCanonicalSigningFields,
} from "./envelope.js";
import { verifyMessage } from "ethers";
import type { MemoryCommit } from "./types.js";

// Deterministic test keys — NOT used anywhere real
const OPERATOR_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const AGENT_KEY    = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const operatorWallet = new Wallet(OPERATOR_KEY);
const agentWallet    = new Wallet(AGENT_KEY);

function makeCommit(overrides: Partial<MemoryCommit> = {}): MemoryCommit {
  return {
    memory_id:      "0xaabbcc",
    agent_id:       "test-agent",
    cid_ciphertext: "QmTestCID123",
    payload_hash:   "a".repeat(64),
    schema_version: 1,
    event_id:       "b".repeat(64),
    signer:         operatorWallet.address,
    signature:      null,
    task_id:        "0x" + "0".repeat(64),
    ...overrides,
  };
}

// ── Operator signing ──────────────────────────────────────────────────────────

describe("computeSigningDigest", () => {
  it("is deterministic for identical inputs", () => {
    const f: CanonicalSigningFields = {
      agent_id: "a", cid_ciphertext: "b", event_id: "c".repeat(64),
      parent_event_ids: [], payload_hash: "d".repeat(64), task_id: "0x" + "0".repeat(64),
    };
    expect(Buffer.from(computeSigningDigest(f)).toString("hex"))
      .toBe(Buffer.from(computeSigningDigest(f)).toString("hex"));
  });

  it("changes when any field changes", () => {
    const base: CanonicalSigningFields = {
      agent_id: "a", cid_ciphertext: "b", event_id: "c".repeat(64),
      parent_event_ids: [], payload_hash: "d".repeat(64), task_id: "0x" + "0".repeat(64),
    };
    const d1 = Buffer.from(computeSigningDigest(base)).toString("hex");
    const d2 = Buffer.from(computeSigningDigest({ ...base, agent_id: "changed" })).toString("hex");
    expect(d1).not.toBe(d2);
  });

  it("digest changes when agent_signer is added", () => {
    const base: CanonicalSigningFields = {
      agent_id: "a", cid_ciphertext: "b", event_id: "c".repeat(64),
      parent_event_ids: [], payload_hash: "d".repeat(64), task_id: "0x" + "0".repeat(64),
    };
    const without = Buffer.from(computeSigningDigest(base)).toString("hex");
    const with_   = Buffer.from(computeSigningDigest({ ...base, agent_signer: agentWallet.address })).toString("hex");
    expect(without).not.toBe(with_);
  });
});

describe("signEventEnvelope + verifyEventEnvelope", () => {
  it("round-trips without agent_signer (Phase 2 backward compat)", async () => {
    const commit = makeCommit();
    const sig = await signEventEnvelope(commit, [], OPERATOR_KEY);
    const result = verifyEventEnvelope({ ...commit, signature: sig }, [], operatorWallet.address);
    expect(result.valid).toBe(true);
    expect(result.recoveredSigner?.toLowerCase()).toBe(operatorWallet.address.toLowerCase());
  });

  it("round-trips with agent_signer (Phase 3)", async () => {
    const commit = makeCommit({ agent_signer: agentWallet.address });
    const sig = await signEventEnvelope(commit, [], OPERATOR_KEY);
    const result = verifyEventEnvelope({ ...commit, signature: sig }, [], operatorWallet.address);
    expect(result.valid).toBe(true);
  });

  it("fails when agent_signer is tampered after operator signing", async () => {
    const commit = makeCommit({ agent_signer: agentWallet.address });
    const sig = await signEventEnvelope(commit, [], OPERATOR_KEY);
    const tampered = { ...commit, agent_signer: "0x" + "1".repeat(40), signature: sig };
    const result = verifyEventEnvelope(tampered, [], operatorWallet.address);
    expect(result.valid).toBe(false);
  });

  it("Phase 2 sig fails if agent_signer is added after signing", async () => {
    // Sign without agent_signer (Phase 2 style)
    const commit = makeCommit();
    const sig = await signEventEnvelope(commit, [], OPERATOR_KEY);
    // Try to verify with agent_signer added (different digest)
    const withAgent = { ...commit, agent_signer: agentWallet.address, signature: sig };
    const result = verifyEventEnvelope(withAgent, [], operatorWallet.address);
    expect(result.valid).toBe(false);
  });

  it("fails when signature is null", () => {
    expect(verifyEventEnvelope(makeCommit({ signature: null }), []).valid).toBe(false);
  });

  it("fails when payload_hash is tampered", async () => {
    const commit = makeCommit();
    const sig = await signEventEnvelope(commit, [], OPERATOR_KEY);
    const tampered = { ...commit, payload_hash: "f".repeat(64), signature: sig };
    expect(verifyEventEnvelope(tampered, [], operatorWallet.address).valid).toBe(false);
  });

  it("is sensitive to parent_event_ids", async () => {
    const commit = makeCommit();
    const sig = await signEventEnvelope(commit, ["p1", "p2"], OPERATOR_KEY);
    // Wrong parents → wrong digest → wrong recovered signer
    expect(verifyEventEnvelope({ ...commit, signature: sig }, ["p1"], operatorWallet.address).valid).toBe(false);
    // Correct parents (order shouldn't matter — both are sorted before hashing)
    expect(verifyEventEnvelope({ ...commit, signature: sig }, ["p2", "p1"], operatorWallet.address).valid).toBe(true);
  });

  it("fails closed when no expectedSigner is provided (does not treat any signature as valid)", async () => {
    // Even a perfectly valid signature must NOT be reported valid without an expected
    // signer to check identity against — recovering a signer is not proof of authenticity.
    const commit = makeCommit();
    const sig = await signEventEnvelope(commit, [], OPERATOR_KEY);
    const result = verifyEventEnvelope({ ...commit, signature: sig }, []);
    expect(result.valid).toBe(false);
    // The recovered address is still surfaced for inspection.
    expect(result.recoveredSigner?.toLowerCase()).toBe(operatorWallet.address.toLowerCase());
    expect(result.reason).toMatch(/no expected signer/i);
  });
});

describe("recoverEnvelopeSigner", () => {
  it("recovers the signing address without asserting authorisation", async () => {
    const commit = makeCommit();
    const sig = await signEventEnvelope(commit, [], OPERATOR_KEY);
    const recovered = recoverEnvelopeSigner({ ...commit, signature: sig }, []);
    expect(recovered?.toLowerCase()).toBe(operatorWallet.address.toLowerCase());
  });

  it("returns null when there is no signature", () => {
    expect(recoverEnvelopeSigner(makeCommit({ signature: null }), [])).toBeNull();
  });

  it("recovers a different address for a signature sorted with wrong parents", async () => {
    // Wrong parents produce a different digest, so recovery yields some other address
    // (not the operator) — proving recovery alone cannot be trusted for authenticity.
    const commit = makeCommit();
    const sig = await signEventEnvelope(commit, ["p1", "p2"], OPERATOR_KEY);
    const recovered = recoverEnvelopeSigner({ ...commit, signature: sig }, ["p1"]);
    expect(recovered).not.toBeNull();
    expect(recovered?.toLowerCase()).not.toBe(operatorWallet.address.toLowerCase());
  });
});

// ── Agent signing (Phase 3) ────────────────────────────────────────────────────

describe("computeAgentSigningDigest", () => {
  it("is deterministic", () => {
    const f: AgentCanonicalSigningFields = {
      agent_id: "a", agent_signer: agentWallet.address,
      parent_event_ids: [], payload_hash: "b".repeat(64), task_id: "",
    };
    const d1 = Buffer.from(computeAgentSigningDigest(f)).toString("hex");
    const d2 = Buffer.from(computeAgentSigningDigest(f)).toString("hex");
    expect(d1).toBe(d2);
  });

  it("uses different domain than operator (different digest for same logical fields)", () => {
    // Operator and agent signing over "equivalent" fields should produce different digests
    const agentFields: AgentCanonicalSigningFields = {
      agent_id: "x", agent_signer: agentWallet.address,
      parent_event_ids: [], payload_hash: "a".repeat(64), task_id: "t",
    };
    const operatorFields: CanonicalSigningFields = {
      agent_id: "x", agent_signer: agentWallet.address, cid_ciphertext: "c",
      event_id: "e".repeat(64), parent_event_ids: [], payload_hash: "a".repeat(64), task_id: "t",
    };
    const agentDigest    = Buffer.from(computeAgentSigningDigest(agentFields)).toString("hex");
    const operatorDigest = Buffer.from(computeSigningDigest(operatorFields)).toString("hex");
    expect(agentDigest).not.toBe(operatorDigest);
  });
});

describe("signAgentEvent + verifyAgentSignature", () => {
  const baseFields: AgentCanonicalSigningFields = {
    agent_id:         "test-agent",
    agent_signer:     agentWallet.address,
    parent_event_ids: [],
    payload_hash:     "a".repeat(64),
    task_id:          "0x" + "0".repeat(64),
  };

  it("round-trips successfully", async () => {
    const sig = await signAgentEvent(baseFields, AGENT_KEY);
    const result = verifyAgentSignature(baseFields, sig, agentWallet.address);
    expect(result.valid).toBe(true);
    expect(result.recoveredSigner?.toLowerCase()).toBe(agentWallet.address.toLowerCase());
  });

  it("recovers signer without expectedSigner", async () => {
    const sig = await signAgentEvent(baseFields, AGENT_KEY);
    const result = verifyAgentSignature(baseFields, sig);
    expect(result.valid).toBe(true);
    expect(result.recoveredSigner?.toLowerCase()).toBe(agentWallet.address.toLowerCase());
  });

  it("fails when expectedSigner is a different address", async () => {
    const sig = await signAgentEvent(baseFields, AGENT_KEY);
    const result = verifyAgentSignature(baseFields, sig, operatorWallet.address);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/agent signer mismatch/);
  });

  it("fails when payload_hash is tampered", async () => {
    const sig = await signAgentEvent(baseFields, AGENT_KEY);
    const tampered = { ...baseFields, payload_hash: "f".repeat(64) };
    expect(verifyAgentSignature(tampered, sig, agentWallet.address).valid).toBe(false);
  });

  it("fails when agent_id is tampered", async () => {
    const sig = await signAgentEvent(baseFields, AGENT_KEY);
    const tampered = { ...baseFields, agent_id: "evil-agent" };
    expect(verifyAgentSignature(tampered, sig, agentWallet.address).valid).toBe(false);
  });

  it("is order-insensitive for parent_event_ids (sorted before hashing)", async () => {
    const sig = await signAgentEvent({ ...baseFields, parent_event_ids: ["p1", "p2"] }, AGENT_KEY);
    // Verify with reversed order — should still pass (sorted internally)
    const result = verifyAgentSignature({ ...baseFields, parent_event_ids: ["p2", "p1"] }, sig, agentWallet.address);
    expect(result.valid).toBe(true);
  });

  it("agent signature does not verify as operator signature (domain separation)", async () => {
    const agentSig = await signAgentEvent(baseFields, AGENT_KEY);
    // Operator verification should not recover agentWallet from an agent signature
    const commit = makeCommit({ agent_signer: agentWallet.address, event_id: "b".repeat(64) });
    // Forcibly inject the agent sig as operator sig — operator verifier uses different domain
    const result = verifyEventEnvelope({ ...commit, signature: agentSig }, [], agentWallet.address);
    expect(result.valid).toBe(false);
  });

  it("handles invalid signature string gracefully", () => {
    const result = verifyAgentSignature(baseFields, "bad-sig");
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/error/i);
  });
});

// ── Phase 5: digest byte helpers + Solidity ecrecover compatibility ───────────

describe("getOperatorSigningDigestBytes + getAgentSigningDigestBytes", () => {
  it("operator digest is 32 bytes", () => {
    const bytes = getOperatorSigningDigestBytes(makeCommit({ event_id: "b".repeat(64) }), []);
    expect(bytes.length).toBe(32);
  });

  it("agent digest is 32 bytes", () => {
    const bytes = getAgentSigningDigestBytes({
      agent_id: "a", agent_signer: agentWallet.address,
      parent_event_ids: [], payload_hash: "b".repeat(64), task_id: "",
    });
    expect(bytes.length).toBe(32);
  });

  it("operator digest bytes → signMessage → verifyMessage recovers correct address (Solidity-compatible)", async () => {
    const commit = makeCommit({ event_id: "b".repeat(64) });
    const digestBytes = getOperatorSigningDigestBytes(commit, []);
    // This is what Solidity's _recoverEthSignedMessage does on-chain
    const sig = await operatorWallet.signMessage(digestBytes); // EIP-191 personal_sign
    const recovered = verifyMessage(digestBytes, sig);
    expect(recovered.toLowerCase()).toBe(operatorWallet.address.toLowerCase());
  });

  it("agent digest bytes → signMessage → verifyMessage recovers correct address", async () => {
    const fields = {
      agent_id: "test-agent", agent_signer: agentWallet.address,
      parent_event_ids: ["p1"], payload_hash: "a".repeat(64), task_id: "t1",
    };
    const digestBytes = getAgentSigningDigestBytes(fields);
    const sig = await agentWallet.signMessage(digestBytes);
    const recovered = verifyMessage(digestBytes, sig);
    expect(recovered.toLowerCase()).toBe(agentWallet.address.toLowerCase());
  });

  it("digest bytes differ from digest hex string (bytes vs string path)", () => {
    const commit = makeCommit({ event_id: "b".repeat(64) });
    const digestBytes = getOperatorSigningDigestBytes(commit, []);
    const digestHex = "0x" + digestBytes.toString("hex");
    // signMessage(bytes) and signMessage(string) produce different signatures
    // because signMessage(string) converts to UTF-8 bytes then signs
    // This test documents the expected contract: always pass bytes, never hex string
    expect(digestBytes.length).toBe(32);
    expect(digestHex.length).toBe(66); // 0x + 64 hex chars
  });

  it("getOperatorSigningDigestBytes matches computeSigningDigest output", () => {
    const commit = makeCommit({ event_id: "b".repeat(64) });
    const fromHelper = getOperatorSigningDigestBytes(commit, ["p1", "p2"]);
    const fields = extractSigningFields(commit);
    fields.parent_event_ids = ["p1", "p2"].sort();
    const fromDirect = Buffer.from(computeSigningDigest(fields));
    expect(fromHelper.equals(fromDirect)).toBe(true);
  });
});

// ── verifyEventId ─────────────────────────────────────────────────────────────

describe("verifyEventId", () => {
  it("verifies a correctly computed event_id without agent fields", () => {
    const base = {
      memory_id: "0xaa", agent_id: "agent", cid_ciphertext: "Qm",
      payload_hash: "a".repeat(64), schema_version: 1, signature: null,
      signer: operatorWallet.address,
    };
    const event_id = createHash("sha256").update(JSON.stringify(base), "utf8").digest("hex");
    expect(verifyEventId({ ...base, event_id }).valid).toBe(true);
  });

  it("verifies a correctly computed event_id WITH agent fields (Phase 3)", () => {
    const base = {
      memory_id: "0xbb", agent_id: "agent", cid_ciphertext: "Qm2",
      payload_hash: "b".repeat(64), schema_version: 1, signature: null,
      signer: operatorWallet.address,
      agent_signer: agentWallet.address,
      agent_signature: "0x" + "c".repeat(130),
    };
    const event_id = createHash("sha256").update(JSON.stringify(base), "utf8").digest("hex");
    expect(verifyEventId({ ...base, event_id }).valid).toBe(true);
  });

  it("fails for tampered event_id", () => {
    const result = verifyEventId(makeCommit({ event_id: "0".repeat(64) }));
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/event_id mismatch/);
  });

  it("fails when event_id is absent", () => {
    expect(verifyEventId(makeCommit({ event_id: undefined })).valid).toBe(false);
  });
});

// ── Phase TEE: agent TEE signing + verification ───────────────────────────────

describe("signAgentTeeEvent + verifyAgentTeeSignature", () => {
  const QUOTE_HASH = "a".repeat(64);
  const baseFields: AgentTeeCanonicalSigningFields = {
    agent_id:         "tee-agent",
    agent_signer:     agentWallet.address,
    parent_event_ids: [],
    payload_hash:     "b".repeat(64),
    task_id:          "0x" + "0".repeat(64),
    tee_quote_hash:   QUOTE_HASH,
  };

  it("sign + verify round-trip succeeds", async () => {
    const sig = await signAgentTeeEvent(baseFields, AGENT_KEY);
    const result = verifyAgentTeeSignature(baseFields, sig, agentWallet.address);
    expect(result.valid).toBe(true);
    expect(result.recoveredSigner?.toLowerCase()).toBe(agentWallet.address.toLowerCase());
  });

  it("verifies without expectedSigner", async () => {
    const sig = await signAgentTeeEvent(baseFields, AGENT_KEY);
    const result = verifyAgentTeeSignature(baseFields, sig);
    expect(result.valid).toBe(true);
  });

  it("rejects wrong expectedSigner", async () => {
    const sig = await signAgentTeeEvent(baseFields, AGENT_KEY);
    const result = verifyAgentTeeSignature(baseFields, sig, operatorWallet.address);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/mismatch/i);
  });

  it("is order-insensitive for parent_event_ids", async () => {
    const sig = await signAgentTeeEvent({ ...baseFields, parent_event_ids: ["p1", "p2"] }, AGENT_KEY);
    const result = verifyAgentTeeSignature(
      { ...baseFields, parent_event_ids: ["p2", "p1"] }, sig, agentWallet.address
    );
    expect(result.valid).toBe(true);
  });

  it("rejects signature when tee_quote_hash is tampered", async () => {
    const sig = await signAgentTeeEvent(baseFields, AGENT_KEY);
    const tampered = { ...baseFields, tee_quote_hash: "c".repeat(64) };
    expect(verifyAgentTeeSignature(tampered, sig, agentWallet.address).valid).toBe(false);
  });

  it("rejects standard agent signature (domain separation — TEE sig ≠ standard sig)", async () => {
    // Sign with standard domain, try to verify with TEE verifier
    const standardSig = await signAgentEvent(
      { agent_id: baseFields.agent_id, agent_signer: baseFields.agent_signer,
        parent_event_ids: baseFields.parent_event_ids, payload_hash: baseFields.payload_hash,
        task_id: baseFields.task_id },
      AGENT_KEY
    );
    const result = verifyAgentTeeSignature(baseFields, standardSig, agentWallet.address);
    expect(result.valid).toBe(false);
  });

  it("rejects TEE signature when verified as standard (domain separation)", async () => {
    const teeSig = await signAgentTeeEvent(baseFields, AGENT_KEY);
    const stdFields: AgentCanonicalSigningFields = {
      agent_id:         baseFields.agent_id,
      agent_signer:     baseFields.agent_signer,
      parent_event_ids: baseFields.parent_event_ids,
      payload_hash:     baseFields.payload_hash,
      task_id:          baseFields.task_id,
    };
    const result = verifyAgentSignature(stdFields, teeSig, agentWallet.address);
    expect(result.valid).toBe(false);
  });

  it("handles invalid signature gracefully", () => {
    const result = verifyAgentTeeSignature(baseFields, "bad-sig");
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/error/i);
  });
});

describe("computeAgentTeeSigningDigest", () => {
  const fields: AgentTeeCanonicalSigningFields = {
    agent_id: "a", agent_signer: "0x" + "1".repeat(40),
    parent_event_ids: [], payload_hash: "b".repeat(64),
    task_id: "0x" + "0".repeat(64), tee_quote_hash: "c".repeat(64),
  };

  it("returns 32-byte digest", () => {
    expect(Buffer.from(computeAgentTeeSigningDigest(fields)).length).toBe(32);
  });

  it("getAgentTeeSigningDigestBytes matches computeAgentTeeSigningDigest", () => {
    const direct = Buffer.from(computeAgentTeeSigningDigest(fields));
    const helper = getAgentTeeSigningDigestBytes(fields);
    expect(helper.equals(direct)).toBe(true);
  });

  it("TEE digest differs from standard agent digest (domain separation)", () => {
    const stdFields: AgentCanonicalSigningFields = {
      agent_id: fields.agent_id, agent_signer: fields.agent_signer,
      parent_event_ids: fields.parent_event_ids,
      payload_hash: fields.payload_hash, task_id: fields.task_id,
    };
    const stdDigest = Buffer.from(computeAgentSigningDigest(stdFields));
    const teeDigest = Buffer.from(computeAgentTeeSigningDigest(fields));
    expect(teeDigest.equals(stdDigest)).toBe(false);
  });

  it("TEE digest is deterministic regardless of field insertion order", () => {
    const f1: AgentTeeCanonicalSigningFields = { ...fields };
    const f2: AgentTeeCanonicalSigningFields = {
      tee_quote_hash:   fields.tee_quote_hash,
      task_id:          fields.task_id,
      payload_hash:     fields.payload_hash,
      parent_event_ids: fields.parent_event_ids,
      agent_signer:     fields.agent_signer,
      agent_id:         fields.agent_id,
    };
    expect(
      Buffer.from(computeAgentTeeSigningDigest(f1)).equals(
        Buffer.from(computeAgentTeeSigningDigest(f2))
      )
    ).toBe(true);
  });
});
