/**
 * Event envelope signing and verification.
 *
 * Phase 2: Operator ECDSA signatures over canonical commit fields.
 * Phase 3: Agent countersignatures over pre-commit fields.
 *
 * Cryptographic model:
 *
 *  AGENT signature (Phase 3):
 *    Domain: "memora:agent:v1\n"
 *    Fields: agent_id, agent_signer, parent_event_ids, payload_hash, task_id
 *    Signed BEFORE IPFS upload — agent commits to payload content + identity.
 *    The agent doesn't know cid_ciphertext or event_id at signing time.
 *    payload_hash binds the agent to specific plaintext content.
 *
 *  OPERATOR signature (Phase 2+3):
 *    Domain: "memora:event:v1\n"
 *    Fields: agent_id, [agent_signer], cid_ciphertext, event_id, parent_event_ids, payload_hash, task_id
 *    Signed AFTER IPFS upload and event_id computation.
 *    When agent_signer is present, operator signing fields include it — binding operator
 *    acceptance to the specific agent that originated the write.
 *
 *  Trust chain:
 *    content → payload_hash → agent_signature (pre-commit)
 *              → IPFS upload → cid → event_id
 *                                    → operator_signature (post-commit, covers agent_signer)
 *
 *  What agent signature proves:
 *    The registered agent ECDSA key authorised this specific payload for this agent_id and task.
 *
 *  What operator signature proves:
 *    The operator accepted this write, uploaded to IPFS, computed event_id, and committed to HCS.
 *    When agent_signer is included, it also proves the operator accepted THIS SPECIFIC agent's write.
 *
 *  What neither signature proves alone:
 *    - That the agent and operator are acting honestly (only a compromised key breaks this).
 *    - That the plaintext matches the hash (requires decryption).
 *
 *  Backward compatibility:
 *    - Commits without agent_signer use Phase 2 operator signing (same digest as before).
 *    - Commits without signature use Phase 1 infrastructure-trust model.
 */

import { createHash } from "crypto";
import { Wallet, verifyMessage } from "ethers";
import type { MemoryCommit } from "./types.js";

// ── Domain separators ─────────────────────────────────────────────────────────

const OPERATOR_DOMAIN   = "memora:event:v1\n";
const AGENT_DOMAIN      = "memora:agent:v1\n";
/** Phase TEE: distinct domain prevents cross-path signature reuse. */
const AGENT_TEE_DOMAIN  = "memora:agent:tee:v1\n";

// ── Operator signing types and functions ─────────────────────────────────────

/**
 * The subset of MemoryCommit fields signed by the operator.
 * Must be stable: never add mutable fields here.
 * When agent_signer is present, it is included to bind operator acceptance to the specific agent.
 * When tee_quote_hash is present (TEE commit), it is included to bind the quote to the operator sig.
 */
export interface CanonicalSigningFields {
  agent_id: string;
  /** Phase 3: agent's EVM address. Included when the write carries an agent countersignature. */
  agent_signer?: string;
  cid_ciphertext: string;
  event_id: string;
  parent_event_ids: string[];
  payload_hash: string;
  task_id: string;
  /** Phase TEE: sha256 hex of the raw TEE quote. Included when the commit carries a TEE attestation. */
  tee_quote_hash?: string;
}

function sortedJson(fields: Record<string, unknown>): string {
  const sorted: Record<string, unknown> = {};
  for (const k of Object.keys(fields).sort()) sorted[k] = fields[k];
  return JSON.stringify(sorted);
}

/**
 * Compute the 32-byte operator signing digest.
 * sha256("memora:event:v1\n" + sortedJson(fields))
 */
export function computeSigningDigest(fields: CanonicalSigningFields): Uint8Array {
  const f = fields as unknown as Record<string, unknown>;
  // Exclude undefined optional keys so digest is deterministic
  const clean: Record<string, unknown> = {};
  for (const k of Object.keys(f).sort()) {
    if (f[k] !== undefined) clean[k] = f[k];
  }
  return createHash("sha256").update(OPERATOR_DOMAIN + sortedJson(clean), "utf8").digest();
}

/**
 * Extract signing fields from a MemoryCommit.
 * Requires event_id. Includes agent_signer when present.
 * Includes tee_quote_hash when present (Phase TEE commits).
 */
export function extractSigningFields(commit: MemoryCommit): CanonicalSigningFields {
  if (!commit.event_id) throw new Error("event_id is required for signing");
  const fields: CanonicalSigningFields = {
    agent_id:         commit.agent_id,
    cid_ciphertext:   commit.cid_ciphertext,
    event_id:         commit.event_id,
    parent_event_ids: [],
    payload_hash:     commit.payload_hash,
    task_id:          commit.task_id ?? "0x0000000000000000000000000000000000000000000000000000000000000000",
  };
  if (commit.agent_signer)   fields.agent_signer   = commit.agent_signer;
  if (commit.tee_quote_hash) fields.tee_quote_hash = commit.tee_quote_hash;
  return fields;
}

/**
 * Sign a MemoryCommit using the operator's ECDSA private key.
 * @param commit         Must have event_id populated.
 * @param parentEventIds Sorted parent memory IDs.
 * @param operatorKey    Hex private key (ECDSA only; ED25519 keys throw).
 */
export async function signEventEnvelope(
  commit: MemoryCommit,
  parentEventIds: string[],
  operatorKey: string
): Promise<string> {
  const fields = extractSigningFields(commit);
  fields.parent_event_ids = [...parentEventIds].sort();
  const digest = computeSigningDigest(fields);
  const wallet = new Wallet(operatorKey.startsWith("0x") ? operatorKey : "0x" + operatorKey);
  return wallet.signMessage(digest);
}

export interface VerifyResult {
  valid: boolean;
  recoveredSigner: string | null;
  reason?: string;
}

/**
 * Verify the operator ECDSA signature on a MemoryCommit.
 * Automatically includes agent_signer in the digest when present on the commit.
 *
 * Fail-closed: `expectedSigner` is REQUIRED to return `valid: true`. Recovering *a*
 * signer from a signature proves nothing about authenticity (any key can produce a
 * valid-looking signature), so when `expectedSigner` is omitted this returns
 * `valid: false` with the recovered address populated for inspection. Callers that
 * only need the recovered address (e.g. display/inspection) must use
 * `recoverEnvelopeSigner()` explicitly rather than relying on this function.
 */
export function verifyEventEnvelope(
  commit: MemoryCommit,
  parentEventIds: string[],
  expectedSigner?: string
): VerifyResult {
  if (!commit.signature) {
    return { valid: false, recoveredSigner: null, reason: "no signature present (pre-Phase-2 commit)" };
  }
  if (!commit.event_id) {
    return { valid: false, recoveredSigner: null, reason: "no event_id (cannot reconstruct signing payload)" };
  }
  let recoveredSigner: string;
  try {
    const fields = extractSigningFields(commit);
    fields.parent_event_ids = [...parentEventIds].sort();
    const digest = computeSigningDigest(fields);
    recoveredSigner = verifyMessage(digest, commit.signature);
  } catch (err) {
    return {
      valid: false,
      recoveredSigner: null,
      reason: `signature verification error: ${(err as Error).message}`,
    };
  }
  if (!expectedSigner) {
    return {
      valid: false,
      recoveredSigner,
      reason: "no expected signer provided — cannot confirm operator identity (use recoverEnvelopeSigner to inspect)",
    };
  }
  const valid = recoveredSigner.toLowerCase() === expectedSigner.toLowerCase();
  return {
    valid,
    recoveredSigner,
    reason: valid ? undefined : `signer mismatch: got ${recoveredSigner}, expected ${expectedSigner}`,
  };
}

/**
 * Recover the address that signed a commit envelope, WITHOUT asserting it is
 * authorised. Returns null when there is no signature/event_id or recovery fails.
 *
 * This is for display/inspection only. To authenticate a commit, use
 * verifyEventEnvelope(commit, parentEventIds, expectedSigner) with a known signer.
 */
export function recoverEnvelopeSigner(
  commit: MemoryCommit,
  parentEventIds: string[]
): string | null {
  if (!commit.signature || !commit.event_id) return null;
  try {
    const fields = extractSigningFields(commit);
    fields.parent_event_ids = [...parentEventIds].sort();
    const digest = computeSigningDigest(fields);
    return verifyMessage(digest, commit.signature);
  } catch {
    return null;
  }
}

/**
 * Recompute event_id from a commit's stable fields and verify it matches.
 * Includes agent_signer and agent_signature when present (Phase 3).
 */
export function verifyEventId(commit: MemoryCommit): { valid: boolean; recomputed: string; reason?: string } {
  if (!commit.event_id) {
    return { valid: false, recomputed: "", reason: "no event_id field" };
  }
  const base: Record<string, unknown> = {
    memory_id:      commit.memory_id,
    agent_id:       commit.agent_id,
    cid_ciphertext: commit.cid_ciphertext,
    payload_hash:   commit.payload_hash,
    schema_version: commit.schema_version,
    signature:      null,
  };
  if (commit.task_id          != null) base.task_id          = commit.task_id;
  if (commit.signer           != null) base.signer           = commit.signer;
  if (commit.agent_signer     != null) base.agent_signer     = commit.agent_signer;
  if (commit.agent_signature  != null) base.agent_signature  = commit.agent_signature;
  if (commit.event_type       != null) base.event_type       = commit.event_type;
  if (commit.mission_id       != null) base.mission_id       = commit.mission_id;
  if (commit.parent_count          != null) base.parent_count          = commit.parent_count;
  if (commit.derived_from_count    != null) base.derived_from_count    = commit.derived_from_count;
  if (commit.tee_quote_hash   != null) base.tee_quote_hash   = commit.tee_quote_hash;
  if (commit.tee_quote_cid    != null) base.tee_quote_cid    = commit.tee_quote_cid;

  const recomputed = computeEventIdFromBase(base);
  const valid = recomputed === commit.event_id;
  return {
    valid,
    recomputed,
    reason: valid ? undefined : `event_id mismatch: stored=${commit.event_id} recomputed=${recomputed}`,
  };
}

/** Compute an event ID from the stable commit fields used by v1 records. */
export function computeEventId(commit: MemoryCommit): string {
  const base: Record<string, unknown> = {
    memory_id:      commit.memory_id,
    agent_id:       commit.agent_id,
    cid_ciphertext: commit.cid_ciphertext,
    payload_hash:   commit.payload_hash,
    schema_version: commit.schema_version,
    signature:      null,
  };
  if (commit.task_id          != null) base.task_id          = commit.task_id;
  if (commit.signer           != null) base.signer           = commit.signer;
  if (commit.agent_signer     != null) base.agent_signer     = commit.agent_signer;
  if (commit.agent_signature  != null) base.agent_signature  = commit.agent_signature;
  if (commit.event_type       != null) base.event_type       = commit.event_type;
  if (commit.mission_id       != null) base.mission_id       = commit.mission_id;
  if (commit.parent_count          != null) base.parent_count          = commit.parent_count;
  if (commit.derived_from_count    != null) base.derived_from_count    = commit.derived_from_count;
  if (commit.tee_quote_hash   != null) base.tee_quote_hash   = commit.tee_quote_hash;
  if (commit.tee_quote_cid    != null) base.tee_quote_cid    = commit.tee_quote_cid;
  return computeEventIdFromBase(base);
}

function computeEventIdFromBase(base: Record<string, unknown>): string {
  return createHash("sha256").update(JSON.stringify(base), "utf8").digest("hex");
}

/**
 * Get the raw 32-byte operator signing digest as a Buffer.
 * This is the exact value passed to Solidity's commitMemoryVerified as `eventDigest`.
 * Pass to wallet.signMessage(getBytes(digest)) for a Solidity-compatible EIP-191 signature.
 */
export function getOperatorSigningDigestBytes(
  commit: MemoryCommit,
  parentEventIds: string[]
): Buffer {
  const fields = extractSigningFields(commit);
  fields.parent_event_ids = [...parentEventIds].sort();
  return Buffer.from(computeSigningDigest(fields));
}

/**
 * Get the raw 32-byte agent signing digest as a Buffer.
 * This is the exact value passed to Solidity's commitMemoryVerified as `agentCommitDigest`.
 * Pass to wallet.signMessage(getBytes(digest)) for a Solidity-compatible EIP-191 signature.
 */
export function getAgentSigningDigestBytes(fields: AgentCanonicalSigningFields): Buffer {
  const sorted: AgentCanonicalSigningFields = {
    ...fields,
    parent_event_ids: [...fields.parent_event_ids].sort(),
  };
  return Buffer.from(computeAgentSigningDigest(sorted));
}

// ── Agent signing types and functions (Phase 3) ───────────────────────────────

/**
 * Fields the agent signs BEFORE the indexer processes the write.
 * Known at emit time: agent_id, signer address, parent_ids, task_id.
 * payload_hash is computed by the agent from the canonical payload — this is the binding.
 * cid_ciphertext and event_id are NOT included (not yet known).
 */
export interface AgentCanonicalSigningFields {
  agent_id:          string;
  agent_signer:      string;   // agent's own EVM address
  parent_event_ids:  string[]; // sorted; [] when no parents
  payload_hash:      string;   // sha256 of canonical payload (64-char hex, no 0x)
  task_id:           string;   // raw task_id string; "0x00...00" when absent
}

/**
 * Compute the 32-byte agent signing digest.
 * sha256("memora:agent:v1\n" + sortedJson(fields))
 * Different domain from operator prevents cross-use of signatures.
 */
export function computeAgentSigningDigest(fields: AgentCanonicalSigningFields): Uint8Array {
  const f = fields as unknown as Record<string, unknown>;
  return createHash("sha256").update(AGENT_DOMAIN + sortedJson(f), "utf8").digest();
}

/**
 * Sign a pre-commit event with the agent's private key.
 * Call this BEFORE sending the write request to the indexer.
 * The payload_hash must be computed from the same canonicalize → sha256 pipeline used by the indexer.
 */
export async function signAgentEvent(
  fields: AgentCanonicalSigningFields,
  agentKey: string
): Promise<string> {
  const sortedFields: AgentCanonicalSigningFields = {
    ...fields,
    parent_event_ids: [...fields.parent_event_ids].sort(),
  };
  const digest = computeAgentSigningDigest(sortedFields);
  const wallet = new Wallet(agentKey.startsWith("0x") ? agentKey : "0x" + agentKey);
  return wallet.signMessage(digest);
}

export interface AgentVerifyResult {
  valid: boolean;
  recoveredSigner: string | null;
  reason?: string;
}

/**
 * Verify an agent's ECDSA signature.
 * @param fields         The pre-commit signing fields (agent_id, agent_signer, payload_hash, etc.).
 * @param signature      The agent's signature hex string.
 * @param expectedSigner Optional: check recovered signer matches this address.
 */
export function verifyAgentSignature(
  fields: AgentCanonicalSigningFields,
  signature: string,
  expectedSigner?: string
): AgentVerifyResult {
  try {
    const sortedFields: AgentCanonicalSigningFields = {
      ...fields,
      parent_event_ids: [...fields.parent_event_ids].sort(),
    };
    const digest = computeAgentSigningDigest(sortedFields);
    const recovered = verifyMessage(digest, signature);
    if (expectedSigner) {
      const valid = recovered.toLowerCase() === expectedSigner.toLowerCase();
      return {
        valid,
        recoveredSigner: recovered,
        reason: valid
          ? undefined
          : `agent signer mismatch: got ${recovered}, expected ${expectedSigner}`,
      };
    }
    return { valid: true, recoveredSigner: recovered };
  } catch (err) {
    return {
      valid: false,
      recoveredSigner: null,
      reason: `agent signature error: ${(err as Error).message}`,
    };
  }
}

// ── Phase TEE: Agent TEE signing types and functions ──────────────────────────

/**
 * Fields the agent signs on TEE commits. Extends AgentCanonicalSigningFields
 * with tee_quote_hash. Uses a distinct domain to prevent cross-path signature reuse.
 *
 * Domain: "memora:agent:tee:v1\n"
 * Signed BEFORE the indexer processes the write — agent commits to payload content,
 * identity, and the specific TEE attestation quote (binding the key to the enclave).
 */
export interface AgentTeeCanonicalSigningFields {
  agent_id:         string;
  agent_signer:     string;   // agent's EVM address (generated inside the TEE)
  parent_event_ids: string[]; // sorted; [] when no parents
  payload_hash:     string;   // sha256 of canonical payload (64-char hex, no 0x)
  task_id:          string;   // "0x00...00" when absent
  tee_quote_hash:   string;   // sha256 hex of raw TEE quote (64-char, no 0x) — binds signature to enclave
}

/**
 * Compute the 32-byte agent TEE signing digest.
 * sha256("memora:agent:tee:v1\n" + sortedJson(fields))
 *
 * Produces a different digest than computeAgentSigningDigest for identical inputs
 * because the domain separator differs — cross-path replay is impossible.
 */
export function computeAgentTeeSigningDigest(fields: AgentTeeCanonicalSigningFields): Uint8Array {
  const sorted: AgentTeeCanonicalSigningFields = {
    ...fields,
    parent_event_ids: [...fields.parent_event_ids].sort(),
  };
  const f = sorted as unknown as Record<string, unknown>;
  const canonical: Record<string, unknown> = {};
  for (const k of Object.keys(f).sort()) canonical[k] = f[k];
  return createHash("sha256").update(AGENT_TEE_DOMAIN + JSON.stringify(canonical), "utf8").digest();
}

/**
 * Sign a pre-commit TEE event with the agent's private key.
 * Call BEFORE sending the write request to the indexer.
 * The tee_quote_hash binds this signature to the specific enclave attestation quote.
 */
export async function signAgentTeeEvent(
  fields: AgentTeeCanonicalSigningFields,
  agentKey: string
): Promise<string> {
  const digest = computeAgentTeeSigningDigest(fields);
  const wallet = new Wallet(agentKey.startsWith("0x") ? agentKey : "0x" + agentKey);
  return wallet.signMessage(digest);
}

/**
 * Verify an agent's TEE ECDSA signature.
 * Uses the "memora:agent:tee:v1\n" domain — not interchangeable with verifyAgentSignature.
 */
export function verifyAgentTeeSignature(
  fields: AgentTeeCanonicalSigningFields,
  signature: string,
  expectedSigner?: string
): AgentVerifyResult {
  try {
    const digest    = computeAgentTeeSigningDigest(fields);
    const recovered = verifyMessage(digest, signature);
    if (expectedSigner) {
      const valid = recovered.toLowerCase() === expectedSigner.toLowerCase();
      return {
        valid,
        recoveredSigner: recovered,
        reason: valid
          ? undefined
          : `agent TEE signer mismatch: got ${recovered}, expected ${expectedSigner}`,
      };
    }
    return { valid: true, recoveredSigner: recovered };
  } catch (err) {
    return {
      valid: false,
      recoveredSigner: null,
      reason: `agent TEE signature error: ${(err as Error).message}`,
    };
  }
}

/**
 * Get the raw 32-byte agent TEE signing digest as a Buffer.
 * Pass to wallet.signMessage(getBytes(digest)) for a Solidity-compatible EIP-191 signature.
 */
export function getAgentTeeSigningDigestBytes(fields: AgentTeeCanonicalSigningFields): Buffer {
  return Buffer.from(computeAgentTeeSigningDigest(fields));
}
