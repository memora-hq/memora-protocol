/** Explicit v1 byte recipes. Profile selection is caller policy, never evidence authority. */
import { createHash } from "crypto";
import { verifyEventEnvelope, type VerifyResult } from "./envelope.js";
import type { MemoryCommit } from "./types.js";

export const EVENT_ID_PROFILES = Object.freeze({
  shared: "shared-protocol-json-stringify-v1",
  hosted: "hosted-indexer-json-stringify-v1",
} as const);
export type EventIdProfile = typeof EVENT_ID_PROFILES[keyof typeof EVENT_ID_PROFILES];
/** Keep the existing writer's semantics and signed domain unchanged. */
export const HOSTED_WRITE_EVENT_ID_PROFILE = EVENT_ID_PROFILES.hosted;

function validate(commit: MemoryCommit, profile: EventIdProfile): void {
  if (profile !== EVENT_ID_PROFILES.shared && profile !== EVENT_ID_PROFILES.hosted) throw new Error("unsupported event-ID profile");
  if (!commit || commit.schema_version !== 1) throw new Error("unsupported commit version");
  for (const key of ["memory_id", "agent_id", "cid_ciphertext", "payload_hash"] as const) {
    if (typeof commit[key] !== "string" || !commit[key]) throw new Error(`invalid ${key}`);
  }
  for (const key of ["task_id", "signer", "agent_signer", "event_type", "mission_id", "tee_quote_hash", "tee_quote_cid"] as const) {
    if (profile === EVENT_ID_PROFILES.shared && (key === "tee_quote_hash" || key === "tee_quote_cid") && commit[key] === null) continue;
    if (commit[key] !== undefined && typeof commit[key] !== "string") throw new Error(`invalid ${key}`);
  }
  if (commit.agent_signature != null && typeof commit.agent_signature !== "string") throw new Error("invalid agent signature");
  for (const key of ["parent_count", "derived_from_count"] as const) {
    if (commit[key] !== undefined && (!Number.isSafeInteger(commit[key]) || commit[key]! < 0)) throw new Error(`invalid ${key}`);
  }
  if (commit.parent_event_ids !== undefined && (!Array.isArray(commit.parent_event_ids) || commit.parent_event_ids.some(p => typeof p !== "string"))) throw new Error("invalid parents");
  if (profile === EVENT_ID_PROFILES.hosted) {
    if (!/^0x[0-9a-f]{64}$/.test(commit.memory_id) || !/^[0-9a-f]{64}$/.test(commit.payload_hash)) throw new Error("invalid hosted hash encoding");
    const allowed = new Set(["memory_id", "agent_id", "task_id", "cid_ciphertext", "payload_hash", "schema_version", "signature", "signer", "agent_signer", "agent_signature", "tee_quote_hash", "tee_quote_cid", "event_type", "mission_id", "parent_count", "derived_from_count", "event_id", "parent_event_ids"]);
    if (Object.keys(commit).some(k => !allowed.has(k))) throw new Error("unsupported hosted commit field");
    const parents = commit.parent_event_ids ?? [];
    if (JSON.stringify(parents) !== JSON.stringify([...parents].sort()) || (commit.parent_count ?? 0) !== parents.length) throw new Error("inconsistent hosted parents");
  }
}

/** Exact UTF-8 JSON bytes hashed before event_id and the operator signature exist. */
export function getEventIdPreimage(commit: MemoryCommit, profile: EventIdProfile): Buffer {
  validate(commit, profile);
  const base: Record<string, unknown> = { memory_id: commit.memory_id, agent_id: commit.agent_id };
  if (profile === EVENT_ID_PROFILES.hosted && commit.task_id !== undefined) base.task_id = commit.task_id;
  Object.assign(base, { cid_ciphertext: commit.cid_ciphertext, payload_hash: commit.payload_hash, schema_version: commit.schema_version, signature: null });
  if (profile === EVENT_ID_PROFILES.shared && commit.task_id != null) base.task_id = commit.task_id;
  if (profile === EVENT_ID_PROFILES.hosted) {
    if (commit.signer) base.signer = commit.signer;
    if (commit.agent_signer) base.agent_signer = commit.agent_signer;
  } else {
    if (commit.signer != null) base.signer = commit.signer;
    if (commit.agent_signer != null) base.agent_signer = commit.agent_signer;
  }
  if (commit.agent_signature != null) base.agent_signature = commit.agent_signature;
  if (profile === EVENT_ID_PROFILES.hosted) {
    if (commit.tee_quote_hash) base.tee_quote_hash = commit.tee_quote_hash;
    if (commit.tee_quote_cid) base.tee_quote_cid = commit.tee_quote_cid;
  }
  for (const key of ["event_type", "mission_id", "parent_count", "derived_from_count"] as const) {
    if (commit[key] != null) base[key] = commit[key];
  }
  if (profile === EVENT_ID_PROFILES.shared) {
    if (commit.tee_quote_hash != null) base.tee_quote_hash = commit.tee_quote_hash;
    if (commit.tee_quote_cid != null) base.tee_quote_cid = commit.tee_quote_cid;
  }
  return Buffer.from(JSON.stringify(base), "utf8");
}

export function computeProfiledEventId(commit: MemoryCommit, profile: EventIdProfile): string {
  return createHash("sha256").update(getEventIdPreimage(commit, profile)).digest("hex");
}

/** Integrity only. Does not authenticate a signer or trust an artifact's recipe label. */
export function verifyProfiledEventId(commit: MemoryCommit, profile: EventIdProfile, originalPreimage?: Uint8Array): { valid: boolean; recomputed: string; reason?: string } {
  try {
    const expected = getEventIdPreimage(commit, profile);
    if (originalPreimage !== undefined && (!(originalPreimage instanceof Uint8Array) || !expected.equals(Buffer.from(originalPreimage)))) throw new Error("original preimage does not correspond to commit/profile");
    const recomputed = createHash("sha256").update(expected).digest("hex");
    const valid = typeof commit.event_id === "string" && /^[0-9a-f]{64}$/.test(commit.event_id) && recomputed === commit.event_id;
    return { valid, recomputed, reason: valid ? undefined : "event_id mismatch or invalid encoding" };
  } catch (e) {
    return { valid: false, recomputed: "", reason: (e as Error).message };
  }
}

/** Profile and expected signer MUST come from verifier policy, outside the evidence.
 * No recipe guessing/fallback. Historical originals without bytes may use the frozen
 * constructor. This authenticates the operator statement, not signer governance,
 * agent signatures, hardware authenticity, or the unsigned storage wrapper.
 */
export function verifyProfiledEvent(commit: MemoryCommit, policy: { profile: EventIdProfile; expectedOperatorSigner: string }, originalPreimage?: Uint8Array): VerifyResult {
  const id = verifyProfiledEventId(commit, policy.profile, originalPreimage);
  if (!id.valid) return { valid: false, recoveredSigner: null, reason: id.reason };
  return verifyEventEnvelope(commit, commit.parent_event_ids ?? [], policy.expectedOperatorSigner);
}

/** Minimal byte-preserved original seam, independent of any hosted storage wrapper.
 * Strict canonical base64 and JSON round-trip prevent lossy decodes/duplicate keys.
 * policy is supplied by the verifier, never copied from a user's profile label.
 */
export function verifyOriginalEvent(original: { commit_bytes_b64: string; event_id_preimage_b64: string }, policy: { profile: EventIdProfile; expectedOperatorSigner: string }): VerifyResult {
  try {
    const decode = (value: string): Buffer => {
      if (typeof value !== "string") throw new Error("invalid original byte encoding");
      const bytes = Buffer.from(value, "base64");
      if (bytes.toString("base64") !== value) throw new Error("invalid original base64");
      return bytes;
    };
    const commitBytes = decode(original.commit_bytes_b64);
    const text = new TextDecoder("utf-8", { fatal: true }).decode(commitBytes);
    const commit = JSON.parse(text) as MemoryCommit;
    if (JSON.stringify(commit) !== text) throw new Error("invalid original commit JSON encoding");
    return verifyProfiledEvent(commit, policy, decode(original.event_id_preimage_b64));
  } catch (e) {
    return { valid: false, recoveredSigner: null, reason: (e as Error).message };
  }
}
