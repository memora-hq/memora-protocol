/**
 * Memora shared types – canonical definitions for payloads, commits, refs, and envelopes.
 *
 * Phase 1 additions:
 *  - SignedEventEnvelope: foundational schema for future cryptographic provenance.
 *    The `signature` field is explicitly null until runtime signing is implemented.
 *    Mark all unverified paths with UNVERIFIED_PROVENANCE below.
 *  - MemoryCommit gains event_id, signer (operator EVM address).
 *  - AgentCredential: per-agent write authority record.
 */

// ── Lineage / actor types ────────────────────────────────────────────────────

/** Event type for execution lineage (v0.2). */
export type LineageEventType =
  | "task_started"
  | "tool_called"
  | "tool_result"
  | "reasoning_summary"
  | "memory_written"
  | "task_completed"
  | "capsule_created";

/** Actor type for lineage attribution. */
export type ActorType = "agent" | "user" | "system";

// ── Local execution evidence ─────────────────────────────────────────────────

export type LocalCaptureSource =
  | "wrapper_observed"
  | "filesystem_observed"
  | "git_derived"
  | "adapter_reported"
  | "user_declared";

export type LocalCaptureStatus = "complete" | "partial" | "interrupted";

export interface LocalCaptureWarning {
  code: string;
  message: string;
  source?: LocalCaptureSource;
}

/** Signed, versioned index for one offline Memora execution. */
export interface LocalExecutionManifestV1 {
  format: "memora.local.execution";
  version: 1;
  session_id: string;
  agent_id: string;
  capture_source: string;
  capture_root_hash: string;
  started_at: string;
  completed_at?: string;
  root_event_id: string;
  event_ids: string[];
  signer: string;
  capture_status: LocalCaptureStatus;
  capture_warnings: LocalCaptureWarning[];
  signature: string | null;
}

/** Metadata stored beside a canonical MemoryCommit in the local journal. */
export interface LocalEventRecordV1 {
  format: "memora.local.event";
  version: 1;
  observed_at: string;
  source: LocalCaptureSource;
  commit: MemoryCommit;
}

export interface LocalEvidenceBundleV1 {
  format: "memora.local.bundle";
  version: 1;
  manifest: LocalExecutionManifestV1;
  events: LocalEventRecordV1[];
  payloads: Record<string, EncryptedPayloadBundle>;
}

/**
 * v2 adds opt-in disclosure. A v1 bundle is encrypted to the exporter's key, so a recipient can
 * prove it is sealed and unaltered while reading nothing at all. `disclosed` carries plaintext for
 * the records the exporter chose to reveal; a verifier binds each one to the signed
 * `payload_hash`, so disclosed content is provable without the recipient ever holding a key.
 *
 * The bundle is a container, not a signed structure — no signature covers these fields.
 */
export interface LocalEvidenceBundleV2 {
  format: "memora.local.bundle";
  version: 2;
  manifest: LocalExecutionManifestV1;
  events: LocalEventRecordV1[];
  /** Ciphertext for every event, always complete, keyed by object ID. */
  payloads: Record<string, EncryptedPayloadBundle>;
  /** Plaintext for a subset of those object IDs. Absent means nothing was disclosed. */
  disclosed?: Record<string, MemoryPayload>;
}

export type LocalEvidenceBundle = LocalEvidenceBundleV1 | LocalEvidenceBundleV2;

// ── Payload ───────────────────────────────────────────────────────────────────

/** Plaintext memory content (before encryption). */
export interface MemoryPayload {
  /** Protocol version (e.g. "0.1", "0.2"). Optional; canonicalize defaults appropriately. */
  memora_version?: string;
  contentType: string;
  content: unknown;
  tags?: string[];
  taskId?: string;
  access?: AccessPolicySummary;
  /** Optional metadata; included in canonical bytes for hashing. */
  meta?: Record<string, unknown>;
  /** --- v0.2 execution lineage (optional, backwards compatible) --- */
  event_type?: string;
  mission_id?: string;
  parent_ids?: string[];
  derived_from?: string[];
  tool_ref?: string;
  capsule_id?: string;
  actor_type?: ActorType;
  actor_id?: string;
}

/** Summary of access policy (stored on-chain / HCS for discovery only). */
export interface AccessPolicySummary {
  owner?: string;
  delegates?: string[];
  mode?: "private" | "shared";
}

/** Encrypted payload bundle stored on IPFS (ciphertext only). */
export interface EncryptedPayloadBundle {
  version: number;
  alg: "AES-256-GCM";
  nonce: string;      // base64
  ciphertext: string; // base64
  tag: string;        // base64 auth tag
}

// ── Signed event envelope (Phase 1 foundation) ────────────────────────────────

/**
 * Canonical envelope schema for verifiable execution provenance.
 *
 * PROVENANCE STATUS (Phase 1):
 *  - event_id:         COMPUTED (sha256 of canonical MemoryCommit JSON). Deterministic.
 *  - parent_event_ids: POPULATED from payload.parent_ids if present. Not cryptographically linked.
 *  - signer:           POPULATED (operator EVM address derived from the operator's signing key). Not verified by recipients yet.
 *  - signature:        NULL — explicitly unimplemented. Do not treat as verified.
 *  - payload_hash:     VERIFIED (sha256 of canonical plaintext, cross-checked on read).
 *
 * Future phases will add:
 *  - ECDSA signature over canonical(envelope) using operator private key
 *  - On-chain signature verification in the registry modifier
 *  - Agent-side countersignature for dual-signed provenance
 */
export interface SignedEventEnvelope {
  /** Deterministic ID: sha256(canonical(MemoryCommit)). Computed by writeHandler. */
  event_id: string;
  /** Parent memory_ids in the execution chain (from payload.parent_ids). */
  parent_event_ids?: string[];
  /** EVM address of the operator that submitted this commit. Populated, not yet verified. */
  signer?: string;
  /**
   * ECDSA signature over the canonical signing payload (Phase 2+).
   * EIP-191 personal_sign of sha256("memora:event:v1\n" + canonicalSigningFields).
   * null = unsigned (Phase 1 commit).
   */
  signature: string | null;
  /** SHA-256 hex of canonical plaintext — the primary integrity anchor. */
  payload_hash: string;
}

// ── HCS commit message ────────────────────────────────────────────────────────

// ── TEE attestation types (Phase TEE) ────────────────────────────────────────

/** TEE platform identifier. "mock" is for CI only — never use in production. */
export type TeeMode = "amd-sev-snp" | "intel-tdx" | "mock";

/** Result returned by a TeeVerifier after verifying a raw attestation quote. */
export interface TeeQuoteVerificationResult {
  valid: boolean;
  /** Detected platform. */
  platform: TeeMode;
  /** EVM address of the agent signing key bound via report_data (recovered from sha256 preimage match). */
  agent_signer: string;
  /** Primary code measurement: MEASUREMENT (SEV-SNP) or MRTD (TDX). Hex string. */
  measurement: string;
  /** Populated on failure. */
  reason?: string;
}

/** Persisted record of a verified TEE attestation quote (stored in tee_quotes table). */
export interface TeeQuoteRecord {
  /** sha256 hex of raw quote bytes (64-char, no 0x). Primary lookup key. */
  quote_hash:   string;
  /** IPFS/storage CID of the raw quote bytes. */
  quote_cid:    string;
  platform:     TeeMode;
  agent_signer: string;
  agent_id:     string;
  /** Primary code measurement extracted from the quote. Hex string. */
  measurement:  string;
  verified_at:  string;
}

/**
 * Message published to HCS topic (canonical ordering layer).
 *
 * Phase 1 additions: event_id, signer (from SignedEventEnvelope).
 * These fields are populated by writeHandler but their trustworthiness
 * is bounded by the operator being honest (not cryptographically enforced yet).
 */
export interface MemoryCommit {
  memory_id: string;
  agent_id: string;
  task_id?: string;
  cid_ciphertext: string;
  /** SHA-256 hex of canonical plaintext. Normalised to 64-char hex (no 0x prefix). */
  payload_hash: string;
  schema_version: number;
  access_policy_summary?: AccessPolicySummary;
  /** --- v0.2 lineage summary --- */
  event_type?: string;
  mission_id?: string;
  parent_count?: number;
  /**
   * Parent memory IDs included in the operator/agent signing digests.
   * This is HCS metadata for signature verification; event_id remains based on
   * the stable commit summary fields above for backwards compatibility.
   */
  parent_event_ids?: string[];
  derived_from_count?: number;
  /**
   * Phase 1 provenance fields.
   * Populated by writeHandler; not yet cryptographically verified by recipients.
   */
  /** sha256 of canonical(MemoryCommit minus event_id itself). */
  event_id?: string;
  /** EVM address of the submitting operator. */
  signer?: string;
  /**
   * Operator ECDSA signature. See SignedEventEnvelope and envelope.ts for canonical format.
   * null = unsigned (pre-Phase-2 commits). Absent = old schema without field.
   */
  signature?: string | null;
  /**
   * Phase 3: EVM address of the agent runtime's signing key.
   * Registered in agent_signers table. Included in operator signing digest when present.
   */
  agent_signer?: string;
  /**
   * Phase 3: Agent's ECDSA signature over pre-commit fields (payload_hash, agent_id, task_id, etc.).
   * Domain: "memora:agent:v1\n". null = unsigned by agent.
   * For TEE commits, domain is "memora:agent:tee:v1\n" and tee_quote_hash is included in fields.
   */
  agent_signature?: string | null;
  /**
   * Phase TEE: sha256 hex of the raw TEE attestation quote (64-char, no 0x).
   * Included in both agent and operator signing digests for TEE commits.
   * null/absent = not a TEE commit.
   */
  tee_quote_hash?: string | null;
  /**
   * Phase TEE: IPFS/storage CID of the raw TEE attestation quote bytes.
   * Stored for replay retrieval. null/absent = not a TEE commit.
   */
  tee_quote_cid?: string | null;
}

// ── Indexed view ──────────────────────────────────────────────────────────────

/** Indexed view (Supabase / indexer query response). */
export interface MemoryRef {
  memory_id: string;
  agent_id: string;
  task_id: string | null;
  cid_ciphertext: string;
  payload_hash: string;
  hcs_topic_id: string;
  hcs_sequence: string;
  hcs_timestamp: string;
  contract_tx_hash: string;
  created_at: string;
  /** Phase 1: provenance envelope fields (nullable for back-compat with pre-phase1 records). */
  event_id?: string | null;
  signer?: string | null;
  /** --- v0.2 lineage (optional) --- */
  event_type?: string | null;
  mission_id?: string | null;
  parent_ids?: string[] | null;
  derived_from?: string[] | null;
  tool_ref?: string | null;
  capsule_id?: string | null;
  actor_type?: string | null;
  actor_id?: string | null;
  /** Phase 11: pluggable storage backend fields. Null on legacy IPFS records. */
  storage_provider?: string | null;
  storage_object_id?: string | null;
  storage_uri?: string | null;
  /** Phase TEE: TEE attestation fields. Null on non-TEE records. */
  tee_quote_hash?: string | null;
  tee_quote_cid?: string | null;
  tee_verified?: boolean | null;
  tee_platform?: TeeMode | null;
}

// ── Agent authority records ───────────────────────────────────────────────────

/** Agent record. */
export interface AgentRef {
  agent_id: string;
  owner_address: string;
  created_at: string;
}

/** Delegate record (off-chain index; source of truth is on-chain DelegatePolicy). */
export interface DelegateRef {
  agent_id: string;
  delegate_address: string;
  enabled: boolean;
  updated_at: string;
}

/**
 * Per-agent write credential (stored in agent_credentials Supabase table).
 * api_key_hash is SHA-256(raw_api_key) — raw key is never stored.
 *
 * Phase 1 trust model:
 *  - Caller proves possession of the raw key via HTTP Bearer token.
 *  - Server hashes the provided token and compares to stored hash using timingSafeEqual.
 *  - This is infrastructure-level trust (Supabase + TLS), not cryptographic proof.
 *  - Future phases may replace this with signed JWT or wallet-signed challenges.
 */
export interface AgentCredential {
  agent_id: string;
  api_key_hash: string; // SHA-256 hex, 64 chars
  enabled: boolean;
  created_at: string;
  /**
   * Phase 5: EVM address of the ECDSA signing key bound to this HTTP credential.
   * When set, writes must include a matching agent_signer — closes the split-trust gap where
   * a Bearer key could authorise writes for an agent while the signature belongs to an
   * unrelated signer. null = no binding enforced (backward compatible).
   */
  signer_address?: string | null;
}

// ── Batch provenance types (Phase 6+) ────────────────────────────────────────

/** Which chain/backend the batch checkpoint is anchored on. */
export type BatchBackend = "hedera" | "enterprise" | "base";

/** How the batch root is proven. "anchored" = HCS-only; "verified" = HCS + contract ecrecover. */
export type BatchIntegrityMode = "anchored" | "verified";

/** Lifecycle status of a provenance batch. */
export type BatchStatus = "pending" | "anchored" | "failed";

/**
 * A provenance batch groups N execution events under a single Merkle root.
 * The root is anchored to HCS (and optionally the contract) in one checkpoint message.
 * Individual events prove inclusion via a Merkle proof against this root.
 */
export interface MerkleBatch {
  batch_id:         string;
  backend:          BatchBackend;
  integrity_mode:   BatchIntegrityMode;
  merkle_root:      string;     // 64-char hex (no 0x)
  event_count:      number;
  first_event_id:   string | null;
  last_event_id:    string | null;
  hcs_topic_id:     string | null;
  hcs_sequence:     string | null;
  hcs_timestamp:    string | null;
  contract_tx_hash: string | null;
  created_at:       string;
  status:           BatchStatus;
}

/**
 * Per-event record linking a memory event to a batch.
 * merkle_proof_json contains the MerkleProof (see merkle.ts) as raw JSON.
 */
export interface MerkleBatchEvent {
  batch_id:          string;
  event_id:          string;   // references memories.event_id
  leaf_hash:         string;   // 64-char hex
  leaf_index:        number;
  merkle_proof_json: unknown;  // MerkleProof from merkle.ts, stored as JSONB
}

/** Key store row (key-broker only; never exposed via API). */
export interface KeyStoreRow {
  memory_id: string;
  agent_id: string;
  aes_key_base64: string;
  created_at: string;
}

/**
 * On-chain agent signer policy (mirrors MemoraRegistry.AgentSignerPolicy).
 * Retrieved via getAgentSignerPolicy(). Used for historical replay verification.
 * validFrom = block.timestamp when setAgentSigner() was called.
 * validUntil = 0 means no expiry.
 */
export interface OnChainAgentSignerPolicy {
  enabled: boolean;
  validFrom: number;   // Unix timestamp (seconds) — block.timestamp at registration
  validUntil: number;  // 0 = no expiry
}

// ── Replay verification (Phase 7) ─────────────────────────────────────────────

/** Outcome of a persisted replay verification run. */
export type ReplayVerificationStatus = "passed" | "warning" | "failed" | "unknown";

/** A single check within a replay verification run. */
export interface ReplayVerificationCheck {
  id: string;
  label: string;
  status: ReplayVerificationStatus;
  detail?: string;
}

/**
 * A persisted replay verification result.
 * One result per (subject_type, subject_id, verifier_version).
 * Stale results are preserved when the verifier version changes.
 */
export interface ReplayVerificationResult {
  /** What this result was produced for. */
  subject_type: "event" | "run" | "batch" | "agent";
  subject_id: string;
  status: ReplayVerificationStatus;
  /** ISO timestamp of when the verifier ran. */
  verified_at: string;
  /** Semver-like string identifying the verifier build (e.g. "cli@0.5.0"). */
  verifier_version: string;
  /** The commit path of the subject at verification time. null for batch/agent subjects. */
  commit_path?: "TEE" | "VERIFIED" | "ATTESTED" | "LEGACY";
  checks: ReplayVerificationCheck[];
  /** Arbitrary structured output from the verifier (timing, sequence numbers, etc.). */
  summary: Record<string, unknown>;
}
