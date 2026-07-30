#!/usr/bin/env node
/**
 * Golden conformance vector generator.
 *
 * ── APPEND-ONLY ─────────────────────────────────────────────────────────────
 * Re-running this script must only ever ADD new vector files. It must NEVER
 * overwrite or mutate a vector file that has already been committed. A frozen
 * vector changing means a previously-shipped signing domain produced a
 * different output, which must never happen — the vector is the regression
 * pin, so "the vector changed" is the failure, not the fix.
 *
 * The script therefore refuses to write over an existing file: to add new
 * coverage, add a new `write(...)` call with a NEW filename and run it again.
 * ────────────────────────────────────────────────────────────────────────────
 *
 * Vectors are produced by calling the real, unchanged implementations in
 * packages/protocol and packages/local — never by hand-computing hashes. Build
 * both packages before running:
 *
 *   pnpm --filter @smritheon/memora-protocol build
 *   pnpm --filter @memora/local build
 *   node packages/protocol/vectors/generate.mjs
 *
 * Keys are the well-known Hardhat dev accounts #0/#1 used throughout this
 * repo's tests. They are public, test-only, and never used for anything real.
 */

import { createHash } from "node:crypto";
import { existsSync, writeFileSync, mkdirSync } from "node:fs";
import { mkdtemp, mkdir, writeFile, copyFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Wallet } from "ethers";

import {
  computeSigningDigest,
  extractSigningFields,
  signEventEnvelope,
  computeAgentSigningDigest,
  signAgentEvent,
  computeAgentTeeSigningDigest,
  signAgentTeeEvent,
  computeEventLeafHash,
  buildMerkleTree,
  getMerkleProof,
  verifyMerkleProof,
  buildMockTeeQuote,
} from "../dist/index.js";

import { FileKeyProvider, getOrCreateIdentity } from "../../local/dist/identity.js";
import { LocalSession } from "../../local/dist/session.js";
import { LocalEvidenceStore } from "../../local/dist/store.js";
import { exportLocalBundle, readLocalBundle, verifyLocalBundle } from "../../local/dist/bundle.js";

const VECTORS_DIR = path.dirname(fileURLToPath(import.meta.url));

// Well-known Hardhat dev accounts #0 and #1. Test-only, never used for real value.
const OPERATOR_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const AGENT_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const operatorWallet = new Wallet(OPERATOR_KEY);
const agentWallet = new Wallet(AGENT_KEY);

const KEY_NOTE =
  "Well-known Hardhat dev accounts #0 and #1. Public, test-only keys used throughout this repo's tests — never used for production value.";

const ZERO_TASK = "0x" + "0".repeat(64);

function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

/** Refuses to overwrite: vectors are append-only once committed. */
function write(filename, data) {
  const target = path.join(VECTORS_DIR, filename);
  if (existsSync(target)) {
    console.log(`SKIP  ${filename} (already exists — vectors are append-only)`);
    return false;
  }
  mkdirSync(VECTORS_DIR, { recursive: true });
  writeFileSync(target, JSON.stringify(data, null, 2) + "\n");
  console.log(`WROTE ${filename}`);
  return true;
}

// ── memora:event:v1 ───────────────────────────────────────────────────────────

async function eventVectors() {
  const cases = [];

  // Case 1 — no parents, no agent countersignature (Phase 2 shape).
  {
    const commit = {
      memory_id: "mem_0000000000000000000000000000000a",
      agent_id: "conformance-agent",
      cid_ciphertext: "QmConformanceVectorCidOne",
      payload_hash: "a".repeat(64),
      schema_version: 1,
      event_id: "b".repeat(64),
      signer: operatorWallet.address,
      signature: null,
      task_id: ZERO_TASK,
    };
    const parentsInput = [];
    const fields = extractSigningFields(commit);
    fields.parent_event_ids = [...parentsInput].sort();
    const signature = await signEventEnvelope(commit, parentsInput, OPERATOR_KEY);
    cases.push({
      name: "operator-no-parents",
      note: "Baseline Phase 2 operator envelope: no parents, no agent countersignature.",
      commit,
      parent_event_ids_input: parentsInput,
      parent_event_ids_sorted: fields.parent_event_ids,
      signing_fields: fields,
      digest_hex: hex(computeSigningDigest(fields)),
      signature,
      recovered_signer: operatorWallet.address,
    });
  }

  // Case 2 — parents supplied OUT OF ORDER, plus an agent_signer (Phase 3 shape).
  // Pins that computeSigningDigest/signEventEnvelope sort parents before hashing.
  {
    const commit = {
      memory_id: "mem_0000000000000000000000000000000b",
      agent_id: "conformance-agent",
      cid_ciphertext: "QmConformanceVectorCidTwo",
      payload_hash: "c".repeat(64),
      schema_version: 1,
      event_id: "d".repeat(64),
      signer: operatorWallet.address,
      agent_signer: agentWallet.address,
      signature: null,
      task_id: "task-conformance-001",
    };
    // Deliberately unsorted: "f..." before "1..." before "9...".
    const parentsInput = ["f".repeat(64), "1".repeat(64), "9".repeat(64)];
    const fields = extractSigningFields(commit);
    fields.parent_event_ids = [...parentsInput].sort();
    const signature = await signEventEnvelope(commit, parentsInput, OPERATOR_KEY);
    cases.push({
      name: "operator-unsorted-parents-with-agent-signer",
      note:
        "parent_event_ids_input is deliberately unsorted. The frozen digest is the SORTED-parent digest — " +
        "signing/verifying with the unsorted input must produce exactly this digest (see AGENTS.md gotcha #5).",
      commit,
      parent_event_ids_input: parentsInput,
      parent_event_ids_sorted: fields.parent_event_ids,
      signing_fields: fields,
      digest_hex: hex(computeSigningDigest(fields)),
      signature,
      recovered_signer: operatorWallet.address,
    });
  }

  return {
    vector_id: "event-v1",
    domain: "memora:event:v1\\n",
    generated_by: "packages/protocol/src/envelope.ts — computeSigningDigest / signEventEnvelope",
    key_note: KEY_NOTE,
    operator_private_key: OPERATOR_KEY,
    operator_address: operatorWallet.address,
    cases,
  };
}

// ── memora:agent:v1 ───────────────────────────────────────────────────────────

async function agentVectors() {
  const cases = [];

  {
    const fields = {
      agent_id: "conformance-agent",
      agent_signer: agentWallet.address,
      parent_event_ids: [],
      payload_hash: "a".repeat(64),
      task_id: ZERO_TASK,
    };
    cases.push({
      name: "agent-no-parents",
      note: "Baseline agent countersignature over a parentless event.",
      fields_input: fields,
      fields_sorted: fields,
      digest_hex: hex(computeAgentSigningDigest(fields)),
      signature: await signAgentEvent(fields, AGENT_KEY),
      recovered_signer: agentWallet.address,
    });
  }

  {
    const unsorted = ["e".repeat(64), "2".repeat(64), "7".repeat(64)];
    const fieldsInput = {
      agent_id: "conformance-agent",
      agent_signer: agentWallet.address,
      parent_event_ids: unsorted,
      payload_hash: "c".repeat(64),
      task_id: "task-conformance-001",
    };
    const fieldsSorted = { ...fieldsInput, parent_event_ids: [...unsorted].sort() };
    cases.push({
      name: "agent-unsorted-parents",
      note:
        "fields_input.parent_event_ids is deliberately unsorted. The frozen digest is the SORTED-parent digest — " +
        "signAgentEvent/verifyAgentSignature sort internally.",
      fields_input: fieldsInput,
      fields_sorted: fieldsSorted,
      digest_hex: hex(computeAgentSigningDigest(fieldsSorted)),
      signature: await signAgentEvent(fieldsInput, AGENT_KEY),
      recovered_signer: agentWallet.address,
    });
  }

  return {
    vector_id: "agent-v1",
    domain: "memora:agent:v1\\n",
    generated_by: "packages/protocol/src/envelope.ts — computeAgentSigningDigest / signAgentEvent",
    key_note: KEY_NOTE,
    agent_private_key: AGENT_KEY,
    agent_address: agentWallet.address,
    cases,
  };
}

// ── memora:agent:tee:v1 ───────────────────────────────────────────────────────

async function agentTeeVectors() {
  const quotePayload = "memora-conformance-vector-v1";
  const quote = buildMockTeeQuote(quotePayload);
  const quoteHash = createHash("sha256").update(quote).digest("hex");

  const cases = [];

  {
    const fields = {
      agent_id: "conformance-agent",
      agent_signer: agentWallet.address,
      parent_event_ids: [],
      payload_hash: "a".repeat(64),
      task_id: ZERO_TASK,
      tee_quote_hash: quoteHash,
    };
    cases.push({
      name: "agent-tee-no-parents",
      note: "Baseline TEE-domain agent signature. Distinct domain from memora:agent:v1 — not interchangeable.",
      fields_input: fields,
      fields_sorted: fields,
      digest_hex: hex(computeAgentTeeSigningDigest(fields)),
      signature: await signAgentTeeEvent(fields, AGENT_KEY),
      recovered_signer: agentWallet.address,
    });
  }

  {
    const unsorted = ["d".repeat(64), "3".repeat(64), "8".repeat(64)];
    const fieldsInput = {
      agent_id: "conformance-agent",
      agent_signer: agentWallet.address,
      parent_event_ids: unsorted,
      payload_hash: "c".repeat(64),
      task_id: "task-conformance-001",
      tee_quote_hash: quoteHash,
    };
    const fieldsSorted = { ...fieldsInput, parent_event_ids: [...unsorted].sort() };
    cases.push({
      name: "agent-tee-unsorted-parents",
      note: "fields_input.parent_event_ids is deliberately unsorted; computeAgentTeeSigningDigest sorts internally.",
      fields_input: fieldsInput,
      fields_sorted: fieldsSorted,
      digest_hex: hex(computeAgentTeeSigningDigest(fieldsSorted)),
      signature: await signAgentTeeEvent(fieldsInput, AGENT_KEY),
      recovered_signer: agentWallet.address,
    });
  }

  return {
    vector_id: "agent-tee-v1",
    domain: "memora:agent:tee:v1\\n",
    generated_by:
      "packages/protocol/src/envelope.ts — computeAgentTeeSigningDigest / signAgentTeeEvent; quote from packages/protocol/src/tee.ts buildMockTeeQuote",
    key_note: KEY_NOTE,
    agent_private_key: AGENT_KEY,
    agent_address: agentWallet.address,
    tee_quote: {
      builder: "buildMockTeeQuote(payload)",
      payload: quotePayload,
      raw_utf8: quote.toString("utf8"),
      raw_base64: quote.toString("base64"),
      quote_hash: quoteHash,
      quote_hash_note: "sha256(raw quote bytes), 64-char lowercase hex, no 0x — same derivation the indexer's teeVerifier uses.",
    },
    cases,
  };
}

// ── memora:leaf:v1 + Merkle tree/proofs ───────────────────────────────────────

function merkleVectors() {
  // 5 leaves — odd count, so the tree exercises Bitcoin-style duplicate-last-node
  // padding at both level 0 (5 → 3) and level 1 (3 → 2).
  const leafInputs = [
    {
      event_id: "0".repeat(63) + "1",
      payload_hash: "1".repeat(64),
      agent_id: "conformance-agent",
      agent_signer: agentWallet.address,
      operator_signer: operatorWallet.address,
      parent_event_ids: [],
      event_digest: "a".repeat(64),
      agent_commit_digest: "b".repeat(64),
    },
    {
      event_id: "0".repeat(63) + "2",
      payload_hash: "2".repeat(64),
      agent_id: "conformance-agent",
      agent_signer: agentWallet.address,
      operator_signer: operatorWallet.address,
      // Deliberately unsorted — canonicalLeafFields sorts before hashing.
      parent_event_ids: ["0".repeat(62) + "0f", "0".repeat(63) + "1"],
      event_digest: "c".repeat(64),
      agent_commit_digest: null,
    },
    {
      event_id: "0".repeat(63) + "3",
      payload_hash: "0x" + "3".repeat(64),
      agent_id: "conformance-agent",
      agent_signer: null,
      operator_signer: operatorWallet.address,
      parent_event_ids: ["0".repeat(63) + "2"],
      event_digest: null,
      agent_commit_digest: null,
    },
    {
      event_id: "0".repeat(63) + "4",
      payload_hash: "4".repeat(64),
      agent_id: "conformance-agent-two",
      operator_signer: operatorWallet.address,
      parent_event_ids: ["0".repeat(63) + "3"],
    },
    {
      event_id: "0".repeat(63) + "5",
      payload_hash: "5".repeat(64),
      agent_id: "conformance-agent-two",
      agent_signer: agentWallet.address,
      operator_signer: operatorWallet.address,
      parent_event_ids: ["0".repeat(63) + "4"],
      event_digest: "e".repeat(64),
      agent_commit_digest: "f".repeat(64),
    },
  ];

  const leaves = leafInputs.map((input) => computeEventLeafHash(input));
  const tree = buildMerkleTree(leaves);

  const cases = [];

  // Index 2: non-first, non-last. Level 0 → sibling on the right; level 1 → the
  // node is at index 1 (odd), so its sibling is on the left. Exercises both sides.
  for (const index of [2, 4]) {
    const proof = getMerkleProof(leaves, index);
    const expected = verifyMerkleProof(proof.leaf, proof, tree.root);
    if (expected !== true) throw new Error(`positive vector for index ${index} did not verify`);
    cases.push({
      name: `valid-proof-index-${index}`,
      note:
        index === 2
          ? "Interior leaf: proof contains both a right-side and a left-side step."
          : "Last leaf of an odd-length level: exercises duplicate-last-node padding.",
      leaf: proof.leaf,
      proof,
      root: tree.root,
      expected: true,
    });
  }

  // Negative vector: flip one byte of the FIRST proof step's sibling hash.
  {
    const good = getMerkleProof(leaves, 2);
    const tamperedStep = { ...good.proof[0] };
    const firstChar = tamperedStep.hash[0];
    tamperedStep.hash = (firstChar === "0" ? "1" : "0") + tamperedStep.hash.slice(1);
    if (tamperedStep.hash === good.proof[0].hash) throw new Error("tamper was a no-op");
    const tampered = { ...good, proof: [tamperedStep, ...good.proof.slice(1)] };
    const expected = verifyMerkleProof(tampered.leaf, tampered, tree.root);
    if (expected !== false) throw new Error("tampered vector unexpectedly verified as TRUE");
    cases.push({
      name: "tampered-proof-index-2",
      note:
        "NEGATIVE vector. Identical to valid-proof-index-2 except the first proof step's sibling hash has one " +
        "character flipped. Every conforming verifier must return false. A verifier returning true here is broken.",
      leaf: tampered.leaf,
      proof: tampered,
      root: tree.root,
      expected: false,
      tampered_from: "valid-proof-index-2",
    });
  }

  return {
    vector_id: "merkle-v1",
    domain: "memora:leaf:v1\\n",
    generated_by:
      "packages/protocol/src/merkle.ts — computeEventLeafHash / buildMerkleTree / getMerkleProof / verifyMerkleProof",
    key_note: KEY_NOTE,
    tree: {
      leaf_inputs: leafInputs,
      leaves,
      levels: tree.levels,
      root: tree.root,
    },
    cases,
  };
}

// Same fixture as merkleVectors() — duplicated deliberately so this file stays
// self-contained and doesn't depend on merkleVectors()'s internal locals.
function merkleEdgeCaseVectors() {
  const leafInputs = [
    {
      event_id: "0".repeat(63) + "1",
      payload_hash: "1".repeat(64),
      agent_id: "conformance-agent",
      agent_signer: agentWallet.address,
      operator_signer: operatorWallet.address,
      parent_event_ids: [],
      event_digest: "a".repeat(64),
      agent_commit_digest: "b".repeat(64),
    },
    {
      event_id: "0".repeat(63) + "2",
      payload_hash: "2".repeat(64),
      agent_id: "conformance-agent",
      agent_signer: agentWallet.address,
      operator_signer: operatorWallet.address,
      parent_event_ids: ["0".repeat(62) + "0f", "0".repeat(63) + "1"],
      event_digest: "c".repeat(64),
      agent_commit_digest: null,
    },
    {
      event_id: "0".repeat(63) + "3",
      payload_hash: "0x" + "3".repeat(64),
      agent_id: "conformance-agent",
      agent_signer: null,
      operator_signer: operatorWallet.address,
      parent_event_ids: ["0".repeat(63) + "2"],
      event_digest: null,
      agent_commit_digest: null,
    },
  ];

  const leaves = leafInputs.map((input) => computeEventLeafHash(input));
  const tree = buildMerkleTree(leaves);
  const cases = [];

  // Case: proof.root is stale/wrong (simulates a re-anchored batch whose stored
  // proof metadata wasn't refreshed), but leaf + steps still reconstruct to the
  // caller's expectedRoot. Ground truth is the reconstruction, not the
  // self-reported proof.root field — every conforming verifier must return true.
  {
    const good = getMerkleProof(leaves, 1);
    const staleRootProof = { ...good, root: "f".repeat(64) };
    const expected = verifyMerkleProof(staleRootProof.leaf, staleRootProof, tree.root);
    if (expected !== true) {
      throw new Error("stale-proof-root vector unexpectedly failed to verify");
    }
    cases.push({
      name: "stale-proof-root-metadata",
      note:
        "proof.root is deliberately wrong (simulates a stale/re-anchored batch's proof metadata). " +
        "leaf + proof steps still reconstruct to the real, separately-supplied root. A conforming " +
        "verifier must return true — proof.root is descriptive metadata, not part of the check.",
      leaf: good.leaf,
      proof: staleRootProof,
      root: tree.root,
      expected: true,
    });
  }

  // Case: leaf, proof.leaf, every proof step's hash, and the root are all
  // 0x-prefixed. A conforming verifier must normalize this the same as
  // unprefixed hex and still return true.
  {
    const good = getMerkleProof(leaves, 1);
    const prefixed = {
      ...good,
      leaf: "0x" + good.leaf,
      proof: good.proof.map((step) => ({ ...step, hash: "0x" + step.hash })),
      root: "0x" + good.root,
    };
    const expected = verifyMerkleProof(prefixed.leaf, prefixed, "0x" + tree.root);
    if (expected !== true) {
      throw new Error("0x-prefixed vector unexpectedly failed to verify");
    }
    cases.push({
      name: "0x-prefixed-inputs",
      note:
        "leaf, proof.leaf, every proof step's hash, and root are all 0x-prefixed. A conforming " +
        "verifier must normalize the prefix the same as unprefixed hex and still return true.",
      leaf: prefixed.leaf,
      proof: prefixed,
      root: "0x" + tree.root,
      expected: true,
    });
  }

  return {
    vector_id: "merkle-v2-edge-cases",
    domain: "memora:leaf:v1\\n",
    generated_by:
      "packages/protocol/src/merkle.ts — verifyMerkleProof (edge cases: stale proof.root metadata, 0x-prefixed inputs)",
    key_note: KEY_NOTE,
    tree: {
      leaf_inputs: leafInputs,
      leaves,
      levels: tree.levels,
      root: tree.root,
    },
    cases,
  };
}

// ── .memora bundle (real artifact from packages/local) ────────────────────────

async function bundleVector(filename) {
  const target = path.join(VECTORS_DIR, filename);
  if (existsSync(target)) {
    console.log(`SKIP  ${filename} (already exists — vectors are append-only)`);
    return;
  }

  const root = await mkdtemp(path.join(tmpdir(), "memora-vector-bundle-"));
  const keyPath = path.join(root, "identity", "key.json");

  // Pin a deterministic identity: FileKeyProvider.load() returns whatever JSON is
  // already at its path, so getOrCreateIdentity never reaches Wallet.createRandom().
  await mkdir(path.dirname(keyPath), { recursive: true, mode: 0o700 });
  await writeFile(
    keyPath,
    JSON.stringify(
      {
        agentId: `local:conformance:${agentWallet.address.slice(2, 10).toLowerCase()}`,
        address: agentWallet.address,
        privateKey: AGENT_KEY,
      },
      null,
      2,
    ) + "\n",
    { mode: 0o600 },
  );

  const store = new LocalEvidenceStore(root);
  const identity = await getOrCreateIdentity(new FileKeyProvider(keyPath), "conformance");
  if (identity.privateKey !== AGENT_KEY) throw new Error("identity was not pinned to the known test key");

  const session = new LocalSession({
    store,
    identity,
    // Literal, not the tmpdir, so the manifest's capture_root_hash is reproducible
    // and no machine-local path is embedded in the frozen artifact.
    captureRoot: "memora-conformance-vector",
  });
  await session.start();
  await session.record("prompt_submitted", { provider: "claude" }, "adapter_reported");
  await session.record(
    "tool_completed",
    { tool_name: "Edit", tool_input: { file_path: "src/app.ts" } },
    "adapter_reported",
  );
  const manifest = await session.finish("complete");

  const exportPath = path.join(root, "sealed.memora");
  const result = await exportLocalBundle(store, manifest.session_id, exportPath);
  if (result.disclosure !== "none") throw new Error("expected a sealed bundle");

  const verification = verifyLocalBundle(await readLocalBundle(exportPath));
  if (!verification.valid) throw new Error(`generated bundle did not verify: ${verification.errors.join("; ")}`);

  await copyFile(exportPath, target);
  console.log(
    `WROTE ${filename} (signer=${verification.signer}, events=${verification.eventCount}, fingerprint=${result.fingerprint})`,
  );
}

// ── main ──────────────────────────────────────────────────────────────────────

async function main() {
  write("event-v1.json", await eventVectors());
  write("agent-v1.json", await agentVectors());
  write("agent-tee-v1.json", await agentTeeVectors());
  write("merkle-v1.json", merkleVectors());
  write("merkle-v2-edge-cases.json", merkleEdgeCaseVectors());
  await bundleVector("bundle-v2-sealed.memora");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
