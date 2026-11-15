import { readFileSync } from "node:fs";
import { describe, it, expect } from "vitest";
import { Wallet } from "ethers";
import { computeEventId, signEventEnvelope, getOperatorSigningDigestBytes, verifyEventId } from "../src/envelope.js";
import type { MemoryCommit } from "../src/types.js";
import { EVENT_ID_PROFILES as P, getEventIdPreimage, computeProfiledEventId, verifyProfiledEventId, verifyProfiledEvent, type EventIdProfile } from "../src/eventId.js";
interface Vector { name: string; profile: EventIdProfile; preimage: string; event_id: string; signing_digest: string; commit: MemoryCommit }
const vectors: Vector[] = JSON.parse(readFileSync(new URL("./hosted-event-id-v1.json", import.meta.url), "utf8"));
const metadata: Vector[] = JSON.parse(readFileSync(new URL("./event-id-metadata-v1.json", import.meta.url), "utf8"));
const operator = new Wallet("17".repeat(32));
const policy = { profile: P.hosted, expectedOperatorSigner: operator.address };
describe("explicit event-ID profiles", () => {
  it.each(vectors)("frozen actual hosted writer: $name", (v) => {
    expect(getEventIdPreimage(v.commit, P.hosted).toString()).toBe(v.preimage);
    expect(computeProfiledEventId(v.commit, P.hosted)).toBe(v.event_id);
    expect(getOperatorSigningDigestBytes(v.commit, v.commit.parent_event_ids ?? []).toString("hex")).toBe(v.signing_digest);
    expect(verifyProfiledEvent(v.commit, policy, Buffer.from(v.preimage)).valid).toBe(true);
    expect(verifyEventId(v.commit).valid).toBe(v.name === "absent-task");
    expect(computeProfiledEventId(v.commit, P.shared)).toBe(computeEventId(v.commit));
  });
  it.each(metadata)("frozen $name metadata/signature bytes", (v) => {
    expect(getEventIdPreimage(v.commit, v.profile).toString()).toBe(v.preimage);
    expect(computeProfiledEventId(v.commit, v.profile)).toBe(v.event_id);
    expect(getOperatorSigningDigestBytes(v.commit, v.commit.parent_event_ids ?? []).toString("hex")).toBe(v.signing_digest);
    expect(verifyProfiledEvent(v.commit, { ...policy, profile: v.profile }, Buffer.from(v.preimage)).valid).toBe(true);
  });
  it("preserves the shared type's nullable legacy TEE fields", () => {
    const commit = { ...vectors[2].commit, tee_quote_hash: null, tee_quote_cid: null };
    commit.event_id = computeEventId(commit);
    expect(verifyProfiledEventId(commit, P.shared).valid).toBe(true);
    expect(verifyProfiledEventId(commit, P.hosted).valid).toBe(false);
  });
  it("keeps the shared task recipe explicit, without trying the hosted recipe", async () => {
    const commit = { ...vectors[2].commit };
    commit.event_id = computeEventId(commit);
    commit.signature = await signEventEnvelope(commit, commit.parent_event_ids ?? [], operator.privateKey);
    expect(verifyProfiledEvent(commit, { ...policy, profile: P.shared }).valid).toBe(true);
    expect(verifyProfiledEvent(commit, policy).valid).toBe(false);
  });
  it("requires an external signer pin, even for a self-consistent attacker artifact", async () => {
    const c = { ...vectors[2].commit };
    expect(verifyProfiledEvent(c, { ...policy, expectedOperatorSigner: "" }).valid).toBe(false);
    const attacker = new Wallet("18".repeat(32)); c.signer = attacker.address;
    c.event_id = computeProfiledEventId(c, P.hosted);
    c.signature = await signEventEnvelope(c, c.parent_event_ids ?? [], attacker.privateKey);
    expect(verifyProfiledEvent(c, policy).valid).toBe(false);
  });
  it.each([
    (c: any) => { c.task_id = "altered"; },
    (c: any) => { delete c.task_id; },
    (c: any) => { c.event_id = "00".repeat(32); },
    (c: any) => { c.event_id = "0x" + c.event_id; },
    (c: any) => { c.parent_event_ids = ["a", "b", "b"]; },
    (c: any) => { c.parent_count = 2; },
    (c: any) => { c.schema_version = 2; },
    (c: any) => { c.signature = "0x" + "00".repeat(65); },
    (c: any) => { c.agent_id = "other"; },
    (c: any) => { c.payload_hash = "00".repeat(32); },
    (c: any) => { c.agent_signature = "altered"; },
  ])("rejects mutations", (mutate) => {
    const c = structuredClone(vectors[2].commit); mutate(c);
    expect(verifyProfiledEvent(c, policy, Buffer.from(vectors[2].preimage)).valid).toBe(false);
  });
  it("rejects arbitrary labels, invalid UTF-8, duplicate JSON keys, unrelated or reserialized preimages", () => {
    const v = vectors[2];
    expect(verifyProfiledEvent(v.commit, { ...policy, profile: "guess-any" as any }).valid).toBe(false);
    for (const bytes of [Buffer.from([255]), Buffer.from(v.preimage + "\n"), Buffer.from(vectors[0].preimage), Buffer.from(v.preimage.replace('"schema_version":1', '"schema_version":1,"schema_version":1'))]) {
      expect(verifyProfiledEvent(v.commit, policy, bytes).valid).toBe(false);
    }
    // Hashing arbitrary saved bytes is insufficient, even if the operator signed that ID.
    expect(verifyProfiledEventId(v.commit, P.shared, Buffer.from(v.preimage)).valid).toBe(false);
  });
  it("freezes metadata, agent and legacy TEE field order separately from the shared order", () => {
    const c: MemoryCommit = { ...vectors[2].commit, agent_signer: operator.address, agent_signature: "historical-agent-proof", tee_quote_hash: "ab".repeat(32), tee_quote_cid: "ipfs://quote", event_type: "tool_called", mission_id: "mission", derived_from_count: 2 };
    const base = { memory_id: c.memory_id, agent_id: c.agent_id, task_id: c.task_id, cid_ciphertext: c.cid_ciphertext, payload_hash: c.payload_hash, schema_version: 1, signature: null, signer: c.signer, agent_signer: c.agent_signer, agent_signature: c.agent_signature, tee_quote_hash: c.tee_quote_hash, tee_quote_cid: c.tee_quote_cid, event_type: c.event_type, mission_id: c.mission_id, parent_count: c.parent_count, derived_from_count: c.derived_from_count };
    expect(getEventIdPreimage(c, P.hosted).toString()).toBe(JSON.stringify(base));
    expect(computeProfiledEventId(c, P.shared)).toBe(computeEventId(c));
  });
});
