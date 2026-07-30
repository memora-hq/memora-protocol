import { describe, it, expect } from "vitest";
import { canonicalizePayload } from "./canonicalize.js";
import { hashPayload } from "./crypto.js";
import type { MemoryPayload } from "./types.js";

describe("canonicalizePayload", () => {
  it("produces stable output for same payload", () => {
    const p: MemoryPayload = {
      contentType: "application/json",
      content: { foo: "bar", num: 42 },
      tags: ["a", "b"],
    };
    const a = canonicalizePayload(p);
    const b = canonicalizePayload({ ...p });
    expect(a).toBe(b);
  });

  it("key order does not affect output", () => {
    const p1: MemoryPayload = {
      contentType: "text/plain",
      content: "hello",
      tags: ["z", "a"],
    };
    const p2: MemoryPayload = {
      contentType: "text/plain",
      content: "hello",
      tags: ["a", "z"],
    };
    expect(canonicalizePayload(p1)).toBe(canonicalizePayload(p2));
  });

  it("different content produces different output", () => {
    const a = canonicalizePayload({
      contentType: "text/plain",
      content: "alpha",
    });
    const b = canonicalizePayload({
      contentType: "text/plain",
      content: "beta",
    });
    expect(a).not.toBe(b);
  });

  it("v0.2 lineage fields are included in canonical form", () => {
    const p: MemoryPayload = {
      memora_version: "0.2",
      contentType: "application/json",
      content: { step: 1 },
      event_type: "task_started",
      mission_id: "m1",
      parent_ids: ["id0"],
      actor_type: "agent",
      actor_id: "my-agent",
    };
    const out = canonicalizePayload(p);
    expect(out).toContain("task_started");
    expect(out).toContain("m1");
    expect(out).toContain("id0");
    expect(out).toContain("agent");
    expect(out).toContain("my-agent");
  });

  it("payload without lineage defaults to v0.1 for backward compatibility", () => {
    const p: MemoryPayload = { contentType: "text/plain", content: "x" };
    const out = canonicalizePayload(p);
    expect(out).toContain('"memora_version":"0.1"');
  });
});

describe("hashPayload", () => {
  it("same canonical string gives same hash", () => {
    const s = '{"content":"x","contentType":"text/plain","schemaVersion":1}';
    expect(hashPayload(s)).toBe(hashPayload(s));
  });

  it("different string gives different hash", () => {
    expect(hashPayload("a")).not.toBe(hashPayload("b"));
  });

  it("hash is 64 hex chars (sha256)", () => {
    const h = hashPayload("test");
    expect(h).toMatch(/^[a-f0-9]{64}$/);
  });
});
