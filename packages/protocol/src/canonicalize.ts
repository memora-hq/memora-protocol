/**
 * Stable JSON canonicalization for deterministic hashing (RFC 8785 style).
 * Ensures same payload always produces same bytes across machines.
 */

import type { MemoryPayload } from "./types.js";

const SCHEMA_VERSION = 1;
/** Default for new lineage-enabled writes. */
export const DEFAULT_MEMORA_VERSION = "0.2";

function hasLineageFields(p: MemoryPayload): boolean {
  return (
    p.event_type != null ||
    p.mission_id != null ||
    (p.parent_ids != null && p.parent_ids.length > 0) ||
    (p.derived_from != null && p.derived_from.length > 0) ||
    p.tool_ref != null ||
    p.capsule_id != null ||
    p.actor_type != null ||
    p.actor_id != null
  );
}

/**
 * Canonicalize MemoryPayload to a deterministic JSON string.
 * Keys sorted; no extra whitespace; consistent number/string encoding.
 * Backward compatible: if memora_version omitted and no lineage fields, default to "0.1".
 */
export function canonicalizePayload(payload: MemoryPayload): string {
  const defaultVersion = payload.memora_version ?? (hasLineageFields(payload) ? DEFAULT_MEMORA_VERSION : "0.1");
  const normalized: Record<string, unknown> = {
    memora_version: defaultVersion,
    contentType: payload.contentType,
    content: payload.content,
    schemaVersion: SCHEMA_VERSION,
  };
  if (payload.tags != null && payload.tags.length > 0) {
    normalized.tags = [...payload.tags].sort();
  }
  if (payload.taskId != null) {
    normalized.taskId = payload.taskId;
  }
  if (payload.access != null) {
    normalized.access = sortKeys(payload.access as Record<string, unknown>);
  }
  if (payload.meta != null) {
    normalized.meta = sortKeys(payload.meta);
  }
  /* v0.2 lineage: include in canonical form for deterministic hash */
  if (payload.event_type != null) normalized.event_type = payload.event_type;
  if (payload.mission_id != null) normalized.mission_id = payload.mission_id;
  if (payload.parent_ids != null && payload.parent_ids.length > 0) {
    normalized.parent_ids = [...payload.parent_ids].sort();
  }
  if (payload.derived_from != null && payload.derived_from.length > 0) {
    normalized.derived_from = [...payload.derived_from].sort();
  }
  if (payload.tool_ref != null) normalized.tool_ref = payload.tool_ref;
  if (payload.capsule_id != null) normalized.capsule_id = payload.capsule_id;
  if (payload.actor_type != null) normalized.actor_type = payload.actor_type;
  if (payload.actor_id != null) normalized.actor_id = payload.actor_id;
  return canonicalStringify(normalized);
}

/**
 * Recursively sort object keys and stringify deterministically.
 */
function sortKeys(obj: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(obj).sort()) {
    const v = obj[k];
    if (v !== null && typeof v === "object" && !Array.isArray(v)) {
      out[k] = sortKeys(v as Record<string, unknown>);
    } else {
      out[k] = v;
    }
  }
  return out;
}

/**
 * JSON.stringify with sorted keys for any object (recursive).
 */
function canonicalStringify(obj: unknown): string {
  if (obj === null) return "null";
  if (typeof obj === "boolean") return obj ? "true" : "false";
  if (typeof obj === "number") {
    if (!Number.isFinite(obj)) return "null";
    return String(obj);
  }
  if (typeof obj === "string") return JSON.stringify(obj);
  if (Array.isArray(obj)) {
    const parts = obj.map((item) => canonicalStringify(item));
    return "[" + parts.join(",") + "]";
  }
  if (typeof obj === "object") {
    const o = obj as Record<string, unknown>;
    const keys = Object.keys(o).sort();
    const parts = keys.map((k) => JSON.stringify(k) + ":" + canonicalStringify(o[k]));
    return "{" + parts.join(",") + "}";
  }
  return "null";
}
