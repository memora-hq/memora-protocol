/**
 * Crypto utilities: SHA-256 hash of canonical bytes, AES-256-GCM encrypt/decrypt.
 */

import { randomBytes, createHash, createCipheriv, createDecipheriv } from "crypto";
import type { EncryptedPayloadBundle } from "./types.js";

const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const KEY_LENGTH = 32;
const ALG = "aes-256-gcm";

/**
 * Hash canonical payload bytes with SHA-256; return hex string.
 */
export function hashPayload(canonicalBytes: string): string {
  const buf = Buffer.from(canonicalBytes, "utf8");
  return createHash("sha256").update(buf).digest("hex");
}

/**
 * Generate a random AES-256 key (32 bytes).
 */
export function generateAesKey(): Buffer {
  return randomBytes(KEY_LENGTH);
}

/**
 * Encrypt plaintext with AES-256-GCM. Returns bundle with nonce, ciphertext, tag.
 */
export function encrypt(plaintext: string, key: Buffer): EncryptedPayloadBundle {
  const nonce = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALG, key, nonce, { authTagLength: TAG_LENGTH });
  const enc = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    version: 1,
    alg: "AES-256-GCM",
    nonce: nonce.toString("base64"),
    ciphertext: enc.toString("base64"),
    tag: tag.toString("base64"),
  };
}

/**
 * Decrypt an EncryptedPayloadBundle with the given key.
 */
export function decrypt(bundle: EncryptedPayloadBundle, key: Buffer): string {
  const nonce = Buffer.from(bundle.nonce, "base64");
  const ciphertext = Buffer.from(bundle.ciphertext, "base64");
  const tag = Buffer.from(bundle.tag, "base64");
  if (bundle.alg !== "AES-256-GCM") {
    throw new Error(`Unsupported alg: ${bundle.alg}`);
  }
  const decipher = createDecipheriv(ALG, key, nonce, { authTagLength: TAG_LENGTH });
  decipher.setAuthTag(tag);
  return decipher.update(ciphertext, undefined, "utf8") + decipher.final("utf8");
}
