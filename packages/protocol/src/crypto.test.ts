import { describe, it, expect } from "vitest";
import { encrypt, decrypt, generateAesKey, hashPayload } from "./crypto.js";

describe("AES-256-GCM round-trip", () => {
  it("decrypts to original plaintext", () => {
    const key = generateAesKey();
    const plain = '{"content":"secret","contentType":"application/json"}';
    const bundle = encrypt(plain, key);
    const out = decrypt(bundle, key);
    expect(out).toBe(plain);
  });

  it("different keys cannot decrypt", () => {
    const key1 = generateAesKey();
    const plain = "secret data";
    const bundle = encrypt(plain, key1);
    const key2 = generateAesKey();
    expect(() => decrypt(bundle, key2)).toThrow();
  });

  it("tampered ciphertext fails verification", () => {
    const key = generateAesKey();
    const bundle = encrypt("original", key);
    const tampered = Buffer.from(bundle.ciphertext, "base64");
    tampered[0] ^= 1;
    expect(() =>
      decrypt(
        { ...bundle, ciphertext: tampered.toString("base64") },
        key
      )
    ).toThrow();
  });

  it("tampered tag fails verification", () => {
    const key = generateAesKey();
    const bundle = encrypt("original", key);
    const tagBuf = Buffer.from(bundle.tag, "base64");
    tagBuf[0] ^= 1;
    expect(() =>
      decrypt({ ...bundle, tag: tagBuf.toString("base64") }, key)
    ).toThrow();
  });
});

describe("hashPayload", () => {
  it("produces deterministic sha256 hex", () => {
    const h = hashPayload("same input");
    expect(hashPayload("same input")).toBe(h);
    expect(h).toMatch(/^[a-f0-9]{64}$/);
  });
});
