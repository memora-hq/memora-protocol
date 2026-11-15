import { afterEach, describe, it, expect, vi } from "vitest";
import { createHash } from "crypto";
import { createTeeVerifier, buildMockTeeQuote } from "./tee.js";

// ── MockTeeVerifier ───────────────────────────────────────────────────────────

describe("MockTeeVerifier (MEMORA_TEE_MOCK=true)", () => {
  const env = { MEMORA_TEE_MOCK: "true" };
  const CLAIMED_SIGNER = "0x" + "a".repeat(40);

  it("returns valid for a correctly-built mock quote", async () => {
    const quote = buildMockTeeQuote("test");
    const hash  = createHash("sha256").update(quote).digest("hex");
    const verifier = createTeeVerifier(env);
    const result = await verifier.verifyQuote(quote, hash, CLAIMED_SIGNER);
    expect(result.valid).toBe(true);
    expect(result.platform).toBe("mock");
    expect(result.agent_signer).toBe(CLAIMED_SIGNER);
    expect(result.measurement).toBe("0".repeat(96));
  });

  it("rejects when hash does not match quote bytes", async () => {
    const quote    = buildMockTeeQuote("test");
    const badHash  = "b".repeat(64);
    const verifier = createTeeVerifier(env);
    const result = await verifier.verifyQuote(quote, badHash, CLAIMED_SIGNER);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/hash mismatch/i);
  });

  it("rejects bytes that don't have MOCK_TEE: prefix", async () => {
    const bytes   = Buffer.from("NOT_A_TEE_QUOTE");
    const hash    = createHash("sha256").update(bytes).digest("hex");
    const verifier = createTeeVerifier(env);
    const result  = await verifier.verifyQuote(bytes, hash, CLAIMED_SIGNER);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/missing MOCK_TEE:/i);
  });

  it("rejects in production (NODE_ENV=production)", () => {
    const orig = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    try {
      expect(() => createTeeVerifier(env)).toThrow(/not allowed in production/i);
    } finally {
      process.env.NODE_ENV = orig;
    }
  });

  it("verifier platform is 'mock'", () => {
    const verifier = createTeeVerifier(env);
    expect(verifier.platform).toBe("mock");
  });
});

// ── buildMockTeeQuote ─────────────────────────────────────────────────────────

describe("buildMockTeeQuote", () => {
  it("returns a Buffer starting with MOCK_TEE:", () => {
    const buf = buildMockTeeQuote("hello");
    expect(buf.slice(0, 9).toString()).toBe("MOCK_TEE:");
  });

  it("includes the payload", () => {
    const buf = buildMockTeeQuote("custom-payload");
    expect(buf.toString()).toBe("MOCK_TEE:custom-payload");
  });

  it("defaults to 'test' payload", () => {
    const buf = buildMockTeeQuote();
    expect(buf.toString()).toBe("MOCK_TEE:test");
  });
});

// ── createTeeVerifier factory ─────────────────────────────────────────────────

describe("createTeeVerifier factory", () => {
  it("returns MockTeeVerifier when MEMORA_TEE_MOCK=true", () => {
    const v = createTeeVerifier({ MEMORA_TEE_MOCK: "true" });
    expect(v.platform).toBe("mock");
  });

  it("returns SevSnpVerifier when no platform override", () => {
    const v = createTeeVerifier({});
    expect(v.platform).toBe("amd-sev-snp");
  });

  it("returns TdxVerifier when MEMORA_TEE_PLATFORM=intel-tdx", () => {
    const v = createTeeVerifier({ MEMORA_TEE_PLATFORM: "intel-tdx" });
    expect(v.platform).toBe("intel-tdx");
  });

  it("returns SevSnpVerifier when MEMORA_TEE_PLATFORM=amd-sev-snp", () => {
    const v = createTeeVerifier({ MEMORA_TEE_PLATFORM: "amd-sev-snp" });
    expect(v.platform).toBe("amd-sev-snp");
  });
});

// ── SevSnpVerifier structural validation ─────────────────────────────────────

describe("SevSnpVerifier — structural validation", () => {
  // We test the non-hardware path: quotes that are too short or have zero binding.
  // REPORT_BODY_OFFSET=32, REPORT_DATA_OFFSET=0x088, MEASUREMENT_OFFSET=0x0B8
  const REPORT_START   = 32;
  const REPORT_DATA_OFF = REPORT_START + 0x088;  // 168
  const MEASUREMENT_OFF = REPORT_START + 0x0B8;  // 216
  const MEASUREMENT_END = MEASUREMENT_OFF + 48;   // 264

  function makeSnpQuote(opts?: { zeroBind?: boolean }): Buffer {
    const buf = Buffer.alloc(MEASUREMENT_END + 32, 0);
    // Place non-zero binding bytes in report_data[0:32] unless zeroBind
    if (!opts?.zeroBind) {
      buf.fill(0xab, REPORT_DATA_OFF, REPORT_DATA_OFF + 32);
    }
    // Place non-zero measurement
    buf.fill(0xcd, MEASUREMENT_OFF, MEASUREMENT_END);
    return buf;
  }

  const CLAIMED_SIGNER = "0x" + "1".repeat(40);

  it("inspects legacy synthetic fields without authenticating hardware", async () => {
    const quote = makeSnpQuote();
    const hash  = createHash("sha256").update(quote).digest("hex");
    const verifier = createTeeVerifier({ MEMORA_TEE_PLATFORM: "amd-sev-snp" });
    const result = await verifier.verifyQuote(quote, hash, CLAIMED_SIGNER);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/unsupported hardware verification/);
    expect(result.agent_signer).toBe("");
    expect(result.platform).toBe("amd-sev-snp");
    expect(result.measurement.length).toBe(96); // 48 bytes = 96 hex chars
  });

  it("rejects a quote that is too short", async () => {
    const quote = Buffer.alloc(10, 0);
    const hash  = createHash("sha256").update(quote).digest("hex");
    const verifier = createTeeVerifier({ MEMORA_TEE_PLATFORM: "amd-sev-snp" });
    const result = await verifier.verifyQuote(quote, hash, CLAIMED_SIGNER);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/too short/i);
  });

  it("rejects a quote where report_data binding is all zeros", async () => {
    const quote = makeSnpQuote({ zeroBind: true });
    const hash  = createHash("sha256").update(quote).digest("hex");
    const verifier = createTeeVerifier({ MEMORA_TEE_PLATFORM: "amd-sev-snp" });
    const result = await verifier.verifyQuote(quote, hash, CLAIMED_SIGNER);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/all zeros/i);
  });

  it("rejects when quote hash does not match", async () => {
    const quote = makeSnpQuote();
    const badHash = "0".repeat(64);
    const verifier = createTeeVerifier({ MEMORA_TEE_PLATFORM: "amd-sev-snp" });
    const result = await verifier.verifyQuote(quote, badHash, CLAIMED_SIGNER);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/hash mismatch/i);
  });
});


describe("hardware authenticity cannot be synthesized", () => {
  afterEach(() => { vi.unstubAllGlobals(); });
  const signer = "0x" + "1".repeat(40);
  const digest = (quote: Buffer) => createHash("sha256").update(quote).digest("hex");

  it.each(["amd-sev-snp", "intel-tdx"])("rejects arbitrary nonzero %s quotes at every inspected length", async (platform) => {
    const verifier = createTeeVerifier({ MEMORA_TEE_PLATFORM: platform });
    for (const length of [0, 10, 239, 240, 263, 264, 296, 1024, 4096]) {
      const quote = Buffer.alloc(length, 0xab);
      const result = await verifier.verifyQuote(quote, digest(quote), signer);
      expect(result.valid).toBe(false);
      expect(result.reason).toMatch(/too short|unsupported hardware verification/);
    }
  });

  it("preserves legacy TDX measurement inspection without binding the claimed signer", async () => {
    const quote = Buffer.alloc(1024, 0);
    quote.fill(0xcd, 48 + 0x28, 48 + 0x28 + 48);
    quote.fill(0xab, 48 + 0x80, 48 + 0x80 + 32);
    const verifier = createTeeVerifier({ MEMORA_TEE_PLATFORM: "intel-tdx" });
    for (const claimed of [signer, "0x" + "2".repeat(40)]) {
      const result = await verifier.verifyQuote(quote, digest(quote), claimed);
      expect(result).toMatchObject({ valid: false, agent_signer: "", measurement: "cd".repeat(48) });
    }
    expect((await verifier.verifyQuote(quote, "0".repeat(64), signer)).reason).toMatch(/hash mismatch/);
    quote.fill(0, 48 + 0x80, 48 + 0x80 + 32);
    expect((await verifier.verifyQuote(quote, digest(quote), signer)).reason).toMatch(/all zeros/);
  });

  it.each([
    { valid: true, platform: "intel-tdx", agent_signer: signer, measurement: "ab".repeat(48) },
    { valid: "true" }, null,
  ])("does not trust the legacy external verifier response %j", async (response) => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => response });
    vi.stubGlobal("fetch", fetchMock);
    const quote = Buffer.alloc(1024, 0xab);
    const verifier = createTeeVerifier({ MEMORA_TEE_PLATFORM: "intel-tdx", MEMORA_TDX_VERIFY_URL: "https://verifier.test" });
    const result = await verifier.verifyQuote(quote, digest(quote), signer);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/unsupported.*external TDX verifier/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects unknown platform configurations instead of defaulting to SNP", () => {
    expect(() => createTeeVerifier({ MEMORA_TEE_PLATFORM: "unknown" })).toThrow(/unsupported TEE platform/);
  });
});
