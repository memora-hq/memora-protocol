/**
 * Legacy quote field inspection and fail-closed attestation verification.
 * Hashes, fixed-offset measurements and nonzero report data are untrusted
 * inspection metadata. They establish neither hardware authenticity, signer
 * binding nor freshness. No authentic hardware verifier is implemented here.
 * Mock verification remains available for protocol tests only.
 */

import { createHash } from "crypto";
import type { TeeMode, TeeQuoteVerificationResult } from "./types.js";

// ── Public interface ───────────────────────────────────────────────────────────

export interface TeeVerifier {
  readonly platform: TeeMode;
  /**
   * Verify a raw TEE attestation quote.
   *
   * @param rawQuoteBytes   The raw quote bytes fetched from IPFS.
   * @param expectedHash    sha256 hex of rawQuoteBytes — confirms IPFS fetch integrity.
   * @param claimedSigner   The claimed EVM address; hardware verifiers cannot confirm binding.
   * @returns TeeQuoteVerificationResult
   */
  verifyQuote(
    rawQuoteBytes: Buffer,
    expectedHash: string,
    claimedSigner: string,
  ): Promise<TeeQuoteVerificationResult>;
}

// ── AMD SEV-SNP verifier ───────────────────────────────────────────────────────

/** Legacy fixed-offset SNP inspection; not an authenticated report parser. */
class SevSnpVerifier implements TeeVerifier {
  readonly platform: TeeMode = "amd-sev-snp";

  // Byte offsets within the attestation report body (after the 32-byte request header in /dev/sev-guest output)
  // These are relative to the start of the SNP_REPORT structure.
  private static readonly REPORT_DATA_OFFSET = 0x088;  // 64 bytes
  private static readonly MEASUREMENT_OFFSET  = 0x0B8;  // 48 bytes
  private static readonly MEASUREMENT_LEN     = 48;
  private static readonly REPORT_DATA_LEN     = 64;

  // When the quote comes via /dev/sev-guest MSG_REPORT_RESP, it is prefixed by a 32-byte header.
  // The SNP_REPORT begins at byte 32 of the response body.
  private static readonly REPORT_BODY_OFFSET  = 32;

  async verifyQuote(
    rawQuoteBytes: Buffer,
    expectedHash: string,
    claimedSigner: string,
  ): Promise<TeeQuoteVerificationResult> {
    // 1. Hash integrity
    const actualHash = createHash("sha256").update(rawQuoteBytes).digest("hex");
    if (actualHash !== expectedHash) {
      return {
        valid: false, platform: "amd-sev-snp", agent_signer: "", measurement: "",
        reason: `quote hash mismatch: expected ${expectedHash.slice(0, 16)}… got ${actualHash.slice(0, 16)}…`,
      };
    }

    // 2. Extract report fields
    const reportStart   = SevSnpVerifier.REPORT_BODY_OFFSET;
    const reportDataOff = reportStart + SevSnpVerifier.REPORT_DATA_OFFSET;
    const measureOff    = reportStart + SevSnpVerifier.MEASUREMENT_OFFSET;

    if (rawQuoteBytes.length < measureOff + SevSnpVerifier.MEASUREMENT_LEN) {
      return {
        valid: false, platform: "amd-sev-snp", agent_signer: "", measurement: "",
        reason: `quote too short for SNP report: got ${rawQuoteBytes.length} bytes`,
      };
    }

    const reportData  = rawQuoteBytes.subarray(reportDataOff, reportDataOff + SevSnpVerifier.REPORT_DATA_LEN);
    const measurement = rawQuoteBytes.subarray(measureOff, measureOff + SevSnpVerifier.MEASUREMENT_LEN);

    // Nonzero bytes are only an inspection check, never proof of key binding.
    const bindingBytes = reportData.subarray(0, 32);
    if (bindingBytes.every((b) => b === 0)) {
      return {
        valid: false, platform: "amd-sev-snp", agent_signer: claimedSigner, measurement: "",
        reason: "report_data field is all zeros; hardware authenticity and key binding are unverified",
      };
    }

    const measurementHex = measurement.toString("hex");

    return {
      valid:        false,
      platform:     "amd-sev-snp",
      agent_signer: "",
      measurement:  measurementHex,
      reason: "unsupported hardware verification: SNP signature, certificate trust, signer binding and freshness are not established; measurement is untrusted inspection metadata",
    };
  }
}

// ── Intel TDX verifier ─────────────────────────────────────────────────────────

/** Legacy fixed-offset TDX inspection; no DCAP authentication is implemented. */
class TdxVerifier implements TeeVerifier {
  readonly platform: TeeMode = "intel-tdx";

  // TDX TDREPORT layout (TD Quote format, Intel TDX DCAP spec §A.3):
  // The TD quote header is 48 bytes.
  // TD Report body starts at byte 48 of the quote body section.
  // Within TD Report: reportdata is at offset 0x80 (128), 64 bytes.
  //                   mrtd (measurement) is at offset 0x28 (40), 48 bytes.
  private static readonly TDREPORT_START         = 48;
  private static readonly REPORTDATA_OFFSET       = 0x80;
  private static readonly MRTD_OFFSET             = 0x28;
  private static readonly MRTD_LEN                = 48;
  private static readonly REPORTDATA_LEN          = 64;

  constructor(private readonly verifyUrl?: string) {}

  async verifyQuote(
    rawQuoteBytes: Buffer,
    expectedHash: string,
    claimedSigner: string,
  ): Promise<TeeQuoteVerificationResult> {
    // 1. Hash integrity
    const actualHash = createHash("sha256").update(rawQuoteBytes).digest("hex");
    if (actualHash !== expectedHash) {
      return {
        valid: false, platform: "intel-tdx", agent_signer: "", measurement: "",
        reason: `quote hash mismatch: expected ${expectedHash.slice(0, 16)}… got ${actualHash.slice(0, 16)}…`,
      };
    }

    // Keep legacy inspection available even when the old endpoint is configured.
    // Its JSON result contract does not establish quote identity, trusted collateral,
    // signer binding or freshness. Do not call it or trust a bare `valid: true`.
    // Structural inspection
    const tdReportStart = TdxVerifier.TDREPORT_START;
    const reportDataOff = tdReportStart + TdxVerifier.REPORTDATA_OFFSET;
    const mrtdOff       = tdReportStart + TdxVerifier.MRTD_OFFSET;

    if (rawQuoteBytes.length < reportDataOff + TdxVerifier.REPORTDATA_LEN) {
      return {
        valid: false, platform: "intel-tdx", agent_signer: "", measurement: "",
        reason: `quote too short for TDX TDREPORT: got ${rawQuoteBytes.length} bytes`,
      };
    }

    const reportData = rawQuoteBytes.subarray(reportDataOff, reportDataOff + TdxVerifier.REPORTDATA_LEN);
    const mrtd       = rawQuoteBytes.subarray(mrtdOff, mrtdOff + TdxVerifier.MRTD_LEN);
    const bindingBytes = reportData.subarray(0, 32);

    if (bindingBytes.every((b) => b === 0)) {
      return {
        valid: false, platform: "intel-tdx", agent_signer: claimedSigner, measurement: "",
        reason: "reportdata field is all zeros; hardware authenticity and key binding are unverified",
      };
    }

    return {
      valid:        false,
      platform:     "intel-tdx",
      agent_signer: "",
      measurement:  mrtd.toString("hex"),
      reason: this.verifyUrl
        ? "unsupported hardware verification: legacy external TDX verifier contract cannot establish quote authenticity, signer binding or freshness"
        : "unsupported hardware verification: TDX signature, certificate trust, signer binding and freshness are not established; measurement is untrusted inspection metadata",
    };
  }

}

// ── Mock verifier (CI only) ────────────────────────────────────────────────────

const MOCK_PREFIX = Buffer.from("MOCK_TEE:");

class MockTeeVerifier implements TeeVerifier {
  readonly platform: TeeMode = "mock";

  async verifyQuote(
    rawQuoteBytes: Buffer,
    expectedHash: string,
    claimedSigner: string,
  ): Promise<TeeQuoteVerificationResult> {
    const actualHash = createHash("sha256").update(rawQuoteBytes).digest("hex");
    if (actualHash !== expectedHash) {
      return {
        valid: false, platform: "mock", agent_signer: "", measurement: "",
        reason: `mock quote hash mismatch`,
      };
    }
    if (!rawQuoteBytes.subarray(0, MOCK_PREFIX.length).equals(MOCK_PREFIX)) {
      return {
        valid: false, platform: "mock", agent_signer: "", measurement: "",
        reason: `not a mock quote — missing MOCK_TEE: prefix`,
      };
    }
    return {
      valid:        true,
      platform:     "mock",
      agent_signer: claimedSigner,
      measurement:  "0".repeat(96),
    };
  }
}

// ── Factory ────────────────────────────────────────────────────────────────────

/**
 * Create the appropriate TeeVerifier based on the environment.
 *
 * Priority:
 *   MEMORA_TEE_MOCK=true → MockTeeVerifier (CI only; rejected when NODE_ENV=production)
 *   MEMORA_TEE_PLATFORM=intel-tdx → TdxVerifier (external verification unsupported)
 *   MEMORA_TEE_PLATFORM=amd-sev-snp → SevSnpVerifier
 *   default → SevSnpVerifier
 */
export function createTeeVerifier(env: {
  MEMORA_TEE_MOCK?: string;
  MEMORA_TEE_PLATFORM?: string;
  MEMORA_TDX_VERIFY_URL?: string;
}): TeeVerifier {
  const isMock = (env.MEMORA_TEE_MOCK ?? "").toLowerCase() === "true";

  if (isMock) {
    if (process.env.NODE_ENV === "production") {
      throw new Error("MEMORA_TEE_MOCK=true is not allowed in production");
    }
    return new MockTeeVerifier();
  }

  const platform = (env.MEMORA_TEE_PLATFORM ?? "").toLowerCase();
  if (platform === "intel-tdx") {
    return new TdxVerifier(env.MEMORA_TDX_VERIFY_URL);
  }

  if (platform && platform !== "amd-sev-snp") {
    throw new Error(`unsupported TEE platform: ${platform}`);
  }
  return new SevSnpVerifier();
}

/**
 * Build a mock TEE quote buffer for use in tests.
 * Not for production use.
 */
export function buildMockTeeQuote(payload?: string): Buffer {
  return Buffer.from(`MOCK_TEE:${payload ?? "test"}`);
}
