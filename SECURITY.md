# Security policy

## Scope

This policy covers `@memora-hq/memora-protocol` — the schema, canonicalization, signing digest,
Merkle proof, and TEE attestation-verification code in this repository. It does not cover
Memora's hosted service (key custody, write authorization, service infrastructure) — that has
its own private security process.

## Supported versions

Developer preview. There are no versioned stable releases yet. Security reports should target
the current `main` branch and the latest published npm version.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities by emailing: **akuniyil@purdue.edu**

Include:
- A clear description of the vulnerability
- Steps to reproduce or a proof of concept
- The file(s) and function(s) involved
- Your assessment of impact and severity

You will receive an acknowledgement within 72 hours. Fixes are prioritized by severity. Given
this package's role — its digests are what on-chain `ecrecover` checks and what every Memora
verifier trusts — a correctness bug here is treated as high severity by default.

## Known limitations in this package

**No TEE attestation proof, only quote verification.** `tee.ts` verifies the *content* of a TEE
attestation quote; it does not prove the quote was produced by genuine hardware — that trust
chain terminates at the hardware vendor's attestation service, outside this package's scope.

**Signing key possession is not proof of honest execution.** A compromised agent runtime holding
a valid signing key can produce a validly-signed digest over incorrect content. `ecrecover`
proves a key signed something; it does not prove what that something *should have been*.
