# See it work — real output

Actual output from this repo (OVMF / edk2), not mock-ups. Reproduce the self-contained ones with
`make test` / `make coverage`; the firmware-derived ones need an edk2 tree + a built OVMF image.

---

## 1. The gate ALLOWs a clean release — 18 signed checks, each tagged with the control it earns

```
   ✅ sbom-present: SBOM attached to the artifact  [CRA-AnnexI-1, CISA-2026-min-elements, NTIA-2021]
   ✅ attestation-signature: attestation signature verified (keyless)  [SSDF-PS.2, in-toto-DSSE]
   ✅ sbom-binding: SBOM digest bound to the signed attestation subject  [in-toto-subject-binding]
   ✅ firmware-digest-anchor: firmware-image digest consistent (build == reconcile == deployed)  [firmware-image-binding, SI-7, SR-4(3), CISA-2026-hash]
   ✅ provenance-identity: built by the expected builder and source  [SLSA-provenance-L1, SSDF-PS.3]
   ✅ slsa-provenance: SLSA L2 provenance verified (platform-generated)  [SLSA-provenance-L2, SSDF-PO.3.3]
   ✅ chipsec-posture: platform protections verified (applicable critical modules passed)  [SP800-193-4.2, SP800-147]
   ✅ reconcile-membership: every declared module observed; no undeclared artifact  [SI-7, CM-8(3)]
   ✅ component-integrity: every hashable module carries a hash (or a reviewed exemption)  [SI-7(1), CISA-2026-hash]
   ✅ component-byte-integrity: shipped module bytes match the SBOM's declared hash (detects a same-GUID swap)  [SI-7(1), SR-4(3), S2C2F-AUD-3]
   ✅ vex-adjudicated: every high/critical CVE carries a non-empty VEX justification  [SSDF-RV.1.1, RV.1.2, S2C2F-SCA-1]
   ✅ thirdparty-identifiers: every third-party component carries a purl + license  [CISA-2026-license, S2C2F-SCA-2, SSDF-PW.4.4]
   ✅ build-tools-signed: build-tools SBOM present, signature verified, all pinned  [SSDF-PO.3.2, S2C2F-REB-3]
   ✅ slsa-level-floor: SLSA build level >= 2 (not L3)  [SR-4, SR-4(3)]
   ✅ evidence-chain-bound: SBOM, attestation, and provenance bound to one subject digest  [SLSA-subject-binding, SR-4(3)]
   ✅ signer-identity-pinned: signed by a trusted keyless identity (cert SAN in the allowlist)  [SI-7(15), CM-14, SR-4(1)]
   ✅ reconcile: declared SBOM matches observed firmware bytes  [reconcile-declared-vs-observed]
   ✅ cve-triage: no un-triaged critical CVEs  [NIST-800-161, OpenVEX]
✅ ALLOW — clean.json  (VSA: PASSED, verifiedLevels=[SLSA_BUILD_LEVEL_2])
```

## 2. The gate BLOCKs a same-GUID trojan — byte-integrity catches what membership misses

Swap a module for malware but keep its `FILE_GUID`: membership still passes, but the bytes no longer match the
declared hash.

```
   ⛔ component-byte-integrity: byte-integrity: 1 module(s) MODIFIED — shipped bytes differ from the
      SBOM's declared hash (possible same-GUID swap)  [SI-7(1), SR-4(3), S2C2F-AUD-3]
⛔ DENY — byte-integrity-modified.json  (VSA: FAILED)
   • byte-integrity: 1 module(s) MODIFIED — shipped bytes differ from the SBOM's declared hash (possible same-GUID swap)
```

Real coverage over the whole image (from the committed `inputs/byte-integrity.json`):

```
checked=122  byte_verified=122  (direct 111 + un-rebase 11)  modified=0  skipped=0  clean=true
```

## 3. The consumer CLI — run the gate on YOUR firmware → a per-framework scorecard

```
fw-supplychain-verify — consumer-side supply-chain gate
──────────────────────────────────────────────────────────────────
Firmware image : OVMF.fd  (4194304 bytes)
  sha256       : 374472f026fc4948b00bdcb4d3deb2d8f71d725fec24d2f4ee21dfb396c8e0ce
Evidence (VSA) : vsa.json   verificationResult=PASSED

▶ Binding — is this evidence about THESE bytes?
  ✅ BOUND — the VSA's firmware-image subject matches your image.

▶ Framework coverage (from the signed VSA's verifier reports)
  ✅ SLSA v1.0 — Build track L2                 3/3  [required]
  ✅ NIST SSDF (SP 800-218 v1.1)                6/6  [required]
  ✅ NIST SP 800-53 Rev 5 (SR/SI/CM/RA)         8/8  [required]
  ✅ NIST SP 800-193 — Platform Firmware Resiliency (Protection) 1/1  [required]
  ✅ OpenSSF S2C2F v2                           3/3  [required]
  ✅ EU CRA / BSI TR-03183-2 / CISA-2026 (SBOM obligations) 4/4  [required]
──────────────────────────────────────────────────────────────────
VERDICT: ✅ ACCEPT — firmware bound + all required frameworks pass.
```

## 4. Honest degradation — point it at UNKNOWN firmware with no evidence

The killer feature: it doesn't guess or fail-confusingly. No attestation ⇒ every framework is
`MISSING_EVIDENCE` (a supply-chain *gap*), never a false pass and never conflated with a real failure.

```
▶ Binding — is this evidence about THESE bytes?
  ❔ no evidence supplied — this firmware is unattested (see coverage below).

▶ Framework coverage — no evidence, so every control is MISSING_EVIDENCE
  ❔ SLSA v1.0 — Build track L2                 0/3  [required]
  ❔ NIST SSDF (SP 800-218 v1.1)                0/6  [required]
  ❔ NIST SP 800-53 Rev 5 (SR/SI/CM/RA)         0/8  [required]
  ...
──────────────────────────────────────────────────────────────────
VERDICT: ⛔ REJECT — no evidence — cannot attest this firmware (frameworks MISSING_EVIDENCE).
```
