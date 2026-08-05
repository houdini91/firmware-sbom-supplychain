# See it work — real output

Actual output from this repo (OVMF / edk2), not mock-ups. Reproduce the self-contained ones with
`make test` / `make coverage`; the firmware-derived ones need an edk2 tree + a built OVMF image.

---

## 1. The gate ALLOWs a clean release — 19 signed checks, each tagged with the control it earns

```
   ✅ sbom-present: SBOM attached to the artifact  [CRA-AnnexI-1, CISA-2026-min-elements, NTIA-2021]
   ✅ attestation-signature: attestation signature verified (keyless)  [SSDF-PS.2, in-toto-DSSE]
   ✅ sbom-binding: SBOM digest bound to the signed attestation subject  [in-toto-subject-binding]
   ✅ firmware-digest-anchor: firmware-image digest consistent: build-time SBOM digest == reconcile's independent re-hash (== deployed image when a flash-time verifier supplies FW_IMAGE; assumed equal otherwise)  [firmware-image-binding, SI-7, SR-4(3), CISA-2026-hash]
   ✅ provenance-identity: built by the expected builder and source  [SLSA-provenance-L1, SSDF-PS.3]
   ✅ slsa-provenance: SLSA L2 provenance verified (platform-generated: attest-build-provenance + gh attestation verify)  [SLSA-provenance-L2, SSDF-PO.3.3]
   ✅ chipsec-posture: platform protections verified (CHIPSEC: applicable critical modules passed)  [SP800-193-4.2, SP800-147-write-protect]
   ✅ reconcile-membership: every declared module observed in the image; no undeclared artifact  [SI-7, CM-8(3)]
   ✅ component-integrity: every hashable module carries a hash (or a reviewed exemption)  [SI-7(1), CISA-2026-hash]
   ✅ component-byte-integrity: shipped module bytes match the SBOM's declared hash (byte-integrity — detects a same-GUID swap)  [SI-7(1), SR-4(3), S2C2F-AUD-3]
   ✅ binary-hardening: every DXE-class module declares NX_COMPAT (W^X-ready; declared-posture evidence, not runtime enforcement)  [SI-16, SSDF-PW.6.2]
   ✅ vex-adjudicated: every high/critical CVE carries a non-empty VEX justification  [SSDF-RV.1.1, SSDF-RV.1.2, S2C2F-SCA-1]
   ✅ thirdparty-identifiers: every third-party component carries a purl + license  [CISA-2026-license, CISA-2026-software-id, S2C2F-SCA-2, SSDF-PW.4.4]
   ✅ build-tools-signed: build-tools SBOM present, signature verified, and every component SHA/version-pinned  [SSDF-PO.3.2, S2C2F-REB-3]
   ✅ slsa-level-floor: SLSA build level >= 2 (platform-generated provenance; not L3)  [SR-4, SR-4(3)]
   ✅ evidence-chain-bound: SBOM, attestation, and SLSA provenance all bound to one subject digest  [SLSA-subject-binding, SR-4(3)]
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

Real coverage over the shipped PE32 modules (from the committed `inputs/byte-integrity.json`):

```
checked=122  byte_verified=122  (direct 111 + un-rebase 11)  modified=0  skipped=0  clean=true
```

### Binary-hardening posture — the declared exploit-mitigation state of every shipped module

The same PE32 carve, read for `DllCharacteristics` instead of hashed (from the committed
`inputs/binary-hardening.json`). Honest about what's there and what isn't:

```
binary-hardening: checked=122  dxe_class=106  dxe_nx_compat=106  skipped=1  errored=0  -> clean
  NX_COMPAT (W^X-ready) ....... 111 / 122 modules   (all 106 DXE-class + 5 others)
  DYNAMIC_BASE / relocatable .. 122 / 122 keep relocations
  ASLR (HIGH_ENTROPY_VA) ...... 0 / 122   ← edk2 does not randomize load addresses
  Control-Flow Guard .......... 0 / 122   ← not emitted by the edk2 toolchain
```

The gate asserts only the defensible part — every DXE-class module the image-protection policy
governs is NX-compatible — and *reports* the ASLR/CFG gap rather than papering over it. The one
skip is `ResetVector` (a raw blob, no PE32).

## 3. The consumer CLI — run the gate on YOUR firmware → a per-framework scorecard

```
fw-supplychain-verify — consumer-side supply-chain gate
──────────────────────────────────────────────────────────────────
Firmware image : OVMF_CODE.fd  (3653632 bytes)
  sha256       : 7965c31705bb824133d173fb9afe64d649005df2d4fc8878274ef25162fb8f37
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
