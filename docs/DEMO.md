# See it work — real output

Actual output from this repo (OVMF / edk2), not mock-ups. Reproduce the self-contained ones with
`make test` / `make coverage` / `make attack-demo`; the firmware-derived ones need an edk2 tree + a
built OVMF image. Section 5 (the same-GUID trojan) is self-contained — it runs anywhere.

---

## 1. The gate ALLOWs a clean release — 19 signed checks, each tagged with the control it earns

A fixture carrying complete, valid evidence: the gate ANDs all 19 verifier reports and signs the VSA.

```
   ✅ sbom-present: SBOM attached to the artifact  [cra-bsi-cisa:cra-annex-I-II-1, ssdf:PS.3.1]
   ✅ attestation-signature: attestation signature verified (keyless)  [ssdf:PS.2.1]
   ✅ sbom-binding: SBOM digest bound to the signed attestation subject  [slsa.l2:subject-binding]
   ✅ firmware-digest-anchor: firmware-image digest consistent: build-time SBOM digest == reconcile's independent re-hash (== deployed image when a flash-time verifier supplies FW_IMAGE; assumed equal otherwise)  [cra-bsi-cisa:cisa-fw-binding, sp-800-53:SR-4(3)]
   ✅ provenance-identity: built by the expected builder and source  [slsa.l2:provenance-exists, ssdf:PS.3.1]
   ✅ slsa-provenance: SLSA L2 provenance verified (platform-generated: attest-build-provenance + gh attestation verify)  [slsa.l2:provenance-authentic, ssdf:PO.3.3]
   ✅ chipsec-posture: platform protections verified (CHIPSEC: applicable critical modules passed)  [sp-800-193:4.2]
   ✅ reconcile-membership: every declared module observed in the image; no undeclared artifact  [sp-800-53:CM-8(3), sp-800-53:SI-7, sp-800-53:SR-4(3)]
   ✅ component-integrity: every hashable module carries a hash (or a reviewed exemption)  [cra-bsi-cisa:cisa-hash, sp-800-53:SI-7, sp-800-53:SI-7(1)]
   ✅ component-byte-integrity: shipped module bytes match the SBOM's declared hash (byte-integrity — detects a same-GUID swap)  [sp-800-53:SI-7(1), sp-800-53:SR-4(3)]
   ✅ binary-hardening: every DXE-class module declares NX_COMPAT (W^X-ready; declared-posture evidence, not runtime enforcement)  [sp-800-53:SI-16, ssdf:PW.6.2]
   ✅ vex-adjudicated: every high/critical CVE carries a non-empty VEX justification  [s2c2f:SCA-1, ssdf:RV.1.1]
   ✅ thirdparty-identifiers: every third-party component carries a purl + license  [cra-bsi-cisa:cisa-license-id, s2c2f:SCA-2, ssdf:PW.4.4]
   ✅ build-tools-signed: build-tools SBOM present, signature verified, and every component SHA/version-pinned  [s2c2f:REB-3, ssdf:PO.3.2]
   ✅ slsa-level-floor: SLSA build level >= 2 (platform-generated provenance; not L3)  [slsa.l2:provenance-authentic, sp-800-53:SR-4, sp-800-53:SR-4(3)]
   ✅ evidence-chain-bound: SBOM, attestation, and SLSA provenance all bound to one subject digest  [slsa.l2:subject-binding, sp-800-53:SR-4(3)]
   ✅ signer-identity-pinned: signed by a trusted keyless identity (cert SAN in the allowlist)  [sp-800-53:CM-14, sp-800-53:SI-7(15)]
   ✅ reconcile: declared SBOM matches observed firmware bytes  []
   ✅ cve-triage: no un-triaged critical CVEs  [s2c2f:SCA-1, sp-800-53:RA-5, ssdf:PW.4.4, ssdf:RV.1.1]
✅ ALLOW — clean.json  (VSA: PASSED, verifiedLevels=[SLSA_BUILD_LEVEL_2])
```

## 2. The gate BLOCKs a same-GUID trojan — byte-integrity catches what membership misses

Swap a module for malware but keep its `FILE_GUID`: membership still passes, but the bytes no longer match the
declared hash.

```
   ⛔ component-byte-integrity: byte-integrity: 1 module(s) MODIFIED — shipped bytes differ from the
      SBOM's declared hash (possible same-GUID swap)  [sp-800-53:SI-7(1), sp-800-53:SR-4(3)]
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

Hand it a firmware image plus its signed VSA; it re-checks the binding and prints per-framework coverage.

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
  ✅ NIST SSDF (SP 800-218 v1.1)                7/7  [required]
  ✅ NIST SP 800-53 Rev 5 (SR/SI/CM/RA)         9/9  [required]
  ✅ NIST SP 800-193 — Platform Firmware Resiliency (Protection) 1/1  [required]
  ✅ OpenSSF S2C2F v2                           3/3  [required]
  ✅ EU CRA / BSI TR-03183-2 / CISA 2026 Minimum Elements (SBOM obligations) 4/4  [required]
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
  ❔ NIST SSDF (SP 800-218 v1.1)                0/7  [required]
  ❔ NIST SP 800-53 Rev 5 (SR/SI/CM/RA)         0/9  [required]
  ...
──────────────────────────────────────────────────────────────────
VERDICT: ⛔ REJECT — no evidence — cannot attest this firmware (frameworks MISSING_EVIDENCE).
```

---

## 5. Attack demo: same-GUID trojan caught

The flagship claim, proven end-to-end on a real module — not a hand-authored fixture.
A same-GUID swap (a malicious module shipped under an existing module's `FILE_GUID`)
sails past membership and signatures: the GUID is still "present," the SBOM file is
unchanged and still validly signed. **Byte-integrity is the check that catches it** —
it re-hashes the shipped PE32 bytes and compares them to the SBOM's declared hash.

`make attack-demo` takes a committed real edk2 PE32 (`tests/fixtures/pe/pcdpeim.declared.efi`),
registers it in a 1-module SBOM, wraps it in a real FFS, then ships a copy with **one
byte flipped in the PE body under the SAME GUID/name**. It runs the **real producer**
(`producers/reconcile/byte-integrity.py`) and the **real gate** (`oss-lane/gate.sh`)
over both the clean and the trojaned image. Self-contained (committed fixtures + opa +
python3) — runs locally and in CI (`tests/test_attack_demo.py`). It is genuine
byte-tampering run through the genuine tools; the only substitution is the extraction
*source* — the producer reads the pre-carved FFS via `--ffs-dir` instead of an
`--image` + FMMT carve (the FFS is exactly what `FMMT -e` emits, so the downstream
PE32-carve + SHA-256 verdict is byte-for-byte identical).

```
== attack demo: same-GUID trojan caught ==
   real producer: producers/reconcile/byte-integrity.py    real gate: oss-lane/gate.sh

▶ 0. Stage a real module + a same-GUID byte-tampered copy (from committed fixtures)
staged same-GUID trojan demo in /tmp/attack-demo.XXXXXX
  module          : DemoNetworkDxe  (GUID deadbeef-1111-2222-3333-444455556666)
  known-good bytes : 3b830c78cb7480d6…  (19840 bytes, from tests/fixtures/pe/pcdpeim.declared.efi)
  TAMPER           : flipped 1 byte at PE offset 0x1000: 0xE0 -> 0xE1  (SAME GUID/name)
  tampered bytes   : e5fc5b4bad653e05…  (declared hash unchanged in the SBOM — that's the point)

▶ 1. Clean image — the real producer byte-verifies the module
$ python3 producers/reconcile/byte-integrity.py --sbom demo-sbom.cdx.json --ffs-dir clean -o verdict.json
byte-integrity: verified=1 modified=0 skipped=0 errored=0 -> .../clean-verdict.json
   producer exit=0
{"checked":1,"byte_verified":1,"modified":[],"clean":true}

▶ 2. Trojaned image — SAME GUID, 1 byte flipped — the real producer flags it MODIFIED
$ python3 producers/reconcile/byte-integrity.py --sbom demo-sbom.cdx.json --ffs-dir tampered -o verdict.json
byte-integrity: verified=0 modified=1 skipped=0 errored=0 -> .../tampered-verdict.json
   producer exit=1
  ⛔ MODIFIED DemoNetworkDxe: declared 3b830c78cb7480d6 != observed e5fc5b4bad653e05
{"checked":1,"byte_verified":0,"modified":[{"name":"DemoNetworkDxe","guid":"deadbeef111122223333444455556666","declared":"3b830c78cb7480d6","observed":"e5fc5b4bad653e05"}],"clean":false}

▶ 3. The deploy gate ALLOWs the clean image
  verifier reports (clean-gate-input.json):
   ✅ reconcile-membership: every declared module observed in the image; no undeclared artifact  [sp-800-53:CM-8(3), sp-800-53:SI-7, sp-800-53:SR-4(3)]
   ✅ component-byte-integrity: shipped module bytes match the SBOM's declared hash (byte-integrity — detects a same-GUID swap)  [sp-800-53:SI-7(1), sp-800-53:SR-4(3)]
   … (17 other reports, all ✅) …
✅ ALLOW — clean-gate-input.json  (VSA: PASSED, verifiedLevels=[SLSA_BUILD_LEVEL_2])

▶ 4. The deploy gate DENYs the trojaned image (membership passes, bytes fail)
  verifier reports (tampered-gate-input.json):
   ✅ reconcile-membership: every declared module observed in the image; no undeclared artifact  [sp-800-53:CM-8(3), sp-800-53:SI-7, sp-800-53:SR-4(3)]
   ⛔ component-byte-integrity: byte-integrity: 1 module(s) MODIFIED — shipped bytes differ from the SBOM's declared hash (possible same-GUID swap)  [sp-800-53:SI-7(1), sp-800-53:SR-4(3)]
   … (17 other reports, all ✅) …
⛔ DENY — tampered-gate-input.json  (VSA: FAILED)
   • byte-integrity: 1 module(s) MODIFIED — shipped bytes differ from the SBOM's declared hash (possible same-GUID swap)
────────────────────────────────────────────────────────────────────
RESULT: same-GUID byte swap — reconcile-membership PASSED, component-byte-integrity DENIED. ✔ caught.
```

The `… (17 other reports, all ✅) …` lines are the only elision — `make attack-demo`
prints all 19 verifier reports in full both times. **The crux is the contrast:**
`reconcile-membership` PASSES the swap in both runs (the GUID is present); only
`component-byte-integrity` flips from ✅ to ⛔, and that flip is what turns the gate's
verdict from ALLOW to DENY.

**Real vs. user-supplied.** The run above is fully real — a real edk2 PE32, real
byte-tampering, the real producer, the real OPA gate — over a **minimal 1-module demo
image built from committed fixtures**, so it runs anywhere with no edk2 tree. To also
exercise the producer's `--image` + **FMMT carve** path over a full multi-module image,
supply your own OVMF build:

```
make attack-demo FW_IMAGE=/path/to/OVMF.fd EDK2=/path/to/edk2
```

That adds a step 5 that runs `byte-integrity.py --image … --edk2 …` against
`inputs/sbom.cdx.json` (the real 122-module reference SBOM). A clean build byte-verifies
every module; tamper a module in your `OVMF.fd` to see `MODIFIED` on the full image too.
