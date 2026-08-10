# Evidence roadmap — the next artifacts and the controls they unlock

Forward-looking companion to [`FRAMEWORKS.md`](../FRAMEWORKS.md) (which maps *current* evidence to controls).
Each item below is a **new or enriched evidence artifact**, the **specific controls it flips**, its effort, and
its acceptance criteria. Everything follows the same lane pattern the pipeline already uses:

```
produce report  →  attest as an in-toto predicate (keyless-signed)  →  add a verifier report in firmware.rego
                →  add the control rows to FRAMEWORKS.md + the overlap matrix  →  cover with a test
```

The organizing insight from FRAMEWORKS.md: we produce rich *composition/provenance* evidence but **zero
code-analysis and zero platform-security evidence**. The roadmap closes that, in value order.

## Summary

| # | New / enriched evidence | Controls it flips (exact refs) | Effort | Track |
|---|---|---|:--:|---|
| **R0a** | `slsa-provenance` verifier report | SLSA L2 row `(CI)` → `(gate)`; VSA lists the L2 report | S | now |
| **R0b** | policy/lane cleanup (dir + two-lane clarity + dedup) | none (hygiene; single source of truth) | S–M | now |
| **R1** | **SBOM third-party identity** (PURL/CPE/license/version/supplier on openssl (the one in-image third-party dep)) | CRA AnnexI §II(1) completeness · BSI §5.2.2 licenses+deps, §5.2.4 CPE/PURL/URIs · CISA'26 License+SoftwareID+Supplier+completeness · S2C2F SCA-2, INV-1 · SSDF PS.3.2, PW.4.1 · 800-53 CM-8, SR-4(4) — **+ makes the E4 CVE gate real** | M | broad |
| **R2** | **SAST report** (CodeQL `build-mode:none` / Semgrep → SARIF) | SSDF PW.7.1, PW.7.2, PW.8, RV.1.2 · 800-53 **SA-11**, SA-11(1) · CRA AnnexI §II(3) | M | broad |
| **R3** | **CHIPSEC platform-security assessment** (vs OVMF/QEMU) | SP **800-193 §4.2** Protection (partial→real) · SP **800-147/147B** BIOS update protection · Secure Boot config | M–H | **flagship** |
| **R4** | **Byte-integrity reconcile** (canonicalized per-region digest, not membership) | 800-53 SR-4(3) "not altered", SI-7, SI-7(1) · S2C2F AUD-3 — PARTIAL → strong | M–H | differentiator |
| **R5** | OpenSSF **Scorecard** (attested) | S2C2F posture · SSDF PO.1, PO.5 | S | quick win |
| **R6** | **CSAF/VEX** (convert OpenVEX → CSAF) | BSI §8.1.14 (named vuln format) | S | quick win |
| **R7** | **Binary-hardening posture** (PE `NX_COMPAT` / memory-attributes / stack-protector report) | defense-in-depth; 800-193 §4.2-adjacent | M | later |
| **R8** | **Fuzzing evidence** (edk2 parsers) | SSDF PW.8 · CRA §II(3) · 800-53 SA-11(5)/(8) | H | later |
| **R9** | **Runtime attestation** (signed TPM quote + golden RIM) | the entire FUTURISTIC block: 800-193 §4.3 Detection · RATS §8.x · TCG RIM · 800-155 | XH | horizon |

Effort: S ≈ hours · M ≈ 1–2 days · H ≈ multi-day · XH ≈ project-scale.

## Sequencing (three parallel tracks)

- **Broad-and-cheap track** (bank compliance progress fast): R0a → R0b → **R1** → **R2** → R5/R6.
  These flip the most *currently-audited* controls (SBOM-field regs + the code-review/testing family) for the
  least effort, and R1 feeds the upstream edk2 `-Y SBOM` PR while R2 feeds the exploratory security review.
- **Flagship track — CHIPSEC (hands-on)** — R3. Run in parallel; the platform-security assessment is the most
  firmware-distinctive evidence and the one that begins converting the "futuristic zero" (SP 800-193 Protection,
  SP 800-147) into real coverage **without** needing a TPM quote — it checks *protections/config*, not measured
  boot. Hands-on CHIPSEC tooling experience is a deliverable in its own right.
- **Differentiator + horizon track** — R4 (byte-integrity — the *composition* is our differentiator; byte-checking firmware modules itself isn't new, CHIPSEC does it — see Related work), then R7/R8, then R9 (the honest
  long-horizon runtime-attestation project).

---

## Detail

### R0a — `slsa-provenance` verifier report
**Why:** today SLSA L2 is enforced only by the CI `gh attestation verify` step, not a rego rule — so the VSA's
report list doesn't assert it (FRAMEWORKS Gap #3). **Do:** add an input fact (`provenance.slsa_verified`) set by
the pipeline after `gh attestation verify`, a `slsa-provenance` verifier report gating on it, and derive VSA
`verifiedLevels` from that fact. **Accept:** the L2 row in FRAMEWORKS moves from `ENFORCED (CI)` to
`ENFORCED (gate)`; VSA `verifierReports` includes `slsa-provenance`; tests green.

### R0b — policy / lane cleanup
**Why:** the OSS lane, Valint lane, `policy/`, `compliance-map.md`, and FRAMEWORKS overlap. **Do:** tidy the
`oss-lane/policy/` structure, write one crisp statement of what each lane *proves* (OSS = enforcing gate; Valint
= report-mode framework runs), and make `compliance-map.md` the enforced-subset pointer to FRAMEWORKS as the
single source of truth. **Accept:** no contradictory statements across docs; a reader can tell the two lanes
apart in one paragraph.

### R1 — SBOM third-party dependency identity  *(DONE — in-image, per-artifact)*
**Status:** the generator emits vendored submodules *actually linked into the image* (ancestor rule) with
PURL/version/SPDX-license/CPE/supplier + `dependsOn`. Honest correction to the original framing: OVMF X64 links
**only openssl** (openssl-3.5.7), so the SBOM lists one third-party component, not ~13 — the rest belong to other
platforms. openssl's CPE enables real openssl CVE mapping. Generator on the fork branch `add-y-spdx-generator`
(reviewed, not upstreamed); demo SBOM enriched; reconcile re-verified clean 123/123.

*(original plan, kept for context)*
**Why:** the 13 vendored submodules (openssl, brotli, oniguruma, mbedtls, libspdm…) are currently **invisible**
in the SBOM (~0 submodule components). That is both the biggest SBOM-field-regulation gap *and* the reason the
CVE gate can't map real CVEs. **Do:** enumerate the gitlink SHAs → emit each as a real component with
`pkg:github/...` PURL, version (`git describe`), SPDX `licenses`, real `supplier`; keep the honest N/A for edk2
FFS modules (no sensible PURL). **Accept:** submodules appear as components with PURL+license+version; grype maps
CVEs against real versions; FRAMEWORKS rows for BSI §5.2.2/§5.2.4, CISA License/SoftwareID/Supplier, CRA §II(1),
S2C2F SCA-2/INV-1, 800-53 CM-8/SR-4(4) advance. Feeds the edk2 `-Y SBOM` PR.

### R2 — SAST report (SARIF)  *(new evidence category)*
**Why:** we have no code-analysis evidence at all; PW.7/PW.8/RV.1.2 are `N/A` only because grype is SCA, not
SAST. **Do:** run CodeQL `build-mode:none` for `c-cpp` scoped to a package (e.g. NetworkPkg) — or Semgrep as the
build-free fallback — emit SARIF, attest it, add a `sast` verifier report ("no un-triaged high-severity
finding"). **Accept:** signed SARIF predicate in the pipeline; SSDF PW.7/PW.8, 800-53 SA-11(1), CRA §II(3) rows
added as real; SARIF also lands in the repo Security tab. Pairs with the exploratory security review (#40).

### R3 — CHIPSEC platform-security assessment  *(firmware flagship)*
**Why:** the most firmware-distinctive evidence; maps to the platform-firmware frameworks currently at "honest
zero," and checks *protections/config* (achievable against OVMF) rather than runtime measured boot. **Do:** run
CHIPSEC modules against the OVMF/QEMU target (e.g. `common.bios_wp`, `common.spi_desc`, `common.secureboot.*`,
SMM checks); capture the report; attest it as an in-toto predicate; add a `chipsec-posture` verifier report.
**Accept:** signed CHIPSEC-report predicate; FRAMEWORKS rows for SP 800-193 §4.2.1/§4.2.2 Protection and SP
800-147/147B move from FUTURISTIC toward PARTIAL/real, with honest scoping (OVMF target, not physical silicon).

### R4 — Byte-integrity reconcile  *(the differentiator, strengthened)*
**Why:** E3 is membership-only, so every "not altered" claim is PARTIAL. **Do:** for each carved FFS region,
re-canonicalize (handle rebasing/relocation) and compare a per-region digest to the declared SHA-512; record
`validated / modified / skipped` per component with the reason. **Accept:** reconcile verdict carries per-region
byte integrity; SR-4(3), SI-7, SI-7(1), S2C2F AUD-3 advance PARTIAL → strong; `ResetVector`-style no-reference
cases documented, not faked.

### R5 — OpenSSF Scorecard (attested)  ·  R6 — CSAF/VEX  *(DONE)*
R5: `scorecard.yml` runs Scorecard on push + weekly, uploads the SARIF, publishes to the OpenSSF API (badge),
and keyless-signs the result (E9) → SSDF PO / S2C2F posture evidence. R6: triage authored as OpenVEX
(`inputs/vex.openvex.json`) and converted to BSI's named CSAF 2.0 VEX by `producers/interop/to-csaf.py`
(`inputs/vex.csaf.json`) → BSI §8.1.14 met.

### R7 — Binary-hardening posture · R8 — Fuzzing · R9 — Runtime attestation  *(later / horizon)*
R7: report PE hardening flags (`NX_COMPAT`, memory-protection attributes, stack protectors) on DXE drivers. R8:
run edk2 fuzz harnesses on parser-heavy code, attest crash/coverage evidence (SSDF PW.8, CRA §II(3), SA-11(5)).
R9: the FUTURISTIC block — a signed **TPM quote** (Attester/Evidence) + a signed **golden RIM** (Reference
Values) unlocks SP 800-193 §4.3 Detection, RATS §8.x, TCG RIM, and 800-155 at once. Project-scale; the honest
long-horizon target that would make the runtime frameworks real.
