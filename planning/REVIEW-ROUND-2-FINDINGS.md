# Review Round 2 — findings & priority-ranked action list

*Working doc (2026-08-09). Five sequential persona reviews + one compliance follow-up. NO code
changed yet — this is the menu to pick from. Reviewers: **[CA]** compliance auditor · **[SEC]**
security/adversarial · **[PE]** principal engineer · **[CC]** clean-code/org · **[OM]** OSS
maintainer. A finding flagged by multiple personas is higher-confidence.*

## The one strategic decision (yours, not mine)

**[PE1/PE4/CA8]** The reviewers converge that the **"8 frameworks / 46 controls" scoreboard is
standing in front of the strong core** and that this session *added* to the breadth. Of the 46,
~12 verify a claim against **independent** evidence (byte-integrity, reconcile-membership,
firmware-digest-anchor, evidence-chain-bound, component-integrity, signer-identity-pinned,
slsa-provenance/floor, cve-triage/vex, thirdparty, build-tools); ~19 are **declared-field/shape
checks over our own generator's SBOM** (sbom-author/-timestamp/-supplier/-serial/-completeness,
generation-tool/-context, component-supplier, dependency-relationships, data-quality,
osf-identity-shape) or **sample-CHIPSEC PASSED strings**. Labeling each honestly does not make the
aggregate "45/46 satisfied" honest at the headline. **Decision: keep building breadth (fix its
honesty) vs. re-center on the verified core + the byte-integrity story?** Everything in P0 is worth
doing either way.

---

## P0 — Credibility-critical (honesty + security integrity). Do regardless of direction.

| # | Finding | Who | Sev | Effort | Fix |
|---|---|---|---|---|---|
| P0.1 | **`inputs/byte-integrity.json` (the keystone evidence) is UNSIGNED** and outside the D-anchored signed graph — every other image verdict (reconcile/SBOM/VEX/CHIPSEC) is wrapped+signed; this one and `binary-hardening.json` are read as loose files (`supply-chain.yml:184`). An attacker with `inputs/` write access but **no signing key** rewrites it to `modified=0` for a trojan. | SEC1 | BYPASS | **M** | Wrap both as D-subjected signed attestations via `producers/wrap.sh`; assembler consumes the signed subject, not the loose file. |
| P0.2 | **Threat-model honesty:** README banner says the threat is a *"compromised build step"* — but a bad build writes the SBOM+hashes too, so byte-integrity **cannot** catch it. The body (supply-chain-players) correctly targets the **mid-chain re-signer (IBV/ODM)**. `SECURITY.md:18-19` even lists "producer misrepresents shipped bytes" as *in scope*. `DESIGN.md:267` calls ResetVector "covered by membership" (the check proven insufficient). | SEC2, PE2, SEC6 | HONESTY | **S** | Rewrite the README threat banner → mid-chain re-signer; state the compromised-build ceiling ("that's what SLSA provenance is for") in SECURITY.md + DESIGN; fix the ResetVector line to say "whole-image D", not membership. |
| P0.3 | **Shadow-duplicate GUID bypass — a bypass INSIDE the marquee attack class.** Add a *second* FFS under an already-declared GUID; the carve extracts one FFS per GUID (`byte-integrity.py:177-186`) and reconcile is GUID-set membership → the shadow evades both. Currently softened to a roadmap bullet (`DESIGN.md:196-200`). | PE3 | SECURITY | **S** own / **M-L** close | At minimum elevate to a stated headline limitation; ideally implement duplicate-GUID detection (fail if >1 FFS share a GUID) in the carve + a `no-duplicate-guid` report. |
| P0.4 | **No machine-readable evidence grade** — `control_assessments[].status` is only satisfied/not/missing, so sample-CHIPSEC, empty-scan, DEV_ASSUME-anchor, and declared-field controls all render as plain ✅ and feed "45/46 satisfied." The honesty lives only in prose. | CA7, CA1-3, PE4 | DISCLOSURE | **M** | Add `evidenceGrade` (`verified` / `declared` / `sample` / `assumed`) to each report+control_assessment; drive the scoreboard from it; a non-`verified` control must not render as a plain green nor count in the headline total. |
| P0.5 | **Doc-drift (3 reviewers).** `COMPLIANCE-MATRIX.md:173` + `CONFORMANCE.md:108-109` still say author/timestamp/supplier are "not yet gated" — **false since this session**. Stale counts: `oss-lane/README` "21 reports" (actual 37), `README:130` "24 per-rule observations", `README:182` "33+25th". The annotated-evidence admission lives only in `inputs/README`, not the auditor-facing matrix ledger. | CA9, CC4, OM5, CA4 | HONESTY | **S** | Fix the false "not yet gated" lines; drop/generate hard counts; add the "some reference fields are annotated, image verdicts are committed-not-regenerated" note to COMPLIANCE-MATRIX's cross-cutting ledger. |

---

## P1 — Turn "sample" evidence into real evidence (your question). Also closes SEC3 / CA1-3.

Root-cause legend: **(a)** genuine silicon/device limit — unfixable in CI · **(b)** demo/offline
shortcut a CI fork-build could make real · **(c)** reference-consistency freeze (stable `D` +
shipped-byte hashes that the 26 fixtures depend on).

| # | Category | Root cause | Effort | Action |
|---|---|---|---|---|
| P1.1 | **Firmware anchor leg-3 / §4.3.1** (DEV_ASSUME, CI never builds the `.fd`) | **(b)** + entangled **(c)** | **L** | Add a CI job that builds the fork OVMF → real SBOM, real shipped-byte hashes, real `D`; set `FW_IMAGE=<built .fd>` (plumbing already at `assemble_gate_input.py:552-555`) → real leg-3, §4.3.1 claimable; run reconcile+byte-integrity+binary-hardening against the built image. **Wrinkle:** a fresh `D` forces re-cutting the 26 negative fixtures — the exact reason the reference is frozen today. |
| P1.2 | **CISA KEV** — 3-entry seed | **(b)** trivial | **S** | Fetch the live CISA KEV feed (the curl one-liner is already in `data.json:19`) in CI; refresh each run. Zero hardware. |
| P1.3 | **CHIPSEC config checks** (secureboot/bios_wp/smm — hand-authored) | **(b)** partial | **M** | Run real CHIPSEC against a QEMU-booted OVMF for the 3 config-level modules. **The 4 hardware-rooted modules (bios_ts/smrr/spi_desc/spi_lock) stay permanently N/A — (a). Mark them as such, never green.** |
| P1.4 | **CVE cutoff mismatch** — `severity-cutoff: critical` means HIGH CVEs never reach the gate, yet `vex-adjudicated` claims HIGH+CRITICAL coverage | CA2 | **S** | Lower the cutoff to `high` (so HIGH actually reaches the gate) or narrow the vex claim to CRITICAL-only. |
| P1.5 | **CVE matchability** — 310/311 edk2 modules have no purl/cpe, so even a real grype scan assesses only openssl | CA5, CA6, PE | **M** | Either enrich edk2 modules with CPEs (hard — edk2 modules aren't in NVD) or honestly scope RA-5/RV.1.1 to "the CVE-matchable dependency set (currently openssl)". Prefer the honest scope statement. |
| P1.6 | **Genuine hardware limits (a) — cannot be fixed in CI, ever** | SEC/CA | — | CHIPSEC SPI-lock/descriptor/SMRR/top-swap; deploy-time on-device detection; any TPM-quote/measured-boot evidence. State these as out-of-CI-by-nature (they already partly are). |

---

## P2 — Strategic re-centering (only if you choose "depth over breadth")

| # | Finding | Who | Effort | Action |
|---|---|---|---|---|
| P2.1 | Demote the ~19 declared-field + sample controls out of the headline count into a fenced **"SBOM hygiene / platform posture — declared or sample, not verified"** section; lead with the ~12 verified controls + the byte-integrity mechanism + the attack demo + the shadow-duplicate limitation. | PE1, CA8 | M | The principal engineer's single highest-signal change. |
| P2.2 | Cut the CSAF/VEX/SPDX emitters + `provider-comparison.py`/`PROVIDERS.md` (format surface without added verification; a second tangential scoreboard). | PE5 | S | Optional; frees ~490 lines + 1k words. The coSWID round-trip earned its keep — keep that. |

---

## P3 — Clean-code / maintainability (real debt from fast growth; architecture is sound)

| # | Finding | Who | Effort | Action |
|---|---|---|---|---|
| P3.1 | The `deny` block re-derives the reports and **has already drifted** (two strings for one failure; `firmware.rego:857-943`). | CC1 | M | `deny contains r.message if { some r in verifier_reports; not r.isSuccess }` — kills the drift class, −~85 lines. |
| P3.2 | **Gate-input schema is implicit + untested** (assembler output ↔ rego reads ↔ 40 fixtures, no schema). Fixtures are hand-copied & drifting (`critical-cve.json` missing whole sections). | CC2, CC3 | M | Add a JSON Schema for gate-input; validate the assembler's output + every fixture against it; convert fixtures to merge-patch overlays on `clean.json`. |
| P3.3 | Five docs describe the same framework→control spine (`FRAMEWORKS`/`COMPLIANCE-MATRIX`/`CONFORMANCE`/`compliance-map`/`POLICY-EXPANSION`); they've drifted. | CC5, PE6 | M | Generate the matrix from `frameworks.yaml`; keep `FRAMEWORKS.md` as the single narrative; fold the rest. |
| P3.4 | Duplicated constants across languages: `DXE_CLASS` (assemble + binary-hardening.py — the coverage denom vs numerator!), GUID regex, `edk2:moduleType` extraction, the `components` guard idiom (~6 sites). | CC7 | S/M | Single-source `DXE_CLASS`; add a `_components(sbom)` helper. |
| P3.5 | `firmware.rego` 1049 lines (honesty-essays inline); `main()` ~150 lines; test-harness style split (pytest vs print-PASS); Makefile hand-lists tests; `FMMT_Build.log` stray; `planning/` (14 files) reads as active but is stale; `valint-lane/` is a stub. | CC6/8/9/10 | S each | Move ceiling essays to a POLICY doc keyed by report; extract `_extract_subjects`/`_firmware_legs`; archive `planning/` → `docs/history/`; rm the stray log; conscious keep/retire on `valint-lane`. |

---

## P4 — Project health / adoption

| # | Finding | Who | Effort | Action |
|---|---|---|---|---|
| P4.1 | **Consumer CLI (`make verify`) has no runnable sample** — the one command an adopter would try needs a `.fd` that isn't committed. | OM4 | S/M | Ship a `make verify-demo` (or a tiny committed image) so the consumer path self-demonstrates like `make test`. |
| P4.2 | `CHANGELOG.md` has no `v0.1.1` entry though the tag exists and drives `release.yml`. | OM6 | S | Add the entry; keep semver→changelog discipline. |
| P4.3 | **Adoption blockers (strategic/known):** flagship depends on the *unmerged single-author* edk2 fork generator (OM1); hard-locked to edk2/OVMF via `edk2:*` props (OM2, honestly framed as "reference"); bus factor 1 (OM3, honestly stated). | OM1-3 | L | Not quick fixes — but if portability is a goal, document a property-mapping seam so a non-edk2 producer can feed the same gate. |

---

## Non-findings worth recording (don't waste time on these)
- **License is NOT inconsistent** (OM7): repo MIT (code) vs SBOM `BSD-2-Clause-Patent` (the *subject* edk2's license) — correct.
- **Keys are NOT leaked** (CC): `oss-lane/.keys/cosign.key` etc. are gitignored.
- **The vacuous-pass class from Round 1 is closed** (SEC, CC): every fact is `default false`; non-vacuity guards verified; a MODIFIED module is never exemptable.

## What all five reviewers credited (the real strengths — don't lose these in any refactor)
The byte-integrity PE32 un-rebase (real firmware engineering), the fail-closed rego + non-vacuity +
cherry-picking guards, the advisory-control trick, honest test skips, the ~40 isolating negative
fixtures + real 1-byte attack demo, real merged upstream work (uswid #98, edk2 #12936),
`EDK2-DEPENDENCY-RISK.md`, accurate badges, and the honest consumer CLI.

## Suggested sequence (my recommendation, you decide)
1. **P0** in full (credibility — a few days; P0.1 sign-verdict + P0.4 evidenceGrade are the meaty ones).
2. **P1.2 + P1.4** (live KEV feed, CVE cutoff — cheap real-evidence wins) now; **P1.1/P1.3** (CI fork
   build, chipsec-on-QEMU) as a larger follow-up, accepting the fixture re-cut cost.
3. **P2** decision point — after P0, re-judge whether to re-center or keep breadth.
4. **P3/P4** as ongoing hygiene.
</content>
