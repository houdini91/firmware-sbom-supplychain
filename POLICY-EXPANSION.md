# Policy expansion — new rego rules to enforce conformance (careful review)

The deploy gate enforces 7 verifier_reports today. Now that we produce a larger evidence set (E1–E9 + CHIPSEC),
this is the **honest, deduplicated set of new rego rules** that would move named controls from `EVIDENCE`/`PARTIAL`
→ `ENFORCED`. Produced by a control-by-control review of SLSA, NIST SSDF/800-53/800-161, S2C2F, CISA/NTIA, CRA,
BSI, SP 800-190, and the firmware-platform frameworks — reviewers instructed to be **skeptical and refuse
rubber-stamps**. Companion to [`FRAMEWORKS.md`](./FRAMEWORKS.md) (the control map) and
[`oss-lane/policy/firmware.rego`](./oss-lane/policy/firmware.rego) (the gate).

## The rules (honest set)

Each is a new/tightened `verifier_report`. "Honesty clause" = the specific condition that keeps it from being a
rubber-stamp; drop the clause and the rule is theater.

| Rule | Control(s) | Evidence | Pass condition (essence) | Honesty clause | Status |
|---|---|---|---|---|:--:|
| **`chipsec-posture`** | SP 800-193 §4.2.1/§4.2.2, SP 800-147/147B | CHIPSEC | `chipsec.critical_passed` | `NOTAPPLICABLE`≠fail, but ≥1 applicable critical must PASS | **implemented** |
| **`reconcile-membership`** | SI-7, CM-8(3) | E3 | `declared==observed==matched ∧ undeclared_observed==0 ∧ missing==0` | `undeclared_observed==0` (real unauthorized-component detector) | **implemented** |
| **`component-integrity`** | SI-7(1), CISA Hash | E1 | every hashable non-lib module has SHA-256/512 | **no "≥122" relaxation** — the 1 gap (ResetVector) needs a hash or a reviewed `data.hash_exempt[]` entry | **implemented** (verified RED without the exemption) |
| **`signer-identity-pinned`** | SI-7(15), CM-14, SR-4(1) | E5, E2 | `sig.verified ∧ SAN==expected ∧ issuer==expected ∧ builder∈approved` | pin **issuer + SAN**, not just "a signature verified" | planned |
| **`sast-gate`** | SA-11(1), PW.7.2 | E8 | `sast.sig_verified ∧ sast.commit==provenance.commit ∧ critical==0 ∧ high≤thr` | **`sast.commit == build commit`** — else an old passing scan satisfies it | planned |
| **`vex-adjudicated`** | RV.1.1, RV.2.2, S2C2F SCA-1 | E4+VEX+CSAF | every high/critical finding has a **non-empty justification** | require the **justification string** — an unjustified/absent one fails; extends gating to HIGH | **implemented** |
| **`thirdparty-identifiers`** | PW.4.4, CM-8, CISA License/ID, S2C2F SCA-2 | E1 | every **third-party** component has purl+license | edk2 FFS **explicitly excluded** via `data.first_party_modules[]` (not a loosened threshold); `thirdparty.total≥1` | planned |
| **`slsa-level-floor`** | SR-4, SR-4(3) | E2 | `slsa_verified ∧ slsa_level≥2 ∧ source_repo==expected` | floor **`≥2`, never L3** — E2 is L2 (hosted), not hermetic/isolated | planned (tighten `slsa-provenance`) |
| **`build-tools-signed`** | SSDF PO.3.2, S2C2F REB-3 | E7 | `sbom_present ∧ sig_verified ∧ pinning=="sha" ∧ direct_only` | map to **PO.3.x, NOT PW.6.1** — this proves *which* tools, not hardening flags | planned |
| **`evidence-chain-bound`** | SLSA subject binding | E1/E2/E5/E6 | all subject digests equal one artifact digest | binds SBOM↔attestation↔provenance↔VSA↔signature into one chain | planned (extend `sbom-binding`) |

## Rules we deliberately do NOT write (refusing conformance theater)

- **`vsa-well-formed` (gate on E6 VSA) — circular.** The VSA is *this gate's own output*; feeding it back would
  gate on its own prior verdict. VSA stays a downstream chain-of-custody output, not an input.
- **`scorecard-threshold` as a hard gate — brittle rubber-stamp.** Scorecard's aggregate is a repo-health
  heuristic, not a per-release integrity fact, and is gameable/drift-prone. Keep E9 as **soft/informational**
  evidence (or, if ever gated, only specific binary checks — Signed-Releases, Branch-Protection — *bound to
  `provenance.source_repo`*), never the composite score as a deploy blocker.
- **Process/org controls — no rule can satisfy them.** SR-11 (anti-counterfeit policy), SR-3 (C-SCRM plan),
  SA-11(2) (threat modeling), SA-15 base (documented process), PS.1.1 (access control), PO.5 (secure build env),
  RV.1.3 (disclosure policy), PW.7.1 (human code review). Documented as `N/A (process)` in FRAMEWORKS.
- **PW.6.1 (build-tool hardening flags) — needs evidence we don't produce.** Requires per-binary compiler/linker
  hardening records (RELRO, stack canary, CFI, `_FORTIFY_SOURCE`). That is roadmap **R7** (binary-hardening
  posture), not an E7 rule. Mapping E7 to PW.6.1 would over-claim.

## Curated policy data the rules require (must be authored + reviewed)

These live in `oss-lane/policy/data.json` and are the load-bearing, human-curated inputs — get these wrong and
the strong rules become vacuous:

- `data.first_party_modules[]` / classification for `thirdparty-identifiers` (else it passes vacuously).
- `data.trusted_signer_identities[]` (SAN) + `data.trusted_builders[]` for `signer-identity-pinned`.
- `data.hash_exempt[]` (with reasons) for `component-integrity-coverage` — currently just `ResetVector`
  (a raw reset-vector blob, not a PE image → no canonical hash), which must be an *explicit reviewed exemption*,
  not a silent pass.

## Two design notes that decide honest-vs-theater

1. **`sast-gate`'s SARIF↔commit binding** and **`thirdparty-identifiers`'s explicit edk2 exclusion** are the two
   places a careless assembler turns an honest rule into a rubber-stamp. The assembler must *derive* facts from
   the signed evidence (E2 predicate, E5 cert, E8 SARIF `versionControlProvenance`), never trust a bare boolean.
2. **A signature/attestation rule proves a claim is *asserted and signed*, not *true*.** `vex-adjudicated`
   enforces triage discipline, not vulnerability absence; `sast-gate` enforces "a signed clean SAST attestation
   exists," not SAST quality. State these ceilings in the control mapping — don't let them read as more.

## Implementation order

1. **`chipsec-posture`** (done — closes R3) and **`reconcile-membership`** + **`component-integrity-coverage`**
   — the real SI-7 integrity story; the last surfaces the 122/123 gap immediately.
2. **`sast-gate`** (commit-bound) — pulls E8 into the gate; biggest control-coverage gain.
3. **`signer-identity-pinned`**, **`vex-adjudicated`** — identity pinning + triage discipline.
4. **`slsa-level-floor`**, **`build-tools-signed`**, **`evidence-chain-bound`** — tighten the chain.

Each needs assembler plumbing to derive its fact from evidence + a negative fixture proving it blocks. Staged so
each rule ships verified, not a big-bang rego drop.
