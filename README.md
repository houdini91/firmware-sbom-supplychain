# firmware-sbom-supplychain

[![pr-checks](https://github.com/houdini91/firmware-sbom-supplychain/actions/workflows/pr-checks.yml/badge.svg)](https://github.com/houdini91/firmware-sbom-supplychain/actions/workflows/pr-checks.yml)
![license](https://img.shields.io/badge/license-MIT-blue.svg)
![release](https://img.shields.io/badge/release-v0.1.0-3ddbd9.svg)
![byte-integrity](https://img.shields.io/badge/byte--integrity-122%2F122-3fb950.svg)
![gate](https://img.shields.io/badge/gate-18%20signed%20checks-4aa8ff.svg)

> ### Prove that a firmware image runs the exact code its signed bill of materials declares — and block a *same-GUID trojan* that signatures and inventories miss.

An **evidence-centric supply-chain gate** for firmware, on the open **OVMF / edk2** UEFI reference target. Every
claim about a build becomes signed evidence; a policy engine ANDs it into one verdict; the release is blocked
unless the **executable code that ships in the image** matches the signed **SBOM** (Software Bill of Materials —
the "ingredients list": every module + its hash). The headline check, **byte-integrity**, catches a
*same-GUID trojan*: a module whose code was swapped but whose ID (`FILE_GUID`) was kept — so it passes an
inventory check, but not a byte check.

> **New to firmware, SBOMs, or GUIDs?** → **[PRIMER.md](PRIMER.md)** explains it all from scratch (~2 min).
> **See it run:** [**docs/DEMO.md**](docs/DEMO.md) (real gate + CLI output). **Visual walkthroughs:**
> [showcase](docs/showcase.html) · [byte-integrity explainer](docs/byte-integrity.html) (open in a browser).

`18 signed checks → one gate` &nbsp;·&nbsp; `122 of 123 modules byte-verified` &nbsp;·&nbsp; `6 frameworks, per-control` &nbsp;·&nbsp; `a portable signed verdict (OSCAL / RATS)`

**See it run** — the gate blocks a same-GUID swap that an inventory (membership) check waves through:

```text
✅ ALLOW  clean release          — 18/18 signed checks pass → signed verdict: PASSED
⛔ DENY   same-GUID swap          — component-byte-integrity: 1 module MODIFIED (shipped bytes ≠ declared hash)
```

> **Design & rationale:** [`DESIGN.md`](DESIGN.md) — the security / functional / operational design and the
> who-does-what boundary, doubling as the note for the upstream edk2 generator discussion (#10507).

## Quickstart

```bash
make deps      # Python deps (PyYAML); see requirements.txt for the CLI tools (opa, jq, cosign, grype)
make test      # gate honesty tests — ALLOW a clean release, DENY each failure mode (16 negative fixtures + clean + triaged-allow, exercising all 18 reports)
make coverage  # per-framework, per-control compliance coverage from a fresh signed VSA
make demo      # the full OSS lane end to end (needs cosign + grype)
```

`make test` and `make coverage` are self-contained (opa + jq + python3/PyYAML). The gate itself is
[`oss-lane/policy/firmware.rego`](oss-lane/policy/firmware.rego) — **18 verifier reports** ANDed into a signed
SLSA VSA, each with an isolating negative fixture under [`oss-lane/fixtures/`](oss-lane/fixtures).

**Consumer side** — run the gate on *your own* firmware:

```bash
make verify FW=path/to/OVMF.fd VSA=vsa.intoto.json   # hash it, bind it, per-framework scorecard
```

[`cli/fw-supplychain-verify`](cli/README.md) hashes the image itself, checks the evidence is bound to *those
bytes*, and prints a `PASS / FAIL / MISSING_EVIDENCE` scorecard — degrading honestly to `MISSING_EVIDENCE` on
unattested firmware it has never seen.

## Documentation

Read in this order:

1. **[`PRIMER.md`](PRIMER.md)** — start here if you're new to firmware: what this does and why, from scratch.
2. **README** (this file) — what it is, how to run it.
3. [`DESIGN.md`](DESIGN.md) — the security / functional / operational design + the upstream-generator rationale.
4. [`FRAMEWORKS.md`](FRAMEWORKS.md) — the evidence→control map (exact section numbers; the 18 enforced
   reports over evidence atoms E1–E10).
5. [`oss-lane/compliance-map.md`](oss-lane/compliance-map.md) — the enforced subset + the two-lane story.
6. [`oss-lane/README.md`](oss-lane/README.md) — how the enforcing lane fits together (gate, assembler, fixtures).
7. [`EDK2-DEPENDENCY-RISK.md`](EDK2-DEPENDENCY-RISK.md) — the edk2 vendored-submodule risk map: maintenance /
   security posture of each dependency and the stale-pin / org-mirror attack surface.

Internal worklog (not product docs): [`DESIGN-REVIEW.md`](planning/DESIGN-REVIEW.md) (architecture review + verdict),
[`POLICY-EXPANSION.md`](planning/POLICY-EXPANSION.md) (the rule set), [`EVIDENCE-ROADMAP.md`](planning/EVIDENCE-ROADMAP.md)
(forward evidence lanes), [`TODO.md`](planning/TODO.md) (punch-list).

## The pipeline

```mermaid
flowchart LR
    A["1. Generate SBOM<br/>the ingredients list of<br/>every firmware module"]
    B["2. Verify signature<br/>+ build provenance<br/>who built it, really?"]
    C["3. Reconcile<br/>membership + byte-integrity<br/>does the chip contain<br/>exactly those bytes?"]
    D["4. CVE scan<br/>any known<br/>vulnerabilities?"]
    E{"5. Policy gate<br/>do all rules pass?"}
    F["6. Signed VSA<br/>the signed verdict,<br/>re-checkable downstream"]
    G["Deploy"]
    H["Block"]
    A --> B --> C --> D --> E
    E -->|all pass| F --> G
    E -->|any fail| H
```

In one line: `generate → verify(sig+provenance) → reconcile(bytes==SBOM) → CVE map → attest → OPA/compliance
gate → deploy`.

## Three checks, three questions

Three checks are the core of trusting a firmware image. **Two ask "does the firmware match its bill of
materials?"** (reconcile, byte-integrity); the **third asks a different question entirely** — "are the
platform's own defenses switched on?" (CHIPSEC). Different questions, different levels:

| Check | Question it answers | Level | Catches |
|---|---|---|---|
| **Reconcile** (membership) | Are all the declared modules actually **present**? | composition — by module ID (`FILE_GUID`) | a missing module, or an **undeclared** one that shouldn't be there |
| **Byte-integrity** | Do each module's shipped **code bytes** match the declared hash? | content — the executable (PE32) of every module | a **same-GUID trojan**: same ID, swapped code |
| **CHIPSEC** (platform posture) | Are the platform's firmware **protections** switched on? | platform config — not about the modules at all | BIOS-write-protect / SMM / Secure-Boot-variable **misconfiguration** |

Three complementary layers: **the right parts are present** (reconcile), **the parts are genuine**
(byte-integrity), and — separately — **the platform's defenses are on** (CHIPSEC). Membership alone is fooled by
a same-GUID swap; byte-integrity catches it. Each maps to specific controls (byte-integrity → NIST
`SI-7(1)`/`SR-4(3)`; CHIPSEC → `SP 800-193 §4.2`), carried per-control in the signed verdict.

> **Honest scope.** Byte-integrity covers each module's **PE32 executable code** — 122 of the 123 modules
> (`ResetVector`, a raw reset blob, is the one non-PE32 skip); it does not yet cover a module's DEPEX/other
> sections, or TE/compressed sections. CHIPSEC on the **QEMU/OVMF** target runs the config checks that apply
> there (`bios_wp`, `secureboot.variables`, `smm`); hardware-root checks (SPI-lock, SMRR…) report **N/A**, not
> pass — assessed, not asserted.

```mermaid
flowchart TB
    FW["🔩 Firmware image (.fd)"]
    FW --> R["① Reconcile — <b>composition</b><br/>are the declared modules present?"]
    FW --> B["② Byte-integrity — <b>content</b><br/>do the shipped bytes match the SBOM?"]
    FW --> C["③ CHIPSEC — <b>platform</b><br/>are the firmware protections enabled?"]
    R --> G{"Policy gate<br/>(18 signed checks)"}
    B --> G
    C --> G
    G -->|all pass| OK["✅ signed verdict → deploy"]
    G -->|any fail| NO["⛔ blocked"]
```

### Implementation status

The source of truth for what is actually built vs. designed. `DESIGN.md` describes the full intended
shape; this table says what exists. ✅ implemented · ⚠️ canned/stubbed · ❌ not built · ⛔ aspirational.

| Stage | Designed | Status |
|---|---|---|
| 1 — Generate declared SBOM | edk2 `-Y SBOM` | ✅ implemented (edk2 fork PR #6; CycloneDX 1.6, per-module SHA-256/512, firmware-image digest in `metadata.component`, CISA/BSI Tier-1 metadata; **311-component example committed** — the upstream generator emits 310, the demo enriches it with `openssl` as an in-image third-party dep, R1) |
| 2 — Observed carve → observed FFS | edk2 FMMT | ✅ implemented (`producers/reconcile/carve.sh` — FMMT decompresses the FVs and lists FFS `FILE_GUID`s) |
| 3 — Reconcile declared vs observed | `producers/reconcile/sbom-reconcile.py` + `byte-integrity.py` | ✅ **generated** (not canned) — real carve → verdict: 123/123 modules validated, 0 missing, 0 suspicious (*membership*). **Byte-integrity (R4) now covers the whole image — 122/122 modules:** `byte-integrity.py` extracts each module's PE32 from the deployed `.fd` and matches it to the SBOM's declared hash — a **same-GUID trojan is detected** (gate report `component-byte-integrity`). DXE drivers match directly (111); XIP/PEI modules (rebased) are byte-verified via un-rebase canonicalization (11). |
| 4 — CDX → SPDX | protobom `sbom-convert` | ✅ implemented (`producers/interop/to-spdx.sh` + `inputs/sbom.spdx.json`) |
| 4b — CDX → coSWID + embed | uSWID | ✅ implemented (`producers/interop/to-coswid.sh` + `inputs/sbom.uswid`) — CDX→coSWID round-trips (310→311), and embeds into a PE `.sbom` section + re-extracts, verified |
| 5 — CVE map | grype | ✅ implemented (CI) |
| 6 — Attest + sign | cosign / Valint | ✅ implemented |
| 7 — Store to OCI | cosign | ✅ implemented (CI) |
| 8 — Policy gate | OPA / Valint | ✅ implemented (verifier-reports + SLSA VSA) |
| runtime — measured boot / RIM bind | TCG RIM / RATS | ⛔ aspirational, documented in DESIGN (not implemented) |

The enforcing gate (stages 5–8), the SPDX interop (4), and now the real observed-carve + reconcile (2/3) run
here; the generator (1) is edk2 fork PR #6. **Byte-integrity (R4) is now enforced over the whole image (122/122 modules)** — DXE directly, XIP/PEI via un-rebase canonicalization; a same-GUID trojan is caught (`component-byte-integrity`). Every other designed
stage now runs.

## The tools, in one line each

- **SBOM** (Software Bill of Materials) — the ingredient list of the firmware: every module, library, and
  third-party component, in [CycloneDX](https://cyclonedx.org) JSON.
- **[cosign](https://github.com/sigstore/cosign)** — sigstore's signing tool. It cryptographically signs
  the SBOM (and an attestation about it) and later verifies that signature. "Keyless" mode signs with a
  short-lived certificate tied to the CI job's identity (no long-lived private key).
- **[OPA](https://www.openpolicyagent.org)** (Open Policy Agent) — a policy engine. You hand it facts
  (JSON) and a policy written in *Rego*; it answers allow/deny. It does the *deciding*, not the gathering.
- **[Valint](https://github.com/scribe-public)** — a supply-chain evidence + policy tool (author: this
  project's author). It both *signs* evidence (like cosign) and *verifies compliance policies* against it,
  resolving named rules and whole-framework "initiatives" (SLSA, SSDF, SP-800-53) from a policy bundle.
- **[grype](https://github.com/anchore/grype)** — scans the SBOM's components for known CVEs.
- **reconcile** — this project's own check: carve the actual firmware binary and confirm it contains
  exactly what the SBOM claims (verify, don't trust).

The two lanes below run over the *same* signed evidence — one with cosign+OPA (the enforcing gate), one with
Valint (the same compliance checks, currently reporting) — so the result isn't tied to a single tool.

## Two lanes, side by side

```mermaid
flowchart TD
    EV["Same signed evidence<br/>SBOM + attestations + reconcile verdict"]
    EV --> OSS["OSS lane — cosign + OPA<br/><b>enforcing gate</b>:<br/>a policy violation fails the run"]
    EV --> VAL["Valint lane — same compliance checks<br/><b>report mode</b>:<br/>independent check, non-blocking"]
```

| Step | `oss-lane/` | `valint-lane/` |
|---|---|---|
| **Sign evidence** | `cosign attest` (in-toto/DSSE) | `valint` signed evidence |
| **Verify signature** | `cosign verify-attestation` | `valint verify` (pulls the cosign/in-toto envelope) |
| **Policy / compliance** | `opa eval` over `policy/*.rego` | `valint verify` → YAML policy → sample-policy rego hierarchy |

Locally both sign with a key so the demo runs offline; the reference GitHub Actions workflow swaps that for
**keyless OIDC** signing (`cosign` via Fulcio/Rekor, using the runner's workload identity). *(The repo is public, so the SLSA provenance is generated by GitHub's attestation store via
`actions/attest-build-provenance` — platform-generated, SLSA Build L2 — and verified with `gh attestation
verify`, rather than a self-signed predicate.)*

## Compliance frameworks

The gate is the "compliance framework" engine. This repo ships one worked example end-to-end (SLSA
provenance + a custom firmware-composition policy) and a mapping showing how additional frameworks express
as policy rules:

- **SLSA** — build provenance at **L2**: GitHub's attestation store (`actions/attest-build-provenance`)
  generates and signs the SBOM's provenance from the run's metadata (platform-generated, not tenant-forgeable),
  verified in CI with `gh attestation verify`. L3 (isolated/hardened builder) is the remaining step. See
  [`FRAMEWORKS.md`](./FRAMEWORKS.md).
- **Custom firmware composition** — SBOM present ∧ signature verified ∧ reconcile clean ∧ no critical CVE ∧
  provenance bound to the trusted builder.
- **NIST SSDF (SP 800-218)** and **BSI TR-03183** — control→rule mapping in `oss-lane/compliance-map.md`.

## Honesty tests

`tests/` proves the gate actually blocks — not just passes a clean input:

- a **tampered SBOM** (fails reconcile),
- a **wrong builder identity** (fails provenance),
- an **injected critical CVE** (fails the CVE clause).

## Status

**Green on CI** (`.github/workflows/supply-chain.yml`), all keyless via the runner's OIDC identity. The
`attest-and-gate` job keyless-signs the SBOM **and a real SLSA provenance predicate**, verifies both, runs a
**grype** CVE scan (`anchore/scan-action`), assembles a gate input entirely from *verified* evidence
(signer identity extracted from the Fulcio cert, SBOM-hash ↔ signed-subject binding, reconcile verdict
decoded from the signed payload), enforces the **OPA gate** (with a **VEX allowlist** for triaged CVEs) and
keyless-signs its verdict as a **SLSA VSA** (Verification Summary Attestation),
runs fixture + in-pipeline negative tests, and demonstrates cosign's **native `verify-attestation --policy`**
over the OCI-stored SBOM. The `valint-lane` job signs + runs compliance keyless (report mode).

Locally the OSS lane runs end-to-end over real OVMF data (311-component SBOM, reconcile clean 123/123 →
ALLOW, emitting a signed SLSA VSA; honesty tests block tampered / wrong-builder / critical-CVE /
swapped-SBOM). Reference/demo,
defensive use only. Not affiliated with or endorsed by TianoCore.

## Trust model & limitations

The gate is only as trustworthy as its inputs, so it's worth being explicit about what it does and
doesn't protect:

- **Actions are pinned to commit SHAs** (not mutable tags), and each job takes the **minimum token scope**
  (only `attest-and-gate` gets `id-token: write`, for keyless signing).
- **The gate's decision inputs live in the repo** — `inputs/reconcile-verdict.json` (the reconcile
  predicate), `oss-lane/policy/cve-allowlist.json` (VEX), and `oss-lane/policy/data.json` (the expected
  builder identity). A commit that edits these can change the verdict, so they are covered by
  [`CODEOWNERS`](.github/CODEOWNERS) and **require branch protection on `main`** to be meaningful. Signing
  does *not* protect them — they're inside the signed repo.
- **Demo limitation:** in this demo the reconcile verdict is *committed*, not regenerated in CI (CI has the
  SBOM but not the multi-hundred-MB firmware image to re-carve). A real operator pipeline would **regenerate
  the reconcile verdict inside the isolated builder** from the actual firmware, so the gate *proves* the
  bytes rather than *trusting* a committed file. That's the intended production shape; the demo shows the
  policy/attestation machinery around it.
- The local runner's `DEV_ASSUME_IDENTITY` fallback (used only when signing with a local key, which carries
  no cert identity) is **unreachable in CI** — CI keyless signing always yields a real, extracted signer
  identity. A local `ALLOW` therefore proves less than a CI `ALLOW`.

[Valint]: https://github.com/scribe-public
