# CI that produces REAL firmware supply-chain evidence — DRAFT for review

> Status: **DRAFT / planning only.** Deliverable pair: this doc + `planning/ci-real-evidence.draft.yml`.
> Nothing here modifies `.github/workflows/supply-chain.yml` (which is green and must stay green) or any
> other repo file. The draft workflow is a `*.yml` under `planning/` on purpose — GitHub Actions only
> schedules workflows under `.github/workflows/`, so this file will never run until someone deliberately
> moves + wires it. Do not do that as part of reviewing it.

## Why

The reference pipeline (`.github/workflows/supply-chain.yml`) is a **verify-side** demo: it CONSUMES committed
evidence and does the signing / gating / VSA for real. Specifically, today it:

| Leg | Today in `supply-chain.yml` | Real or committed? |
|---|---|---|
| SBOM (`inputs/sbom.cdx.json`) | committed (a real prior `-Y SBOM` build, checked in) | **committed** |
| reconcile verdict (`inputs/reconcile-verdict.json`) | committed | **committed** |
| byte-integrity (`inputs/byte-integrity.json`) | committed | **committed** |
| binary-hardening (`inputs/binary-hardening.json`) | committed | **committed** |
| CHIPSEC (`producers/chipsec/sample-results.json`) | committed hand-authored OVMF/QEMU sample | **committed** |
| firmware image (leg-3 measurement) | `DEV_ASSUME_FWIMAGE=1` — leg-3 copied from the SBOM self-claim, no image hashed | **assumed** |
| CISA KEV (`data.cisa_kev`) | committed illustrative seed (2 CVEs) | **committed seed** |
| grype CVE scan | `anchore/scan-action` runs live | **REAL** |
| SLSA provenance (E2) | `actions/attest-build-provenance` + `gh attestation verify` | **REAL** |
| cosign keyless sign/verify of every bundle | real keyless OIDC | **REAL** |
| build-tools SBOM (E7) | `build-tools-sbom.sh` inventories the live toolchain | **REAL** |
| OPA gate + signed VSA + initiative coverage | real | **REAL** |

The draft (`ci-real-evidence.draft.yml`) keeps every REAL leg exactly as-is and converts the **committed**
and **assumed** legs into evidence **built in CI from source**, so the demo becomes a reproducible, adoptable
pipeline rather than one anchored on checked-in artifacts.

## What the draft does, job by job

1. **`build-firmware`** — checks out the **edk2 fork** (`houdini91/edk2`, the `-Y SBOM` branch — *not*
   tianocore), `git submodule update --init`, `make -C BaseTools`, then
   `build -p OvmfPkg/OvmfPkgX64.dsc -a X64 -b DEBUG -t GCC5 -Y COMPILE_INFO -Y SBOM`. Output: a **real**
   `sbom.cdx.json` (generator-emitted) + a **real** `OVMF_CODE.fd`. Then the real producers run against the
   built `.fd`: `producers/reconcile/carve.sh` (FMMT carve → `sbom-reconcile.py`), `byte-integrity.py`,
   `binary-hardening.py` → real verdicts. Uploaded as the `real-evidence` artifact.
2. **`chipsec-qemu`** (experimental, `continue-on-error`) — boots the built OVMF in QEMU and runs chipsec
   in-guest for the config-visible modules only. See the CHIPSEC section for exactly what this can and
   cannot substantiate.
3. **`attest-and-gate`** — the **same** sign / assemble / gate / VSA / initiative steps as
   `supply-chain.yml`, over the real evidence. The one intentional change: `FW_IMAGE=inputs/OVMF_CODE.fd`
   replaces `DEV_ASSUME_FWIMAGE=1`, so `assemble_gate_input.py` hashes the real deployed image and sets
   `firmware.freshly_measured=true` (SP 800-193 §4.3.1), which the DEV_ASSUME path deliberately withholds.
   It also refreshes `data.cisa_kev` from the **live** CISA KEV feed (ephemeral in-runner `jq`-merge of the
   checked-out `oss-lane/policy/data.json` — not a commit).

## Evidence artifact → REAL-in-this-draft vs. NEEDS

| Evidence artifact | How the draft produces it | REAL here? | NEEDS |
|---|---|---|---|
| `sbom.cdx.json` | edk2 fork build `-Y SBOM` | ✅ real (build-time) | **a pushed fork** carrying PR #6's `-Y SBOM` report type |
| `OVMF_CODE.fd` (firmware image) | edk2 fork OVMF DEBUG/GCC build | ✅ real | pushed fork; hosted runner OK (~minutes) |
| `reconcile-verdict.json` | `carve.sh` FMMT carve of the built `.fd` + `sbom-reconcile.py` | ✅ real | built `.fd` + built BaseTools FMMT |
| `byte-integrity.json` | `byte-integrity.py --image <built .fd> --edk2 <tree>` | ✅ real | built `.fd` + edk2 tree + `pefile` (~6 min) |
| `binary-hardening.json` | `binary-hardening.py --image <built .fd> --edk2 <tree>` | ✅ real | same as above |
| leg-3 firmware measurement / `freshly_measured` | `FW_IMAGE=<built .fd>`, hashed by the assembler | ✅ real measurement (not DEV_ASSUME) | the built `.fd` present in the gate job |
| `grype.json` (CVE scan) | `anchore/scan-action` over the built SBOM | ✅ real (already) | none (hosted OK) |
| `data.cisa_kev` (KEV catalog) | live CISA KEV feed → `jq`-merge into the ephemeral checkout | ✅ real / live | egress to `cisa.gov`; a reachable feed (fails closed if not) |
| `build-tools.cdx.json` | `build-tools-sbom.sh` | ✅ real (already) | none |
| SLSA provenance (E2) + `gh attestation verify` | `actions/attest-build-provenance` | ✅ real | **public repo** (or GH Enterprise) attestation store |
| cosign keyless signatures on every verdict/SBOM/VSA | keyless OIDC (`id-token: write`) | ✅ real | hosted OK |
| signed SLSA **VSA** (gate verdict) | `gate.sh` + cosign | ✅ real | none |
| CHIPSEC config-level (`secureboot.variables`, some config reads) | QEMU/OVMF boot + chipsec-in-guest | 🟡 **experimental** real | QEMU **TCG** boot in-job; only config-visible modules; SB must be provisioned to be meaningful |
| CHIPSEC HW-root critical (`spi_lock`, `spi_desc`, `smrr`, `bios_ts`, top-swap) | — | ❌ **cannot** in hosted CI | **physical silicon** (self-hosted bare-metal); QEMU returns NOTAPPLICABLE |
| on-device deploy-time measurement (real flash, real §4.3.1 admission) | — | ❌ **cannot** | a physical device + flashing harness |

## The hard precondition: a pushed fork (read before running anything)

The `-Y SBOM` generator is **not upstream tianocore** and **not in this repo**. It lives in the edk2 fork as
**PR #6** (`houdini91/edk2`), wired into `BaseTools/.../BuildReport.py` as an `-Y SBOM` report type
(`planning/UPSTREAM-BRANCH-PLAN.md` §0). Grounding caveats that gate this draft:

- `UPSTREAM-BRANCH-PLAN.md` records that the in-tree PR #6 form is **"not present on this machine to inspect"**
  and may be **stale or not yet existing** — the standalone prototype at `edk2-sbom/generate.py` is its origin.
  **First action before wiring the draft live: confirm PR #6 exists on the fork, applies to the fork's
  `master`, and builds.** If it does not, there is no `-Y SBOM` for CI to invoke and the `build-firmware` job
  fails at the build step (by design — it does not fall back to the committed sample).
- The draft's `build-firmware` checkout of `houdini91/edk2 @ sbom-report-type` **will fail until that branch is
  pushed publicly**. Both the repo and ref are `workflow_dispatch` inputs so a reviewer can point them at
  whatever the real fork/branch turns out to be.
- **Confirm two output details against PR #6 at wire-up:** (a) the exact filename/path the `-Y SBOM` report
  type writes the CycloneDX SBOM to (the draft `find`s `*.cdx.json` and fails loudly if absent — it must not
  silently fall back to the committed SBOM); (b) which image the generator's `metadata.component` digest is
  taken over. The draft warns (does not fail) if the built `OVMF_CODE.fd` digest ≠ the SBOM's
  `metadata.component` D — but that mismatch means the firmware-digest-anchor legs diverge and the gate will
  DENY. If the generator hashes the full `OVMF.fd` (code+vars) rather than `OVMF_CODE.fd`, align `FW_IMAGE`
  and the reconcile `--image` to the same artifact.

## CHIPSEC: what is honestly feasible in CI, and what is not

CHIPSEC reads platform state that only exists on real silicon — SPI flash controller MMIO, the flash
descriptor, SMRR MSRs, top-swap/BIOS-control registers. Two honest tiers:

**Feasible (experimental) — config-level chipsec against a QEMU/OVMF boot.** Hosted GitHub runners have **no
KVM**, so QEMU runs under **TCG** (pure software emulation): bootable but slow. You can boot the *built*
`OVMF_CODE.fd` in QEMU `q35`, run chipsec in a small Linux guest, and get a **real** result for modules that
read UEFI-variable / config state — chiefly `common.secureboot.variables` (meaningful only if Secure Boot is
provisioned in the OVMF varstore; otherwise it honestly reports SB disabled), and config-level reads like
`common.bios_wp` / `common.smm` to the extent QEMU exposes them. `to-predicate.py` already treats
`NOTAPPLICABLE` as *not a failure and not a pass*, so this stays honest by construction. The draft's
`chipsec-qemu` job **sketches** this (it does not claim a captured run) and is `continue-on-error`; if it
yields nothing, the gate job falls back to the committed OVMF/QEMU **sample** and labels it as a sample, never
as a hardware measurement.

**NOT feasible in hosted CI — the hardware-root critical modules.** `common.spi_lock`, `common.spi_desc`,
`common.smrr`, `common.bios_ts` (and top-swap) require the real chipset. On QEMU they are legitimately
`NOTAPPLICABLE` — the emulator does not faithfully implement the protected-range / descriptor-lock / SMRR MSR
semantics these modules assert on. **Do not mark them PASS from an emulated run.** A subtle honesty trap: the
gate's `critical_passed` requires only the *applicable* critical modules to PASS **and at least one to run** —
so a QEMU run where only `secureboot.variables` is applicable could yield `critical_passed=true` on a very
thin basis. That is a correct-but-weak posture; the report must make clear that SPI-lock / descriptor / SMRR /
top-swap were **not measured**, not that they passed.

**Genuinely un-producible without hardware (state plainly):**
- Hardware-rooted CHIPSEC — SPI flash write-protection lock (`FLOCKDN`), flash descriptor read/write
  protection, SMRR range protection, BIOS top-swap — needs **physical silicon**.
- On-device, deploy-time measurement of the flashed image (the real SP 800-193 §4.3.1 admission-time
  detection on a device) — needs a **physical device + flashing harness**. The draft's `freshly_measured`
  leg is a real *measurement of the built image in CI*, which is a strict improvement over `DEV_ASSUME`, but
  it is not the same as measuring what a device actually admitted at flash time.
- A TPM quote / golden RIM (RATS §8.1 evidence, measured boot) — out of scope everywhere in this repo today.

## Self-hosted runner option (for the heavy build and for real CHIPSEC)

Two distinct reasons to reach for a **self-hosted GitHub runner**, with different trust implications:

1. **Speed / KVM for the OVMF build + QEMU chipsec.** A self-hosted Linux runner with nested-virt/KVM makes
   the OVMF build and any QEMU chipsec run dramatically faster than hosted TCG. This does **not** change what
   can be *substantiated* — QEMU is still emulation — only how fast the experimental lane runs. Wire it by
   setting `runs-on: [self-hosted, linux, x64]` on `build-firmware` / `chipsec-qemu`.
2. **Real hardware-root CHIPSEC.** A self-hosted runner **on real hardware** (bare metal, with privileged
   access) is the only way to get genuine `spi_lock` / `spi_desc` / `smrr` / `bios_ts` results in a GitHub
   Actions job. This runs privileged chipsec (kernel module / `/dev/mem`) on the runner host — a real
   security decision, not a config toggle.

**Self-hosted security caveat (call out to the manager):** self-hosted runners must **not** be exposed to
untrusted pull requests — a PR could run arbitrary code, and here that code would run *privileged* (chipsec
needs root and raw hardware access). Restrict the draft to `workflow_dispatch` / trusted branches only (it
already is `workflow_dispatch`-only), use an ephemeral/one-shot runner if possible, and never attach a
hardware self-hosted runner to a public-PR trigger. Running privileged chipsec on the runner host also means
the *evidence's trust root* is now that machine's physical security — document which physical box produced the
posture.

## Notes for the reviewer (honesty ledger)

- **Reused verbatim from `supply-chain.yml`** (so the signed evidence graph is the same code path): the OPA
  install + SHA, `sigstore/cosign-installer@…v3` pinned to `v2.6.0`, `actions/attest-build-provenance@…v4.1.1`,
  `anchore/scan-action@…v6`, `actions/checkout@…v4`, `wrap.sh` multi-subject wrapping, the
  `assemble-gate-input.sh` env contract, `gate.sh`, `verify-initiative.py`.
- **New action pins that need confirmation:** `actions/upload-artifact` and `actions/download-artifact` are
  not used by `supply-chain.yml`, so the SHAs in the draft are placeholders to verify/repin against the
  versions you standardize on before this ever runs.
- **KEV injection is an ephemeral in-runner edit**, not a repo change: the draft `jq`-rewrites the *checked-out*
  `oss-lane/policy/data.json`'s `cisa_kev` array from the live feed, which is exactly the refresh the seed's
  own `_comment` documents. `gate.sh` is called unchanged. (An alternative that avoids touching the file at all
  would be a small `gate.sh` enhancement to accept an extra `-d` KEV override — deliberately **not** done here,
  since the task is not to modify existing files.)
- **The producers exit non-zero on an adverse verdict** (e.g. byte-integrity `modified`, binary-hardening
  missing-NX). The draft runs them with `|| true` so the **gate** adjudicates the verdict rather than the
  producer step failing the job — matching how the reference pipeline lets the OPA gate be the decision point.
- **This is a draft for review, not a merge.** It is intentionally not under `.github/workflows/`.
