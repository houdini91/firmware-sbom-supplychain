> ## ⚠️ DRAFT — planning only. Do NOT create the public branch, push, or open a PR without an explicit
> human greenlight. The uSWID #98 precondition (Richard Hughes engagement) is NOT met; this document
> only describes how the branch/PR *would* be shaped when the greenlight comes.

# Upstream branch / PR plan — the `-Y SBOM` generator

## 0. What actually ships upstream (and what does not)

The upstream contribution is **the generator only**, into **edk2 `BaseTools`**. Everything else in the
research tree is operator-side and stays out. Ground truth from the repos on disk:

| Thing | Location on disk | Upstream? |
|---|---|---|
| Generator (build-time CycloneDX, stdlib-only) | `/home/mikey/research/secure_boot/edk2-sbom/generate.py` (+ `edk2_sbom.py` CLI wrapper) | **YES** — this is the payload |
| In-tree form of it | edk2 fork PR #6 (`houdini91/edk2`, **remote — not on this machine**) | **YES** — the actual PR vehicle |
| `validate.py`, `spdx_add_creator.py` | `edk2-sbom/` | Maybe (see §3) |
| `reconcile.py` (consumer-side, needs `uefi-firmware-parser`) | `edk2-sbom/reconcile.py` | **NO** — operator-side |
| byte-integrity, gate, VSA, two lanes, CHIPSEC, interop | `firmware-sbom-supplychain/` | **NO** — operator-side reference repo, MIT, never proposed upstream |

**Critical grounding note:** the generator exists in **two forms** and they are not obviously in sync:
1. A standalone, stdlib-only prototype at `edk2-sbom/` — **not a git repo** (no `.git`), licensed
   `BSD-2-Clause-Patent` (edk2's license — good).
2. A claimed in-tree `-Y SBOM` `BuildReport.py` report type as edk2 fork **PR #6** — referenced
   throughout `DESIGN.md` but **not present on this machine to inspect**.

Before any branch work: **confirm which is the real PR vehicle.** The clean-branch story below assumes
the in-tree `BuildReport.py` form (PR #6) is the artifact; the standalone `edk2-sbom/` is its origin and
its self-contained test harness. If PR #6 does not yet exist / is stale, that is the first thing to build,
not a branch to polish.

## 1. Target & mechanics

- **Repo:** a fresh fork of `tianocore/edk2`, branch off current `master`.
- **Canonical submission path:** edk2 takes patches on `devel@edk2.groups.io` via `git send-email`, with
  maintainers Cc'd — for BaseTools that's **Bob Feng** and **Yuwei Chen** (confirm from
  `Maintainers.txt` at submit time). The GitHub PR is a *convenience mirror*, not the review venue.
- **Branch name:** `sbom-report-type` or similar — descriptive, no personal handle.

## 2. Commit structure (small, reviewable, each self-contained)

edk2 reviewers prefer a short logically-split series over one mega-commit. Proposed split:

1. **`BaseTools: add -Y SBOM build report type`** — the generator wired into `BuildReport.py`, reusing the
   `-Y COMPILE_INFO` AutoGen data. Core patch. No new required dependency (stdlib JSON).
2. **`BaseTools: SBOM report — per-module digests + FV placement`** — the digest + `<FvName>.Fv.txt`
   parsing, *if* it's cleanly separable from commit 1. Fold in if separating adds noise.
3. **(reserve, do NOT include by default)** native `-Y SPDX` — held back per the format question in the
   #10507 draft. Only add if maintainers ask for native SPDX.
4. **`BaseTools: SBOM report — docs`** — a short `.md`/section under BaseTools docs + a `--help` line.

Each commit: builds clean, one concern, imperative subject prefixed `BaseTools:` (edk2 convention).

## 3. What to LEAVE OUT (the exclusion list — enforce before pushing)

- **The entire `valint-lane/`** and any Valint reference. Valint is a Scribe (the author's former
  employer) tool, **not OSS** in the relevant sense and irrelevant to BaseTools. Zero mentions upstream.
- **`reconcile.py` / byte-integrity / carve / the OPA gate / VSA / CHIPSEC / interop producers** — all
  operator-side; `DESIGN.md` is explicit that edk2 hosting a signing/gate pipeline would be "dead
  infrastructure." The most that reaches upstream is a *one-sentence* mention as motivation (see the
  #10507 draft), never code.
- **Anything unfinished / aspirational:** measured-boot / RIM / RATS bind (aspirational per README status
  table), the reserve `-Y SPDX` unless asked, the A4 in-toto-subject refactor.
- **Curated CPE map** if it rides along in the generator: it is flagged `DRAFT` /
  `firmware:cpe_review=unverified` in `generate.py`. Either drop CPE emission from the upstream patch or
  keep it clearly labeled and off the critical path — an unverified NVD identity in an upstream SBOM
  generator invites correctness objections. Recommend: **omit CPEs from the first upstream cut.**
- **All signing material & local artifacts** — none should exist in an edk2 branch anyway, but note the
  operator repo has demo keys on disk (`oss-lane/.keys/`, `valint-lane/.keys/*.pem`, `.key`/`.pub`).
  They are `.gitignore`d there; make sure none are copied into the edk2 branch.
- **Personal/portfolio framing** — no "portfolio", no role-application or employer-submission language, no
  `firmware-sbom-supplychain` repo URL in commit messages or the PR body. Cite only public #10507.

## 4. Licensing & DCO (edk2 hard requirements)

- **License header on every new file:** `SPDX-License-Identifier: BSD-2-Clause-Patent` — the standalone
  generator files already carry this (`generate.py`, `edk2_sbom.py` top lines). The operator repo is MIT;
  **do not** carry MIT headers into edk2.
- **DCO sign-off is mandatory.** Every commit needs `Signed-off-by: Real Name <email>` (`git commit -s`).
  edk2 enforces the Developer Certificate of Origin; the `Michael D. Strauss` name on the generator's
  copyright line must match the sign-off identity. Use a real name + reachable email.
- **Copyright line:** `Copyright (c) 2026, <name>. All rights reserved.` — matches the existing generator
  header style; confirm edk2's current preferred wording from a recent BaseTools commit.
- **No GPG requirement upstream** (that's the operator repo's own `CONTRIBUTING.md` rule); edk2 wants DCO
  sign-off, not necessarily signed commits — but signing does no harm.

## 5. Pre-post checklist (ALL must be true before any greenlight is even requested)

- [ ] **Precondition met:** Richard Hughes has engaged on uSWID #98. Until then, STOP.
- [ ] PR #6 (in-tree `-Y SBOM`) actually exists, applies to current edk2 `master`, and builds.
- [ ] A clean `OvmfPkgX64` DEBUG/GCC build with `-Y COMPILE_INFO -Y SBOM` produces the SBOM end-to-end on
      a fresh checkout (not just from committed example data).
- [ ] The **component count in the comment matches a real clean generator run** (resolve the 310 vs 311 /
      submodules-emitted-or-not divergence — see the #10507 draft's reviewer notes).
- [ ] Generated example validates (CycloneDX 1.6) — `validate.py` clean, and ideally an external validator.
- [ ] Every new file: `BSD-2-Clause-Patent` header + copyright line.
- [ ] Every commit: `git commit -s` sign-off, real identity, `BaseTools:` subject prefix.
- [ ] Exclusion list (§3) verified — grep the branch for `valint`, `reconcile`, `.pem`, `.key`, MIT,
      `firmware-sbom-supplychain`, `portfolio` → zero hits.
- [ ] Patch series generated with `git format-patch` / `git send-email --dry-run`, maintainers from
      `Maintainers.txt` confirmed current.
- [ ] The #10507 comment text finalized (one draft chosen, not both) and its claims reconciled.
- [ ] Human greenlight obtained, explicitly, in writing.
