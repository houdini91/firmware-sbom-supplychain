# Phase 2 — Real "green" Secure Boot on a gated firmware image

Status: PLAN (de-risked). Author date: 2026-08-09.
Scope: turn the current **red / not-provisioned** Secure Boot posture into a **real,
enforcing green** on a GATED image, with the whole SBOM → reconcile → byte-integrity →
posture → gate chain re-derived honestly. No policy/fixture/rego changes here.

---

## TL;DR — Recommendation: **Path A (rebuild the edk2 fork with `-D SECURE_BOOT_ENABLE`)**

Path A is the only path that yields a real green **without breaking the supply-chain
story**. The gated image `D` is the fork build's `OVMF_CODE.fd`; its digest is
`sha256:7965c317…` and it is the exact subject the gate already binds
(`deployed_digest` = `reconcile_digest` = `firmware_subject` = `7965c317…`). Rebuilding
the SAME fork (commit `eb53e5a`) with one added macro keeps SBOM/reconcile/byte-integrity/
SLSA-provenance all legitimately "our build" — we just re-derive them against the new
`OVMF_CODE.fd`. Path B (swap in the distro `OVMF_CODE_4M.secboot.fd`) gives enforcement
but is a **different build we have no source for**, which detonates the entire evidence
chain (see §4).

---

## 0. The architectural fact that drives everything

Secure Boot **posture** and the **gated image `D`** live in two separate files:

| File | Role | Digest | Consumed by |
|---|---|---|---|
| `OVMF_CODE.fd` (3 653 632 B) | the firmware code = image `D` | `sha256:7965c317…` | SBOM `metadata.component`, reconcile, byte-integrity, `deployed/reconcile/firmware_digest` |
| `OVMF_VARS.fd` (540 672 B) | UEFI variable store (the keys) | `sha256:5d2ac383…` (blank) | `secureboot-from-varstore.py` → `inputs/chipsec.json` |

Enrolling keys touches **only `OVMF_VARS.fd`** — it does NOT change `D`. So the naïve
move ("just enroll keys into the current fork VARS") produces `secureboot.variables =
PASSED` from the offline producer **while the CODE still cannot enforce**:
`OvmfPkgX64.dsc` line 252 links `AuthVariableLibNull` when `SECURE_BOOT_ENABLE=FALSE`,
which is exactly why a real QEMU boot logged `AuthVariableLibInitialize() returns
Unsupported`. That PASSED would be a **lie**. Phase 2's whole point is a CODE image that
actually consumes the enrolled keys — hence Path A.

Note: the fork's `OVMF_VARS.fd` is **byte-identical to the system blank**
`/usr/share/OVMF/OVMF_VARS_4M.fd` (both `sha256:5d2ac383…`) — the varstore template is
generic, so we can enroll into either and get the same result.

---

## 1. VALIDATED enrollment proof (NOTAPPLICABLE → PASSED)

This proves we can **manufacture a provisioned varstore offline**. Run in
`scratchpad/step1-proof/` against copies only; originals untouched.

```bash
PY=scratchpad/chipsec-venv/bin/python
VFV=scratchpad/chipsec-venv/bin/virt-fw-vars
SB=producers/chipsec/secureboot-from-varstore.py

# 1. copy the BLANK (Setup Mode) system varstore
cp /usr/share/OVMF/OVMF_VARS_4M.fd OVMF_VARS_blank.fd       # sha256 5d2ac383…

# 2. BEFORE: real producer on the blank copy
$PY $SB OVMF_VARS_blank.fd
#   secureboot.variables.result = NOTAPPLICABLE
#   detail = pk_enrolled:false pk_bytes:0 secure_boot_enable:false total_vars:0

# 3. ENROLL Microsoft PK+KEK+db and set SecureBootEnable=1
$VFV -i OVMF_VARS_blank.fd --enroll-microsoft --secure-boot -o OVMF_VARS_enrolled.fd
#   … create variable PK / KEK / db / dbx …
#   set variable SecureBootEnable: True     ← the decisive line
#   writing raw edk2 varstore to OVMF_VARS_enrolled.fd   (exit 0)

# 4. AFTER: real producer on the enrolled copy
$PY $SB OVMF_VARS_enrolled.fd
#   secureboot.variables.result = PASSED
#   detail = pk_enrolled:true pk_bytes:1575 kek_enrolled:true db_enrolled:true
#            secure_boot_enable:true total_vars:6
```

Cross-check against the vendor MS store: `secureboot-from-varstore.py
/usr/share/OVMF/OVMF_VARS_4M.ms.fd` → **PASSED** (pk_bytes:870, total_vars:30). Same
verdict, independent varstore — the producer is not keyed to our enrollment quirks.

**Result: NOTAPPLICABLE → PASSED confirmed.** Enrollment mechanism works end-to-end.
(`--secure-boot` flag is what flips `SecureBootEnable`; `--enroll-microsoft` writes PK/KEK/db.)

---

## 2. Path A — rebuild the fork with `SECURE_BOOT_ENABLE` (RECOMMENDED)

### Feasibility: GREEN. Everything needed is present.
- edk2 tree buildable at `/media/mikey/T71/firmware_artifacts/edk2`:
  `edksetup.sh` present, **BaseTools C binaries already built**
  (`BaseTools/Source/C/bin/{GenFw,GenFfs,GenFv,GenSec,LzmaCompress,…}`), `FMMT.py` present.
- Toolchain present: `gcc 13.3.0`, `nasm 2.16.01`, `iasl` present. Prior build used
  `-a X64 -t GCC -b DEBUG` → output dir `Build/OvmfX64/DEBUG_GCC/` (toolchain tag = `GCC`).
- The current build is provably WITHOUT Secure Boot: **zero** `SecureBoot*` modules in the
  SBOM build report; `OvmfPkgX64.dsc` line 32 `DEFINE SECURE_BOOT_ENABLE = FALSE`.

### What the macro actually changes (`OvmfPkg/OvmfPkgX64.dsc`)
- L245–252: `SECURE_BOOT_ENABLE==TRUE` swaps `AuthVariableLibNull` → real
  `AuthVariableLib` + `SecureBootVariableLib` — **fixes the "Unsupported" enforcement gap.**
- L1046–1047: adds `SecurityPkg/…/SecureBootConfigDxe/SecureBootConfigDxe.inf` (new module).
- L579, L888: secure-boot-gated PCDs.
- We deliberately leave `SMM_REQUIRE=FALSE` (default). `SECURE_BOOT_ENABLE` alone makes
  the platform enforce; `SMM_REQUIRE=TRUE` adds SMM-protected varstore, which QEMU can't
  fully back and which is not needed for the posture we're demonstrating.

### Exact build command (DO NOT run in a planning pass — ~5–10 min near-full rebuild)
```bash
cd /media/mikey/T71/firmware_artifacts/edk2
. edksetup.sh
build -a X64 -t GCC -p OvmfPkg/OvmfPkgX64.dsc -b DEBUG -D SECURE_BOOT_ENABLE \
      -y scratchpad/ovmf-secureboot-build-report.txt
# → new Build/OvmfX64/DEBUG_GCC/FV/{OVMF.fd,OVMF_CODE.fd,OVMF_VARS.fd,MEMFD.fd}
#   OVMF_CODE.fd now has a NEW digest D' and now ENFORCES.
```
(The `-y …report.txt` re-emits the `Report Content: SBOM` module report the SBOM pipeline
already ingests.) Changing a `-D` macro forces AutoGen to regenerate, so expect a
near-full OVMF rebuild, not a 23-second incremental — still minutes, not hours.

### Effort estimate (single session, ~30–45 min pipeline)
| Step | Time |
|---|---|
| Rebuild OVMF with the macro | 5–10 min |
| Regen `sbom.cdx.json` from new build report | few min (existing pipeline) |
| `make reconcile` carve of new `OVMF_CODE.fd` | 1–2 min |
| `make byte-integrity` (re-hash all modules) | ~6 min |
| Enroll new `OVMF_VARS.fd` + run posture producer | seconds (proven §1) |
| Reassemble `gate-input.json` + re-sign bundles | few min |

### Why A is honest
Same fork, same source commit `eb53e5a`, same builder identity — the SBOM/SLSA provenance
stays truthful; we are re-measuring OUR build after a documented config change, not
importing a foreign binary. The green `secureboot.variables=PASSED` is now backed by a
CODE image that genuinely enforces.

---

## 3. Evidence artifacts to RE-DERIVE for Path A

Because `D` → `D'` (new `OVMF_CODE.fd`) and the module set gains/changes modules, **every
image-bound artifact must be regenerated** — do not hand-edit digests:

1. **`inputs/sbom.cdx.json`** — regen from the new build's SBOM report.
   Changes: `metadata.component.hashes` (new `D'`), the `firmware:fd-image` props
   (`OVMF.fd`/`OVMF_CODE.fd`/`MEMFD.fd` digests+sizes), **+ new `SecureBootConfigDxe`
   component**, and the **variable-driver component hash changes** (real AuthVariableLib
   vs Null).
2. **`inputs/reconcile-verdict.json`** — `EDK2=/media/mikey/T71/firmware_artifacts/edk2
   make reconcile IMG=…/DEBUG_GCC/FV/OVMF_CODE.fd`. New declared/matched set including
   `SecureBootConfigDxe`; the three structural `apriori/FV structure` GUIDs remain expected
   `added`.
3. **`inputs/byte-integrity.json`** — `make byte-integrity EDK2=… IMG=…/OVMF_CODE.fd`
   (~6 min, needs pefile+FMMT). Re-hashes every module against the new SBOM.
4. **`inputs/chipsec.json`** — enroll the freshly-built `OVMF_VARS.fd`
   (`virt-fw-vars --enroll-microsoft --secure-boot`), then
   `secureboot-from-varstore.py …enrolled.fd | to-predicate.py … -o inputs/chipsec.json`.
   Now `common.secureboot.variables = PASSED`.
5. **`inputs/gate-input.json`** — reassemble: `deployed/reconcile/firmware_digest = D'`,
   `sbom.hash` updated, `chipsec.secure_boot = PASSED`.
6. **Attestation bundles** (`inputs/{sbom,byte-integrity,binary-hardening}.att.bundle`,
   `*.intoto.json`) — re-sign over the new subjects/digests.

Honest caveat for A: the enrolled `OVMF_VARS.fd` is **not** a build output — it is a
provisioning step we perform with `virt-fw-vars`. Document it as such (offline enrollment
of Microsoft keys), exactly as a factory/first-boot provisioning would. The CODE is our
build; the VARS is our provisioning.

---

## 4. Path B — reuse the distro `OVMF_CODE_4M.secboot.fd` (NOT recommended)

Idea: use `/usr/share/OVMF/OVMF_CODE_4M.secboot.fd` (already `-D SECURE_BOOT_ENABLE`, and
same size 3 653 632 B) + an enrolled/`.ms.fd` VARS as the gated image. Enforcement is real.

**Why it breaks the whole story:**
- `secboot.fd` is a **Debian/Ubuntu OVMF package build**, NOT our fork at `eb53e5a`. Its
  module set, GUIDs, and per-module hashes differ from `inputs/sbom.cdx.json`. Running
  `carve.sh`/`byte-integrity.py` against it would produce **mass missing/added + hash
  mismatch**, not a clean reconcile.
- To make the gate green we would have to **regenerate the entire SBOM for a binary we did
  not build and have no source for** → `provenance.source_repo`/`source_commit` and the
  SLSA builder identity become fiction. That is precisely the fabrication the project
  exists to prevent.
- Same *size* as our CODE is a coincidence of the 4 MB layout; the bytes and provenance are
  unrelated. It is a drop-in for **QEMU boot**, never for the **evidence chain**.

B is only defensible as a throwaway "does QEMU enforce at all" smoke test — not as the
gated green. Do not ship it as the demo image.

---

## 5. Post-Phase-2: what STAYS "verify on silicon" (unchanged)

Phase 2 makes exactly ONE hardware-adjacent check real — `common.secureboot.variables`
(config-level, read from the real varstore). The **HW-rooted CHIPSEC checks remain
`NOTAPPLICABLE` with the honest "verify on silicon" note**, because QEMU does not model the
chipset registers/MSRs they read — they must never be faked to PASS:

- `common.bios_wp` — BIOS flash write-protect (BIOS_CNTL.BLE/SMM_BWP)
- `common.smm` — SMRAM lock (D_LCK)
- `common.spi_desc` — SPI descriptor access control (no SPI controller in QEMU)
- `common.spi_lock` — SPI config lock (FLOCKDN)
- `common.smrr` — System Management Range Registers (MSRs not modelled)
- `common.bios_ts` — BIOS top-swap

(`common.uefi.access_uefispec` stays `WARNING`.) So the Phase-2 green is precisely:
"Secure Boot is provisioned and the platform is built to enforce it (config-level PASSED
from the real varstore + an enforcing CODE image); the flash/SMM/SPI hardware protections
are unmodelled by QEMU and remain to be verified on silicon." That framing is the whole
point — a real green that is still honest about its emulated boundary.

---

## 6. Execution checklist (Path A)
- [ ] `build … -D SECURE_BOOT_ENABLE -y scratchpad/ovmf-secureboot-build-report.txt`
- [ ] Confirm new FV has `SecureBootConfigDxe` + real `AuthVariableLib`; capture new `D'`
- [ ] Regen `inputs/sbom.cdx.json` from the new report
- [ ] `make reconcile IMG=…/OVMF_CODE.fd` → `reconcile-verdict.json`
- [ ] `make byte-integrity IMG=…/OVMF_CODE.fd` → `byte-integrity.json`
- [ ] Enroll new `OVMF_VARS.fd`; `secureboot-from-varstore.py | to-predicate.py` → `chipsec.json` (PASSED)
- [ ] Reassemble `gate-input.json` (D', sbom hash, secure_boot=PASSED); re-sign bundles
- [ ] `make gate FIXTURE=inputs/gate-input.json` → **ALLOW (real green)**
- [ ] (Optional) real QEMU boot with new CODE+enrolled VARS to confirm no "Unsupported"
