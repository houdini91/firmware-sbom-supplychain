# CHIPSEC lane — platform-security posture evidence (R3)

CHIPSEC assesses the **platform-firmware protections** of a running target: BIOS write-protection, SPI
flash descriptor locks, Secure Boot configuration, SMM/SMRR. Its per-module PASS/FAIL results are signed
evidence that maps to the firmware-resiliency frameworks the SBOM/provenance evidence cannot touch:

| CHIPSEC module | Checks | Framework control |
|---|---|---|
| `common.bios_wp` | BIOS region write-protection (BIOSWE/BLE/SMM_BWP, PRx) | SP 800-193 §4.2.1 (authenticated update), SP 800-147/147B |
| `common.spi_desc` | SPI flash descriptor read/write protection | SP 800-193 §4.2.2 (protect immutable code) |
| `common.spi_lock` | SPI controller configuration lock (FLOCKDN) | SP 800-193 §4.2.2 |
| `common.secureboot.variables` | Secure Boot enabled + keys provisioned | SP 800-147B, UEFI Secure Boot |
| `common.smm` / `common.smrr` | SMRAM lock / SMRR range protection | SP 800-193 §4.2.3 (runtime protection) |
| `common.bios_ts` | BIOS top-swap protection | SP 800-193 §4.2.1 |

## Honest scope — read first

This is **platform-configuration assessment against the OVMF/QEMU target**, *not* physical silicon and *not*
runtime measured boot. Two consequences, stated up front so the evidence never overclaims:

1. **Many hardware-root checks are `NOTAPPLICABLE` on QEMU** (no real SPI flash controller, no physical
   SMRR). The gate treats `NOTAPPLICABLE` as *not a failure* — it only requires the **applicable** critical
   modules to PASS. On real hardware the same runbook exercises the HW checks for real.
2. CHIPSEC proves *protections are configured*; it does **not** produce a TPM quote or a golden RIM, so
   SP 800-193 **runtime** Detection (the on-device boot-time RTD: measured-boot measurement + golden RIM)
   and RATS **§8.1 Evidence** remain FUTURISTIC (see `../FRAMEWORKS.md`). The **admission-time** §4.3.1 leg
   is covered (advisory) by `firmware-freshly-measured` + byte-integrity; the **deploy-time / on-device**
   §4.3.1 leg **is now covered by CHIPSEC** — the Track A [`deploy-reconcile.py`](deploy-reconcile.py)
   producer below reconciles CHIPSEC-extracted per-module bytes against the signed build-born SBOM
   (advisory-when-absent, gating-when-present). What stays FUTURISTIC is the on-device boot-time RTD.

## Run it (you drive this)

CHIPSEC needs privileged access to the target. Two paths:

**A — against the OVMF firmware image (offline, config-level):**
```bash
# Secure Boot / UEFI variable + BIOS-config modules that work from the image/NVRAM.
sudo python chipsec_main.py -m common.secureboot.variables -m common.bios_wp \
     --json chipsec.raw.json
```

**B — against a live QEMU/OVMF boot** (boot OVMF in QEMU with the chipsec EFI/Linux target, run the module
set). See the CHIPSEC docs for the QEMU/OVMF harness; export results with `--json`.

Then convert + (in CI) sign:
```bash
python producers/chipsec/to-predicate.py chipsec.raw.json -o inputs/chipsec.json
# CI keyless-signs inputs/chipsec.json like the other evidence, and the gate reads
# inputs/chipsec.json -> input.chipsec.{critical_passed, results} (see the chipsec-posture rego rule).
```

`to-predicate.py` accepts CHIPSEC's `--json` output (module → {result}) **or** a normalized
`{module: "PASSED|FAILED|NOTAPPLICABLE|WARNING"}` map, and emits an in-toto-style predicate plus the
gate fact `critical_passed` (all applicable critical modules PASSED).

**Real evidence source.** The committed `inputs/chipsec.json` is produced by
[`secureboot-from-varstore.py`](secureboot-from-varstore.py), which reads the actual OVMF variable
store (PK/KEK/db/SecureBootEnable — the same variables CHIPSEC's `common.secureboot.variables`
inspects) with `python-virt-firmware`, and emits the HW-rooted checks as `NOTAPPLICABLE` (no QEMU
register backing). On the plain demo OVMF that is `secureboot.variables = NOTAPPLICABLE` (Secure Boot
not provisioned) — a real, measured result, not a guess. `sample-results.json` is a **format example
only** (illustrative values documenting the `to-predicate.py` ingest shape); it is **not** evidence
and must not be used as such.

## Critical module set (gated)
`common.bios_wp`, `common.spi_desc`, `common.spi_lock`, `common.secureboot.variables`, `common.smm`,
`common.smrr`, `common.bios_ts`. A `FAILED` on any **applicable** one blocks; `NOTAPPLICABLE` does not.

---

# Deploy-time reconcile (Track A) — `deploy-reconcile.py`

CHIPSEC is not only a *posture* source; it is also a **deploy-time byte source**. `chipsec_util uefi decode`
writes every module's PE/TE bytes to disk, so at deploy time we run those bytes through **our** normalizer
and reconcile them — GUID-bound, bidirectional — against the **same signed, build-born SBOM** that
byte-integrity uses at admission. CHIPSEC is a **second, independent carver** (the admission path carves
with edk2 FMMT); cross-carver agreement is itself a robustness result. This extends the SBOM baseline from
"at rest" (the admitted `.fd`) to "on silicon" (what is actually flashed), catching post-admission /
flash-time drift the at-rest gate cannot see. Collection-point rationale: [ADR 0001](../../docs/adr/0001-chipsec-is-a-deploy-time-collection-point.md);
design: [DESIGN.md → Deploy-time reconcile](../../DESIGN.md); mapping: [FRAMEWORKS.md §4.3.1](../../FRAMEWORKS.md);
task map: [planning/CHIPSEC-INTEGRATION.md](../../planning/CHIPSEC-INTEGRATION.md).

**Novelty is honest:** the carve-and-hash *primitive* is prior-arted by CHIPSEC's `tools.uefi.scan_image`
(credit it). What is new here is the *composition* — driving the reconcile from a build-born SBOM, GUID-bound
and bidirectional, folded into a signed admission gate.

## Run the deploy-time reconcile

You need a firmware image (or a live SPI dump) and CHIPSEC installed. Two equivalent paths:

**A — one step (the Makefile target self-decodes via CHIPSEC):**
```bash
make deploy-reconcile IMG=<image.fd> SBOM=inputs/sbom.cdx.json
# -> writes inputs/deploy-reconcile.json ; exit 0 iff the reconcile is clean
```

**B — decode first, then reconcile a pre-decoded tree** (what the target does under the hood):
```bash
chipsec_util uefi decode <image.fd>                 # -> <image.fd>.dir + <image.fd>.UEFI.json
python producers/chipsec/deploy-reconcile.py \
    --sbom inputs/sbom.cdx.json \
    --decode-dir <image.fd>.dir \
    -o inputs/deploy-reconcile.json
# make deploy-reconcile DECODE_DIR=<image.fd>.dir SBOM=inputs/sbom.cdx.json  does the same
```

Collection reads CHIPSEC's authoritative `<img>.UEFI.json` (per-node `FILE_GUID` + FFS type, robust to
compressed / GUID-defined / nested-FV nesting); a module is found by its `MZ` (PE32) / `VZ` (TE) **magic**,
never by file extension.

### CHIPSEC-compatible `efilist.json` interop (A7)

From the **same** extracted module set the producer can emit a CHIPSEC-`scan_image`-compatible efilist so
our tool and CHIPSEC's `scan_image` cross-check each other:

```bash
python producers/chipsec/deploy-reconcile.py --sbom inputs/sbom.cdx.json --decode-dir <img>.dir \
    --emit-efilist efilist.json               # byte-schema-identical to scan_image's own output
    # --emit-efilist-annotated efilist.ann.json   # adds a NON-STANDARD sha256_norm field (see below)
# cross-check: chipsec_main -i -n -m tools.uefi.scan_image -a check,efilist.json,<image.fd>
```

- `--emit-efilist` is keyed by the module's **as-found** sha256 (== CHIPSEC's `EFI_MODULE.SHA256`), value
  `{sha1, guid, name, type}` in scan_image's exact field order — so `chipsec_main … scan_image -a check`
  consumes it unchanged.
- `--emit-efilist-annotated` adds a **non-standard, additive** `sha256_norm` value field. `sha256_norm` is
  the **rebase-0 (base-0) normalized hash — the SBOM-declared per-module hash**; it is **null** for a TE /
  non-PE module (nothing to un-rebase) and when pefile is unavailable, never faked. CHIPSEC's `check` keys
  on the sha256 and **ignores** `sha256_norm`, so the annotated file stays `check`-consumable. It is a
  concrete demonstration of the [Track B upstream proposal](../../planning/UPSTREAM-CHIPSEC-DRAFT.md) —
  a **proposal in discussion**, not a merged CHIPSEC feature. These emits are producer **outputs**; no gate
  control or count depends on them.

## How the verdict folds into the gate

Set `DEPLOY_RECONCILE_JSON=inputs/deploy-reconcile.json` (or, signed, `DEPLOY_RECONCILE_BUNDLE=<bundle>`)
when assembling the gate input. The leg is **conditional**: absent on the offline/CI demo (no device), so
SP 800-193 §4.3.1 stays advisory-MISSING **without** flipping `allow`. When present it emits + **gates**:

- **Coverage floor.** To be clean, `matched == declared` and `declared == sbom.integrity.hashed` — the
  verdict must cover **every** declared hashable module (parity with byte-integrity's `checked == hashed`).
  A 1-of-N reconcile does **not** pass.
- **Unverifiable ⇒ DENY, not a benign skip.** A declared module that returns a TE / non-PE section, is
  unextractable, or errors is **unverifiable drift** (a same-GUID PE→TE swap looks exactly like this). It
  **FAILS the gate and is named** unless it is a **reviewed exemption** in `data.deploy_reconcile_exempt`
  (default **empty**). A `MISMATCH` / `MISSING` / `UNEXPECTED` module is never exemptable.
- **D-anchored, signed-when-required.** A **present** loose `DEPLOY_RECONCILE_JSON` must self-anchor —
  its `image_digest` MUST equal the firmware anchor `D`, else it fails closed to advisory-absent (never a
  pass). Under `REQUIRE_SIGNED_EVIDENCE=1`, a present loose verdict with **no** `DEPLOY_RECONCILE_BUNDLE`
  **aborts** (the deploy-reconcile forge is closed, mirroring byte-integrity). A signed bundle must carry a
  `firmware-image` subject == `D`, or it fails closed.

The signed predicate uses the stable-namespace `predicateType`
`https://firmware-sbom-supplychain/deploy-reconcile/v1` — deliberately frozen across the repo rename to
`uefi-supply-chain` (a stable identifier baked into signed evidence; see [DESIGN.md](../../DESIGN.md)).
