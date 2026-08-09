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
   SP 800-193 **Detection (§4.3)** and RATS **§8.1 Evidence** remain FUTURISTIC (see `../FRAMEWORKS.md`).

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
