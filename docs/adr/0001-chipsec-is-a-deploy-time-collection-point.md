# ADR 0001 — CHIPSEC is a deploy-time collection point, not an admission-time file check

*Status: accepted · Supersedes the "sample CHIPSEC posture" approach.*

## Context

This gate is an **admission-time** control: it decides whether a firmware **artifact at rest**
(a `.fd` file + its SBOM/attestations) may ship, by re-deriving facts from those bytes. Its
strengths — byte-integrity re-hash, reconcile, SBOM/provenance binding — are all *artifact-at-rest*
checks a file can answer.

CHIPSEC is a different kind of tool. Its modules split into two categories:

| CHIPSEC module | Question it answers | Where the answer physically lives | Answerable from a `.fd` file? |
|---|---|---|---|
| `common.secureboot.variables` | Are PK/KEK/db enrolled and is Secure Boot enabled? | **In the firmware image** (the UEFI variable store) — *configuration at rest* | **Yes** |
| `common.bios_wp` | Is the SPI flash write-lock latched right now? | A live **chipset register** (`BIOS_CNTL.BLE`, `SMM_BWP`) | No |
| `common.smm` | Is SMRAM locked (`D_LCK`) right now? | A live hardware register | No |
| `common.spi_lock` / `common.spi_desc` | Is the SPI controller locked down (`FLOCKDN`) / descriptor access restricted? | Live SPI-controller registers | No |
| `common.smrr` | Are the SMM range registers set? | Live **CPU MSRs** | No |
| `common.bios_ts` | Is BIOS top-swap disabled? | A live chipset register | No |

**Only `secureboot.variables` is configuration data stored *in the image*.** The other six read the
**live silicon's register state** — "is this booted machine locked down at this instant." That state
does not exist inside a firmware file, and QEMU does not model those registers. They can only be
answered by running CHIPSEC on the **real (or register-accurate) hardware at deploy/run time.**

Earlier the repo carried a hand-authored `sample-results.json` that asserted `secureboot=PASSED` and
`bios_wp/smm=PASSED` for the OVMF/QEMU target. A real QEMU boot of the demo OVMF disproved it: the
plain `DEBUG_GCC` build is compiled without `SECURE_BOOT_ENABLE` (`AuthVariableLibInitialize()
returns Unsupported`), so Secure Boot is **not provisioned**. A placeholder was simply wrong.

## Decision

Split CHIPSEC evidence by its true collection point.

1. **`secureboot.variables` is an admission-time, file-derived check — and it is REAL.**
   `producers/chipsec/secureboot-from-varstore.py` reads the actual OVMF variable store (PK / KEK /
   db / `SecureBootEnable` — the same variables CHIPSEC inspects) with `python-virt-firmware`. It is
   PASSED only when a platform key is enrolled **and** Secure Boot is enabled; a no-PK image is
   `NOTAPPLICABLE` (Setup Mode). This is a genuine, measured "was the image *shipped* provisioned?"
   check — a `verified` grade, gated on the same image the rest of the evidence describes. (Caveat:
   it attests the *as-shipped* varstore, not a guarantee of runtime enforcement, which also depends
   on the CODE build supporting authenticated variables — see the boot-log check.)

2. **The six hardware-rooted checks are a deploy-time platform-attestation slot — not something this
   file gate performs.** The gate *declares the requirement* and will *ingest a signed CHIPSEC report
   that the operator runs on the real target platform*, gating on it **only when such evidence is
   present**. Absent a live scan, these controls are **advisory** — reported honestly as
   MISSING/NOTAPPLICABLE, **never a passing sample**. This is a **collection-point mismatch, not a
   compliance gap**: the answer is collected on the running platform, and reporting "not substantiated
   here" is the correct, honest result.

## Consequences

- The gate emits the CHIPSEC posture reports **conditionally** (like SP 800-193 §4.3.1): present +
  gating only when the target substantiates them, absent + advisory otherwise. On the demo OVMF all
  are absent, so the NIST SP 800-147 / 147B and SP 800-193 §4.2/§4.2.3 controls are advisory-MISSING.
- A **provisioned** platform makes `secureboot.variables` a real green (see the Secure-Boot OVMF
  profile / Phase 2). The hardware-rooted checks remain **"verify on silicon"** even then — QEMU
  cannot model their registers; only a real deployment's operator scan can fill that slot.
- A consumer of the VSA reads an honest picture: what the admission gate proved from the artifact,
  and what remains for the deployed platform to attest. No control claims more than its evidence.
- **CHIPSEC is also a deploy-time byte-*source*, not only a posture source (Track A, extending this
  ADR).** The same "collect it where the answer physically lives" split gives CHIPSEC a second job:
  its `uefi decode` writes each module's PE bytes to disk, so at deploy time we run those bytes through
  OUR normalizer and reconcile them — GUID-bound, bidirectional — against the same signed, build-born
  SBOM (`producers/chipsec/deploy-reconcile.py` → the conditional `deploy-time-reconcile` verifier
  report, SP 800-193 §4.3.1). This is the deploy-time/on-device twin of the admission-time byte-integrity
  check: it extends the SBOM baseline from "at rest" (the admitted `.fd`) to "on silicon" (what is
  actually flashed), catching post-admission / flash-time drift. It follows the **same conditional +
  advisory-when-absent** discipline as the posture reports above: **absent** on the demo (no device →
  §4.3.1 advisory-MISSING, `allow` unaffected), **gating when present** (a confirmed on-device MISMATCH /
  MISSING / UNEXPECTED module DENYs). It stays deploy-time, not runtime: it needs a device or image and
  is CHIPSEC reading flash — not the boot-time Root of Trust for Detection. Live-silicon SPI readback is
  roadmap A6.

## Alternatives considered

- **Drop the six hardware checks from the control map entirely** (out of admission scope). Defensible
  and leaner; rejected in favor of keeping them as an explicit, advisory deploy-time slot so the gate
  documents the full platform-security requirement and offers a real integration point rather than
  silently omitting it.
- **Keep the sample "posture."** Rejected — a placeholder that can be (and was) factually wrong is
  exactly the dishonesty this project exists to eliminate.
