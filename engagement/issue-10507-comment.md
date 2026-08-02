> **DRAFT — pending review, not yet posted upstream.** This is a working draft of a comment for tianocore/edk2 issue #10507. Nothing here has been sent to the list or posted to the tracker.

---

Hi — this issue (#10507) has been open and unassigned for a while, and #6455 seeded a *static* CycloneDX template across a number of upstreams (edk2 included) that then auto-closed. That template gestured at a generator, but as far as I can tell nobody built the thing that actually produces an SBOM from a real build. This comment proposes that generator, with a working branch to look at rather than just a design.

## What it is

A new `-Y SBOM` build report type in `BaseTools/Source/Python/build/BuildReport.py` that emits a **CycloneDX 1.6** SBOM by reusing the AutoGen data already collected for `-Y COMPILE_INFO`. Because CycloneDX is plain JSON, this adds **no new build-system dependency** — it's a post-build consumer of data the build already has.

There's a working branch and a committed example to review: a full **OvmfPkgX64 (DEBUG/GCC) build produces a 310-component SBOM**, checked in for direct inspection. Link: https://github.com/houdini91/edk2/pull/2 — it's a personal fork branch for now; happy to send it to `devel@edk2.groups.io` via the normal `git send-email` process if there's interest in the shape.

Per component, the generator emits:

- `FILE_GUID` as the `bom-ref`
- a CycloneDX component `type` derived from the module (`firmware` for SEC/PEI/DXE/SMM cores, `application`, `library`, `device-driver`)
- `edk2:moduleType` / `edk2:arch` / `edk2:isLibrary` properties
- a workspace-relative `externalReference` to the module `.inf`
- a module → library `dependsOn` dependency graph (122 edges in the OVMF example)

It also records **SHA-256 / SHA-512 hashes** of each built module, rebased to base 0 via GenFw (the same canonicalization `-Y HASH` uses, so relocated/rebased images hash consistently). Library instances are `.lib` with no standalone artifact, so they carry no hash. Plus metadata: `lifecycle = build`, author, and tool name + version.

Those metadata and hash fields line the output up with the mandatory SBOM fields in **CISA's 2026 minimum elements** and **BSI TR-03183-2**, which is part of why they're there.

## CycloneDX vs SPDX

I know the thread cares about format, so to be clear about the stance: **CycloneDX is the canonical emit** (ECMA-424, JSON, no dependency), and SPDX can be had two ways. I'm proposing only the first upstream for now:

1. **Downstream conversion (what I'm proposing).** CycloneDX converts cleanly to SPDX via OpenSSF **protobom**; I've run an SPDX-2.3 conversion and the per-component hashes survive. This keeps BaseTools to a single format. To be explicit: **protobom is a Go tool and is NOT proposed for BaseTools** — it's how a *consumer* converts, entirely outside the build.

2. **Native `-Y SPDX` (drafted, held in reserve).** If the group would rather the generator emit SPDX directly, that's a small, dependency-free addition (SPDX is also just JSON). I've already prototyped it as a `-Y SPDX` report type — a full OvmfPkgX64 build emits a valid SPDX 2.3 document (310 packages, SHA-256/512 checksums). It's kept on a separate branch (reference: https://github.com/houdini91/edk2/pull/5) and intentionally **not** bundled into this proposal, to avoid format proliferation in one PR; I'm happy to finish and send it if native emission is preferred over downstream conversion.

So: canonical CycloneDX now, SPDX by conversion by default, and native SPDX ready if you want it — your call on which fits edk2 best.

## What is *not* being proposed here

Being upfront about scope so this doesn't read as bigger than it is:

- **Third-party submodule components** (openssl, brotli, etc. with `purl` / version / license) are a natural next increment but are **not emitted yet**.
- The whole **verification side** — reconstructing an SBOM from the shipped binary, reconciling declared-vs-observed, signing, an OPA policy gate, measured-boot / RIM — is deliberately **operator-side and NOT proposed for edk2**. edk2 ships source, not signed firmware, so a signing/gate workflow living here would be dead infrastructure. That work belongs to whoever builds and consumes the firmware.

So the only upstream ask is the generator (optionally plus native SPDX later).

## Two questions back to you

1. Is a `-Y SBOM` report type inside `BuildReport.py` the right home for this, or would you prefer a standalone script under `BaseTools`?
2. CycloneDX as the canonical format with conversion for SPDX consumers, or should the generator emit SPDX natively as well?

Happy to take this to the list in whatever form fits your process. Thanks for reading.
