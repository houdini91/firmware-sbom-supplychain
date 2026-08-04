> **DRAFT — pending review, not yet posted upstream.** Nothing here has been sent to the list or the tracker.

---

Hi — thanks for filing this (@vincent-j-zimmer). I'm an engineer working on firmware reverse-engineering and
software supply-chain, and I put together the build-time SBOM generator this issue asks for. Rather than another
design write-up, here's working code and two concrete questions.

**Two questions for the maintainers:**

1. Is a `-Y SBOM` report type in `BuildReport.py` the right home for this, or would you prefer a standalone
   script under `BaseTools`?
2. CycloneDX as the canonical format with conversion for SPDX consumers, or should the generator emit SPDX
   natively too?

## What it is

A new `-Y SBOM` build report type that emits a **CycloneDX 1.6** SBOM by reusing the AutoGen data already
gathered for `-Y COMPILE_INFO` — so it adds **no new build dependency** (CycloneDX is plain JSON). #6455 proposed a
*static* CycloneDX SBOM template but was closed without merging; this generates the SBOM from a real build
instead.

A full OvmfPkgX64 (DEBUG/GCC) build yields a CycloneDX SBOM of **311 components** (one per built module and
resolved library instance, plus the CycloneDX document-root component), with:

- a module → library **dependency graph** (`dependsOn`);
- **per-module SHA-256 + SHA-512 digests** over the GenFw *rebase-0* canonical form (each module's PE image
  normalized to load base 0), for the 122 of 123 non-library modules that carry a PE (ResetVector has none);
- edk2 **module-type / arch / `.inf`** metadata per component;
- the vendored dependency actually **linked into this image — openssl** — emitted as a real third-party
  component (`pkg:github/openssl/openssl@openssl-3.5.7`, with SPDX license + CPE); edk2 FFS modules keep an
  honest `N/A` where no sensible PURL exists.

Working branch (personal fork — happy to send to `devel@edk2.groups.io` via `git send-email` if there's
interest): https://github.com/houdini91/edk2/pull/6 — the `-Y SBOM` generator (plus a drafted `-Y SPDX` report
type in reserve). The PR description walks through the design; happy to attach a sample generated SBOM if
that's useful for review.

## Consumable on-device (uSWID / coSWID)

The CycloneDX output round-trips through uSWID → coSWID — the compact SWID tag fwupd can embed and read
on-device (`uswid --load sbom.cdx.json --save sbom.uswid` and back preserves the components). A fix so uSWID
imports a real firmware SBOM without choking on CycloneDX `device-driver` types recently landed upstream
(`hughsie/python-uswid#98`), so what this generates is usable by that on-device path today, not only as a
build artifact.

## On format (CycloneDX vs SPDX)

I emit CycloneDX 1.6 as the canonical format. For SPDX consumers, I'd convert downstream with protobom
(a Go tool, entirely outside the build) rather than add a second emitter to BaseTools — disclosure: I formerly
helped maintain protobom, so that's a firsthand recommendation, not a plug. If you'd rather edk2 emit SPDX
natively, I have a `-Y SPDX` report type drafted in reserve (same generator, still dependency-free). I've
deliberately kept this to one format so the proposal stays small.

## What is *not* proposed here

Being upfront so this doesn't read as bigger than it is: the **verification side** — reconstructing an SBOM
from the shipped binary, reconciling declared-vs-observed, signing, a policy gate, measured boot — is
deliberately **operator-side and NOT proposed for edk2**. edk2 ships source, not signed firmware, so that
machinery living here would be dead infrastructure; it belongs to whoever builds and consumes the image.

So the only upstream ask is the generator (optionally plus native SPDX later). Thanks for reading.
