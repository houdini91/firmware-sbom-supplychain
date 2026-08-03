# `producers/` — evidence producers

The tools that **produce** signed evidence artifacts into [`../inputs/`](../inputs). They are distinct from
the **verification lanes** (`oss-lane/`, `valint-lane/`) that *consume* that evidence and render a verdict.

| Dir | Produces | Consumed by |
|---|---|---|
| [`reconcile/`](reconcile) | the declared-vs-observed verdict — carve the real image with edk2 FMMT, compare to the SBOM by GUID, and record the image digest (`sbom-reconcile.py`, `carve.sh`) | `reconcile` + `firmware-digest-anchor` gate reports |
| [`interop/`](interop) | format conversions of the SBOM/VEX — CycloneDX→SPDX, CycloneDX→coSWID(+embed), OpenVEX→CSAF (`to-spdx.sh`, `to-coswid.sh`, `to-csaf.py`) | downstream toolchains; BSI CSAF evidence |
| [`chipsec/`](chipsec) | the platform-firmware posture predicate — normalize a CHIPSEC run into `critical_passed` (`to-predicate.py`) | `chipsec-posture` gate report |

Each script derives repo paths from its own location, so run them from anywhere (or via the `Makefile`).
