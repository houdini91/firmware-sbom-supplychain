# Security policy

This is a **research / portfolio demo** of a firmware supply-chain verification gate — not a product with
production deployments. There is no supported release to patch. That said, the whole point of the project is
supply-chain integrity, so security reports are very welcome and taken seriously.

## Reporting a vulnerability

- **Preferred:** open a [GitHub private security advisory](https://github.com/houdini91/uefi-supply-chain/security/advisories/new)
  (Security → Report a vulnerability). This keeps the report private until a fix is ready.
- Please include: what's affected (file/function), how to reproduce, and the impact (e.g. "the gate can be made
  to ALLOW a tampered image because …").

Please **do not** open a public issue for a vulnerability that could let the gate pass tampered firmware.

## Scope

In scope — anything that lets the deploy gate reach a **false ALLOW** (approve firmware that should be
blocked), or a producer emit evidence that misrepresents the shipped bytes. Examples: a same-GUID module swap
the byte-integrity check misses; a canonicalization that masks a real change; a way to make a failing check
report as passed or skipped.

Out of scope — the offline-demo `DEV_ASSUME_*` opt-ins (they are loudly warned, CI-unreachable local
conveniences, documented as such); missing runtime/measured-boot attestation (a documented future class of
evidence, not a bug); anything already listed as an honest limitation in `FRAMEWORKS.md` / `DESIGN.md`.

### What this gate does not defend against

The byte-integrity check closes the gap between a re-signed, same-GUID module swap and the born-in-build
SBOM's declared per-module hash. It does **not** defend against a build step that is *itself* compromised and
produces both the trojaned bytes and the SBOM that describes them — that hash would match, because the same
compromised build authored both sides. Catching that is the **SLSA build-provenance** layer's job (the inputs
are build outputs, not hand-edited artifacts); see the pre-signing attacker note under **Trust model & known
ceilings** below.

## Trust model & known ceilings

The signed evidence graph proves **"CI signed these bytes, and they are internally consistent with the
firmware anchor D"** — it does *not*, on its own, prove the bytes are a true measurement of real firmware.
Stated plainly so no reader over-trusts a green gate:

- **Pre-signing vs. post-signing attacker.** The byte-integrity keystone (and every other verdict:
  reconcile / SBOM / VEX / CHIPSEC) is generated from committed `inputs/` and then D-anchored + signed by CI.
  This defeats a **post-signing / in-transit / offline-re-run** attacker who rewrites `inputs/*.json` after
  the fact (the loose file is ignored — the gate reads the signed, D-anchored bundle; see the forge tests in
  `tests/pipeline-negative.sh`). It does **not** defeat an attacker who writes `inputs/` *before* the CI
  signing step — CI would D-anchor and sign the forgery. That pre-signing surface is the SLSA build-provenance
  layer's concern (the inputs are build outputs, not hand-edited artifacts), and is a **shared ceiling of the
  entire evidence graph**, not specific to byte-integrity.
- **The anchor D is self-asserted until a real image is measured.** `anchor_d` is the SBOM's own
  `metadata.component` SHA-256. Under `DEV_ASSUME_FWIMAGE` (CI + demo), D is never checked against real
  firmware bytes, so the firmware-D binding is **consistency, not ground truth** — an actor who controls the
  SBOM sets D everywhere consistently. Only a real deploy-time measurement (`FW_IMAGE=<the .fd>`, which fires
  the §4.3.1 `firmware-freshly-measured` report and pins `deployed == sbom == reconcile`) turns the binding
  into ground truth. This is the documented SP 800-193 §4.3.1 ceiling.
- **Signed-evidence enforcement is fail-closed in the real pipelines.** `run.sh` and CI set
  `REQUIRE_SIGNED_EVIDENCE=1`, so a missing/empty `*_BUNDLE` env **aborts** rather than silently falling back
  to an unsigned loose verdict (regression-tested: `require-signed-missing-bundle-ABORTS`). Ad-hoc local runs
  without that flag still *work* but **loudly warn** on every loose fallback — the downgrade is never silent.
- **Local `make demo` gives structural assurance only.** The pinned local `bin/cosign` is 2.5.2, which lacks
  `attest-blob --statement`, so `run.sh` synthesizes an **unsigned** but correctly D-anchored bundle: it
  exercises the signed-consumption path and proves the D-binding, but provides **no cryptographic assurance**
  locally. The real keyless signature **and** its `cosign verify-blob-attestation` gate run in **CI**
  (cosign 2.6.0). Treat a green local demo as a wiring check, not a trust anchor.

## Disclosure

Because there is no deployed release, there is no embargo requirement — but I'll acknowledge a report promptly
and credit reporters (unless you prefer otherwise) in the fix commit.
