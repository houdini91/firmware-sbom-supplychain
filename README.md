# firmware-sbom-supplychain

A working demo of a **firmware supply-chain verification gate** for a fleet operator, on the OVMF / edk2
reference target. It takes a build-time SBOM through the full pipeline and refuses to "deploy" anything that
fails policy — shown **two ways over the same evidence**:

- an **OSS lane** — `cosign` + Open Policy Agent (reproducible today with community-standard tools), and
- a **Valint lane** — signing + compliance policy with [Valint], the supply-chain evidence/policy tool.

Same firmware, same signed evidence, same pass/fail outcome — verified by both, so it's provably not
tool-locked.

## The pipeline

```
generate → verify(sig+provenance) → reconcile(bytes==SBOM) → CVE map → attest → OPA/compliance gate → deploy
```

Stages 1–3 (generate the CycloneDX SBOM from the edk2 build, reconcile it against the actual firmware bytes)
come from the companion `edk2-sbom` tooling. **This repo is stages 4–6: attest, and gate.**

## The tools, in one line each

- **SBOM** (Software Bill of Materials) — the ingredient list of the firmware: every module, library, and
  third-party component, in [CycloneDX](https://cyclonedx.org) JSON.
- **[cosign](https://github.com/sigstore/cosign)** — sigstore's signing tool. It cryptographically signs
  the SBOM (and an attestation about it) and later verifies that signature. "Keyless" mode signs with a
  short-lived certificate tied to the CI job's identity (no long-lived private key).
- **[OPA](https://www.openpolicyagent.org)** (Open Policy Agent) — a policy engine. You hand it facts
  (JSON) and a policy written in *Rego*; it answers allow/deny. It does the *deciding*, not the gathering.
- **[Valint](https://github.com/scribe-public)** — a supply-chain evidence + policy tool (author: this
  project's author). It both *signs* evidence (like cosign) and *verifies compliance policies* against it,
  resolving named rules and whole-framework "initiatives" (SLSA, SSDF, SP-800-53) from a policy bundle.
- **[grype](https://github.com/anchore/grype)** — scans the SBOM's components for known CVEs.
- **reconcile** — this project's own check: carve the actual firmware binary and confirm it contains
  exactly what the SBOM claims (verify, don't trust).

The two lanes below do the *same* job — sign the evidence, then gate on policy — one with cosign+OPA, one
with Valint, so the outcome is provably not tied to a single tool.

## Two lanes, side by side

| Step | `oss-lane/` | `valint-lane/` |
|---|---|---|
| **Sign evidence** | `cosign attest` (in-toto/DSSE) | `valint` signed evidence |
| **Verify signature** | `cosign verify-attestation` | `valint verify` (pulls the cosign/in-toto envelope) |
| **Policy / compliance** | `opa eval` over `policy/*.rego` | `valint verify` → YAML policy → sample-policy rego hierarchy |

Locally both sign with a key so the demo runs offline; the reference GitHub Actions workflow swaps that for
**keyless OIDC** (`cosign` / `attest-build-provenance` via Fulcio/Rekor) produced inside an isolated builder.

## Compliance frameworks

The gate is the "compliance framework" engine. This repo ships one worked example end-to-end (SLSA
provenance + a custom firmware-composition policy) and a mapping showing how additional frameworks express
as policy rules:

- **SLSA** — build provenance meets L2+ (builder identity, source, signed).
- **Custom firmware composition** — SBOM present ∧ signature verified ∧ reconcile clean ∧ no critical CVE ∧
  provenance bound to the trusted builder.
- **NIST SSDF (SP 800-218)** and **BSI TR-03183** — control→rule mapping in `oss-lane/compliance-map.md`.

## Honesty tests

`tests/` proves the gate actually blocks — not just passes a clean input:

- a **tampered SBOM** (fails reconcile),
- a **wrong builder identity** (fails provenance),
- an **injected critical CVE** (fails the CVE clause).

## Status

Both lanes run **keyless on CI** (`.github/workflows/supply-chain.yml`, green): cosign and Valint each
sign the firmware SBOM with the GitHub workload OIDC identity, then verify + gate. Locally, the OSS lane
runs end-to-end over real OVMF data (324-component SBOM, reconcile clean 123/123 → gate ALLOW; honesty
tests block tampered / wrong-builder / critical-CVE). Reference/demo, defensive use only. Not affiliated
with or endorsed by TianoCore.

[Valint]: https://github.com/scribe-public
