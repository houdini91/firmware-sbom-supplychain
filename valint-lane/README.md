# Valint lane

The same firmware evidence as the OSS lane, verified with [Valint] — signing plus **compliance policies
per framework**, resolved from the `scribe-public/sample-policies` bundle that `valint verify` auto-clones.

## Why a second lane
The OSS lane (cosign + OPA) proves the pipeline is reproducible with community-standard tools. This lane
shows the same outcome in Valint, whose value here is a **compliance hierarchy**: named rules and
whole-framework *initiatives* (SLSA, SSDF, SP-800-53, SP-800-190) you point at your evidence, instead of
hand-writing rego per control.

## Run
```bash
./run.sh                 # keyless signing (needs network to sigstore) + verify
VALINT_X509=1 ./run.sh   # offline: sign with a local x509 key instead of keyless
```

Steps:
1. `valint bom` — attest the firmware SBOM as signed evidence.
2. `valint slsa` — attest SLSA provenance evidence.
3. `valint verify … --rule policies/firmware-composition.yaml` — the custom gate (mirrors the OSS `firmware.deploy`).
4. `valint verify … --initiative-name slsa.l2` — a whole compliance-framework run.

## Compliance policies here
- `policies/firmware-composition.yaml` — SBOM present & signed (`sbom/require-sbom`), NTIA/TR-03183 minimum
  elements (`sbom/NTIA-compliance`), SLSA L2 authenticated provenance (`slsa/l2-provenance-authenticated`),
  no critical CVE (`sarif/trivy/verify-cve-severity`).
- Framework initiatives come from the bundle: `slsa.l1`, `slsa.l2`, `ssdf`, `sp-800-53`, `sp-800-190`.

See `../oss-lane/compliance-map.md` for the control → rule mapping across both lanes.

## Status — honest
The rule/initiative references are real (verified: `valint verify` auto-clones the bundle and resolves
them). **Local signing** needs either network keyless or the `VALINT_X509=1` offline path; the environment
this was built in had neither sigstore reachability nor a preconfigured signer, so the live *signed* run is
wired into CI (`../.github/workflows/supply-chain.yml`), where keyless OIDC works — the same place the OSS
lane signs keyless. The policy files and commands here are the copy-me artifacts.

[Valint]: https://github.com/scribe-public
