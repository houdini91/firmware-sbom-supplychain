# `oss-lane/` — the enforcing gate (OSS, fully open)

The hard gate: it turns verified evidence into an allow/deny decision and a signed
SLSA VSA, using only community-standard tools (`cosign` + Open Policy Agent). This
is the lane the release is actually blocked on; [`../valint-lane/`](../valint-lane)
runs the same intent in report mode as an independent second opinion.

## How it fits together

```
evidence (../inputs/) ──▶ assemble-gate-input.sh ──▶ gate-input.json ──▶ gate.sh ──▶ VSA + allow/deny
                          (assemble_gate_input.py)                        (opa eval
                           derive every fact from                         firmware.rego)
                           the VERIFIED bundle                                 │
                                                                    verify-initiative.py
                                                                    (per-framework coverage)
```

| File | Role |
|---|---|
| [`policy/firmware.rego`](policy/firmware.rego) | **the gate** — 19 `verifier_reports`, ANDed into `allow`; emits the VSA predicate. Each report is tagged with the controls it satisfies. |
| [`policy/data.json`](policy/data.json) | trust config: expected builder id / source repo, `hash_exempt`, `trusted_signer_identities`. |
| [`assemble_gate_input.py`](assemble_gate_input.py) | derives the gate input from **verified** evidence (DSSE decode, cert-SAN identity, digests, CVE/VEX, firmware anchor). `assemble-gate-input.sh` is a thin shim over it. **Every fact comes from evidence; the policy only decides.** |
| [`gate.sh`](gate.sh) | runs `opa eval`, prints the per-report result, and emits the signed VSA (with the firmware-image subject). |
| [`verify-initiative.py`](verify-initiative.py) + [`initiatives/frameworks.yaml`](initiatives/frameworks.yaml) | map the reports to framework controls → per-framework `PASS / FAIL / MISSING_EVIDENCE`. |
| [`fixtures/`](fixtures) | 21 gate-input **test vectors**: `clean.json` (ALLOW), `accepted-cve.json` (triaged ALLOW), and 19 negative fixtures each isolating a report's failure mode. Driven by [`../tests/run.sh`](../tests/run.sh). |
| [`compliance-map.md`](compliance-map.md) | the enforced-subset view + the two-lane story. |
| [`run.sh`](run.sh) | the full local lane end-to-end (keygen → attest → verify → CVE → assemble → gate). |

## Run it

```bash
make test        # ALLOW clean, DENY each failure mode + assembler unit tests
make coverage    # per-framework coverage from a fresh signed VSA
make gate FIXTURE=oss-lane/fixtures/clean.json
make demo        # full lane (needs cosign + grype)
```

## The one rule

`DEV_ASSUME_*` flags exist only for the offline demo (no keyless OIDC / no rebuilt
image locally) and are **loudly warned**; CI sets none of them — it derives every
fact for real. A local ALLOW therefore proves less than a CI ALLOW, by design.
