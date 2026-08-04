# `cli/` — the consumer-side verifier

**`fw-supplychain-verify`** is the relying-party tool: one command a firmware
engineer runs on **their** image to decide whether to trust it. It is the mirror
image of the producer pipeline — where the pipeline *emits* signed evidence, this
*consumes* it, and it assumes nothing (no `DEV_ASSUME_*` shortcuts live here).

```
fw-supplychain-verify --firmware OVMF.fd --vsa vsa.intoto.json
```

It answers three questions:

1. **Identity** — hashes the image itself (never trusts a handed-over digest).
2. **Binding** — compares that hash to the VSA's `firmware-image` subject: *is this
   evidence actually about the bytes I hold?* A mismatch is a hard REJECT.
3. **Coverage** — maps the VSA's verifier reports to framework controls and prints a
   `PASS / FAIL / MISSING_EVIDENCE` scorecard (SLSA, SSDF, SP 800-53, SP 800-193,
   S2C2F, CRA/BSI/CISA).

## The point: it degrades honestly on firmware it has never seen

Point it at a stock OVMF or a vendor UEFI image **with no attestation** and it
still hashes the bytes and reports every framework as `MISSING_EVIDENCE` — a
supply-chain *gap*, explicitly distinguished from a real `FAIL`. Most tools can't
say "I have the firmware but no evidence"; that three-state is the whole idea.

```
fw-supplychain-verify --firmware unknown-vendor.fd      # no --vsa -> all MISSING_EVIDENCE, REJECT
```

## Trusting the evidence cryptographically

The VSA is signed. To verify that signature before trusting it (recommended — the
tool assumes nothing), pass the cosign bundle and, ideally, the expected signer:

```
fw-supplychain-verify --firmware OVMF.fd --vsa vsa.intoto.json \
  --verify-bundle vsa.sig.bundle \
  --signer-identity https://github.com/houdini91/firmware-sbom-supplychain/.github/workflows/supply-chain.yml@refs/heads/main
```

A missing cosign, a bad signature, or an identity mismatch is a hard error.

## Flags

| Flag | Meaning |
|---|---|
| `--firmware <img.fd>` | the image to hash + bind (omit only if you just want a coverage read) |
| `--vsa <vsa.json>` | the signed SLSA VSA (oss-lane gate output); omit if you have no evidence |
| `--verify-bundle <bundle>` / `--signer-identity <SAN>` | verify the VSA signature first |
| `--require ssdf,sp-800-53` | frameworks that MUST fully pass for exit 0 (default: all) |
| `--show-controls` | per-control detail |
| `--json` | machine-readable output |

Exit 0 iff the firmware is **bound** and every **required** framework fully passes.

## Roadmap (v2)

Discover + fetch signed evidence from an OCI/Rekor reference instead of a local
file; re-run the carve + reconcile against the supplied image in-process (so the
tool supplies the anchor's deploy-time leg from bytes it hashed itself, retiring
the last `DEV_ASSUME` on the consumer path); byte-integrity reconcile once the
canonicalization problem is solved.
