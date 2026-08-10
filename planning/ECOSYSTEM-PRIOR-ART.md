# Ecosystem prior-art survey — firmware supply-chain verification

> Background research (not a public claim doc). Purpose: understand the ecosystem, cite honestly,
> and avoid overclaiming novelty. Distill the defensible parts into README "Related work".

**One-line verdict:** The specific composition — a *same-GUID/same-name firmware module byte-swap
caught by reconciling a **build-born** SBOM's per-module hashes against the **carved shipped image**,
wired to an **admission gate** — does not appear to ship anywhere. The byte-reconcile *primitive* is
partially prior-arted by **CHIPSEC** (carves a UEFI image, per-module SHA256 compare) and, as a
product, by **Eclypsium** (proprietary known-good hash DB); neither is driven by a build-time
CycloneDX/SPDX SBOM or an OPA admission gate. **Novel as a composition, not as an atom.**

## (A) Closest prior art, ranked
1. **CHIPSEC `tools.uefi.scan_image`** (Intel) — carves EFI executables, per-section SHA256 into
   `efilist.json`, re-carves and flags unknown hashes. Closest analog. Gaps vs ours: baseline is a
   golden-image hash *set* (not a build-born SBOM); membership check, not GUID→hash binding;
   one-directional (no missing-module catch); output is a WARNING, not an admission gate.
2. **Eclypsium** (proprietary) — ~12M known-good hash DB, deviation flagging, per-component SBOM.
   Adjacent, closed; carve granularity + same-GUID handling unverified.
3. **Microsoft sbom-tool validate** — recomputes file hashes vs SBOM, but over a loose file tree,
   not modules carved from a packed firmware image.
4. **SLSA verifier** — binds one whole-artifact digest to provenance; does not open the artifact.
5. **TCG RIM / CoRIM + measured boot (HIRS)** — runtime PCR vs golden; different mechanism.
6. **IETF SUIT (RFC 9124)** — per-component digest `condition-image-match`, device-side at install.

## (B) Adjacent building blocks — cite / build on
- **hughsie/python-uSWID + fwupd + LVFS** — coSWID (RFC 9393) embed/extract; structural validation
  only, not byte reconcile. (The coSWID piece we build on.)
- **OSFW Firmware Embedded SBOM Spec** — defines per-component file hash + optional source hash but
  NOT the carve-and-reconcile workflow. We implement verification for a step it leaves open.
- **CISA 2026 Minimum Elements** — adds component hash + signature fields; "verify documented matches
  deployed." Policy driver. (CISA 2026, finalized Jul 2026 — not a 2025 draft.)
- **Binarly FwHunt + "OpenSSL usage exposes SBOM weakness"** — canonical argument that version-based
  SBOMs miss byte differences. Motivation, not competitor.
- **SLSA VSA / in-toto / cosign / Sigstore policy-controller / Kyverno** — attestation + admission
  plumbing. Honest ceiling: these verify the *statement*, not the bytes — none re-hash the artifact.
- **OSCAL + compliance-trestle, sbomqs (Interlynk)** — compliance format + per-framework scoring
  (unsigned, not artifact-bound). Format/scoring substrate.

## (C) Genuinely unfilled (our novelty) — strict
1. Build-born SBOM → carved-image per-module byte reconcile with **GUID-aware binding** (named
   module ⇒ specific hash), **bidirectional** (also catches declared-but-missing). Strongest claim.
2. Verifying SBOM *content* by **re-hashing the artifact at admission** vs trusting a signed
   attestation's claims (the ecosystem norm).
3. A single **signed multi-framework verdict cryptographically bound to the firmware image digest**.

**Not novel (state honestly):** static carve + per-module SHA256 compare (CHIPSEC); known-good hash
comparison as a product (Eclypsium); per-component digest verification (SUIT); measured-boot vs
golden (RIM/CoRIM); SBOM-vs-file-hash validation (Microsoft sbom-tool).

## (D) Recommendations
- **Cite, don't claim against:** CHIPSEC `scan_image` (prior art our reconcile extends), Binarly blog
  (motivation), CISA 2026 hash field (driver), OSFW embedded-SBOM spec (format we verify).
- **Interoperate:** uSWID/coSWID, CycloneDX + SPDX 3.0.1, SLSA VSA + in-toto/cosign, OSCAL export.
  Consider emitting CHIPSEC-compatible `efilist.json` so our reconcile is cross-checkable.
- **Defensible novelty sentence (each clause survives the survey):** *"a build-born SBOM whose
  per-module source+shipped-byte hashes are reconciled (bidirectionally, GUID-bound) against the
  FMMT-carved image to catch a same-GUID re-signed module swap, enforced as an OPA admission gate
  that binds a signed multi-framework verdict to the firmware digest."*
- **Do NOT say** "first to carve firmware and compare module hashes" — CHIPSEC does that.

## Loose ends to close before any public novelty claim
- AMI/UEFI Forum SBOM deck describes "compare SBOM contents vs firmware image actual contents" as a
  *use case* (PDF 403'd — unverified whether shipped tooling exists).
- Eclypsium's exact carve granularity / same-GUID-swap handling is closed-source.
- OpenSSF sub-survey (GUAC, OmniBOR/gittuf, protobom, bomctl, sbomit, Minder) was still running;
  nothing seen contradicts (C). OmniBOR/GitBOM is input-manifest/dependency-graph, not module reconcile.
