> **DRAFT — pending review, NOT FILED.** This has not been submitted to the OSF Firmware Embedded
> SBOM project, any mailing list, or any tracker. It is a prepared proposal for the author's review
> only, to be filed manually (if at all) after review.

---

# Proposal: an optional *Verification Profile* for the OSF Firmware Embedded SBOM

## Summary

The OSF Firmware Embedded SBOM spec deliberately does **not** require the SBOM to be verified against
the binary — `embedding.rst:20`: the SBOM *"does not need to be verified against a binary deliverable"*
(integrity is delegated to Authenticode). That is a reasonable default. This proposal adds an
**optional, opt-in Verification Profile** for producers/operators who *do* want an embedded SBOM that a
downstream party can independently reconcile against the shipped bytes — without changing anything for
implementations that don't opt in.

The profile is additive: a firmware that satisfies today's MUSTs stays conformant; a firmware that
*also* satisfies the Verification Profile carries enough to catch a **same-GUID byte swap** (a module
whose `FILE_GUID` is unchanged but whose bytes were replaced after signing).

## Motivation

- Authenticode integrity proves *who signed the image*, not *that each declared module's bytes match
  its SBOM entry*. A re-signing integrator (IBV/ODM/OEM) who swaps a module under the same
  `FILE_GUID` produces an image that verifies and whose SBOM *membership* still lists the GUID. Only a
  per-module **shipped-byte hash** disagrees.
- Surveying real embedded coSWID today (Dell XPS13, Lenovo X1 Carbon via python-uswid; prebuilt OVMF,
  coreboot, Intel FSP), **none carries a per-module shipped-byte hash** that an operator could
  reconcile — vendors that ship coSWID at all carry a *source-file* hash (`colloquial-version`), which
  is a different thing. So there is currently no interoperable way to express "reconcile me."

## The profile (three additions, all optional)

1. **Per-module shipped-byte hash.** Each module component carries a hash over its shipped bytes in a
   canonical form (for PE/edk2: the GenFw *rebase-0* normalization — the PE image normalized to load
   base 0 — so the hash is stable across relocation). This is distinct from, and may coexist with, the
   `colloquial-version` source-file hash (M-srchash).
2. **Measured-evidence hash carrier.** RFC 9393's semantic home for a device/measured hash is the
   `evidence` branch. Today python-uswid's `uSwidEvidence` has no hash field, so this cannot be
   expressed with the reference tooling. The profile depends on adding an optional `{alg, value}` to
   the evidence entry (raised separately with the python-uswid maintainer). Until then, a producer may
   carry the shipped-byte hash as the component payload hash, labelled as such.
3. **Reconcile conformance statement.** A one-line machine-readable claim in the SBOM metadata that the
   producer intends the SBOM to be shipped-byte-reconcilable (so a consumer knows to attempt it, and a
   missing reconcile is a *gap*, not silently "not applicable").

## Reference implementation + honest limitations

A working operator-side implementation exists (edk2/OVMF target): reconstruct per-module bytes from
the shipped image, re-hash in rebase-0 form, compare to the declared hash, and DENY on a mismatch —
wrapped in a signed SLSA VSA. Honest limitations the spec text should mirror, not paper over:

- The reference gate currently reasons about the **CycloneDX manifest**, i.e. it checks the OSF
  identity/shape at the *manifest* level — it does **not yet parse the coSWID extracted from the
  shipped PE / `.sbom` COFF section**. A fully conformant verifier would parse the embedded coSWID
  from the image. The profile should specify the *embedded* artifact as the source of truth.
- The **source-file hash (M-srchash)** in the reference is not yet populated (the source tree isn't
  vendored), so the reference is *ahead* on shipped-byte reconcile and *behind* on source hash — the
  profile intentionally treats these as **independent** optional fields, since a producer may have one
  and not the other (as Dell/Lenovo have source but not shipped-byte).

## What this is *not*

- Not a change to any existing MUST. Non-opting implementations are unaffected.
- Not a replacement for Authenticode; complementary (Authenticode: who signed the image; reconcile:
  do the declared module bytes match).
- Not measured boot / on-device Root of Trust for Detection — this is **admission-time, off-device**
  reconcile of an artifact at rest.

## Asks

1. Is the OSF project open to an *optional* Verification Profile as an appendix/extension to the
   embedding spec?
2. Is the `evidence`-branch hash field the right semantic carrier (vs. payload hash), pending the
   python-uswid addition?
3. Would a canonical shipped-byte form other than GenFw rebase-0 be preferred for non-edk2 producers?

---

### Notes for my own review before filing (delete before filing)
- Cross-references the Hughes outreach (evidence-hash field) — file/send them together or the
  evidence-hash dependency dangles.
- Keep employer out; personal capacity.
- Verify the `embedding.rst:20` line reference against the current spec revision before quoting.
- This is a PROPOSAL; do not imply the reference gate already parses the shipped-PE coSWID — it does
  not (manifest-level proxy today; see CONFORMANCE.md / COMPLIANCE-MATRIX.md §8).
