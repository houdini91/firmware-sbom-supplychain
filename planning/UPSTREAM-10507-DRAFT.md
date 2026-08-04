> ## ⚠️ DRAFT — NOT POSTED. Do not post, push, or send without an explicit human greenlight.
>
> This is a *cooperative-framed* alternate draft of the #10507 comment, written to the brief:
> lead with the contribution, not the pitch. It is **not** a replacement approved for posting.
>
> **Blocking precondition (NOT yet met):** posting #10507 is gated on Richard Hughes engaging on
> **uSWID #98** (`hughsie/python-uswid#98`, currently *open, no maintainer response*). Per
> `planning/TODO.md` B1→B2, no action on #10507 until that signal lands. This draft exists so the
> text is ready the moment the gate clears — nothing here is cleared to send.
>
> **Relationship to the existing draft:** a prior draft already lives at
> `planning/engagement/issue-10507-comment.md` (it opens with "I put together the generator" + two
> format questions). This file is a *sibling*, not an edit of it — same facts, cooperative framing.
> Pick one before posting; do not post both. Divergences to reconcile before either goes out are
> listed at the bottom of this file.

---

## Ready-to-post comment (cooperative framing)

Hi all — following up on this tracking issue with something concrete rather than another design note.

Back in 2024 a static CycloneDX SBOM template was seeded across ~20 upstreams including edk2 (#6455).
The edk2 one auto-closed from inactivity — the template pointed at an SBOM, but nothing in-tree
actually *produced* one from a build. This issue (#10507, thanks @vincentjzimmer for filing it) has
tracked that gap since. I built the missing piece and would like to offer it back.

**What it is — a build-time CycloneDX generator that needs no edk2 changes to feed it.**

It is a post-build *consumer* of data edk2's build already emits. Run a normal build with
`-Y COMPILE_INFO` and BaseTools writes `CompileInfo/module_report.json` (the authoritative
built-module set, resolved library instances, source `.inf`, package deps); `GenFv` writes
`<FvName>.Fv.txt` (offset → `FILE_GUID`). The generator reads those plus the tree's submodule pins
and emits a CycloneDX 1.6 SBOM. No build-system surgery, no binary parsing on the emit path, and no
new heavy dependency — CycloneDX is plain JSON, so the generator is stdlib-only.

For a full `OvmfPkgX64` DEBUG/GCC build it produces:

- one component per built module and per resolved **library instance** (deduped),
- a module → library-instance `dependsOn` graph,
- per-module SHA-256/512 (reusing the same image the `-Y HASH` report hashes),
- `edk2:moduleType` / `edk2:arch` / `.inf` provenance per component,
- the firmware image digest in `metadata.component`, plus CISA / BSI Tier-1 metadata fields.

The natural home is a native **`-Y SBOM` report type in `BuildReport.py`**, reusing the AutoGen data
`-Y COMPILE_INFO` already gathers — so it sits beside the existing report types rather than adding a
new tool or dependency. A working reference is in hand (see below), formatted for `devel@edk2.groups.io`
via `git send-email`.

**A follow-on, deliberately *not* part of this ask:** on the operator/consumer side I also built a
reconcile step — carve the shipped `.fd` back to its FFS/PE32 modules and check the bytes against the
SBOM's declared hashes, which catches a same-`FILE_GUID` module swap that a membership/inventory check
waves through. That is operator-side machinery (edk2 ships source, not signed firmware, so it doesn't
belong in edk2's tree), and I mention it only because it's *why* the generator emitting per-module
digests is worth doing. The upstream ask here is just the generator.

**Two questions for maintainers:**

1. Is a `-Y SBOM` report type in `BuildReport.py` the right home, or would you prefer a standalone
   script under `BaseTools/` first, promoted later?
2. CycloneDX as the canonical emit with conversion left to consumers, or should the generator also
   emit SPDX natively? (A native `-Y SPDX` path is drafted and dependency-free, held in reserve — I'm
   deliberately not bundling a second format into this proposal.)

Credit where due: this complements @hughsie's uSWID/coSWID embed path (fwupd reads the tag on-device)
rather than competing with it — the generator's CycloneDX round-trips cleanly into coSWID — and it's
the automated producer the #6455 template gestured at. Happy to send the patch series to the list if
there's interest in the `-Y SBOM` direction. Thanks for reading.

---

## Notes for the human reviewer (NOT part of the comment)

**What is deliberately understated / left out of the comment, and why:**

- **No repo link is hard-coded to the personal verification repo.** Per `DESIGN.md` ("Reference
  topology"), upstream-bound text should cite only the public anchor #10507 and the edk2 fork PR, never
  the personal `firmware-sbom-supplychain` repo. Add the fork PR link (`houdini91/edk2` PR #6) only when
  that PR is confirmed reviewable + CI-considered (see branch plan). Do **not** paste the operator-repo URL.
- **The reconcile/byte-integrity work is mentioned in one sentence, as motivation, not as a deliverable.**
  That matches the who-does-what boundary in `DESIGN.md`. Resist expanding it — see `UPSTREAM-RISKS.md`
  on scope creep.
- **No compliance-framework / SLSA / gate language.** None of that is an edk2 concern; it reads as
  overreach on a BaseTools issue.

**Claims in this draft that MUST be reconciled against the real state before posting** (details in the
summary returned to the caller):

1. **Third-party submodule components.** The standalone generator's `generate.py` docstring says it
   *does* emit submodule components (openssl, mbedtls, brotli…) *with versions*. The prior draft and
   `DESIGN.md` say submodules are "not emitted yet," and the "310 vs 311" story frames openssl as a
   *demo enrichment*, not generator output. The committed example (`inputs/sbom.cdx.json`) has **311**
   components. Decide the true generator output and state one number consistently before posting.
2. **Component count.** Use whatever a *clean* generator run emits (310 or 311), not the enriched demo
   count, and label it "for this specific OvmfPkgX64 DEBUG/GCC build; varies by platform/target"
   (already the `DESIGN.md` posture).
3. **`-Y HASH` reuse claim.** The comment says per-module digests reuse `-Y HASH` canonicalization.
   Confirm the fork PR #6 actually wires that, versus computing digests independently, before asserting it.
4. **CPE identities are DRAFT.** If the example SBOM carries curated CPEs, they are tagged
   `firmware:cpe_review=unverified` in `generate.py` — do not describe them as CVE-ready identities.
