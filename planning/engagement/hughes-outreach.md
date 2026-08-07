> **DRAFT — pending review, NOT SENT.** Nothing here has been emailed, filed, or posted. This
> is a prepared message for the maintainer's review only; the author will send it manually, if at
> all, after reviewing it. Channel TBD (GitHub discussion on python-uswid, or email).

---

**To:** Richard Hughes (python-uswid / fwupd / LVFS)
**Re:** feeding uSWID a real build-time firmware SBOM + a small evidence-hash gap

Hi Richard,

I've been building on top of uSWID/coSWID for firmware supply-chain work and wanted to share what
fits together with your tooling — and one concrete gap where a tiny addition to python-uswid would
help. No ask beyond your read; code is linked so this isn't just a design note.

## What connects to your stack

- I wrote a build-time **`-Y SBOM`** report type for edk2 (a personal fork PR, tracked in edk2
  issue #10507) that emits a **CycloneDX 1.6** SBOM from a real OvmfPkgX64 build — no new build
  dependency. It round-trips cleanly through uSWID to coSWID: `uswid --load sbom.cdx.json --save
  sbom.uswid` and back preserves the components.
- Your importer fix **`hughsie/python-uswid#98`** (CycloneDX `device-driver` types) is what makes
  that round-trip work on a real firmware SBOM today — thank you; it's merged and I depend on it.
- I have two further small python-uswid fixes prepared as PRs on my fork (rebased onto the 0.6.x
  line) and can send them upstream whenever you'd like them — I'd rather you pull them on your
  schedule than have them land unsolicited.

## The one real gap: an evidence hash field (RFC 9393 §2.n `evidence`)

Working through coSWID conformance I hit a wall that's worth raising: the semantic home for a
**device-measured / shipped-byte hash** is the RFC 9393 `evidence` branch, but python-uswid's
`uSwidEvidence` currently carries only `{date, device_id}` — **no hash field**. So a coSWID that
wants to say "this is the hash of the bytes actually measured on/from the device" can't express it
with the reference tooling; the hash has to ride in `colloquial-version` (a source-file hash) or the
payload, neither of which is the measured-evidence semantic.

I think an optional evidence-hash field (alg + value) on `uSwidEvidence` would close this, and it's
the enabling piece for a **verification profile** on top of the OSF Firmware Embedded SBOM spec —
which is the second thing I'm circulating (separate proposal, attached in the same review). Happy to
send this as a small PR with a test if you're open to it.

## Honest scope (so this doesn't read bigger than it is)

- My **verification** side — reconstruct the SBOM from shipped bytes, reconcile declared-vs-observed
  per module, sign a SLSA VSA, run a policy gate — is deliberately **operator-side**, not something I
  think belongs in uSWID or edk2. uSWID's job (emit/embed/read coSWID) is the right boundary; I'm not
  proposing to move any of that.
- Where I compared real embedded coSWID (your Dell XPS13 / Lenovo X1 Carbon examples) against my
  output, **your examples are ahead of mine on the M-srchash MUST** — they carry a source-file hash
  in `colloquial-version` and I don't yet (I don't vendor the edk2 source tree). I'm treating that as
  a gap on my side, not a critique. Where I add something new is a per-module *shipped-byte* hash +
  an operator reconcile, which the embedded coSWID doesn't carry.

No urgency and nothing to action unless useful. Mostly I wanted the evidence-hash gap on your radar,
since it's small and it unblocks the verification-profile idea. Thanks for uSWID — it's the piece
that makes any of this consumable on-device.

— [author]

---

### Notes for my own review before sending (delete before send)
- Confirm the exact state/numbers of the two prepared python-uswid PRs before naming them; this draft
  deliberately does NOT cite PR numbers for them (only #98, which is merged) to avoid misstating.
- Decide channel: a python-uswid GitHub Discussion keeps it low-pressure vs. email.
- Keep the employer out of it (personal fork, personal capacity) — as with all this work.
- Do not send until the OSF verification-profile proposal is also reviewed; they reference each other.
