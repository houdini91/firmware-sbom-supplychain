# Proposal: "Embed the anchor, pull the rest" — hash-addressed firmware evidence

> **STATUS: DRAFT / discussion — NOT implemented.** Parked behind the CHIPSEC tracks (Track A hardened;
> Track B upstream normalized-hash pending) and, more fundamentally, behind a *canonical reproducible module
> hash*. This is a design suggestion for community discussion, deliberately ahead of code.

## The gap
Firmware is space-constrained: it cannot carry a full evidence graph — build provenance, VEX, per-framework
compliance mappings, transparency-log inclusion proofs. Embedding an SBOM in the image (the current community
direction — Hughes / uSWID / LVFS) is the right first step, but it is **bounded by what fits**.

## The proposal (two moves)
1. **Embed the anchor.** Put a minimal, *canonical, reproducible* per-module hash (plus a compact coSWID
   identity) inside the firmware. This is the join key — small, fixed-size, embeddable.
2. **Pull the rest.** Publish the full evidence pack **out-of-band, keyed by that hash**, in a
   content-addressable store. The verification gate re-derives the hash from the *shipped bytes* (our
   reconcile), then **dereferences it to pull + verify** the evidence — provenance, VEX, compliance mappings,
   framework attestations — none of which had to ship in the image.

**Complementary to embed-SBOM, not a replacement:** embed = the anchor; pull = everything that doesn't fit.
The minimal anchor Hughes' direction embeds becomes the *key* to the pulled evidence. We extend that work.

## Why it works — the primitives already exist (credit them)
- **in-toto**: `subject` is `{name, digest}` — *any* hash can be a subject.
- **cosign / OCI 1.1 Referrers API**: attestations discoverable by a subject's digest.
- **Rekor** (Sigstore transparency log): **searchable by artifact hash**, globally, with *no pre-known repo* —
  the cleanest "I have a hash, give me all evidence" lookup; tamper-evident.
- **Valint / Scribe "OCI-as-storage"**: evidence packs stored + retrieved by hash — *proven in practice*; this
  proposal generalizes that model to firmware.
- **GUAC**: aggregates + serves supply-chain metadata as a queryable graph (consumer-side aggregator).
- Our own gate **already** emits a signed, multi-subject in-toto / SLSA VSA anchored to the firmware digest,
  keyless via Sigstore. This is the *same machinery pointed at retrieval* — per-module hashes become subjects
  we look up, not only ones we emit.

## We can demo the full loop **today** (publisher + consumer)
We already generate the evidence on our **edk2 fork** (the `-Y SBOM`, per-module normalized hashes,
attestations). For the demo we play **both roles**: publish our evidence pack to an OCI registry / Rekor keyed
by the module hash, then have the gate pull + verify it by that hash. This proves the mechanism end-to-end in a
controlled pipeline **without waiting for ecosystem adoption**. (Adoption at large still needs third-party
publishers — see dependencies.)

## Evidence stores to consider (firmware-aware, with trade-offs)
| Store | Fit | Trade-off |
|---|---|---|
| **OCI registry + cosign/ORAS (Referrers)** | Ubiquitous; reuses cloud-native tooling | Needs a known repo to query |
| **Rekor (Sigstore log)** | Global search-by-hash; tamper-evident | Public by default → disclosure concern |
| **Valint / Scribe (OCI-as-storage)** | Proven pull-by-hash evidence packs | Product-specific; the model we generalize |
| **LVFS / fwupd** | **Firmware-native** distribution Hughes already runs | Would need an evidence-pack convention added |
| **GUAC** | Consumer-side aggregator/graph over attestations | Aggregates, doesn't originate trust |
| (TUF repo, Grafeas) | Mentionable adjacent options | — |

## Trust model — pull-**AND-verify**, not just pull
Retrieval is not trust. Each fetched attestation must be **signed** and its in-toto `subject.digest == the
reconciled hash`; the gate needs **trust roots per publisher** (edk2? the OEM? a service?). Otherwise anyone
can publish fake evidence under any hash. The value is a *verifiable* dereference, not a fetch.

## Honest dependencies / sequencing (why this is downstream, not next-week)
1. **A canonical, reproducible module hash** both publisher and verifier key on — the *unbuilt / unaccepted*
   thing (CHIPSEC normalized hash = Track B; the `-Y SBOM` per-module hash). **This proposal is the payoff of
   that hash, downstream of it.** No canonical hash → the lookup returns nothing.
2. **A publishing convention** (someone emits per-module evidence keyed by the hash). For real adoption this is
   likely **federated / private** per vendor, not one global public store (vendors resist publishing per-module
   build internals).
3. **A version/PURL layer for CVE/VEX** — the hash is byte-exact; vuln data keys on component+version. The
   hash-pointer **complements** SBOM component identity, it doesn't replace it.
4. **Online vs offline** — pulling needs connectivity (or a mirrored/cached pack); embed wins air-gapped. The
   two models coexist by design.

## Relationship to the community (positioning)
- **Extends Hughes / uSWID / LVFS embed-SBOM, does not compete:** embed the anchor (his direction), pull the
  rest (this).
- **Bridges firmware ↔ cloud-native supply-chain** (cosign / Sigstore / OCI / in-toto / GUAC / Valint) — those
  primitives are theirs; our contribution is the *firmware join via a canonical module hash* plus the
  **division of labor** ("anchor embedded, evidence dereferenced").
- Natural venues when ready: the edk2 devel list + Hughes/LVFS (embedding side), and the Sigstore/OCI community
  (retrieval side). Discussion-first, same discipline as the other engagements.

## Not implemented (intentional)
No code. Parked behind the CHIPSEC finalization. Recorded now so the idea is captured honestly and can be
demonstrated as a scoped PoC (reconcile a module → `rekor search --sha <hash>` / OCI referrers → pull a signed
in-toto attestation → verify `subject == hash` → surface it as an extra verifier report) *after* the canonical
hash is settled.
