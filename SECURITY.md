# Security policy

This is a **research / portfolio demo** of a firmware supply-chain verification gate — not a product with
production deployments. There is no supported release to patch. That said, the whole point of the project is
supply-chain integrity, so security reports are very welcome and taken seriously.

## Reporting a vulnerability

- **Preferred:** open a [GitHub private security advisory](https://github.com/houdini91/firmware-sbom-supplychain/security/advisories/new)
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

## Disclosure

Because there is no deployed release, there is no embargo requirement — but I'll acknowledge a report promptly
and credit reporters (unless you prefer otherwise) in the fix commit.
