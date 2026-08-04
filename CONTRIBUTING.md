# Contributing

Thanks for looking. This is a personal research/portfolio project, but issues and PRs are welcome — especially
ones that find a way to make the gate wrong (see [`SECURITY.md`](SECURITY.md)).

## Ground rules

- **Honesty over coverage.** The project's value is that every claim is defensible. A check that can pass
  vacuously is worse than no check. If you add a rule, add the negative fixture that proves it fails when it
  should, and state its honest limits.
- **Evidence in, decision out.** Producers (`producers/`) derive facts from real artifacts; the gate
  (`oss-lane/policy/firmware.rego`) only decides. Keep that separation.
- **Data-processing in Python, orchestration in shell.** See the existing split.

## Setup + running the checks

```bash
make deps        # PyYAML + pefile; fetches opa (pinned, SHA-verified). Also need: jq, and for `make demo` cosign + grype.
make test        # gate honesty tests + assembler + byte-integrity unit tests — run this before every PR
make coverage    # per-framework, per-control coverage from a fresh signed VSA
```

Regenerating the firmware-derived evidence (`byte-integrity.json`, `reconcile-verdict.json`) needs an edk2 tree
+ a built OVMF image + FMMT — see [`inputs/README.md`](inputs/README.md). CI does **not** regenerate these; it
consumes the committed evidence.

## PRs

- Keep commits GPG-signed and `Signed-off-by` (DCO).
- `make test` must pass; the `pr-checks` workflow runs it on every PR.
- New gate rules: update `oss-lane/policy/firmware.rego`, add a fixture + a `tests/run.sh` line, wire the
  control in `oss-lane/initiatives/frameworks.yaml`, and reflect the count in the docs.
