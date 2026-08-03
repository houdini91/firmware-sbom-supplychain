#!/usr/bin/env python3
"""Report per-framework, per-control coverage from a signed SLSA VSA.

The declarative layer over the enforcing gate (see initiatives/frameworks.yaml): the gate's
verifier_reports stay the source of truth; this maps them to framework control IDs and reports
PASS / FAIL / MISSING_EVIDENCE per control — the three-state that distinguishes "attestation
absent" (a supply-chain gap) from "attestation present but failing".

  verify-initiative.py --vsa <vsa.intoto.json> [--framework slsa.l2] [--manifest initiatives/frameworks.yaml]

The VSA is the gate's output (gate.sh VSA_OUT=...). Exit 0 iff every evaluated control PASSED.
"""
import argparse
import json
import os
import sys

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required: pip install pyyaml")

PASS, FAIL, MISSING = "PASS", "FAIL", "MISSING_EVIDENCE"
MARK = {PASS: "✅", FAIL: "⛔", MISSING: "❔"}


def load_reports(vsa_path):
    """name -> isSuccess, from the VSA predicate's verifierReports (or a raw gate value)."""
    doc = json.load(open(vsa_path))
    reports = (doc.get("predicate", {}).get("verifierReports")
               or doc.get("verifierReports")
               or doc.get("verifier_reports") or [])
    return {r["name"]: bool(r.get("isSuccess")) for r in reports}


def evaluate(control, present):
    need = control.get("satisfied_by", [])
    absent = [r for r in need if r not in present]
    if absent:
        return MISSING, absent
    failed = [r for r in need if not present[r]]
    return (FAIL, failed) if failed else (PASS, [])


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--vsa", required=True)
    ap.add_argument("--framework", help="initiative id (default: all)")
    ap.add_argument("--manifest", default=os.path.join(here, "initiatives", "frameworks.yaml"))
    args = ap.parse_args()

    present = load_reports(args.vsa)
    manifest = yaml.safe_load(open(args.manifest))
    initiatives = manifest.get("initiatives", {})
    if args.framework:
        initiatives = {k: v for k, v in initiatives.items() if k == args.framework}
        if not initiatives:
            sys.exit("unknown framework: %s" % args.framework)

    all_pass = True
    print("Compliance coverage (from the signed VSA's verifier reports)\n")
    for key, ini in initiatives.items():
        rows, ok = [], True
        for c in ini.get("controls", []):
            status, detail = evaluate(c, present)
            if status != PASS:
                ok = False
                all_pass = False
            note = (" ← missing: %s" % ", ".join(detail)) if status == MISSING else \
                   (" ← failed: %s" % ", ".join(detail)) if status == FAIL else ""
            rows.append("    %s %-22s %s%s" % (MARK[status], c["id"], c["name"], note))
        print("  %s %s  [%s]" % ("✅" if ok else "⛔", ini["name"], key))
        print("\n".join(rows) + "\n")

    print("=> %s" % ("ALL EVALUATED CONTROLS PASS" if all_pass else "SOME CONTROLS FAIL / MISSING EVIDENCE"))
    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
