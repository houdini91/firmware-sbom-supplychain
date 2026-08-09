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
# Evidence-strength ordering. A control is only as strong as its WEAKEST required report, so a
# control's grade is the minimum over its satisfiers. verified = re-derived from shipped bytes / a
# verified signature; declared = the SBOM/attestation asserts it (present + well-formed, not proven
# true of the running firmware); sample = CHIPSEC config-level posture on QEMU, not silicon.
GRADE_RANK = {"verified": 4, "declared": 3, "sample": 2, "assumed": 1}
GRADE_TAG = {"verified": "verified", "declared": "declared", "sample": "sample (QEMU config)",
             "assumed": "assumed (DEV_ASSUME — not verified this run)"}


def load_reports(vsa_path):
    """(name -> isSuccess, name -> remediation, name -> evidenceGrade), from the VSA predicate's
    verifierReports (or a raw gate value). Remediation rides only on failing reports."""
    with open(vsa_path) as f:
        doc = json.load(f)
    reports = (doc.get("predicate", {}).get("verifierReports")
               or doc.get("verifierReports")
               or doc.get("verifier_reports") or [])
    present = {r["name"]: bool(r.get("isSuccess")) for r in reports if r.get("name")}
    remediation = {r["name"]: r.get("remediation", "") for r in reports if r.get("name") and r.get("remediation")}
    grade = {r["name"]: r.get("evidenceGrade", "declared") for r in reports if r.get("name")}
    return present, remediation, grade


def control_grade(control, grade):
    """The weakest-link grade of a PASSED control: the minimum evidence strength across the
    reports that satisfy it. None if a satisfier carries no grade (shouldn't happen)."""
    ranks = [GRADE_RANK.get(grade.get(r), GRADE_RANK["declared"]) for r in control.get("satisfied_by", [])]
    if not ranks:
        return None
    worst = min(ranks)
    return next(g for g, rk in GRADE_RANK.items() if rk == worst)


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

    present, remediation, grade = load_reports(args.vsa)
    with open(args.manifest) as f:
        manifest = yaml.safe_load(f)
    initiatives = manifest.get("initiatives", {})
    if args.framework:
        initiatives = {k: v for k, v in initiatives.items() if k == args.framework}
        if not initiatives:
            sys.exit("unknown framework: %s" % args.framework)

    all_pass = True
    grade_counts = {"verified": 0, "declared": 0, "sample": 0, "assumed": 0}
    print("Compliance coverage (from the signed VSA's verifier reports)\n")
    for key, ini in initiatives.items():
        rows, ok = [], True
        for c in ini.get("controls", []):
            status, detail = evaluate(c, present)
            # An `advisory: true` control is a roadmap/aspirational mapping whose evidence is
            # legitimately expected-ABSENT in offline/CI (e.g. SP 800-193 §4.3.1, which needs a
            # genuine flash-time measurement; or the CHIPSEC posture controls when the target does
            # not substantiate them). `advisory` exempts a control ONLY when its evidence is MISSING
            # — a control that EMITS a FAILING report is a real failure and counts against the run
            # EVEN IF advisory (mirrors the deploy gate: an emitted report is ANDed into `allow`).
            # Without this, coverage would say ALL PASS while the gate DENYs the same VSA.
            advisory = bool(c.get("advisory"))
            if status == FAIL or (status == MISSING and not advisory):
                ok = False
                all_pass = False
            note = (" ← missing: %s" % ", ".join(detail)) if status == MISSING else \
                   (" ← failed: %s" % ", ".join(detail)) if status == FAIL else ""
            if status == FAIL:
                fixes = [remediation[r] for r in detail if remediation.get(r)]
                if fixes:
                    note += "\n        → fix: " + " | ".join(fixes)
            if advisory and status == MISSING:
                note += " (advisory / roadmap — not counted against coverage)"
            elif advisory and status == FAIL:
                note += " (advisory mapping, but a PRESENT failure — counts against coverage)"
            # A PASSED control's honesty tag: its weakest-link evidence grade, so a green ✅ backed
            # by a declared/sample report is never read as an unqualified proof.
            gtag = ""
            if status == PASS:
                g = control_grade(c, grade)
                if g:
                    grade_counts[g] += 1
                    gtag = "  · %s" % GRADE_TAG[g]
            rows.append("    %s %-22s %s%s%s" % (MARK[status], c["id"], c["name"], note, gtag))
        print("  %s %s  [%s]" % ("✅" if ok else "⛔", ini["name"], key))
        print("\n".join(rows) + "\n")

    total_graded = sum(grade_counts.values())
    assumed_tail = ("" if grade_counts["assumed"] == 0
                    else " · %d assumed" % grade_counts["assumed"])
    print("Evidence grade of PASSED controls (weakest-link): "
          "%d verified · %d declared · %d sample%s  (of %d)"
          % (grade_counts["verified"], grade_counts["declared"], grade_counts["sample"],
             assumed_tail, total_graded))
    print("  verified = re-derived from shipped bytes / a verified signature · "
          "declared = SBOM/attestation asserts it (present + well-formed, not proven of the running firmware) · "
          "sample = CHIPSEC config-level posture on QEMU, not silicon"
          + (" · assumed = a DEV_ASSUME_* leg stood in for a real check this run (offline demo)"
             if grade_counts["assumed"] else "") + ".")
    print("=> %s" % ("ALL EVALUATED CONTROLS PASS" if all_pass else "SOME CONTROLS FAIL / MISSING EVIDENCE"))
    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
