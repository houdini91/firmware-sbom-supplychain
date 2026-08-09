#!/usr/bin/env python3
"""Guard: every verifier report the gate emits MUST carry an explicit, valid evidenceGrade.

evidenceGrade (verified | declared | sample) is the machine-readable honesty tag on each report
(firmware.rego _report -> data.evidence_grade), rendered by verify-initiative.py so a green ✅ is
never read as an unqualified proof. This test fails if a NEW report ships without a grade decision
(it would silently fall back to the conservative "declared" default) or if a grade value is invalid.

Run: OPA=bin/opa python3 tests/test_evidence_grade.py
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
OPA = os.environ.get("OPA", os.path.join(ROOT, "bin", "opa"))
VALID = {"verified", "declared", "sample", "assumed"}  # "assumed" = a verified report downgraded
# for a DEV_ASSUME_* run (input.assumed_reports); the all-facts-true fixtures below never assume, so
# the emitted grade equals the static data.evidence_grade there.


def gate_vsa(fixture):
    vsa = os.path.join(HERE, "_grade_vsa.json")
    env = dict(os.environ, OPA=OPA, VSA_OUT=vsa)
    subprocess.run(["bash", os.path.join(ROOT, "oss-lane", "gate.sh"),
                    os.path.join(ROOT, "oss-lane", "fixtures", fixture)],
                   env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with open(vsa) as f:
        doc = json.load(f)
    os.remove(vsa)
    return doc["predicate"]["verifierReports"]


def main():
    grade_map = json.load(open(os.path.join(ROOT, "oss-lane", "policy", "data.json")))["evidence_grade"]
    ok = True

    # 1) Every report the gate emits carries an explicit, valid grade, AND that grade is the one
    #    declared in data.evidence_grade (not the rego default) — so every report is a deliberate
    #    grading decision, not an accidental floor.
    for fixture in ("clean.json", "firmware-freshly-measured.json"):
        for r in gate_vsa(fixture):
            name, grade = r.get("name"), r.get("evidenceGrade")
            if grade not in VALID:
                print("FAIL  report %r has invalid/missing evidenceGrade %r" % (name, grade)); ok = False
            if name not in grade_map:
                print("FAIL  report %r has no entry in data.evidence_grade — add a deliberate grade "
                      "(it silently defaulted to 'declared')" % name); ok = False
            elif grade_map[name] != grade:
                print("FAIL  report %r grade %r != data.evidence_grade %r" % (name, grade, grade_map[name])); ok = False

    # 2) No grade value in the map is invalid (typo guard).
    for name, g in grade_map.items():
        if name == "_comment":
            continue
        if g not in VALID:
            print("FAIL  data.evidence_grade[%r] = %r is not one of %s" % (name, g, sorted(VALID))); ok = False

    if ok:
        print("PASS  every emitted verifier report carries an explicit, valid evidenceGrade")
        sys.exit(0)
    sys.exit(1)


if __name__ == "__main__":
    main()
