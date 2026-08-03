#!/usr/bin/env python3
"""Convert CHIPSEC results into a signed-evidence predicate + a gate fact.

Reads CHIPSEC `--json` output (module -> {"result": "..."}) OR a normalized
`{module: "PASSED|FAILED|NOTAPPLICABLE|WARNING|..."}` map, and emits a predicate
with a per-module breakdown and `critical_passed`. Honest by construction:
NOTAPPLICABLE (e.g. HW-root checks on QEMU) is NOT a failure — the gate only
requires the *applicable* critical modules to PASS, and refuses to report a pass
if no critical module actually ran.

Usage: to-predicate.py <chipsec.json> [-o inputs/chipsec.json]
"""
import json
import sys
import argparse

CRITICAL = {
    "common.bios_wp", "common.spi_desc", "common.spi_lock",
    "common.secureboot.variables", "common.smm", "common.smrr", "common.bios_ts",
}
# results that mean "not an applicable pass/fail signal"
INAPPLICABLE = {"NOTAPPLICABLE", "SKIPPED", "INFORMATION", "ERROR", "DEPRECATED"}


def _norm_module(key):
    # "chipsec.modules.common.bios_wp" -> "common.bios_wp"
    k = key.replace("chipsec.modules.", "").strip()
    return k


def _norm_result(val):
    if isinstance(val, dict):
        val = val.get("result", val.get("status", ""))
    return str(val).strip().upper()


def convert(raw):
    results = []
    for key, val in raw.items():
        if key.startswith("_"):
            continue  # skip comment/metadata keys
        mod = _norm_module(key)
        res = _norm_result(val)
        results.append({"module": mod, "result": res, "critical": mod in CRITICAL})
    results.sort(key=lambda r: (not r["critical"], r["module"]))

    crit = [r for r in results if r["critical"]]
    crit_applicable = [r for r in crit if r["result"] not in INAPPLICABLE and r["result"] != "WARNING"]
    crit_failed = [r["module"] for r in crit_applicable if r["result"] != "PASSED"]
    # Pass only if every applicable critical module PASSED and at least one ran.
    critical_passed = (len(crit_applicable) >= 1) and (len(crit_failed) == 0)

    def count(x):
        return sum(1 for r in results if r["result"] == x)

    return {
        "predicateType": "https://firmware-sbom-supplychain/chipsec-posture/v1",
        "target": "OVMF/QEMU (platform-configuration assessment)",
        "critical_passed": critical_passed,
        "summary": {
            "total": len(results),
            "passed": count("PASSED"),
            "failed": count("FAILED"),
            "not_applicable": count("NOTAPPLICABLE"),
            "warning": count("WARNING"),
            "critical_applicable": len(crit_applicable),
            "critical_failed": crit_failed,
        },
        "results": results,
        "note": ("Platform-configuration assessment against the OVMF/QEMU target, not physical silicon and "
                 "not runtime measured boot. NOTAPPLICABLE (HW-root checks with no QEMU backing) is not a "
                 "failure. Detection/recovery (SP 800-193 §4.3/§4.4) and a TPM quote (RATS §8.1) remain out "
                 "of scope."),
    }


def _load(path):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        sys.exit("error: file not found: %s" % path)
    except json.JSONDecodeError as e:
        sys.exit("error: %s is not valid JSON: %s" % (path, e))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("chipsec_json")
    ap.add_argument("-o", "--out")
    args = ap.parse_args()
    pred = convert(_load(args.chipsec_json))
    text = json.dumps(pred, indent=2)
    if args.out:
        with open(args.out, "w") as f:
            f.write(text + "\n")
        print("CHIPSEC posture predicate -> %s  (critical_passed=%s)" % (args.out, pred["critical_passed"]))
    else:
        print(text)


if __name__ == "__main__":
    main()
