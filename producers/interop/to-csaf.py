#!/usr/bin/env python3
"""Convert an OpenVEX document to a CSAF 2.0 VEX document.

BSI TR-03183-2 §8.1.14 names CSAF (with the VEX profile) as the format for
vulnerability data alongside the SBOM. We author triage as OpenVEX (the in-toto
/ OpenSSF normal form) and emit CSAF here so a BSI-conformant consumer can
ingest it. Deterministic: all dates come from the OpenVEX timestamps, so the
output is reproducible (no wall-clock).

Usage: to-csaf.py <openvex.json> [-o out.csaf.json]
"""
import json
import sys
import argparse

# OpenVEX status -> CSAF product_status key
STATUS = {
    "not_affected": "known_not_affected",
    "affected": "known_affected",
    "fixed": "fixed",
    "under_investigation": "under_investigation",
}
# OpenVEX justification labels map 1:1 onto CSAF flag labels.
FLAG_LABELS = {
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
}


def _rfc3339(ts):
    # CSAF wants an explicit offset; normalize a trailing Z to +00:00.
    return ts.replace("Z", "+00:00") if ts.endswith("Z") else ts


def convert(vex):
    author = vex.get("author", "unknown")
    ts = _rfc3339(vex.get("timestamp", "1970-01-01T00:00:00+00:00"))
    version = str(vex.get("version", 1))

    # Product tree: one product per distinct OpenVEX product @id.
    pid_by_ref, full_products = {}, []
    for st in vex.get("statements", []):
        for prod in st.get("products", []):
            ref = prod.get("@id", "unknown-product")
            if ref in pid_by_ref:
                continue
            pid = "CSAFPID-%04d" % (len(full_products) + 1)
            pid_by_ref[ref] = pid
            helper = {}
            if ref.startswith("pkg:"):
                helper["purl"] = ref
            elif ref.startswith("cpe:"):
                helper["cpe"] = ref
            entry = {"product_id": pid, "name": ref}
            if helper:
                entry["product_identification_helper"] = helper
            full_products.append(entry)

    vulns = []
    for st in vex.get("statements", []):
        cve = st.get("vulnerability", {}).get("name", "")
        pids = [pid_by_ref[p["@id"]] for p in st.get("products", []) if p.get("@id") in pid_by_ref]
        status_key = STATUS.get(st.get("status", ""), "under_investigation")
        v = {
            "cve": cve,
            "product_status": {status_key: pids},
            "notes": [],
        }
        just = st.get("justification")
        if just in FLAG_LABELS and pids:
            v["flags"] = [{"label": just, "product_ids": pids}]
        if st.get("impact_statement"):
            v["notes"].append({"category": "description", "title": "Impact",
                               "text": st["impact_statement"]})
        if st.get("action_statement"):
            v["notes"].append({"category": "other", "title": "Action",
                               "text": st["action_statement"]})
            if status_key == "known_not_affected" and pids:
                v.setdefault("remediations", []).append(
                    {"category": "no_fix_planned", "details": st["action_statement"], "product_ids": pids})
        vulns.append(v)

    namespace = vex.get("@id", "https://example.com/vex")
    return {
        "document": {
            "category": "csaf_vex",
            "csaf_version": "2.0",
            "title": "OVMF firmware — vulnerability exploitability (VEX)",
            "publisher": {"category": "vendor", "name": author, "namespace": namespace},
            "tracking": {
                "id": vex.get("@id", "VEX-0001").rsplit("/", 1)[-1] or "VEX-0001",
                "status": "final",
                "version": version,
                "initial_release_date": ts,
                "current_release_date": ts,
                "revision_history": [{"number": version, "date": ts, "summary": "Converted from OpenVEX."}],
                "generator": {"engine": {"name": "to-csaf.py", "version": "1.0"}},
            },
        },
        "product_tree": {"full_product_names": full_products},
        "vulnerabilities": vulns,
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
    ap.add_argument("openvex")
    ap.add_argument("-o", "--out")
    args = ap.parse_args()
    out = convert(_load(args.openvex))
    text = json.dumps(out, indent=2)
    if args.out:
        with open(args.out, "w") as f:
            f.write(text + "\n")
        print("CSAF VEX written to %s" % args.out)
    else:
        print(text)


if __name__ == "__main__":
    main()
