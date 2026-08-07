#!/usr/bin/env bash
# multi-firmware-demo — run the SAME deploy gate over three firmware profiles and print a
# side-by-side comparison table (rows = verifier reports, columns = X/Y/Z, cells = ✅/⛔),
# ending with each image's ALLOW/DENY verdict and, for every ⛔, the one-line remediation.
#
#   (X) clean vendor image        — passes every report            -> ALLOW
#   (Y) authentic-but-vulnerable  — ships a CISA KEV'd component + a missing-NX DXE module,
#                                   but integrity/provenance/secure-boot all still pass -> DENY
#   (Z) tampered                  — a same-GUID byte swap (component-byte-integrity) -> DENY
#
# Same policy, same reports — only the evidence differs. Self-contained (opa + python3).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OPA="${OPA:-$ROOT/bin/opa}"
POLICY="$ROOT/oss-lane/policy"
FW="$ROOT/oss-lane/fixtures/firmware"

[ -x "$OPA" ] || { echo "opa not found at $OPA (run: make bin)" >&2; exit 2; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/multi-fw.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# Evaluate the deploy policy for each profile -> a value JSON (allow + verifier_reports).
for pair in "X:X-clean-vendor.json" "Y:Y-authentic-vulnerable.json" "Z:Z-tampered.json"; do
  col="${pair%%:*}"; file="${pair#*:}"
  "$OPA" eval -I -f json \
    -d "$POLICY/firmware.rego" -d "$POLICY/data.json" -d "$POLICY/cve-allowlist.json" -d "$POLICY/initiatives.json" \
    'data.firmware.deploy' < "$FW/$file" \
    | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["result"][0]["expressions"][0]["value"]))' \
    > "$WORK/$col.json"
done

X="$WORK/X.json" Y="$WORK/Y.json" Z="$WORK/Z.json" python3 - <<'PY'
import json, os

cols = ["X", "Y", "Z"]
titles = {"X": "X clean-vendor", "Y": "Y authentic-vuln", "Z": "Z tampered"}
data = {c: json.load(open(os.environ[c])) for c in cols}

# report order = the gate's own order from X (the clean profile emits every always-on report)
order = [r["name"] for r in data["X"]["verifier_reports"]]
reps = {c: {r["name"]: r for r in data[c]["verifier_reports"]} for c in cols}

W = max(len(n) for n in order) + 2
print()
print("  Multi-firmware comparison — one gate, three firmware images")
print("  " + "─" * (W + 3 * 8))
print("  %-*s %s" % (W, "verifier report", "".join("%-8s" % titles[c].split()[0] for c in cols)))
print("  " + "─" * (W + 3 * 8))
for name in order:
    cells = []
    for c in cols:
        r = reps[c].get(name)
        cells.append("  ✅   " if (r and r["isSuccess"]) else ("  ⛔   " if r else "  —    "))
    print("  %-*s %s" % (W, name, "".join(cells)))
print("  " + "─" * (W + 3 * 8))
verdicts = []
for c in cols:
    ok = bool(data[c]["allow"])
    verdicts.append("  %s   " % ("✅" if ok else "⛔"))
print("  %-*s %s" % (W, "VERDICT", "".join(verdicts)))
print("  %-*s %s" % (W, "", "".join("%-8s" % ("ALLOW" if data[c]["allow"] else "DENY") for c in cols)))
print()

# remediation for every ⛔, grouped per image
for c in cols:
    fails = [r for r in data[c]["verifier_reports"] if not r["isSuccess"]]
    if not fails:
        print("  %s: ALLOW — every verifier report passed." % titles[c])
        continue
    print("  %s: DENY — %d failing report(s):" % (titles[c], len(fails)))
    for r in fails:
        print("     ⛔ %s" % r["name"])
        print("        %s" % r["message"])
        fix = r.get("remediation", "")
        if fix:
            print("        → fix: %s" % fix)
    print()
PY
