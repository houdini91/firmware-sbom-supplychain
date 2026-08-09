#!/usr/bin/env bash
# Refresh oss-lane/policy/data.json's cisa_kev from the LIVE CISA KEV catalog.
# The gate matches shipped-component CVEs against this set (data.cisa_kev). Run periodically
# (CI or manually) so KEV membership is current, not stale. Needs curl + jq + python3.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FEED="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
tmp="$(mktemp)"; curl -fsS "$FEED" -o "$tmp"
python3 - "$tmp" "$HERE/oss-lane/policy/kev-catalog.json" <<'PY'
import json,sys
kev=json.load(open(sys.argv[1])); dp=sys.argv[2]; d=json.load(open(dp)) if __import__("os").path.exists(dp) else {}
d["cisa_kev"]=[{"cve":v["cveID"],"name":v.get("vulnerabilityName",""),
               "vendor":v.get("vendorProject",""),"dateAdded":v.get("dateAdded","")}
              for v in kev["vulnerabilities"]]
d["_cisa_kev_meta"]={"source":"CISA KEV catalog (live feed)","catalogVersion":kev.get("catalogVersion"),
                     "count":len(d["cisa_kev"]),"refresh":"make refresh-kev"}
json.dump(d,open(dp,"w"),indent=2); open(dp,"a").write("\n")
print("refreshed cisa_kev: %d entries (catalogVersion %s)" % (len(d["cisa_kev"]), kev.get("catalogVersion")))
PY
rm -f "$tmp"
