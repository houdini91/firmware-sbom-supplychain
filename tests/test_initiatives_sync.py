#!/usr/bin/env python3
"""Guard: oss-lane/policy/initiatives.json (rego data, so per-control results land
in the SIGNED verdict) must stay in sync with oss-lane/initiatives/frameworks.yaml
(the human-authored source consumed by verify-initiative.py). Regenerate with:
  python3 -c "import yaml,json; json.dump({'initiatives':yaml.safe_load(open('oss-lane/initiatives/frameworks.yaml'))['initiatives']}, open('oss-lane/policy/initiatives.json','w'), indent=2)"

Run: python3 tests/test_initiatives_sync.py
"""
import json
import os
import sys

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
yml = yaml.safe_load(open(os.path.join(ROOT, "oss-lane", "initiatives", "frameworks.yaml")))["initiatives"]
js = json.load(open(os.path.join(ROOT, "oss-lane", "policy", "initiatives.json")))["initiatives"]

if yml == js:
    print("PASS  initiatives.json is in sync with frameworks.yaml (%d frameworks)" % len(js))
    sys.exit(0)
print("FAIL  initiatives.json is OUT OF SYNC with frameworks.yaml — regenerate it (see this file's docstring)")
sys.exit(1)
