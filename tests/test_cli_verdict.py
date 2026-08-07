#!/usr/bin/env python3
"""Consumer-CLI (cli/fw-supplychain-verify) verdict regression test.

Guards the advisory-flag contract: a clean release the deploy gate ALLOWs must also be
ACCEPTed by the consumer CLI. Frameworks that carry an ADVISORY control which is honestly
MISSING on clean (SP 800-193 §4.3.1 Detection, OSF source-hash) must NOT drag the framework
— and therefore the whole verdict — to REJECT. Without honoring `advisory`, the CLI rejected
a release the gate accepted (the two disagreed on the same evidence)."""
import hashlib
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OPA = os.environ.get("OPA", os.path.join(ROOT, "bin", "opa"))
CLI = os.path.join(ROOT, "cli", "fw-supplychain-verify")
GATE = os.path.join(ROOT, "oss-lane", "gate.sh")
CLEAN = os.path.join(ROOT, "oss-lane", "fixtures", "clean.json")

fail = 0


def check(msg, cond):
    global fail
    print(("PASS  " if cond else "FAIL  ") + msg)
    if not cond:
        fail = 1


with tempfile.TemporaryDirectory() as td:
    # 1) a stand-in firmware image; bind the VSA to ITS digest so binding == BOUND
    fw = os.path.join(td, "firmware.fd")
    with open(fw, "wb") as f:
        f.write(b"stand-in firmware image for the CLI verdict regression test\n")
    dg = "sha256:" + hashlib.sha256(open(fw, "rb").read()).hexdigest()

    # 2) a consistent clean gate input: every FIRMWARE-side digest = the stand-in's digest
    gi = json.load(open(CLEAN))
    gi["firmware"]["sbom_digest"] = dg
    gi["firmware"]["reconcile_digest"] = dg
    if gi["firmware"].get("deployed_digest"):
        gi["firmware"]["deployed_digest"] = dg
    gi["attestation"]["firmware_subject"] = dg
    gi["provenance"]["firmware_subject"] = dg
    gin = os.path.join(td, "gate-input.json")
    json.dump(gi, open(gin, "w"))

    # 3) emit the signed VSA
    vsa = os.path.join(td, "vsa.json")
    env = dict(os.environ, OPA=OPA, VSA_OUT=vsa)
    r = subprocess.run(["bash", GATE, gin], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       universal_newlines=True)
    check("gate ALLOWs the consistent clean input (advisory controls do not block)", r.returncode == 0)

    # 4) run the consumer CLI (--json) against the bound firmware
    r = subprocess.run([sys.executable, CLI, "--firmware", fw, "--vsa", vsa, "--json"],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    out = json.loads(r.stdout)
    check("CLI binds the firmware to the VSA (binding == BOUND)", out["binding"] == "BOUND")
    check("CLI ACCEPTs the clean bound release (matches the gate's ALLOW)", out["verdict"] == "ACCEPT")

    fwmap = {f["id"]: f for f in out["frameworks"]}
    # the two frameworks whose advisory control is MISSING on clean must still pass
    check("SP 800-193 passes despite §4.3.1 advisory MISSING (2/3)",
          fwmap["sp-800-193"]["ok"] is True)
    check("OSF embedded-SBOM passes despite source-hash advisory MISSING (1/2)",
          fwmap["osf-embedded-sbom"]["ok"] is True)
    # and every framework is ok on a clean release
    check("every framework ok on a clean bound release",
          all(f["ok"] for f in out["frameworks"]))

print("ALL PASS" if not fail else "SOME FAILED")
sys.exit(fail)
