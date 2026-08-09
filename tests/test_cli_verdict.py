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
    # SP 800-193 is ALL-advisory on the demo OVMF: §4.3.1 Detection needs a flash-time measurement,
    # and §4.2 / §4.2.3 (CHIPSEC posture) are NOTAPPLICABLE because Secure Boot is not provisioned
    # and there is no hardware root of trust — every chipsec report is ABSENT. Advisory controls
    # never gate, so the framework must still pass (ok) without blocking the verdict.
    check("SP 800-193 passes despite all-advisory MISSING (Detection + CHIPSEC posture)",
          fwmap["sp-800-193"]["ok"] is True)
    # NIST SP 800-147/147B is likewise all-advisory on the demo OVMF (both controls are CHIPSEC-only
    # and NOTAPPLICABLE here) — it must pass without blocking, on the same advisory contract.
    check("NIST SP 800-147 passes despite all-advisory MISSING (CHIPSEC posture not provisioned)",
          fwmap["nist-800-147"]["ok"] is True)
    # OSF embedded-SBOM is now FULLY satisfied — the reference carries a real per-module
    # edk2:sourceHash, so osf-source-hash (M-srchash) is met, not advisory-pending.
    osf_ctrls = {c["id"]: c["status"] for c in fwmap["osf-embedded-sbom"]["controls"]}
    check("OSF embedded-SBOM fully satisfied (guid-identity + source-hash both PASS)",
          fwmap["osf-embedded-sbom"]["ok"] is True
          and osf_ctrls.get("osf-guid-identity") == "PASS"
          and osf_ctrls.get("osf-source-hash") == "PASS")
    # and every framework is ok on a clean release
    check("every framework ok on a clean bound release",
          all(f["ok"] for f in out["frameworks"]))

    # REGRESSION: an ADVISORY report must NEVER be able to block `allow`. A PARTIAL source-hash
    # (0 < present < total) must NOT flip the gate to DENY — the advisory osf-source-provenance
    # report is emitted only when the MUST is fully met, so a partial state leaves it ABSENT.
    # (Earlier it emitted-failing on partial, so the gate DENYed while consumers ACCEPTed.)
    for present, label in [(1, "partial 1/N"), (gi["sbom"]["osf"]["modules_total"] // 2, "partial half")]:
        gp = json.load(open(CLEAN))
        gp["sbom"]["osf"]["source_hash_present"] = present
        gpin = os.path.join(td, "partial.json")
        json.dump(gp, open(gpin, "w"))
        rp = subprocess.run(["bash", GATE, gpin], env=dict(os.environ, OPA=OPA),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        check("gate ALLOWs a %s source-hash (advisory never blocks allow)" % label, rp.returncode == 0)

print("ALL PASS" if not fail else "SOME FAILED")
sys.exit(fail)
