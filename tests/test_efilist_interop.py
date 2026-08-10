#!/usr/bin/env python3
"""Cross-tool agreement test for the A7 interop artifact — our CHIPSEC-compatible efilist.json.

deploy-reconcile can emit a `scan_image`-compatible `efilist.json` (keyed by the module's
as-found sha256, value {sha1, guid, name, type}) from the SAME CHIPSEC-extracted module set it
reconciles. This test proves two things:

  1) HERMETIC (always runs — no pefile / no CHIPSEC / no OVMF): build_efilist emits the EXACT
     CHIPSEC schema — sha256 as the KEY; value dict {sha1, guid, name, type} in CHIPSEC's field
     order (no `sha256`/`ver` value fields on the base file); guid UPPER-dashed; section type
     S_PE32/S_TE; sha1 over the same bytes; same-hash sections de-duplicated (scan_image drops a
     repeat SHA256 rather than re-adding it). The annotated variant appends a NON-STANDARD
     additive `sha256_norm` (rebase-0 == the SBOM-declared), null when un-normalizable.

  2) CROSS-TOOL (runs ONLY when pefile + a CHIPSEC decode tree + a runnable `chipsec_main` + the
     OVMF image are all reachable, else SKIPS loudly like the coSWID tests): generate CHIPSEC's
     OWN efilist via `chipsec_main -m tools.uefi.scan_image -a generate` on the OVMF reference,
     build OURS from the `uefi decode` tree, and assert they are EQUAL — same key set, same
     per-entry {sha1, guid, name, type}. That is two INDEPENDENT CHIPSEC carve routines (the
     on-disk decode-tree walk vs. scan_image's in-memory model walk) agreeing byte-for-byte,
     which is exactly the interop guarantee A7 claims. No network.

Run: python3 tests/test_efilist_interop.py                       # hermetic tests always run
     <python-with-pefile> tests/test_efilist_interop.py          # + cross-tool when reachable
Env overrides: EFILIST_DECODE_DIR / DEPLOY_RECONCILE_REF (decode tree), EFILIST_OVMF (image),
               CHIPSEC_MAIN (chipsec_main path).
"""
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
_spec = importlib.util.spec_from_file_location(
    "deploy_reconcile", os.path.join(ROOT, "producers", "chipsec", "deploy-reconcile.py"))
dr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dr)

ok = True
skipped = 0


def check(name, cond):
    global ok
    ok = ok and cond
    print(("PASS  " if cond else "FAIL  ") + name)


# ---- synthesize a chipsec `uefi decode` tree (same shape as test_deploy_reconcile) ----
def _dash(g32):
    return "%s-%s-%s-%s-%s" % (g32[0:8], g32[8:12], g32[12:16], g32[16:20], g32[20:32])


def _write_module(base, fv_type, guid32, fname, payload, idx=0):
    d = os.path.join(base, "FV", "%02d_%s.%s.dir" % (idx, _dash(guid32), fv_type))
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, fname), "wb") as f:
        f.write(payload)


PE = b"MZ" + b"\x90" * 62           # a DXE (direct-hash) module body — is_pe True, no pefile
PE2 = b"MZ" + b"\xcc" * 62          # a second, distinct PE body
TE = b"VZ" + b"\x00" * 62           # a TE image — is_pe False -> type S_TE, sha256_norm null
GUID_A = "aa" * 16
GUID_B = "bb" * 16
GUID_TE = "cc" * 16
GUID_DUP = "dd" * 16                # SAME bytes as GUID_A -> de-duped by sha256


# ---- 1) HERMETIC: build_efilist schema, values, dedupe, annotated variant ----
td = tempfile.mkdtemp()
_write_module(td, "FV_DRIVER", GUID_A, "ModA.efi", PE, idx=1)
_write_module(td, "FV_DRIVER", GUID_B, "ModB.efi", PE2, idx=2)
_write_module(td, "FV_PEIM", GUID_TE, "ModTE.te", TE, idx=3)
_write_module(td, "FV_DRIVER", GUID_DUP, "ModDup.efi", PE, idx=4)  # identical bytes to ModA
mods = dr.collect_modules(td)

el = dr.build_efilist(mods, annotated=False)
# Every KEY is a module's as-found sha256 (== sha256 of the extracted bytes == CHIPSEC's key).
check("build_efilist: keyed by the as-found sha256 (== CHIPSEC's efilist key)",
      set(el.keys()) == {m["asfound"] for m in mods}
      and all(k == hashlib.sha256(m["raw"]).hexdigest()
              for m in mods for k in [m["asfound"]]))
# Use GUID_B/PE2 (UNIQUE bytes) for single-entry value assertions — the PE-bytes entry is
# de-duplicated (ModA + ModDup share bytes), so which FILE_GUID wins there is walk-order-dependent.
one = el[hashlib.sha256(PE2).hexdigest()]
check("build_efilist: value dict is EXACTLY {sha1,guid,name,type} in CHIPSEC's field order",
      list(one.keys()) == ["sha1", "guid", "name", "type"])
check("build_efilist: base file carries NO sha256/ver/sha256_norm value fields (check-consumable schema)",
      all(set(v.keys()) == {"sha1", "guid", "name", "type"} for v in el.values()))
check("build_efilist: guid is UPPERCASE-dashed (scan_image form), from the FILE_GUID",
      one["guid"] == _dash(GUID_B).upper())
check("build_efilist: sha1 is over the SAME as-found bytes", one["sha1"] == hashlib.sha1(PE2).hexdigest())
check("build_efilist: a PE32 section -> type 'S_PE32'", one["type"] == "S_PE32")
check("build_efilist: a TE ('.te') section -> type 'S_TE'",
      el[hashlib.sha256(TE).hexdigest()]["type"] == "S_TE")
check("build_efilist: two sections with IDENTICAL bytes collapse to ONE entry (scan_image dedupe)",
      len(el) == 3 and sum(1 for m in mods) == 4)

# write_efilist serialization: scan_image-exact (indent=2, ', '/': ', NO trailing newline).
p = os.path.join(td, "efilist.json")
dr.write_efilist(el, p)
raw = open(p).read()
check("write_efilist: no trailing newline (byte-schema-identical to scan_image's write)",
      not raw.endswith("\n") and raw == json.dumps(el, indent=2, separators=(",", ": ")))
check("write_efilist: re-parses to the same mapping", json.loads(raw) == el)

# annotated variant: additive sha256_norm; direct PE norm == the as-found key; TE norm is null.
ela = dr.build_efilist(mods, annotated=True)
va = ela[hashlib.sha256(PE).hexdigest()]
check("build_efilist(annotated): appends a 5th value field `sha256_norm`",
      list(va.keys()) == ["sha1", "guid", "name", "type", "sha256_norm"])
check("build_efilist(annotated): a DIRECT (non-XIP) module's sha256_norm == its as-found hash",
      va["sha256_norm"] == hashlib.sha256(PE).hexdigest())
check("build_efilist(annotated): a TE section's sha256_norm is null (not normalizable, never faked)",
      ela[hashlib.sha256(TE).hexdigest()]["sha256_norm"] is None)


# ---- 2) CROSS-TOOL: our efilist == CHIPSEC's own scan_image `generate` on the OVMF reference ----
def _find(paths, is_dir=False):
    for pth in paths:
        if pth and (os.path.isdir(pth) if is_dir else os.path.isfile(pth)):
            return pth
    return None


# Reference inputs come ONLY from env overrides (no committed session-specific scratch path); the
# T71 OVMF image is the one stable, non-session default. Absent -> the cross-tool block SKIPs loudly.
decode_dir = _find([os.environ.get("EFILIST_DECODE_DIR"), os.environ.get("DEPLOY_RECONCILE_REF")], is_dir=True)
ovmf = _find([os.environ.get("EFILIST_OVMF"),
              "/media/mikey/T71/firmware_artifacts/edk2/Build/OvmfX64/DEBUG_GCC/FV/OVMF_CODE.fd"])
chipsec_main = _find([os.environ.get("CHIPSEC_MAIN")]) or shutil.which("chipsec_main")

if dr.ffs.pefile is None:
    skipped += 1
    print("SKIP  cross-tool efilist agreement (pefile not installed — the XIP un-rebase path for the "
          "annotated norm cannot run; run with the pefile venv). Hermetic schema tests above still ran.")
elif not (decode_dir and ovmf and chipsec_main):
    skipped += 1
    print("SKIP  cross-tool efilist agreement (need a CHIPSEC decode tree + OVMF image + runnable "
          "chipsec_main — set EFILIST_DECODE_DIR / EFILIST_OVMF / CHIPSEC_MAIN). Hermetic tests ran.")
else:
    with tempfile.TemporaryDirectory() as wd:
        cs_json = os.path.join(wd, "chipsec-efilist.json")
        try:
            r = subprocess.run([chipsec_main, "-i", "-n", "-m", "tools.uefi.scan_image",
                                "-a", "generate,%s,%s" % (cs_json, ovmf)],
                               cwd=wd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300)
            gen_ok = (r.returncode == 0 and os.path.isfile(cs_json))
        except (OSError, subprocess.SubprocessError) as e:  # noqa: BLE001
            gen_ok, r = False, None
            print("      (chipsec_main scan_image generate did not run: %s)" % (str(e)[:120]))
        if not gen_ok:
            skipped += 1
            print("SKIP  cross-tool efilist agreement (chipsec_main scan_image `generate` did not produce "
                  "an efilist — CHIPSEC not runnable here). Hermetic tests above still ran.")
        else:
            chipsec_efilist = json.load(open(cs_json))
            ours = dr.build_efilist(dr.collect_modules(decode_dir), annotated=False)
            check("cross-tool: our efilist and CHIPSEC's have the SAME sha256 KEY SET",
                  set(ours.keys()) == set(chipsec_efilist.keys()))
            per_entry_equal = True
            first_diff = None
            for k in set(ours) & set(chipsec_efilist):
                o, c = ours[k], chipsec_efilist[k]
                if (o["sha1"] != c.get("sha1") or o["guid"] != c.get("guid")
                        or o["name"] != c.get("name") or o["type"] != c.get("type")):
                    per_entry_equal = False
                    first_diff = first_diff or (k, o, c)
            if first_diff:
                print("      first per-entry disagreement: key=%s\n        ours=%s\n        chipsec=%s"
                      % (first_diff[0][:16], first_diff[1], first_diff[2]))
            check("cross-tool: EVERY entry agrees on {sha1,guid,name,type} — our decode-tree carve == "
                  "scan_image's model carve (%d entries)" % len(ours), per_entry_equal)
            check("cross-tool: exactly the same NUMBER of executables (no module dropped/added by either)",
                  len(ours) == len(chipsec_efilist))

print("----")
if skipped:
    print("⚠  %d CROSS-TOOL TEST GROUP(S) SKIPPED — the efilist agreement against a live CHIPSEC "
          "`generate` did NOT run here (pefile / decode tree / chipsec_main unavailable). The hermetic "
          "schema tests ran." % skipped)
print(("ALL PASS%s" % (" (with %d SKIPPED — see warning)" % skipped if skipped else "")) if ok else "FAILURES")
sys.exit(0 if ok else 1)
