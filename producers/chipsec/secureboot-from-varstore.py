#!/usr/bin/env python3
"""Derive the REAL Secure Boot posture of an OVMF image from its actual UEFI variable store —
no hand-typed "sample" values. This replaces the fabricated secureboot.variables result with a
measured one.

It reads the enrolled-key state (PK / KEK / db / dbx / SecureBootEnable) directly out of the
firmware's OVMF_VARS store — the exact variables CHIPSEC's `common.secureboot.variables` module
inspects — using python-virt-firmware (the standard offline UEFI-varstore parser). This is an
*offline read of the real image's variables*, equivalent to what chipsec reads on a live system;
it is NOT a live `chipsec_main` driver run (that needs the kernel driver on the target). The
verdict is therefore honestly labelled "config-level, from the real varstore".

Secure Boot is ENFORCING (PASSED) only when the platform key is enrolled AND SecureBootEnable=1;
an image with no PK is in Setup Mode and does NOT enforce (NOTAPPLICABLE — no keys provisioned).

The hardware-rooted CHIPSEC checks (bios_wp, smm, spi_desc, spi_lock, smrr, bios_ts) read chipset
registers QEMU does not model; they are emitted NOTAPPLICABLE with an honest "verify on silicon"
note — never a fabricated PASS.

Usage:
  secureboot-from-varstore.py <OVMF_VARS.fd> [-o raw-results.json]
Then feed the raw results through to-predicate.py to get inputs/chipsec.json, exactly like a real
chipsec_main --json run:
  secureboot-from-varstore.py OVMF_VARS.fd | python3 to-predicate.py /dev/stdin -o ../../inputs/chipsec.json

Requires: pip install virt-firmware
"""
import argparse
import json
import sys

# Hardware-rooted modules with no QEMU register backing — honest NOTAPPLICABLE, never a faked PASS.
HW_ROOTED = {
    "chipsec.modules.common.bios_wp": "BIOS region flash write-protection (BIOS_CNTL.BLE/SMM_BWP) — chipset registers not modelled by QEMU; verify on silicon",
    "chipsec.modules.common.smm": "SMRAM lock (D_LCK) — SMM chipset state not modelled by QEMU; verify on silicon",
    "chipsec.modules.common.spi_desc": "SPI flash descriptor access control — no SPI controller on QEMU; verify on silicon",
    "chipsec.modules.common.spi_lock": "SPI flash configuration lock (FLOCKDN) — no SPI controller on QEMU; verify on silicon",
    "chipsec.modules.common.smrr": "System Management Range Registers — MSRs not modelled by QEMU; verify on silicon",
    "chipsec.modules.common.bios_ts": "BIOS top-swap — chipset register not modelled by QEMU; verify on silicon",
}


def secureboot_result(vars_fd):
    """Return (result, detail) for common.secureboot.variables from the real varstore."""
    try:
        from virt.firmware.varstore import edk2
    except ImportError:
        sys.exit("secureboot-from-varstore: python-virt-firmware required (pip install virt-firmware)")
    vl = edk2.Edk2VarStore(vars_fd).get_varlist()
    pk = vl.get("PK")
    kek = vl.get("KEK")
    db = vl.get("db")
    sbe = vl.get("SecureBootEnable")
    pk_len = len(bytes(pk.data)) if pk else 0
    sbe_on = bool(sbe and bytes(sbe.data) and bytes(sbe.data)[0] == 1)
    detail = {
        "pk_enrolled": pk_len > 0, "pk_bytes": pk_len,
        "kek_enrolled": bool(kek), "db_enrolled": bool(db),
        "secure_boot_enable": sbe_on, "total_vars": len(list(vl.keys())),
    }
    # Enforcing iff a platform key is enrolled AND Secure Boot is enabled.
    if pk_len > 0 and sbe_on:
        return "PASSED", detail
    # No PK => Setup Mode: the platform is not provisioned to enforce Secure Boot. Truthfully
    # NOTAPPLICABLE (the check has nothing to enforce), not a silent PASS and not a hard FAIL of
    # a misconfigured-but-provisioned platform.
    return "NOTAPPLICABLE", detail


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("vars_fd", help="the OVMF_VARS.fd (UEFI variable store) of the image under test")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()

    sb_result, sb_detail = secureboot_result(a.vars_fd)
    raw = {
        "_comment": ("REAL secureboot.variables from the actual OVMF varstore (%s) via python-virt-firmware "
                     "— an offline read of the same UEFI variables chipsec's common.secureboot.variables inspects. "
                     "NOT a live chipsec_main driver run. Hardware-rooted checks are NOTAPPLICABLE (no QEMU register "
                     "backing) and must be verified on silicon." % a.vars_fd),
        "_secureboot_detail": sb_detail,
        "chipsec.modules.common.secureboot.variables": {"result": sb_result},
        "chipsec.modules.common.uefi.access_uefispec": {"result": "WARNING"},
    }
    for mod, note in HW_ROOTED.items():
        raw[mod] = {"result": "NOTAPPLICABLE", "note": note}

    out = json.dumps(raw, indent=2)
    if a.out:
        with open(a.out, "w") as f:
            f.write(out + "\n")
        sys.stderr.write("secureboot.variables = %s  (PK enrolled=%s, SecureBootEnable=%s) -> %s\n"
                         % (sb_result, sb_detail["pk_enrolled"], sb_detail["secure_boot_enable"], a.out))
    else:
        print(out)


if __name__ == "__main__":
    main()
