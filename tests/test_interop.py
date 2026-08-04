#!/usr/bin/env python3
"""Unit tests for the OpenVEX -> CSAF converter (producers/interop/to-csaf.py).
Hermetic — a synthetic OpenVEX doc; checks the product tree + vulnerability mapping.

Run: python3 tests/test_interop.py
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "to_csaf", os.path.join(HERE, "..", "producers", "interop", "to-csaf.py"))
cs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cs)

ok = True


def check(name, cond):
    global ok
    ok = ok and cond
    print(("PASS  " if cond else "FAIL  ") + name)


VEX = {
    "author": "tester", "timestamp": "2026-01-01T00:00:00+00:00", "version": 3,
    "statements": [
        {"vulnerability": {"name": "CVE-2024-0001"},
         "products": [{"@id": "pkg:github/openssl/openssl@abc"}],
         "status": "not_affected", "justification": "vulnerable_code_not_in_execute_path"},
    ],
}
out = cs.convert(VEX)

check("CSAF document produced with a product_tree", "product_tree" in out and "document" in out)
prods = out["product_tree"]["full_product_names"] if "full_product_names" in out.get("product_tree", {}) \
    else out["product_tree"].get("full_product_names", [])
check("one product, with a PURL identification helper",
      len(prods) == 1 and prods[0]["product_identification_helper"]["purl"] == "pkg:github/openssl/openssl@abc")
check("one vulnerability carrying the CVE id",
      len(out.get("vulnerabilities", [])) == 1 and out["vulnerabilities"][0].get("cve") == "CVE-2024-0001")
check("the not_affected status maps into a product_status bucket",
      "product_status" in out["vulnerabilities"][0])

print("----")
print("ALL PASS" if ok else "FAILURES")
sys.exit(0 if ok else 1)
