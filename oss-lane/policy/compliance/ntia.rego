# Real compliance over a CycloneDX firmware SBOM — NTIA minimum elements + BSI TR-03183-2 core fields.
# `input` is the CycloneDX SBOM document itself (not a pre-normalized verdict), so this evaluates the
# actual component data and reports honest gaps. Run offline: no signing required.
#
#   opa eval -I -f json -d ntia.rego 'data.firmware.compliance.ntia.report' < inputs/sbom.cdx.json
package firmware.compliance.ntia

import rego.v1

# ---------- SBOM-level elements ----------
default has_timestamp := false
has_timestamp if {
	input.metadata.timestamp
	input.metadata.timestamp != ""
}

default has_author := false
has_author if { some _ in input.metadata.tools.components } # CycloneDX 1.5+
has_author if { some _ in input.metadata.tools }            # CycloneDX <= 1.4 (array)
has_author if { some _ in input.metadata.authors }
has_author if { input.metadata.supplier.name }

default has_dependencies := false
has_dependencies if { some _ in input.dependencies }

# ---------- component-level field predicates ----------
has_name(c) if { c.name; c.name != "" }
has_version(c) if { c.version; c.version != "" }

# NTIA "other unique identifiers" = a real external identifier (PURL / CPE / SWID).
# A CycloneDX bom-ref is internal document correlation, NOT an NTIA identifier, so it does NOT count.
has_unique_id(c) if { c.purl; c.purl != "" }
has_unique_id(c) if { c.cpe; c.cpe != "" }
has_unique_id(c) if { c.swid }

has_supplier(c) if { c.supplier.name; c.supplier.name != "" }
has_supplier(c) if { c.publisher; c.publisher != "" }

field_ok(c, "name") if has_name(c)
field_ok(c, "version") if has_version(c)
field_ok(c, "unique-id") if has_unique_id(c)
field_ok(c, "supplier") if has_supplier(c)

required_fields := ["name", "version", "unique-id", "supplier"]

# ---------- per-component gaps ----------
incomplete contains v if {
	some c in input.components
	missing := [f | some f in required_fields; not field_ok(c, f)]
	count(missing) > 0
	v := {
		"ref": object.get(c, "bom-ref", object.get(c, "name", "<unknown>")),
		"type": object.get(c, "type", ""),
		"missing": missing,
	}
}

total := count(input.components)

n_incomplete := count(incomplete)

coverage := {
	"name": count([c | some c in input.components; has_name(c)]),
	"version": count([c | some c in input.components; has_version(c)]),
	"unique_id": count([c | some c in input.components; has_unique_id(c)]),
	"supplier": count([c | some c in input.components; has_supplier(c)]),
}

# ---------- verdict ----------
# Strict NTIA minimum elements: SBOM author + timestamp + dependency relationships + every component complete.
default compliant := false
compliant if {
	has_author
	has_timestamp
	has_dependencies
	n_incomplete == 0
}

# ---------- quality metrics (honest, reflecting the real content) ----------
pct(n) := round((n * 100) / total)

# a "real" version is not just the firmware build label echoed onto every module
build_label := object.get(input.metadata.component, "version", "")

real_version(c) if {
	has_version(c)
	c.version != build_label
}

n_real_version := count([c | some c in input.components; real_version(c)])
n_hashes := count([c | some c in input.components; count(object.get(c, "hashes", [])) > 0])
n_licenses := count([c | some c in input.components; count(object.get(c, "licenses", [])) > 0])

# dependency-graph coverage: how many components actually appear as a graph node
dep_refs contains r if {
	some d in input.dependencies
	r := d.ref
}

n_in_graph := count([c | some c in input.components; c["bom-ref"] in dep_refs])

# the primary component (metadata.component) must be checked separately from components[]
primary := object.get(input.metadata, "component", {})

primary_report := {
	"has_supplier": count([1 | has_supplier(primary)]) > 0,
	"has_external_id": count([1 | has_unique_id(primary)]) > 0,
	"has_hash": count(object.get(primary, "hashes", [])) > 0,
	"has_license": count(object.get(primary, "licenses", [])) > 0,
}

report := {
	"total_components": total,
	"ntia_compliant": compliant,
	"incomplete_components": n_incomplete,
	"identifiers_purl_cpe": {"n": coverage.unique_id, "pct": pct(coverage.unique_id)},
	"version": {"present": coverage.version, "real": n_real_version, "placeholder": total - n_real_version},
	"supplier": {"n": coverage.supplier, "pct": pct(coverage.supplier)},
	"hashes": {"n": n_hashes, "pct": pct(n_hashes)},
	"licenses": {"n": n_licenses, "pct": pct(n_licenses)},
	"dependency_graph_coverage": {"in_graph": n_in_graph, "pct": pct(n_in_graph)},
	"primary_component": primary_report,
	"sbom_author": has_author,
	"sbom_timestamp": has_timestamp,
}
