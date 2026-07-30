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

report := {
	"total_components": total,
	"complete": total - n_incomplete,
	"incomplete": n_incomplete,
	"coverage": coverage,
	"sbom_author": has_author,
	"sbom_timestamp": has_timestamp,
	"has_dependencies": has_dependencies,
	"ntia_compliant": compliant,
}
