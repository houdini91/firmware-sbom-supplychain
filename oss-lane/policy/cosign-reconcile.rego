# cosign-native policy for `cosign verify-attestation --policy` (OCI path, feature b).
# cosign evaluates this Rego against the in-toto statement (input = the attestation statement),
# checking package `signature` — `allow` (bool) must hold and `deny` (messages) must be empty.
# This is the predicate-level check (does the SIGNED reconcile verdict say the bytes match?);
# the composite OPA gate (firmware.rego) still covers SBOM-hash binding, CVE/VEX, and identity.
package signature

import rego.v1

default allow := false

allow if {
	input.predicateType == "https://firmware-sbom-supplychain/reconcile/v1"
	input.predicate.summary.missing == 0
	input.predicate.summary.modified == 0
	input.predicate.summary.added_suspicious == 0
}

deny contains msg if {
	input.predicate.summary.missing != 0
	msg := sprintf("reconcile: %d missing component(s)", [input.predicate.summary.missing])
}

deny contains msg if {
	input.predicate.summary.modified != 0
	msg := sprintf("reconcile: %d modified component(s)", [input.predicate.summary.modified])
}

deny contains msg if {
	input.predicate.summary.added_suspicious != 0
	msg := sprintf("reconcile: %d suspicious added component(s)", [input.predicate.summary.added_suspicious])
}
