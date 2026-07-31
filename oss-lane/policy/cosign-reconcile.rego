# cosign-native policy for `cosign verify-attestation --policy` (OCI path, feature b).
#
# cosign's real contract (verified against pkg/cosign/rego/rego.go, cosign v3/main):
#   - it queries ONLY `data.signature.allow`, hard-coded; package MUST be `signature`.
#   - `allow` MUST evaluate to a boolean `true` — the docs' `allow[msg]` *set* form silently
#     always fails (sigstore/cosign#2871). Hence `default allow := false` + a boolean `allow`.
#   - `deny` below is NOT read by cosign; it's kept for local debugging (`opa eval data.signature.deny`).
#   - cosign forces Rego v0; `import rego.v1` is the bridge that lets the v1 `if`/`contains` compile
#     under it (works on cosign 2.5.2 AND opa 1.18 — validated clean=allow / dirty=deny on both).
#   - `input` is the FULL in-toto Statement: use `input.predicateType` + `input.predicate.*`.
#
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
