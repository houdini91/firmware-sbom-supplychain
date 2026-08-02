# Firmware deploy policy — the OSS-lane gate.
#
# Consumes a normalized "gate input" JSON (produced by verifying the signed
# attestation + the reconcile verdict + the CVE scan) and returns:
#   - allow            : single deploy decision
#   - verifier_reports : per-fact reports {name,isSuccess,message,controls}
#                        (Ratify-style; the gate ANDs isSuccess)
#   - deny             : granular, actionable denial messages
#   - vsa_predicate    : a SLSA Verification Summary Attestation predicate
#                        (gate.sh wraps it in an in-toto Statement + timestamp)
#
# Each verifier report is tagged with the framework control(s) it satisfies.
# See ../../FRAMEWORKS.md for the framework -> control -> evidence -> rule spine.
package firmware.deploy

import rego.v1

default allow := false

# ---------------------------------------------------------------------------
# Fact booleans — kept total (default false) so a missing input field reads as
# "unproven", never as an undefined that would collapse the report array.
# ---------------------------------------------------------------------------
default _sbom_present := false
_sbom_present if input.sbom.present

default _sig_verified := false
_sig_verified if input.signature.verified

default _sbom_bound := false
_sbom_bound if input.sbom.hash == input.attestation.subject_digest

default _provenance_ok := false
_provenance_ok if {
	input.provenance.builder_id == data.expected.builder_id
	input.provenance.source_repo == data.expected.source_repo
}

default _reconcile_clean := false
_reconcile_clean if input.reconcile.clean

default _no_critical := false
_no_critical if count(critical_cves) == 0

# SLSA L2: the pipeline verified platform-generated provenance (attest-build-
# provenance + `gh attestation verify`) and the assembler surfaced it here.
default _slsa_verified := false
_slsa_verified if input.provenance.slsa_verified

# ---------------------------------------------------------------------------
# Normalized verifier reports — one per fact, tagged with the controls it
# satisfies. The gate ANDs isSuccess across all of them.
# ---------------------------------------------------------------------------
verifier_reports := [
	_report(
		"sbom-present", _sbom_present,
		"SBOM attached to the artifact", "no SBOM present",
		["CRA-AnnexI-1", "CISA-2026-min-elements", "NTIA-2021"],
	),
	_report(
		"attestation-signature", _sig_verified,
		"attestation signature verified (keyless)", "attestation signature not verified",
		["SSDF-PS.2", "in-toto-DSSE"],
	),
	_report(
		"sbom-binding", _sbom_bound,
		"SBOM digest bound to the signed attestation subject",
		"SBOM bytes do not match the signed attestation subject (possible swap after signing)",
		["in-toto-subject-binding"],
	),
	_report(
		"provenance-identity", _provenance_ok,
		"built by the expected builder and source", _provenance_msg,
		["SLSA-provenance-L1", "SSDF-PS.3"],
	),
	_report(
		"slsa-provenance", _slsa_verified,
		"SLSA L2 provenance verified (platform-generated: attest-build-provenance + gh attestation verify)",
		"SLSA L2 provenance not verified (needs attest-build-provenance + gh attestation verify)",
		["SLSA-provenance-L2", "SSDF-PO.3.3"],
	),
	_report(
		"reconcile", _reconcile_clean,
		"declared SBOM matches observed firmware bytes",
		"reconcile failed: SBOM does not match firmware bytes",
		["reconcile-declared-vs-observed"],
	),
	_report(
		"cve-triage", _no_critical,
		"no un-triaged critical CVEs", _cve_msg,
		["NIST-800-161", "OpenVEX"],
	),
]

_report(name, ok, pass_msg, _fail, controls) := {
	"name": name, "isSuccess": true, "message": pass_msg, "controls": controls,
} if ok

_report(name, ok, _pass, fail_msg, controls) := {
	"name": name, "isSuccess": false, "message": fail_msg, "controls": controls,
} if not ok

_provenance_msg := sprintf(
	"built outside trusted builder/source: builder=%q source=%q",
	[object.get(input, ["provenance", "builder_id"], ""), object.get(input, ["provenance", "source_repo"], "")],
)

_cve_msg := sprintf("%d un-triaged critical CVE(s)", [count(critical_cves)])

# ---------------------------------------------------------------------------
# Decision: allow iff every verifier report succeeded.
# ---------------------------------------------------------------------------
allow if {
	every r in verifier_reports {
		r.isSuccess
	}
}

# critical CVEs that are NOT triaged-away in the VEX allowlist (data.cve_allowlist)
critical_cves contains c if {
	some c in input.cve.findings
	c.severity == "CRITICAL"
	not data.cve_allowlist[c.id]
}

# criticals explicitly accepted via VEX — surfaced for transparency, do not block
accepted_criticals contains c if {
	some c in input.cve.findings
	c.severity == "CRITICAL"
	data.cve_allowlist[c.id]
}

# ---------------------------------------------------------------------------
# Actionable denials (why it was blocked) — kept granular for operators.
# ---------------------------------------------------------------------------
deny contains "SBOM missing" if not input.sbom.present

deny contains "attestation signature not verified" if not input.signature.verified

deny contains msg if {
	input.provenance.builder_id != data.expected.builder_id
	msg := sprintf("built outside trusted builder: got %q, want %q", [input.provenance.builder_id, data.expected.builder_id])
}

deny contains msg if {
	input.provenance.source_repo != data.expected.source_repo
	msg := sprintf("unexpected source repo: %q", [input.provenance.source_repo])
}

deny contains "SLSA L2 provenance not verified (needs attest-build-provenance + gh attestation verify)" if not input.provenance.slsa_verified

deny contains "reconcile failed: SBOM does not match firmware bytes" if not input.reconcile.clean

deny contains "SBOM bytes do not match the signed attestation subject (possible swap after signing)" if {
	input.sbom.hash != input.attestation.subject_digest
}

deny contains msg if {
	some c in input.cve.findings
	c.severity == "CRITICAL"
	not data.cve_allowlist[c.id]
	msg := sprintf("critical CVE %s in component %q (not in VEX allowlist)", [c.id, c.component])
}

# ---------------------------------------------------------------------------
# SLSA Verification Summary Attestation (VSA) predicate.
# The gate's verdict as portable evidence: gate.sh wraps this in an in-toto
# Statement (subject = firmware digest) and stamps timeVerified.
# verifiedLevels reports SLSA_BUILD_LEVEL_2: in CI the SBOM's provenance is
# platform-generated (attest-build-provenance) and hard-gated by
# `gh attestation verify` before this gate runs (see the _levels note below).
# ---------------------------------------------------------------------------
vsa_predicate := {
	"verifier": {"id": "https://github.com/houdini91/firmware-sbom-supplychain/oss-lane"},
	"policy": {"uri": "https://github.com/houdini91/firmware-sbom-supplychain/blob/main/oss-lane/policy/firmware.rego"},
	"resourceUri": object.get(input, ["artifact", "uri"], "firmware-image"),
	"verificationResult": _result,
	"verifiedLevels": _levels,
	"slsaVersion": "1.0",
	"verifierReports": verifier_reports,
}

_result := "PASSED" if allow
_result := "FAILED" if not allow

# The gate now includes a `slsa-provenance` verifier report, so `allow` implies
# input.provenance.slsa_verified — i.e. SLSA L2 provenance was verified
# (platform-generated via attest-build-provenance + `gh attestation verify`,
# which the shared assembler surfaces as that fact). verifiedLevels is therefore
# gate-backed, not merely asserted on the pass verdict.
_levels := ["SLSA_BUILD_LEVEL_2"] if allow
_levels := [] if not allow
