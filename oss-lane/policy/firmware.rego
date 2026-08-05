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

# CHIPSEC platform posture (R3): the applicable critical protection modules
# PASSED against the target. NOTAPPLICABLE HW-root checks on OVMF/QEMU are not
# failures (see producers/chipsec/to-predicate.py). Platform-config assessment, not
# runtime measured boot.
default _chipsec_posture := false
_chipsec_posture if input.chipsec.critical_passed

# SI-7, CM-8(3): reconcile membership — every declared module was observed in the
# image and no undeclared (suspicious) artifact was present.
default _reconcile_membership := false
_reconcile_membership if {
	input.reconcile.matched == input.reconcile.declared
	input.reconcile.missing_count == 0
	input.reconcile.undeclared_observed == 0
}

# SI-7(1) / SR-4(3): byte-integrity — the shipped PE32 bytes of each CHECKED module
# match the SBOM's declared hash (not merely "a hash is present"). This is the check
# that catches a same-GUID trojan (a malicious module swapped in under the same
# FILE_GUID) that reconcile-membership passes. Non-vacuous: at least one module must
# have been byte-checked, and none may be modified. Coverage (which classes are
# byte-checkable) is reported by the producer, not hidden.
default _byte_integrity_ok := false
_byte_integrity_ok if {
	input.byte_integrity.ran
	input.byte_integrity.checked > 0
	input.byte_integrity.verified > 0 # non-vacuous: something was actually byte-verified
	input.byte_integrity.checked == input.sbom.integrity.hashed # coverage: the verdict covers EVERY declared hashable module — not a cherry-picked / stale subset (parity with reconcile's matched==declared)
	input.byte_integrity.modified_count == 0 # a MODIFIED module always fails — there is NO exemption for tampering
	count(_byte_integrity_unexpected) == 0 # every un-verifiable (skipped/errored) module is a REVIEWED exemption (data.byte_integrity_exempt), else DENY and name it
}

# Modules that could not be byte-verified (skipped or errored) and are NOT on the reviewed
# exemption list. A genuinely-unverifiable module (e.g. a TE-only or compressed section) is
# accepted ONLY when it is listed in data.byte_integrity_exempt with a documented reason;
# anything else fails the gate and is named, so operators always know what did not pass.
_byte_integrity_unexpected contains m if {
	some m in object.get(input.byte_integrity, "unverifiable", [])
	not data.byte_integrity_exempt[m]
}

# Distinct, honest failure messages. A SKIP (a module that could not be byte-checked —
# e.g. swapped to a TE/compressed section) must fail the gate, not pass silently: it is
# an un-verified module, not a clean one.
default _byte_integrity_msg := "byte-integrity not run (no image + edk2 supplied to the producer)"
_byte_integrity_msg := sprintf("byte-integrity: %d module(s) MODIFIED — shipped bytes differ from the SBOM's declared hash (possible same-GUID swap)", [input.byte_integrity.modified_count]) if input.byte_integrity.modified_count > 0
_byte_integrity_msg := sprintf("byte-integrity: %d module(s) could NOT be byte-verified and are not a reviewed exemption: %v — investigate, or add to data.byte_integrity_exempt with a documented reason", [count(_byte_integrity_unexpected), sort([m | some m in _byte_integrity_unexpected])]) if {
	input.byte_integrity.ran
	input.byte_integrity.modified_count == 0
	count(_byte_integrity_unexpected) > 0
}
_byte_integrity_msg := sprintf("byte-integrity: verdict covers only %d of %d declared hashable modules — an under-scoped or stale verdict is not full coverage (cherry-picking guard)", [input.byte_integrity.checked, input.sbom.integrity.hashed]) if {
	input.byte_integrity.ran
	input.byte_integrity.modified_count == 0
	input.byte_integrity.verified == input.byte_integrity.checked
	input.byte_integrity.checked != input.sbom.integrity.hashed
}

# R8 binary-hardening: every DXE-class module the image-protection policy governs
# declares NX_COMPAT (so W^X can be enforced on it). Non-vacuous — requires at least
# one DXE-class module actually examined; an un-scanned image is not a hardened one.
# Scope note: this asserts the DECLARED header posture, not runtime enforcement (see
# producers/reconcile/binary-hardening.py). ASLR/CFG are reported but NOT required —
# edk2 does not randomize load addresses, so requiring DYNAMIC_BASE would be wrong.
default _binary_hardening_ok := false
_binary_hardening_ok if {
	input.binary_hardening.ran
	input.binary_hardening.dxe_class_checked > 0 # non-vacuous: DXE-class modules were examined
	input.binary_hardening.dxe_class_checked == input.sbom.integrity.dxe_class_total # coverage: EVERY declared DXE-class module was scanned — not a cherry-picked / stale subset (parity with byte-integrity)
	input.binary_hardening.missing_nx_count == 0 # a missing-NX DXE module is a regression — NO exemption (parity with byte-integrity's MODIFIED)
	count(_binary_hardening_unexpected) == 0 # every un-scannable DXE-class module is a REVIEWED exemption (data.binary_hardening_exempt), else DENY and name it
}

# DXE-class modules that could not be scanned (skipped or errored) and are NOT on the
# reviewed exemption list. Only DXE-class matters for the NX expectation — a non-DXE skip
# (PEI/SEC/TE) is expected and never "unverifiable" here. Accepted ONLY when listed in
# data.binary_hardening_exempt with a documented reason; anything else denies and is named.
_binary_hardening_unexpected contains m if {
	some m in object.get(input.binary_hardening, "unverifiable", [])
	not data.binary_hardening_exempt[m]
}

default _binary_hardening_msg := "binary-hardening not run (no image + edk2 supplied to the producer)"
_binary_hardening_msg := sprintf("binary-hardening: %d DXE-class module(s) NOT NX-compatible — W^X cannot be enforced on them", [input.binary_hardening.missing_nx_count]) if input.binary_hardening.missing_nx_count > 0
_binary_hardening_msg := sprintf("binary-hardening: %d DXE-class module(s) could NOT be scanned and are not a reviewed exemption: %v — investigate, or add to data.binary_hardening_exempt with a documented reason", [count(_binary_hardening_unexpected), sort([m | some m in _binary_hardening_unexpected])]) if {
	input.binary_hardening.ran
	input.binary_hardening.missing_nx_count == 0
	count(_binary_hardening_unexpected) > 0
}
_binary_hardening_msg := "binary-hardening: no DXE-class module examined — a vacuous scan is not a hardened image" if {
	input.binary_hardening.ran
	input.binary_hardening.missing_nx_count == 0
	count(_binary_hardening_unexpected) == 0
	input.binary_hardening.dxe_class_checked == 0
}
_binary_hardening_msg := sprintf("binary-hardening: verdict covers only %d of %d declared DXE-class modules — an under-scoped or stale verdict is not full coverage (cherry-picking guard)", [input.binary_hardening.dxe_class_checked, input.sbom.integrity.dxe_class_total]) if {
	input.binary_hardening.ran
	input.binary_hardening.missing_nx_count == 0
	count(_binary_hardening_unexpected) == 0
	input.binary_hardening.dxe_class_checked > 0
	input.binary_hardening.dxe_class_checked != input.sbom.integrity.dxe_class_total
}

# SI-7(1), CISA hash field: every hashable (non-library) module carries a hash,
# except explicit reviewed exemptions (data.hash_exempt). No relaxed threshold —
# an unhashed, non-exempt module fails the gate.
_integrity_unresolved := [m | some m in object.get(input, ["sbom", "integrity", "unhashed"], []); not data.hash_exempt[m]]

default _integrity_coverage := false
_integrity_coverage if {
	input.sbom.integrity
	count(_integrity_unresolved) == 0
}

# RV.1.1/RV.1.2, S2C2F SCA-1: every HIGH/CRITICAL finding carries a non-empty VEX
# justification. Extends cve-triage (CRITICAL + allowlist-membership-only) to HIGH
# and requires the justification string, not just that the CVE id is a key.
_unadjudicated contains c if {
	some c in input.cve.findings
	upper(c.severity) in {"CRITICAL", "HIGH"}
	object.get(data.cve_allowlist, c.id, "") == ""
}

default _vex_adjudicated := false
_vex_adjudicated if count(_unadjudicated) == 0

# CISA License + Software-Identifiers, S2C2F SCA-2, SSDF PW.4.4: every third-party
# component carries a purl + license. edk2 FFS modules are excluded by
# construction (not marked edk2:vendored); total>=1 stops an empty third-party
# set from passing vacuously.
default _thirdparty_ok := false
_thirdparty_ok if {
	input.sbom.thirdparty.total >= 1
	count(input.sbom.thirdparty.missing) == 0
}

# SSDF PO.3.2, S2C2F REB-3: the build-tools SBOM (E7 — the CI actions/tools that
# produce & verify the firmware SBOM) is present, its signature verified, and every
# component SHA/version-pinned (none unpinned/"latest"). The assembler surfaces the
# pinning check as `build_tools.unpinned` (components lacking BOTH a version and a hash).
# HONESTY: pinned tool digests prove WHICH tools ran (toolchain integrity + pinning —
# PO.3.2 / REB-3). They do NOT prove build isolation or per-binary hardening flags, so
# this maps to PO.3.2 + REB-3 ONLY — not SLSA L3 and not PW.6.1 (hardening records are
# roadmap R7, not derivable from a pinned tool inventory).
default _build_tools_ok := false
_build_tools_ok if {
	input.build_tools.present
	input.build_tools.signature_verified
	count(input.build_tools.unpinned) == 0
}

# SR-4, SR-4(3): SLSA build-level floor — provenance level >= 2. E2 is L2
# (hosted/platform-generated), never L3 (not hermetic/isolated).
default _slsa_level_floor := false
_slsa_level_floor if input.provenance.slsa_level >= 2

# SLSA subject binding across the chain: the SBOM, the cosign attestation, and the
# SLSA provenance all commit to one subject digest. (The VSA is THIS gate's output
# and cannot be in the chain — that would be circular; see POLICY-EXPANSION.md.)
default _evidence_chain_bound := false
_evidence_chain_bound if {
	input.attestation.subject_digest != ""
	input.sbom.hash == input.attestation.subject_digest
	input.provenance.subject_digest == input.attestation.subject_digest
}

# Firmware-image anchor (the keystone). Three digests of the FIRMWARE BYTES agree:
# (1) the SBOM's own metadata.component digest D — what the build says it shipped;
# (2) the reconcile verdict's image_digest — an INDEPENDENT re-hash of the carved
# image (distinct measurement from (1)); (3) the digest of the deployed .fd — a
# fresh hash a flash-time verifier supplies via FW_IMAGE. Legs (1)+(2) are the two
# independent build/analysis-time measurements; leg (3) is what makes it tamper-
# evident at deploy time, BUT the offline demo + CI set DEV_ASSUME_FWIMAGE (they do
# not rebuild/flash OVMF), so there (3) is copied from (1) — the anchor there proves
# (1)==(2) consistency, not a fresh deploy-time comparison. Do not overstate it.
# Normalize a digest to lower(alg:hex) so leg comparison is immune to case /
# formatting differences between the three independent producers.
_dnorm(d) := lower(d)

default _firmware_anchored := false
_firmware_anchored if {
	s := _dnorm(input.firmware.sbom_digest)
	s != ""
	startswith(s, "sha256:") # assert the algorithm token, not just any string match
	_dnorm(input.firmware.deployed_digest) == s
	_dnorm(input.firmware.reconcile_digest) == s
}

# Distinct failure messages: an ABSENT leg (a producer that emitted no digest —
# a supply-chain gap) reads very differently from a genuine value MISMATCH (a
# possible swap/tamper). SHA-256 is the compared anchor; the generator also
# records SHA-512 in the SBOM for defense-in-depth, not gated (256 suffices).
default _firmware_anchor_msg := "firmware digest not anchored"
_firmware_anchor_msg := "firmware anchor: no image digest present (SBOM/reconcile/deployed leg empty) — cannot bind evidence to firmware bytes" if {
	"" in {_dnorm(input.firmware.sbom_digest), _dnorm(input.firmware.reconcile_digest), _dnorm(input.firmware.deployed_digest)}
}
_firmware_anchor_msg := sprintf("firmware digest MISMATCH: sbom=%v reconcile=%v deployed=%v — evidence is not about these bytes", [input.firmware.sbom_digest, input.firmware.reconcile_digest, input.firmware.deployed_digest]) if {
	not "" in {_dnorm(input.firmware.sbom_digest), _dnorm(input.firmware.reconcile_digest), _dnorm(input.firmware.deployed_digest)}
	not _firmware_anchored
}

# SI-7(15) Code Authentication, CM-14 Signed Components, SR-4(1): the signed
# artifact's cryptographic identity (the keyless cert SAN) is in the trusted set
# AND the signature verified — ties "a signature verified" to "signed by a trusted
# identity" in one check. (OIDC-issuer pinning is a documented enhancement.)
default _signer_pinned := false
_signer_pinned if {
	input.signature.verified
	input.signature.identity in data.trusted_signer_identities
}

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
		"firmware-digest-anchor", _firmware_anchored,
		"firmware-image digest consistent: build-time SBOM digest == reconcile's independent re-hash (== deployed image when a flash-time verifier supplies FW_IMAGE; assumed equal otherwise)",
		_firmware_anchor_msg,
		["firmware-image-binding", "SI-7", "SR-4(3)", "CISA-2026-hash"],
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
	# SP800-147 is anchored on the BIOS write-protection pillar (CHIPSEC bios_wp), which
	# is what actually runs on the QEMU target — NOT the authenticated-update pillar,
	# which this lane does not assess. SP800-193-4.2 is the platform-resiliency mapping.
	_report(
		"chipsec-posture", _chipsec_posture,
		"platform protections verified (CHIPSEC: applicable critical modules passed)",
		"platform protections not verified (CHIPSEC: a critical module failed, or none ran)",
		["SP800-193-4.2", "SP800-147-write-protect"],
	),
	_report(
		"reconcile-membership", _reconcile_membership,
		"every declared module observed in the image; no undeclared artifact",
		_reconcile_membership_msg,
		["SI-7", "CM-8(3)"],
	),
	_report(
		"component-integrity", _integrity_coverage,
		"every hashable module carries a hash (or a reviewed exemption)",
		_integrity_msg,
		["SI-7(1)", "CISA-2026-hash"],
	),
	_report(
		"component-byte-integrity", _byte_integrity_ok,
		"shipped module bytes match the SBOM's declared hash (byte-integrity — detects a same-GUID swap)",
		_byte_integrity_msg,
		["SI-7(1)", "SR-4(3)", "S2C2F-AUD-3"],
	),
	_report(
		"binary-hardening", _binary_hardening_ok,
		"every DXE-class module declares NX_COMPAT (W^X-ready; declared-posture evidence, not runtime enforcement)",
		_binary_hardening_msg,
		["SI-16", "SSDF-PW.6.2"],
	),
	_report(
		"vex-adjudicated", _vex_adjudicated,
		"every high/critical CVE carries a non-empty VEX justification",
		_vex_msg,
		["SSDF-RV.1.1", "SSDF-RV.1.2", "S2C2F-SCA-1"],
	),
	_report(
		"thirdparty-identifiers", _thirdparty_ok,
		"every third-party component carries a purl + license",
		_thirdparty_msg,
		["CISA-2026-license", "CISA-2026-software-id", "S2C2F-SCA-2", "SSDF-PW.4.4"],
	),
	_report(
		"build-tools-signed", _build_tools_ok,
		"build-tools SBOM present, signature verified, and every component SHA/version-pinned",
		_build_tools_msg,
		["SSDF-PO.3.2", "S2C2F-REB-3"],
	),
	_report(
		"slsa-level-floor", _slsa_level_floor,
		"SLSA build level >= 2 (platform-generated provenance; not L3)",
		_slsa_level_msg,
		["SR-4", "SR-4(3)"],
	),
	_report(
		"evidence-chain-bound", _evidence_chain_bound,
		"SBOM, attestation, and SLSA provenance all bound to one subject digest",
		"evidence chain not bound: SBOM / attestation / provenance subject digests differ",
		["SLSA-subject-binding", "SR-4(3)"],
	),
	_report(
		"signer-identity-pinned", _signer_pinned,
		"signed by a trusted keyless identity (cert SAN in the allowlist)",
		_signer_msg,
		["SI-7(15)", "CM-14", "SR-4(1)"],
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

# Framework+control tags for a report, DERIVED from the manifest (data.initiatives) so the
# rego reports and frameworks.yaml can never drift — one source of truth. Each tag is
# "<framework>:<control-id>", so every verdict line is traceable to its framework + control
# number. (The hardcoded 5th arg to _report is now vestigial — kept only to avoid churning
# all 19 call sites; the manifest is authoritative.)
_controls_for(rep) := sort([t |
	some fwkey, fw in data.initiatives
	some ctrl in fw.controls
	rep in ctrl.satisfied_by
	t := sprintf("%s:%s", [fwkey, ctrl.id])
])

_report(name, ok, pass_msg, _fail, _controls) := {
	"name": name,
	"id": sprintf("firmware-sbom-supplychain/%s@v1", [name]), # versioned rule id (neutral namespace)
	"isSuccess": true, "message": pass_msg,
	"controls": _controls_for(name),
} if ok

_report(name, ok, _pass, fail_msg, _controls) := {
	"name": name,
	"id": sprintf("firmware-sbom-supplychain/%s@v1", [name]),
	"isSuccess": false, "message": fail_msg,
	"controls": _controls_for(name),
} if not ok

_provenance_msg := sprintf(
	"built outside trusted builder/source: builder=%q source=%q",
	[object.get(input, ["provenance", "builder_id"], ""), object.get(input, ["provenance", "source_repo"], "")],
)

_cve_msg := sprintf("%d un-triaged critical CVE(s)", [count(critical_cves)])

_reconcile_membership_msg := sprintf(
	"reconcile membership incomplete: matched=%v declared=%v missing=%v undeclared=%v",
	[object.get(input, ["reconcile", "matched"], "?"), object.get(input, ["reconcile", "declared"], "?"),
		object.get(input, ["reconcile", "missing_count"], "?"), object.get(input, ["reconcile", "undeclared_observed"], "?")],
)

_integrity_msg := sprintf("%d module(s) lack a hash and are not in data.hash_exempt: %v", [count(_integrity_unresolved), _integrity_unresolved])

_vex_msg := sprintf("%d high/critical CVE(s) lack a non-empty VEX justification: %v", [count(_unadjudicated), {c.id | some c in _unadjudicated}])

_thirdparty_msg := sprintf(
	"third-party identity incomplete: %d component(s) lack purl/license %v (total third-party=%v)",
	[count(object.get(input, ["sbom", "thirdparty", "missing"], [])), object.get(input, ["sbom", "thirdparty", "missing"], []), object.get(input, ["sbom", "thirdparty", "total"], 0)],
)

_slsa_level_msg := sprintf("SLSA build level %v is below the required floor of 2", [object.get(input, ["provenance", "slsa_level"], 0)])

_signer_msg := sprintf("signer identity %q not in data.trusted_signer_identities (or signature unverified)", [object.get(input, ["signature", "identity"], "")])

_build_tools_msg := sprintf(
	"build-tools SBOM not verified: present=%v signature_verified=%v unpinned=%v",
	[object.get(input, ["build_tools", "present"], false), object.get(input, ["build_tools", "signature_verified"], false), object.get(input, ["build_tools", "unpinned"], [])],
)

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

deny contains "platform protections not verified (CHIPSEC critical module failed or none ran)" if not input.chipsec.critical_passed

deny contains _reconcile_membership_msg if not _reconcile_membership

deny contains _integrity_msg if not _integrity_coverage

deny contains _vex_msg if not _vex_adjudicated

deny contains _thirdparty_msg if not _thirdparty_ok

deny contains _slsa_level_msg if not _slsa_level_floor

deny contains "evidence chain not bound: SBOM / attestation / provenance subject digests differ" if not _evidence_chain_bound

deny contains _firmware_anchor_msg if not _firmware_anchored

deny contains _byte_integrity_msg if not _byte_integrity_ok

deny contains _binary_hardening_msg if not _binary_hardening_ok

deny contains _signer_msg if not _signer_pinned

deny contains _build_tools_msg if not _build_tools_ok

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
# --- Per-control assessment (OSCAL Assessment-Results-shaped) -----------------
# Each verifier report is an OSCAL "observation"; each framework control becomes a
# "finding" whose status is satisfied / not-satisfied / not-applicable, derived from
# the reports that satisfy it (data.initiatives, generated from frameworks.yaml).
_report_present(name) if {
	some r in verifier_reports
	r.name == name
}

_report_pass(name) if {
	some r in verifier_reports
	r.name == name
	r.isSuccess
}

_control_status(need) := "not-applicable" if {
	some r in need
	not _report_present(r)
}

_control_status(need) := "not-satisfied" if {
	every r in need {_report_present(r)}
	some r in need
	not _report_pass(r)
}

_control_status(need) := "satisfied" if {
	every r in need {_report_pass(r)}
}

control_assessments := [ca |
	some fwkey, fw in data.initiatives
	some ctrl in fw.controls
	ca := {
		"framework": fwkey,
		"frameworkName": fw.name,
		"controlId": ctrl.id,
		"name": ctrl.name,
		"description": object.get(ctrl, "description", ""), # the control in the framework's language
		"citation": object.get(ctrl, "citation", ""), # exact framework reference a reader can look up
		"canonical": object.get(ctrl, "canonical", ""), # shared crosswalk id (same across frameworks)
		"status": _control_status(ctrl.satisfied_by),
		"satisfied_by": [r | some r in ctrl.satisfied_by; _report_pass(r)], # reports that PASS it
		"missing_evidence": [r | some r in ctrl.satisfied_by; not _report_present(r)], # required reports ABSENT from the verdict
		"relatedObservations": ctrl.satisfied_by,
	}
]

# --- The signed verdict -------------------------------------------------------
# The signed verdict: a standard SLSA Verification Summary Attestation
# (predicateType https://slsa.dev/verification_summary/v1, subject = the firmware
# digest D — stamped by gate.sh). The VSA summary fields are the standard ones; the
# rich per-rule observations (verifierReports) and per-framework findings
# (controlAssessments) ride as predicate EXTENSIONS. in-toto/SLSA predicates are
# explicitly extensible, so a SLSA-VSA consumer reads the standard summary and ignores
# the rest, while our CLI + initiative layer read the detail. A later step MAY render
# that same detail as an ADDITIONAL CDXA/SARIF attestation — another format over the
# same engine + data, not a replacement (see planning/A2-A4-PLAN.md).
vsa_predicate := {
	"verifier": {"id": "https://github.com/houdini91/firmware-sbom-supplychain/oss-lane"},
	"resourceUri": object.get(input, ["artifact", "uri"], "firmware-sbom-attestation"),
	"policy": {"uri": "https://github.com/houdini91/firmware-sbom-supplychain/blob/main/oss-lane/policy/firmware.rego"},
	"verificationResult": _result,
	"verifiedLevels": _levels,
	"slsaVersion": "1.0",
	# --- extensions: the detail the standard VSA summary intentionally omits ---
	"verifierReports": verifier_reports, # per-rule observations (framework-tagged)
	"controlAssessments": control_assessments, # per-framework findings + citations
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
