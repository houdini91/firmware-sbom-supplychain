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

# SBOM-file integrity (tamper-after-signing): the SBOM file digest H matches the FILE
# subject of the reconcile attestation (a multi-subject in-toto Statement carries both a
# firmware-image subject D and the bound SBOM-file subject H). This is distinct from the
# firmware binding below — it catches a swap of the SBOM bytes after signing.
default _sbom_bound := false
_sbom_bound if input.sbom.hash == input.attestation.file_subject

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
_byte_integrity_msg := sprintf("byte-integrity: %d module(s) MODIFIED: %v — shipped bytes differ from the SBOM's declared hash (possible same-GUID swap)", [input.byte_integrity.modified_count, sort(object.get(input, ["byte_integrity", "modified"], []))]) if input.byte_integrity.modified_count > 0
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
_binary_hardening_msg := sprintf("binary-hardening: %d DXE-class module(s) NOT NX-compatible: %v — W^X cannot be enforced on them", [input.binary_hardening.missing_nx_count, sort(object.get(input, ["binary_hardening", "missing_nx"], []))]) if input.binary_hardening.missing_nx_count > 0
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

# Evidence-chain binding — two distinct, both-required legs on the multi-subject evidence:
#   (a) SBOM-FILE consistency at H: the SBOM file, the reconcile attestation's FILE subject,
#       and the SLSA provenance's FILE subject all commit to one SBOM-file digest H (the
#       tamper/swap-after-signing guard across the H-subjects); and
#   (b) FIRMWARE binding at D: the WE-built reconcile attestation's FIRMWARE subject equals
#       the firmware anchor D (== input.firmware.sbom_digest; firmware-digest-anchor separately
#       cross-checks D across the SBOM/reconcile/deployed image legs). E2 SLSA provenance is
#       platform-generated (single-subject H — GitHub attest-build-provenance over the SBOM
#       file), so its firmware binding is a DEV_ASSUME-class mapping, not asserted here.
# (The VSA is THIS gate's output and cannot be in the chain — that would be circular; see
# POLICY-EXPANSION.md.)
default _evidence_chain_bound := false
_evidence_chain_bound if {
	input.attestation.file_subject != ""
	# (a) SBOM-file consistency at H
	input.sbom.hash == input.attestation.file_subject
	input.provenance.file_subject == input.attestation.file_subject
	# (b) firmware binding at D
	input.attestation.firmware_subject == input.firmware.sbom_digest
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

# CISA 2026 Minimum Elements — Generation Tool: the SBOM DECLARES a generation tool
# (metadata.tools[] with a name+version). HONESTY CEILING: this proves the SBOM declares
# a tool, NOT that the tool actually produced these bytes — same class of claim as
# vex-adjudicated (a justification is declared, not independently proven). The assembler
# surfaces the declared-tool fact from the SBOM into input.sbom.generation.tool_present.
default _sbom_gen_tool := false
_sbom_gen_tool if input.sbom.generation.tool_present

# CISA 2026 Minimum Elements — Generation Context: the SBOM DECLARES the lifecycle phase
# it was generated in (metadata.lifecycles[].phase). Same honesty ceiling as above — this
# proves the phase is DECLARED, not that generation in fact occurred in that phase.
default _sbom_gen_context := false
_sbom_gen_context if input.sbom.generation.context_present

# SP 800-193 §4.3.1 (Detection) input: a GENUINE flash-time image measurement was supplied
# (a real FW_IMAGE hashed at leg-3), as opposed to DEV_ASSUME_FWIMAGE mode where leg-3 is
# copied from the build's own SBOM self-claim. The assembler sets input.firmware.freshly_measured
# true ONLY when a real FW_IMAGE file was hashed. This fact is what distinguishes an
# admission-time off-device detection from a build-time self-attestation; see the conditional
# firmware-freshly-measured report below.
default _fw_freshly_measured := false
_fw_freshly_measured if input.firmware.freshly_measured

# CISA BOD 22-01 (KEV): no SBOM component ships a CVE that is on the CISA Known Exploited
# Vulnerabilities catalog (data.cisa_kev), UNLESS that CVE carries an explicit exec-risk VEX
# waiver (data.kev_waivers). A plain not_affected in the ordinary VEX allowlist does NOT silence
# a KEV finding — a known-exploited bug is a different risk class from a triaged-away CVE, so it
# needs its own, explicit, exec-risk justification. HONESTY CEILING: KEV membership is matched on
# the component's DECLARED version (the SBOM/grype evidence), not proven runtime exploitability.
_kev_ids := {entry.cve | some entry in data.cisa_kev}

_kev_hits contains c if {
	some c in input.cve.findings
	c.id in _kev_ids
	object.get(data.kev_waivers, c.id, "") == "" # not waived by an explicit exec-risk justification
}

default _no_kev := false
_no_kev if count(_kev_hits) == 0

_kev_msg := sprintf(
	"CISA KEV: %d shipped component(s) carry a Known-Exploited CVE with no exec-risk VEX waiver: %v — KEV membership is by DECLARED component version, not proven runtime exploitability",
	[count(_kev_hits), sort([s | some c in _kev_hits; s := sprintf("%s in %q", [c.id, c.component])])],
)

# NIST SP 800-147B + UEFI Spec §32: UEFI Secure Boot is provisioned and enforcing. Reads the
# EXISTING CHIPSEC secureboot.variables sub-result surfaced by the assembler. HONESTY CEILING:
# SAMPLE/ILLUSTRATIVE chipsec.json on the OVMF/QEMU target — config-level posture, not a live
# hardware-rooted CHIPSEC run.
default _uefi_secure_boot := false
_uefi_secure_boot if input.chipsec.secure_boot == "PASSED"

_uefi_sb_msg := sprintf(
	"UEFI Secure Boot not verified: CHIPSEC secureboot.variables = %v (expected PASSED) — SAMPLE/ILLUSTRATIVE chipsec.json on OVMF/QEMU, not a live run",
	[object.get(input, ["chipsec", "secure_boot"], "absent")],
)

# NIST SP 800-147 (flash write-protection) + SP 800-193 §4.2.3 (SMM): the two platform-protection
# pillars that actually run on the QEMU target — CHIPSEC bios_wp (BIOS flash write-protection) and
# smm (System Management Mode isolation) — both PASSED. Reads the EXISTING chipsec sub-results.
# HONEST PARTIAL: bios_ts + smrr report N/A on QEMU (no hardware root of trust), so they are
# reported (not gated) — a config-level posture assessment, not enforced platform resiliency.
default _platform_protection := false
_platform_protection if {
	input.chipsec.smm == "PASSED"
	input.chipsec.bios_wp == "PASSED"
}

_platform_msg := sprintf(
	"platform protection not verified: CHIPSEC bios_wp(800-147)=%v smm(800-193 §4.2.3)=%v (expected PASSED; bios_ts=%v smrr=%v report N/A on QEMU) — SAMPLE/ILLUSTRATIVE chipsec.json, not physical silicon",
	[
		object.get(input, ["chipsec", "bios_wp"], "absent"), object.get(input, ["chipsec", "smm"], "absent"),
		object.get(input, ["chipsec", "bios_ts"], "n/a"), object.get(input, ["chipsec", "smrr"], "n/a"),
	],
)

# ---------------------------------------------------------------------------
# Normalized verifier reports — one per fact, tagged with the controls it
# satisfies. The gate ANDs isSuccess across all of them.
# ---------------------------------------------------------------------------
verifier_reports := array.concat(_core_reports, _detection_reports)

_core_reports := [
	_report(
		"sbom-present", _sbom_present,
		"SBOM attached to the artifact", "no SBOM present",
	),
	_report(
		"attestation-signature", _sig_verified,
		"attestation signature verified (keyless)", "attestation signature not verified",
	),
	_report(
		"sbom-binding", _sbom_bound,
		"SBOM digest bound to the signed attestation subject",
		"SBOM bytes do not match the signed attestation subject (possible swap after signing)",
	),
	_report(
		"firmware-digest-anchor", _firmware_anchored,
		"firmware-image digest consistent: build-time SBOM digest == reconcile's independent re-hash (== deployed image when a flash-time verifier supplies FW_IMAGE; assumed equal otherwise)",
		_firmware_anchor_msg,
	),
	_report(
		"provenance-identity", _provenance_ok,
		"built by the expected builder and source", _provenance_msg,
	),
	_report(
		"slsa-provenance", _slsa_verified,
		"SLSA L2 provenance verified (platform-generated: attest-build-provenance + gh attestation verify)",
		"SLSA L2 provenance not verified (needs attest-build-provenance + gh attestation verify)",
	),
	# SP800-147 is anchored on the BIOS write-protection pillar (CHIPSEC bios_wp), which
	# is what actually runs on the QEMU target — NOT the authenticated-update pillar,
	# which this lane does not assess. SP800-193-4.2 is the platform-resiliency mapping.
	_report(
		"chipsec-posture", _chipsec_posture,
		"platform protections verified (CHIPSEC: applicable critical modules passed) — SAMPLE/ILLUSTRATIVE chipsec.json on the OVMF/QEMU target, not a live CHIPSEC run and no hardware root of trust",
		"platform protections not verified (CHIPSEC: a critical module failed, or none ran)",
	),
	_report(
		"reconcile-membership", _reconcile_membership,
		"every declared module observed in the image; no undeclared artifact",
		_reconcile_membership_msg,
	),
	_report(
		"component-integrity", _integrity_coverage,
		"every hashable module carries a hash (or a reviewed exemption)",
		_integrity_msg,
	),
	_report(
		"component-byte-integrity", _byte_integrity_ok,
		"shipped module bytes match the SBOM's declared hash (byte-integrity — detects a same-GUID swap)",
		_byte_integrity_msg,
	),
	_report(
		"binary-hardening", _binary_hardening_ok,
		"every DXE-class module declares NX_COMPAT (W^X-ready; declared-posture evidence, not runtime enforcement)",
		_binary_hardening_msg,
	),
	_report(
		"vex-adjudicated", _vex_adjudicated,
		"every high/critical CVE carries a non-empty VEX justification",
		_vex_msg,
	),
	_report(
		"thirdparty-identifiers", _thirdparty_ok,
		"every third-party component carries a purl + license",
		_thirdparty_msg,
	),
	_report(
		"build-tools-signed", _build_tools_ok,
		"build-tools SBOM present, signature verified, and every component SHA/version-pinned",
		_build_tools_msg,
	),
	_report(
		"slsa-level-floor", _slsa_level_floor,
		"SLSA build level >= 2 (platform-generated provenance; not L3)",
		_slsa_level_msg,
	),
	_report(
		"evidence-chain-bound", _evidence_chain_bound,
		"evidence chain bound: SBOM-file digests agree (H) across SBOM/attestation/provenance AND the attestation's firmware subject == the firmware anchor D",
		"evidence chain not bound: SBOM-file digests differ across SBOM/attestation/provenance (H), or the attestation's firmware subject != the firmware anchor D",
	),
	_report(
		"signer-identity-pinned", _signer_pinned,
		"signed by a trusted keyless identity (cert SAN in the allowlist)",
		_signer_msg,
	),
	_report(
		"reconcile", _reconcile_clean,
		"declared SBOM matches observed firmware bytes",
		"reconcile failed: SBOM does not match firmware bytes",
	),
	_report(
		"cve-triage", _no_critical,
		"no un-triaged critical CVEs", _cve_msg,
	),
	# CISA 2026 Generation Tool / Context. HONESTY: these assert the SBOM DECLARES a tool /
	# context (name+version in metadata.tools[]; a phase in metadata.lifecycles[]) — not that
	# the declared tool produced these bytes, nor that generation occurred in that phase (the
	# same declared-not-proven ceiling as vex-adjudicated).
	_report(
		"sbom-generation-tool", _sbom_gen_tool,
		"SBOM declares its generation tool (metadata.tools[] carries a name+version) — declared, not independently proven to have produced these bytes",
		"SBOM declares no generation tool (metadata.tools[] missing, or lacks a name+version)",
	),
	_report(
		"sbom-generation-context", _sbom_gen_context,
		"SBOM declares its generation context (metadata.lifecycles[].phase present) — declared, not independently proven",
		"SBOM declares no generation context (metadata.lifecycles[].phase missing)",
	),
	# CISA KEV (BOD 22-01): no shipped component carries a Known-Exploited CVE (unless an explicit
	# exec-risk VEX waiver applies). HONESTY: KEV membership is by the DECLARED component version,
	# not proven runtime exploitability; data.cisa_kev is a small illustrative seed.
	_report(
		"no-kev-component", _no_kev,
		"no shipped component carries a CISA KEV (Known-Exploited) CVE — or each is waived by an explicit exec-risk VEX justification (declared version, not runtime exploitability)",
		_kev_msg,
	),
	# UEFI Secure Boot posture — reads the EXISTING chipsec secureboot.variables result.
	_report(
		"uefi-secure-boot-posture", _uefi_secure_boot,
		"UEFI Secure Boot provisioned + enforcing (CHIPSEC secureboot.variables PASSED) — SAMPLE/ILLUSTRATIVE chipsec.json on OVMF/QEMU, config-level posture not a live hardware-rooted run",
		_uefi_sb_msg,
	),
	# Platform-protection posture — reads the EXISTING chipsec bios_wp (800-147) + smm (800-193 §4.2.3)
	# results. Honest partial: bios_ts + smrr report N/A on QEMU (no HW root of trust), reported not gated.
	_report(
		"platform-protection-posture", _platform_protection,
		"platform protections verified (CHIPSEC bios_wp flash write-protection + smm SMM isolation PASSED; bios_ts/smrr N/A on QEMU) — SAMPLE/ILLUSTRATIVE chipsec.json, config-level posture not physical silicon",
		_platform_msg,
	),
]

# SP 800-193 §4.3.1 Detection (admission-time, off-device) — CONDITIONAL report.
# It is emitted ONLY when a genuine flash-time FW_IMAGE measurement was supplied. In
# DEV_ASSUME_FWIMAGE (offline/CI) mode no fresh measurement exists, so the report is
# ABSENT from verifier_reports — which leaves §4.3.1 as MISSING_EVIDENCE (not-satisfied)
# in the initiative layer WITHOUT flipping `allow` (an absent report is not ANDed). This
# is deliberate: the clean/DEV_ASSUME gate must NOT newly claim §4.3.1 on demo data, and
# firmware-freshly-measured is non-gating precisely so it cannot. CEILING: when present it
# attests a fresh admission-time/off-device measurement was taken — NOT the on-device,
# boot-time Root of Trust for Detection (measured boot + golden RIM) that §4.3.1 envisions.
_detection_reports := [_report(
	"firmware-freshly-measured", _fw_freshly_measured,
	"a genuine flash-time firmware image was freshly measured (real FW_IMAGE hashed at leg-3, not a DEV_ASSUME build self-claim) — admission-time/off-device, not an on-device Root of Trust for Detection",
	"no fresh flash-time firmware measurement supplied (DEV_ASSUME_FWIMAGE: leg-3 copied from the build self-claim)",
)] if _fw_freshly_measured

_detection_reports := [] if not _fw_freshly_measured

# Framework+control tags for a report, DERIVED from the manifest (data.initiatives) so the
# rego reports and frameworks.yaml can never drift — one source of truth. Each tag is
# "<framework>:<control-id>", so every verdict line is traceable to its framework + control
# number. The manifest (frameworks.yaml → data.initiatives) is the sole authority for a
# report's control tags — call sites pass only (name, predicate, pass_msg, fail_msg).
_controls_for(rep) := sort([t |
	some fwkey, fw in data.initiatives
	some ctrl in fw.controls
	rep in ctrl.satisfied_by
	t := sprintf("%s:%s", [fwkey, ctrl.id])
])

_report(name, ok, pass_msg, _fail) := {
	"name": name,
	"id": sprintf("firmware-sbom-supplychain/%s@v1", [name]), # versioned rule id (neutral namespace)
	"isSuccess": true, "message": pass_msg,
	"controls": _controls_for(name),
} if ok

_report(name, ok, _pass, fail_msg) := {
	"name": name,
	"id": sprintf("firmware-sbom-supplychain/%s@v1", [name]),
	"isSuccess": false, "message": fail_msg,
	"controls": _controls_for(name),
	"remediation": _remediation_for(name), # stable "how to fix" — emitted ONLY on a failing report
} if not ok

# Stable per-report remediation strings (the audit's "how to fix"). Emitted on the verifier report
# ONLY when isSuccess=false (see the failing _report branch), surfaced in the VSA verifierReports[]
# finding, rendered by gate.sh as "→ fix: …" and appended to verify-initiative.py's "← failed:" note.
_remediation := {
	"component-byte-integrity": "A MODIFIED module means the shipped bytes differ from the SBOM's declared hash (possible same-GUID swap) — rebuild from trusted source and re-attest; if a module is genuinely un-verifiable, add it to data.byte_integrity_exempt with a reviewed reason. Tampering is NEVER exemptable.",
	"binary-hardening": "Rebuild the named DXE-class module(s) with NX_COMPAT set so W^X can be enforced; a missing-NX regression is not exemptable. Only a genuinely un-scannable (e.g. TE-only/compressed) DXE module may be added to data.binary_hardening_exempt with a reviewed reason.",
	"chipsec-posture": "Re-run CHIPSEC against the target and fix any FAILED critical module (bios_wp/secureboot/smm); a config-level FAILED is a real platform-protection gap, not an N/A. Do not ship until the applicable critical modules PASS.",
	"evidence-chain-bound": "Re-generate the multi-subject reconcile attestation so the SBOM-file digest H agrees across SBOM/attestation/provenance AND the attestation's firmware subject equals the firmware anchor D; a mismatch means the evidence is not about these bytes.",
	"signer-identity-pinned": "Re-sign with a trusted keyless identity and add its cert SAN to data.trusted_signer_identities; an unpinned or unverified signer must not be admitted.",
	"vex-adjudicated": "Adjudicate every HIGH/CRITICAL finding with a non-empty VEX justification (data.cve_allowlist) — investigate and fix, or record a reviewed not_affected/rationale; an empty justification does not discharge the finding.",
	"thirdparty-identifiers": "Add the missing purl + license to each named third-party component in the SBOM (S2C2F SCA-2 / CISA license+identifiers); regenerate the SBOM so every vendored component carries both.",
	"slsa-level-floor": "Build the artifact on a hosted/platform builder that emits SLSA provenance at level >= 2 (attest-build-provenance) and verify it with `gh attestation verify`; a level below 2 does not meet the floor.",
	"slsa-provenance": "Enable attest-build-provenance in the build platform and hard-gate `gh attestation verify` before the deploy gate so the SLSA L2 provenance is platform-generated and verified.",
	"component-integrity": "Ensure every hashable (non-library) module carries a cryptographic hash in the SBOM; for a genuinely unhashable artifact (e.g. a raw reset-vector blob) add a reviewed entry to data.hash_exempt — do not ship an unhashed, non-exempt module.",
	"firmware-digest-anchor": "Make the three firmware-byte digests agree — the SBOM metadata digest D, the reconcile re-hash, and the deployed .fd — by rebuilding/re-measuring; an empty leg is a supply-chain gap and a mismatch is a possible swap.",
	"sbom-generation-tool": "Regenerate the SBOM with a generator that records metadata.tools[] carrying a name AND version (e.g. the edk2 '-Y SBOM' BuildReport generator); a tool-less SBOM does not meet the CISA generation-tool element.",
	"sbom-generation-context": "Regenerate the SBOM so metadata.lifecycles[] declares the generation phase (build-time is the gold standard); a context-less SBOM does not meet the CISA generation-context element.",
	"no-kev-component": "Upgrade or remove the named component so it no longer carries the CISA KEV (Known-Exploited) CVE; a plain not_affected does NOT waive a KEV — only an explicit, reviewed exec-risk justification in data.kev_waivers may, and only after human review.",
	"uefi-secure-boot-posture": "Provision + enforce UEFI Secure Boot (PK/KEK/db/dbx, SecureBoot=1, SetupMode=0) so CHIPSEC secureboot.variables PASSES; do not admit an image whose target does not enforce Secure Boot.",
	"platform-protection-posture": "Fix the platform-protection gap so CHIPSEC bios_wp (flash write-protection, 800-147) and smm (SMM isolation, 800-193 §4.2.3) both PASS; a FAILED pillar is a real protection gap (bios_ts/smrr N/A on QEMU is expected).",
	"reconcile-membership": "Reconcile the SBOM against the observed image so every declared module is present and no undeclared artifact appears; investigate any missing or suspicious module before shipping.",
}

_remediation_for(name) := object.get(_remediation, name, "")

_provenance_msg := sprintf(
	"built outside trusted builder/source: builder=%q source=%q",
	[object.get(input, ["provenance", "builder_id"], ""), object.get(input, ["provenance", "source_repo"], "")],
)

_cve_msg := sprintf("%d un-triaged critical CVE(s)", [count(critical_cves)])

# Absent-input guard: with no reconcile section at all, do NOT print "?" placeholders — that reads
# like a computed verdict. Say plainly that the evidence is absent.
default _reconcile_membership_msg := "reconcile evidence absent (no reconcile section supplied) — cannot confirm module membership"

_reconcile_membership_msg := sprintf(
	"reconcile membership incomplete: matched=%v declared=%v missing=%v undeclared=%v",
	[object.get(input, ["reconcile", "matched"], "?"), object.get(input, ["reconcile", "declared"], "?"),
		object.get(input, ["reconcile", "missing_count"], "?"), object.get(input, ["reconcile", "undeclared_observed"], "?")],
) if input.reconcile

# Absent-input guard: with no sbom.integrity section, do NOT print "0 module(s)…[]" — that reads
# like a clean-but-failing verdict. Say plainly that the evidence is absent.
default _integrity_msg := "SBOM integrity evidence absent (no sbom.integrity section supplied) — cannot confirm component hashes"

_integrity_msg := sprintf("%d module(s) lack a hash and are not in data.hash_exempt: %v", [count(_integrity_unresolved), _integrity_unresolved]) if input.sbom.integrity

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

deny contains "evidence chain not bound: SBOM-file digests differ across SBOM/attestation/provenance (H), or the attestation's firmware subject != the firmware anchor D" if not _evidence_chain_bound

deny contains _firmware_anchor_msg if not _firmware_anchored

deny contains _byte_integrity_msg if not _byte_integrity_ok

deny contains _binary_hardening_msg if not _binary_hardening_ok

deny contains _signer_msg if not _signer_pinned

deny contains _build_tools_msg if not _build_tools_ok

deny contains "reconcile failed: SBOM does not match firmware bytes" if not input.reconcile.clean

deny contains "SBOM bytes do not match the signed attestation subject (possible swap after signing)" if {
	input.sbom.hash != input.attestation.file_subject
}

deny contains msg if {
	some c in input.cve.findings
	c.severity == "CRITICAL"
	not data.cve_allowlist[c.id]
	msg := sprintf("critical CVE %s in component %q (not in VEX allowlist)", [c.id, c.component])
}

# BUG FIX: sbom-generation-tool / sbom-generation-context flipped `allow` but produced NO human
# denial bullet. Add the granular deny reasons so an operator sees WHY it was blocked.
deny contains "SBOM declares no generation tool (metadata.tools[] missing, or lacks a name+version)" if not _sbom_gen_tool

deny contains "SBOM declares no generation context (metadata.lifecycles[].phase missing)" if not _sbom_gen_context

# CISA KEV (BOD 22-01): a shipped component carries a Known-Exploited CVE with no exec-risk waiver.
deny contains msg if {
	some c in _kev_hits
	msg := sprintf("CISA KEV: component %q ships Known-Exploited CVE %s (no exec-risk VEX waiver) — remediate on the BOD 22-01 timeline", [c.component, c.id])
}

deny contains _uefi_sb_msg if not _uefi_secure_boot

deny contains _platform_msg if not _platform_protection

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
# "finding" whose status is satisfied / not-satisfied / missing-evidence, derived from
# the reports that satisfy it (data.initiatives, generated from frameworks.yaml). A required
# report ABSENT from the verdict is missing-evidence (a supply-chain gap), matching
# verify-initiative.py's MISSING_EVIDENCE — NOT "not-applicable" (which would imply the control
# does not apply, hiding the gap).
_report_present(name) if {
	some r in verifier_reports
	r.name == name
}

_report_pass(name) if {
	some r in verifier_reports
	r.name == name
	r.isSuccess
}

_control_status(need) := "missing-evidence" if {
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
	# verifiedLevels applies to THIS VSA's subject — the firmware image D. The firmware's own
	# build level is NOT verified (it is not built on a SLSA hosted builder), so the honest
	# machine-readable value is SLSA_BUILD_LEVEL_0. The real L2 fact — the SBOM/attestation
	# ARTIFACT's platform-generated build provenance (E2, hard-gated by `gh attestation verify`
	# in CI) — rides in the separate `evidenceBuildLevel` field, so a standard SLSA-VSA consumer
	# can never machine-read this as "the firmware is L2".
	"verifiedLevels": _levels,
	"evidenceBuildLevel": _evidence_build_level,
	"verifiedLevelsNote": "verifiedLevels is SLSA_BUILD_LEVEL_0: this VSA's subject is the firmware image, whose own SLSA build level is not verified. The SBOM/attestation evidence backing this verdict was itself built at SLSA_BUILD_LEVEL_2 (platform-generated provenance) — see evidenceBuildLevel; the firmware is bound to that evidence via the digest anchor D.",
	# The evidence graph rooted at D: {uri,digest} for each signed evidence attestation
	# (SBOM/provenance/reconcile/VEX/CHIPSEC/build-tools). Empty offline — the CI signing
	# step injects the real bundle digests (they are only known after each blob is signed).
	"inputAttestations": [],
	"slsaVersion": "1.0",
	# --- extensions: the detail the standard VSA summary intentionally omits ---
	"verifierReports": verifier_reports, # per-rule observations (framework-tagged)
	"controlAssessments": control_assessments, # per-framework findings + citations
}

_result := "PASSED" if allow
_result := "FAILED" if not allow

# The gate includes a `slsa-provenance` verifier report, so `allow` implies
# input.provenance.slsa_verified — the SBOM ARTIFACT's provenance was verified at SLSA L2
# (platform-generated via attest-build-provenance + `gh attestation verify`). That fact is
# recorded on `evidenceBuildLevel`. The firmware SUBJECT carries no verified build level, so
# its standard `verifiedLevels` is the honest floor (L0) — never L2.
_levels := ["SLSA_BUILD_LEVEL_0"] if allow
_levels := [] if not allow
_evidence_build_level := "SLSA_BUILD_LEVEL_2" if allow
_evidence_build_level := "SLSA_BUILD_LEVEL_0" if not allow
