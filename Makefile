# firmware-sbom-supplychain — entry points.
# `make help` lists targets. The self-contained targets (test, coverage) need
# only opa + jq + python3(+PyYAML); the full demo also needs cosign + grype.

SHELL := /bin/bash
ROOT  := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
FIX   := $(ROOT)oss-lane/fixtures
VSA   := /tmp/fw-vsa.json

.DEFAULT_GOAL := help

.PHONY: help
help: ## List targets
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: deps
deps: ## Install Python deps (hash-pinned PyYAML + pefile) + fetch pinned opa (SHA-verified)
	pip install --require-hashes -r requirements.txt
	ONLY=opa bash scripts/fetch-tools.sh

.PHONY: bin
bin: ## Fetch + SHA-verify ALL pinned CLI tools (opa, cosign, grype) into bin/ — needed for `make demo`
	bash scripts/fetch-tools.sh

.PHONY: test
test: ## Gate honesty tests (opa+jq) + assembler + byte-integrity unit tests + cosign-native policy
	bash tests/run.sh
	python3 tests/test_assemble.py
	python3 tests/test_byte_integrity.py
	python3 tests/test_attack_demo.py
	python3 tests/test_reconcile.py
	python3 tests/test_chipsec.py
	python3 tests/test_interop.py
	python3 tests/test_initiatives_sync.py
	bash tests/cosign-policy.sh

.PHONY: coverage
coverage: ## Per-framework, per-control coverage from a fresh signed VSA (opa+python+PyYAML)
	@VSA_OUT=$(VSA) bash oss-lane/gate.sh $(FIX)/clean.json >/dev/null
	@python3 oss-lane/verify-initiative.py --vsa $(VSA)

.PHONY: gate
gate: ## Run the gate on one fixture: make gate FIXTURE=oss-lane/fixtures/clean.json
	bash oss-lane/gate.sh $(or $(FIXTURE),$(FIX)/clean.json)

.PHONY: verify
verify: ## Consumer CLI on your firmware: make verify FW=<image.fd> VSA=<vsa.json>
	@test -n "$(FW)" || { echo "usage: make verify FW=<image.fd> [VSA=<vsa.json>]"; exit 2; }
	cli/fw-supplychain-verify --firmware "$(FW)" $(if $(VSA),--vsa "$(VSA)",)

.PHONY: demo
demo: ## Full OSS lane end to end (needs cosign + grype + opa)
	bash oss-lane/run.sh

.PHONY: reconcile
reconcile: ## Carve a real image + reconcile: make reconcile EDK2=<tree> IMG=<image.fd>
	@test -n "$(EDK2)" -a -n "$(IMG)" || { echo "usage: make reconcile EDK2=<edk2 tree> IMG=<image.fd>"; exit 2; }
	EDK2=$(EDK2) bash producers/reconcile/carve.sh $(IMG)

.PHONY: attack-demo
attack-demo: ## "Same-GUID trojan caught": byte-tamper a real module under its GUID; real producer -> MODIFIED -> gate DENY. Add FW_IMAGE=<OVMF.fd> EDK2=<tree> for the full real-image run.
	OPA=$(or $(OPA),$(ROOT)bin/opa) bash scripts/attack-demo.sh

.PHONY: byte-integrity
byte-integrity: ## Regenerate byte-integrity: make byte-integrity EDK2=<tree> IMG=<image.fd> (needs pefile+FMMT, ~6min)
	@test -n "$(EDK2)" -a -n "$(IMG)" || { echo "usage: make byte-integrity EDK2=<edk2 tree> IMG=<image.fd>"; exit 2; }
	python3 producers/reconcile/byte-integrity.py --sbom inputs/sbom.cdx.json --image "$(IMG)" --edk2 "$(EDK2)" -o inputs/byte-integrity.json

.PHONY: clean
clean: ## Remove generated local artifacts (keys, gate inputs, VSAs)
	rm -f inputs/gate-input.json inputs/sbom.att.bundle inputs/build-tools.cdx.json $(VSA) inputs/grype.json
	rm -rf oss-lane/.keys
