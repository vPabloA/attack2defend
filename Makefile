.PHONY: install install-ai build build-curated build-public build-backbone enforce-provenance build-canonical build-bundle mirror-intelligence validate validate-parity validate-canonical validate-provenance validate-static-first validate-product validate-candidates test ui preview bootstrap-local-full preprod sync-cve2capec clean curate curate-dry-run curate-advanced promote promote-list promote-candidates evaluate-golden clean-candidates

PYTHON ?= python3
UI_DIR := app/navigator-ui

install:
	$(PYTHON) -m pip install -e ".[dev]"
	cd $(UI_DIR) && npm install

install-ai: ## Install AI curation dependencies
	$(PYTHON) -m pip install -e ".[ai]"

build: build-bundle mirror-intelligence

build-curated:
	$(PYTHON) scripts/knowledge_builder/build_knowledge_base.py

build-public:
	$(PYTHON) scripts/knowledge_builder/build_knowledge_base.py --with-public-sources

build-backbone:
	$(PYTHON) scripts/mapping_builder/apply_mapping_backbone.py --last-good

enforce-provenance:
	$(PYTHON) scripts/knowledge_builder/enforce_edge_provenance.py --last-good

build-canonical:
	$(PYTHON) scripts/canonical_exports/build_canonical.py

build-bundle: build-curated build-backbone enforce-provenance build-canonical

mirror-intelligence:
	$(PYTHON) scripts/intelligence/mirror_intelligence_artifacts.py

validate: validate-parity validate-canonical

validate-canonical:
	$(PYTHON) scripts/canonical_exports/validate_canonical.py

validate-provenance:
	$(PYTHON) scripts/knowledge_builder/validate_edge_provenance.py data/knowledge-bundle.json

validate-parity: validate-provenance
	$(PYTHON) scripts/knowledge_builder/validate_bundle.py data/knowledge-bundle.json \
		--require-mapping-backbone \
		--require-semantic-routes \
		--require-framework-chain \
		--require-cpe-index \
		--require-kev-index \
		--require-bidirectional-indexes \
		--require-source-confidence \
		--require-search-index \
		--min-mapping-files 1

validate-static-first:
	bash scripts/validate_static_first.sh

validate-candidates:
	$(PYTHON) scripts/intelligence/validate_candidates.py data/candidates

evaluate-golden:
	$(PYTHON) scripts/intelligence/evaluate_golden_routes.py

validate-product: validate mirror-intelligence validate-static-first evaluate-golden

test:
	pytest -q
	cd $(UI_DIR) && npm run build

ui:
	cd $(UI_DIR) && npm run dev

preview:
	cd $(UI_DIR) && npm run build && npm run preview

bootstrap-local-full:
	bash scripts/bootstrap_local_full.sh

preprod:
	bash scripts/bootstrap_preprod.sh

sync-cve2capec:
	bash scripts/sync_cve2capec_raw.sh

clean:
	rm -rf data/snapshots $(UI_DIR)/dist

# ── Defense Intelligence Navigator / Intelligence Factory ─────────────────
# Offline/build-time only. Browser runtime remains static-first.

curate: curate-advanced

curate-advanced: ## Run offline AI curation — scans gaps + proposes candidates via LLM
	$(PYTHON) scripts/intelligence/run_curator.py \
		--bundle data/knowledge-bundle.json \
		--cache-dir data/raw \
		--output-dir data/candidates

curate-dry-run: ## Scan gaps only — no LLM calls, no provider API key needed
	$(PYTHON) scripts/intelligence/run_curator.py \
		--bundle data/knowledge-bundle.json \
		--cache-dir data/raw \
		--output-dir data/candidates \
		--dry-run

promote: promote-candidates

promote-candidates: ## Non-blocking policy promotion to data/mappings/ai_promoted/
	$(PYTHON) scripts/intelligence/promote_candidates.py \
		--candidates-dir data/candidates \
		--output-dir data/mappings/ai_promoted \
		--json-report

promote-list: ## Dry-run candidate processing with policy report
	$(PYTHON) scripts/intelligence/promote_candidates.py \
		--candidates-dir data/candidates \
		--promotion-mode dry_run \
		--json-report

clean-candidates:
	$(PYTHON) scripts/intelligence/clean_candidates.py
