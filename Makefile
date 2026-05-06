.PHONY: install install-ai build-curated build-public build-backbone build-canonical build-bundle validate validate-parity validate-canonical test ui preview bootstrap-local-full preprod clean curate curate-dry-run promote

PYTHON ?= python3
UI_DIR := app/navigator-ui

install:
	$(PYTHON) -m pip install -e ".[dev]"
	cd $(UI_DIR) && npm install

install-ai: ## Install AI curation dependencies (requires ANTHROPIC_API_KEY to run)
	$(PYTHON) -m pip install -e ".[ai]"

build-curated:
	$(PYTHON) scripts/knowledge_builder/build_knowledge_base.py

build-public:
	$(PYTHON) scripts/knowledge_builder/build_knowledge_base.py --with-public-sources

build-backbone:
	$(PYTHON) scripts/mapping_builder/apply_mapping_backbone.py --last-good

build-canonical:
	$(PYTHON) scripts/canonical_exports/build_canonical.py

build-bundle: build-curated build-backbone build-canonical

validate: validate-parity validate-canonical

validate-canonical:
	$(PYTHON) scripts/canonical_exports/validate_canonical.py

validate-parity:
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

clean:
	rm -rf data/snapshots $(UI_DIR)/dist

# ── Defense Intelligence Navigator (optional, behind flag) ─────────────────
# Requires: pip install -e ".[ai]"  +  ANTHROPIC_API_KEY env var
# Never modifies data/knowledge-bundle.json or data/mappings/ directly.
# All output goes to data/candidates/{run_id}/ for human review first.

curate: ## Run offline AI curation — scans gaps + proposes candidates via LLM
	$(PYTHON) scripts/intelligence/run_curator.py \
		--bundle data/knowledge-bundle.json \
		--cache-dir data/raw \
		--output-dir data/candidates

curate-dry-run: ## Scan gaps only — no LLM calls, no ANTHROPIC_API_KEY needed
	$(PYTHON) scripts/intelligence/run_curator.py \
		--bundle data/knowledge-bundle.json \
		--cache-dir data/raw \
		--output-dir data/candidates \
		--dry-run

promote: ## Interactive candidate review + promotion to data/mappings/ai_promoted/
	$(PYTHON) scripts/intelligence/promote_candidates.py \
		--candidates-dir data/candidates \
		--output-dir data/mappings/ai_promoted

promote-list: ## List all pending candidates without interactive review
	$(PYTHON) scripts/intelligence/promote_candidates.py \
		--candidates-dir data/candidates \
		--list-only
