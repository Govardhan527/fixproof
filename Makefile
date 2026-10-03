# Every target runs through uv against the committed uv.lock. `make check` is CI minus the
# integration, commit-hygiene and security jobs (those need network, Docker or the push range).

UV_RUN := uv run --frozen

.PHONY: setup check lint type test schemas integration live demo release-dry

setup:
	uv sync --locked
	git config core.hooksPath scripts/hooks

check: lint type test schemas

lint:
	$(UV_RUN) ruff check .
	$(UV_RUN) ruff format --check .

type:
	$(UV_RUN) mypy --strict src scripts

test:
	$(UV_RUN) pytest -m "not integration and not live" --cov=src --cov-fail-under=85

schemas:
	$(UV_RUN) python scripts/validate_outputs.py

# Needs the demo cluster from `scripts/demo_cluster.sh up WORKDIR` (registries, fixture images,
# kind) and Syft and Grype on PATH, with FIXPROOF_IT_IMAGES and FIXPROOF_IT_KUBECONFIG pointing at
# WORKDIR/fixture-images.json and WORKDIR/reader.kubeconfig. Without them the tests skip locally
# and fail in CI.
integration:
	$(UV_RUN) pytest -m integration --force-enable-socket

# Real public images from Docker Hub, read anonymously; needs Syft, Grype and a current Grype DB
# (ADR-0008). Runs weekly in CI (.github/workflows/live.yml).
live:
	$(UV_RUN) pytest -m live --force-enable-socket -v

demo:
	@echo "make demo: the SUCCESS TEST demo lands in M6 (step 3 needs the M5 gate; see docs/PROGRESS.md); nothing ran" >&2
	@exit 1

release-dry:
	rm -rf dist
	uv build --no-sources
	uv export --frozen --no-dev --format cyclonedx1.5 --output-file dist/fixproof.cdx.json > /dev/null
	ls -l dist
