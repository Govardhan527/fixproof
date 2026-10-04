# Every target runs through uv against the committed uv.lock. `make check` is CI minus the
# integration, commit-hygiene and security jobs (those need network, Docker or the push range).

UV_RUN := uv run --frozen

.PHONY: setup check lint type test schemas integration integration-minikube live demo demo-down release-dry

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
	$(UV_RUN) pytest -m integration --force-enable-socket \
		--ignore=tests/integration/test_minikube.py

# Needs a minikube node from `scripts/demo_minikube.sh up WORKDIR RUNTIME` (docker or cri-o) and
# Syft and Grype on PATH, with FIXPROOF_IT_MINIKUBE_KUBECONFIG pointing at
# WORKDIR/reader.kubeconfig and FIXPROOF_IT_MINIKUBE_RUNTIME set to RUNTIME.
integration-minikube:
	$(UV_RUN) pytest -m integration --force-enable-socket tests/integration/test_minikube.py

# Real public images from Docker Hub, read anonymously; needs Syft, Grype and a current Grype DB
# (ADR-0008). Runs weekly in CI (.github/workflows/live.yml).
live:
	$(UV_RUN) pytest -m live --force-enable-socket -v

# The SUCCESS TEST end to end on a local kind cluster (ADR-0013 item 1): needs Docker, curl,
# openssl and uv; about 4 minutes on a CI runner. `make demo-down` removes the cluster.
demo:
	scripts/demo.sh up

demo-down:
	scripts/demo.sh down

# What the release workflow builds (.github/workflows/release.yml), without publishing: the
# wheel and sdist, checked by installing the wheel into a fresh environment, and the SBOM.
release-dry:
	rm -rf dist
	scripts/check_package.sh dist/check
	mv dist/check/dist/* dist/ && rm -rf dist/check
	uv export --frozen --no-dev --no-emit-project --format cyclonedx1.5 \
		--preview-features sbom-export --output-file dist/fixproof.cdx.json > /dev/null
	ls -l dist
