"""Build the M2 fixture images, push them to the test registries, and record their digests.

    build_fixtures.py --registry localhost:5001 --auth-registry localhost:5002 --out images.json

scripts/demo_cluster.sh runs it with the demo cluster's registries.

Each directory under tests/fixtures/images/ is built and pushed to `--registry` (open). The
`requests-2.31.0` image is built once more with an extra label and pushed to `--auth-registry`,
which needs credentials: log in with `docker login` first. fixproof is then run without them,
so that image must come out `unknown` (ADR-0007 item 9). The label gives it a digest of its own:
a node holding the same digest under both registries may report either name as the pod's
`imageID` (SPEC_NOTES §12), and then fixproof would read the open copy. Needs Docker. The output
maps each fixture name, plus `auth/requests-2.31.0`, to its `registry/repository@sha256:...`
reference.
"""

import argparse
import json
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

FIXTURES = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "images"
AUTH_FIXTURE = "requests-2.31.0"


def docker(*args: str) -> str:
    done = subprocess.run(["docker", *args], capture_output=True, text=True, check=False)
    if done.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args)} failed: {done.stderr.strip()}")
    return done.stdout.strip()


def push(tag: str, registry: str) -> str:
    """Push `tag` and return its `registry/repository@digest` reference in `registry`."""
    docker("push", "--quiet", tag)
    digests = json.loads(docker("image", "inspect", "--format", "{{json .RepoDigests}}", tag))
    for reference in digests:
        if reference.startswith(registry + "/"):
            return str(reference)
    raise RuntimeError(f"no digest for {tag} in {registry} after push: {digests}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build and push the fixture images.")
    parser.add_argument("--registry", required=True, help="open registry, e.g. localhost:5000")
    parser.add_argument("--auth-registry", required=True, help="registry needing credentials")
    parser.add_argument("--out", type=Path, required=True, help="where to write the digests")
    args = parser.parse_args(argv)

    references: dict[str, str] = {}
    for directory in sorted(p for p in FIXTURES.iterdir() if p.is_dir()):
        tag = f"{args.registry}/fixproof/{directory.name}:it"
        docker("build", "--quiet", "--tag", tag, str(directory))
        references[directory.name] = push(tag, args.registry)
        print(f"{directory.name}: {references[directory.name]}")
    auth_tag = f"{args.auth_registry}/fixproof/{AUTH_FIXTURE}:it"
    docker(
        "build", "--quiet", "--label", "fixproof.fixture.registry=auth", "--tag", auth_tag,
        str(FIXTURES / AUTH_FIXTURE),
    )  # fmt: skip
    references[f"auth/{AUTH_FIXTURE}"] = auth = push(auth_tag, args.auth_registry)
    digest = auth.partition("@")[2]
    shared = [name for name, ref in references.items() if ref != auth and ref.endswith(digest)]
    if shared:
        raise RuntimeError(f"the auth-registry image has the same digest as {shared}")
    print(f"auth/{AUTH_FIXTURE}: {references[f'auth/{AUTH_FIXTURE}']}")
    args.out.write_text(json.dumps(references, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
