# Fixture images (M2)

Seven Dockerfiles; `scripts/build_fixtures.py` builds and pushes each to the open test registry,
and pushes `requests-2.31.0` a second time to a registry that requires credentials fixproof is
not given, making eight images. Each Dockerfile states its expected verdict for CVE-2023-32681.
Everything is pinned: the base image by digest, each `requests` wheel by SHA-256.
