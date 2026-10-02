# fixproof M2 fixture (ADR-0007 item 9): requests 2.25.1, an older vulnerable release
# CVE-2023-32681 affects requests >= 2.3.0, < 2.31.0 (SPEC_NOTES §17). Expected verdict: still_affected.
FROM python:3.12-slim-bookworm@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-deps --require-hashes -r /tmp/requirements.txt && rm /tmp/requirements.txt
