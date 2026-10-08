# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
#
# The verifier as a container image. Built by .github/workflows/image.yml, from
# a release's own, already verified verify-attestation.sh: the build context
# holds that one file, and SCRIPT_SHA256 (from the release's SHA256SUMS) is
# checked again below, so a wrong file fails the build.
#
# The base is debian:trixie-slim, pinned by digest. The same digest is pinned in
# README.md and the workflows; change them all in the same commit
# (tests/container.sh fails if they differ).
FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a

ARG SCRIPT_SHA256
ARG VERSION=unknown
ARG REVISION=unknown

# Debian 13 ships OpenSSL 3.5, the first release with ML-DSA (FIPS 204). The
# packages come from Debian's archive at build time, so they carry its security
# updates up to the day of the build; the image is not rebuilt afterwards.
# hadolint ignore=DL3008
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends openssl python3 jq \
 && rm -rf /var/lib/apt/lists/*

COPY verify-attestation.sh /usr/local/bin/verify-attestation.sh

# Fail the build unless the script in the context is the one SCRIPT_SHA256 names.
RUN test -n "${SCRIPT_SHA256}" \
 && echo "${SCRIPT_SHA256}  /usr/local/bin/verify-attestation.sh" | sha256sum -c - \
 && chmod 0755 /usr/local/bin/verify-attestation.sh

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin verifier
USER 10001
WORKDIR /work

LABEL org.opencontainers.image.title="hodeishield-attest-verifier" \
      org.opencontainers.image.description="Offline verifier for HodeiShield posture attestations" \
      org.opencontainers.image.source="https://github.com/Hodeitek/hodeishield-attest-verifier" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      com.hodeitek.verifier.script-sha256="${SCRIPT_SHA256}"

ENTRYPOINT ["/usr/local/bin/verify-attestation.sh"]
