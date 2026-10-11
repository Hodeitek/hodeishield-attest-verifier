#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
# =============================================================================
# .github/scripts/generate-sbom.sh - write the SPDX JSON SBOM of
# verify-attestation.sh to standard output.
#
#   SOURCE_DATE_EPOCH=<unix time> generate-sbom.sh [SCRIPT]
#
# SCRIPT defaults to scripts/attest/verify-attestation.sh. The release workflow
# sets SOURCE_DATE_EPOCH to the date of the tagged commit
# (`git log -1 --format=%ct`); the wall clock is never read, so the same
# script and the same commit date give a byte-identical file. The version is
# the script's VERIFIER_VERSION. Needs bash and python3 (standard library only).
#
# The package is the script (name, version, sha256, licence, supplier). Its
# runtime requirements are separate packages, related to it as runtime or
# optional dependencies, with the minimum versions README.md states in "What you
# need installed". SPDX has no field for a version range, so a minimum is in the
# package's comment. Used by .github/workflows/release.yml;
# tests/sbom.sh checks the output.
# =============================================================================
set -euo pipefail

script="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/scripts/attest/verify-attestation.sh}"
[ -f "$script" ] || { echo "generate-sbom.sh: no such file: $script" >&2; exit 2; }
[[ "${SOURCE_DATE_EPOCH:-}" =~ ^[0-9]{1,12}$ ]] \
  || { echo "generate-sbom.sh: SOURCE_DATE_EPOCH must be a Unix time in seconds" >&2; exit 2; }

exec python3 -I - "$script" "$SOURCE_DATE_EPOCH" <<'PY'
import datetime
import hashlib
import json
import re
import sys

REPO = "Hodeitek/hodeishield-attest-verifier"
SUPPLIER = "Organization: Hodeitek S.L."

path, epoch = sys.argv[1], int(sys.argv[2])
with open(path, "rb") as fh:
    data = fh.read()
m = re.search(rb'^VERIFIER_VERSION="([0-9]+\.[0-9]+\.[0-9]+)"$', data, re.M)
if not m:
    sys.exit("generate-sbom.sh: no VERIFIER_VERSION=\"X.Y.Z\" line in " + path)
version = m.group(1).decode()
created = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
base = "https://github.com/" + REPO


def dep(spdx_id, name, description, comment):
    return {
        "SPDXID": spdx_id,
        "name": name,
        "description": description,
        "comment": comment,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "supplier": "NOASSERTION",
    }


# (id, name, kind, description, minimum version stated in README.md)
deps = [
    ("bash", "bash", "RUNTIME", "The shell the script is written for. Not POSIX sh.", "4"),
    ("openssl", "openssl", "RUNTIME", "OpenSSL with ML-DSA-65 (FIPS 204). LibreSSL does not qualify.", "3.5"),
    ("python3", "python3", "RUNTIME", "Standard library only. Re-derives the signed bytes from the JSON.", None),
    ("curl", "curl", "OPTIONAL", "Only to fetch --status and --status-keys given as URLs.", None),
    ("cosign", "cosign", "OPTIONAL", "Only for --anchor-file.", "3.1.3"),
]
main_id = "SPDXRef-Package-verify-attestation.sh"
packages = [{
    "SPDXID": main_id,
    "name": "verify-attestation.sh",
    "versionInfo": version,
    "description": "Offline verifier for HodeiShield posture attestations.",
    "downloadLocation": base + "/releases/download/v" + version + "/verify-attestation.sh",
    "homepage": base,
    "filesAnalyzed": False,
    "checksums": [{"algorithm": "SHA256", "checksumValue": hashlib.sha256(data).hexdigest()}],
    "licenseConcluded": "Apache-2.0",
    "licenseDeclared": "Apache-2.0",
    "copyrightText": "Copyright 2026 Hodeitek S.L.",
    "supplier": SUPPLIER,
    "originator": SUPPLIER,
    "primaryPackagePurpose": "APPLICATION",
}]
relationships = [{
    "spdxElementId": "SPDXRef-DOCUMENT",
    "relationshipType": "DESCRIBES",
    "relatedSpdxElement": main_id,
}]
for key, name, kind, desc, minimum in deps:
    sid = "SPDXRef-Package-" + key
    comment = ("minimum version: " + minimum) if minimum else "no minimum version"
    comment += "; " + ("required" if kind == "RUNTIME" else "optional")
    packages.append(dep(sid, name, desc, comment))
    relationships.append({
        "spdxElementId": sid,
        "relationshipType": kind + "_DEPENDENCY_OF",
        "relatedSpdxElement": main_id,
    })

doc = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "verify-attestation.sh " + version,
    "documentNamespace": base + "/releases/download/v" + version + "/verify-attestation.sh.spdx.json",
    "creationInfo": {
        "created": created,
        "creators": [SUPPLIER, "Tool: .github/scripts/generate-sbom.sh"],
    },
    "packages": packages,
    "relationships": relationships,
}
sys.stdout.write(json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=True) + "\n")
PY
