#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
# =============================================================================
# tests/sbom.sh - the SBOM that release.yml publishes for verify-attestation.sh.
#
# Runs .github/scripts/generate-sbom.sh on the script in this repository and
# checks that the output is JSON, SPDX 2.3, carries the script's sha256, its
# VERIFIER_VERSION, the licence and the supplier, lists every runtime
# requirement with the minimum versions README.md states, takes its date from
# SOURCE_DATE_EPOCH, and is byte-identical on a second run. Also checks that
# the generator refuses to run without SOURCE_DATE_EPOCH (it must not fall
# back to the clock). Offline. Needs bash, coreutils and python3.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GEN="$ROOT/.github/scripts/generate-sbom.sh"
SCRIPT="$ROOT/scripts/attest/verify-attestation.sh"
README="$ROOT/README.md"

fail() { printf 'not ok - %s\n' "$*" >&2; exit 1; }
ok() { printf 'ok - %s\n' "$*"; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

EPOCH=1760200382 # 2025-10-11T16:33:02Z
env -u SOURCE_DATE_EPOCH bash "$GEN" "$SCRIPT" >"$tmp/a" 2>/dev/null && fail "the generator ran without SOURCE_DATE_EPOCH"
ok "the generator refuses to run without SOURCE_DATE_EPOCH"

SOURCE_DATE_EPOCH=$EPOCH bash "$GEN" "$SCRIPT" >"$tmp/a"
SOURCE_DATE_EPOCH=$EPOCH bash "$GEN" "$SCRIPT" >"$tmp/b"
cmp -s "$tmp/a" "$tmp/b" || fail "two runs gave different bytes"
ok "two runs give identical bytes"

version="$(sed -n 's/^VERIFIER_VERSION="\([0-9.]*\)"$/\1/p' "$SCRIPT")"
[ -n "$version" ] || fail "no VERIFIER_VERSION in the script"
sum="$(sha256sum "$SCRIPT" | cut -d' ' -f1)"

# The README must state the minimums the SBOM declares (backticks are literal).
grep -qF "| \`bash\` ≥ 4 |" "$README" || fail "README.md no longer states bash ≥ 4 in that form"
grep -qF "| **\`openssl\` ≥ 3.5** |" "$README" || fail "README.md no longer states openssl ≥ 3.5 in that form"
grep -qF "| \`cosign\` ≥ 3.1.3 |" "$README" || fail "README.md no longer states cosign ≥ 3.1.3 in that form"

python3 -I - "$tmp/a" "$version" "$sum" "$EPOCH" <<'PY' || fail "the SBOM is wrong (see above)"
import json
import sys

path, version, sha, epoch = sys.argv[1:5]
with open(path, "rb") as fh:
    raw = fh.read()
assert raw.endswith(b"\n") and not raw.endswith(b"\n\n"), "one trailing newline"
d = json.loads(raw)  # valid JSON
assert d["spdxVersion"] == "SPDX-2.3", d["spdxVersion"]
assert d["SPDXID"] == "SPDXRef-DOCUMENT"
assert d["dataLicense"] == "CC0-1.0"
assert d["creationInfo"]["created"] == "2025-10-11T16:33:02Z", d["creationInfo"]["created"]
assert d["documentNamespace"].startswith("https://") and ("/v" + version + "/") in d["documentNamespace"]

pk = {p["SPDXID"]: p for p in d["packages"]}
assert len(pk) == len(d["packages"]), "duplicate SPDXID"
main = pk["SPDXRef-Package-verify-attestation.sh"]
assert main["name"] == "verify-attestation.sh"
assert main["versionInfo"] == version, main["versionInfo"]
assert main["checksums"] == [{"algorithm": "SHA256", "checksumValue": sha}], main["checksums"]
assert main["licenseDeclared"] == "Apache-2.0" and main["licenseConcluded"] == "Apache-2.0"
assert main["supplier"] == "Organization: Hodeitek S.L."

rel = {(r["spdxElementId"], r["relationshipType"], r["relatedSpdxElement"]) for r in d["relationships"]}
assert ("SPDXRef-DOCUMENT", "DESCRIBES", main["SPDXID"]) in rel
want = {  # name: (relationship, minimum stated in README.md)
    "bash": ("RUNTIME_DEPENDENCY_OF", "minimum version: 4;"),
    "openssl": ("RUNTIME_DEPENDENCY_OF", "minimum version: 3.5;"),
    "python3": ("RUNTIME_DEPENDENCY_OF", "no minimum version;"),
    "curl": ("OPTIONAL_DEPENDENCY_OF", "no minimum version;"),
    "cosign": ("OPTIONAL_DEPENDENCY_OF", "minimum version: 3.1.3;"),
}
for name, (kind, comment) in want.items():
    p = pk["SPDXRef-Package-" + name]
    assert p["name"] == name
    assert p["comment"].startswith(comment), (name, p["comment"])
    assert (p["SPDXID"], kind, main["SPDXID"]) in rel, (name, kind)
assert "jq" not in {p["name"] for p in d["packages"]}, "jq is not a requirement"
assert len(d["packages"]) == 1 + len(want), "unexpected package"
for r in d["relationships"]:
    assert r["spdxElementId"] in pk or r["spdxElementId"] == "SPDXRef-DOCUMENT"
    assert r["relatedSpdxElement"] in pk
PY
ok "valid SPDX-2.3 JSON: sha256, version $version, Apache-2.0, supplier, created from SOURCE_DATE_EPOCH, requirements with README minimums"

# A different commit date changes only the date.
SOURCE_DATE_EPOCH=$((EPOCH + 86400)) bash "$GEN" "$SCRIPT" >"$tmp/c"
diff <(grep -v '"created"' "$tmp/a") <(grep -v '"created"' "$tmp/c") >/dev/null || fail "the date changed more than the date"
cmp -s "$tmp/a" "$tmp/c" && fail "the date did not change the output"
ok "the commit date is the only thing that varies"
