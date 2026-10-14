#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
# =============================================================================
# mint-fixtures.sh - how the protected-header fixtures of cases.json were made
# (fixtures/b*.json and s*.json). Signing is randomised, so running this again writes
# different bytes: the committed files are the fixtures, this script is how to make
# more like them. It signs with the TEST-ONLY keys of tests/vectors/v1/keys, which
# sign nothing real, through tests/lib/mint.py (--header-text: the exact text of the
# protected header, for a header JSON can write more than one way).
#
#   bash tests/web/differential/mint-fixtures.sh
#
# Needs OpenSSL >= 3.5 and python3, as the verifier does.
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
V1="$ROOT/tests/vectors/v1"
FX="$HERE/fixtures"
MINT=(python3 -I "$ROOT/tests/lib/mint.py")

# att NAME HEADER-TEXT: an attestation like v1's valid.json, with this protected header
att() {
  "${MINT[@]}" attest --key "$V1/keys/test-only-issuer.pem" --slug fixture-org --iss https://issuer.test \
    --generated-at 2026-01-01T00:00:00.000Z --expires-at 2026-01-01T00:15:00.000Z \
    --framework iso27001=substantial --framework nis2=basic --header-text "$2" --out "$FX/$1"
}
# status NAME HEADER-TEXT: a status list like v1's empty.json, with this protected header
status() {
  "${MINT[@]}" status --key "$V1/keys/test-only-status.pem" --iss https://issuer.test --seq 7 \
    --issued-at 2026-01-01T00:00:00.000Z --next-update 2026-01-01T02:00:00.000Z --header-text "$2" --out "$FX/$1"
}

A='"alg":"ML-DSA-65"'
K='"kid":"@KID@"'
T='"typ":"application/attest+jws"'

att b1-alg-nul.json '{"alg":"ML-DSA-65\u0000",'"$K,$T"'}'
att b2-kid-lone-surrogate.json '{'"$A"',"kid":"\ud800",'"$T"'}'
att b3-nan-member.json '{'"$A,$K,$T"',"x":NaN}'
PAD="$(python3 -I -c 'print("x" * 5000)')"
att b4-oversize-kid-late.json '{'"$A"',"pad":"'"$PAD"'",'"$K,$T"'}'
att b5-duplicate-alg.json '{"alg":"none",'"$A,$K,$T"'}'
att b6-typ-number.json '{'"$A,$K"',"typ":5}'
att b7-kid-number.json '{'"$A"',"kid":5,'"$T"'}'
att b8-alg-escaped-quote.json '{"alg":"ML-DSA-65\"",'"$K,$T"'}'

# a header split over lines: member name, colon and value on separate lines
att b10-split-lines.json '{"alg"
:
"ML-DSA-65",
'"$K,$T"'}'

# a header nested deep: typ is an empty array inside N-1 more, so the header is N+1 containers
# deep. Up to 64 containers the reader reads it; one more and it does not (no kid). An oversize
# one has a padding member first.
deep() {   # NAME N PAD
  python3 -I - "$FX/.deep.txt" "$2" "$3" <<'PY'
import sys
n, pad = int(sys.argv[2]), int(sys.argv[3])
p = '"pad":"' + "x" * pad + '",' if pad else ""
open(sys.argv[1], "w").write('{"alg":"ML-DSA-65",' + p + '"kid":"@KID@","typ":' + "[" * n + "]" * n + "}")
PY
  att "$1" "@$FX/.deep.txt"
  rm -f "$FX/.deep.txt"
}
deep b11-deep-64-containers.json 63 0
deep b12-deep-65-containers.json 64 0
deep b13-deep-66-containers.json 65 0
deep b14-deep-1001-containers.json 1000 0
deep b15-oversize-deep-64-containers.json 63 5000
deep b16-oversize-deep-65-containers.json 64 5000
deep b17-oversize-deep-1001-containers.json 1000 5000

# a byte that is not UTF-8 in the kid: edited into a signed document, so it is not signed
python3 -I - "$FX/b7-kid-number.json" "$FX/b9-kid-invalid-utf8.json" <<'PY'
import base64, json, sys
d = json.load(open(sys.argv[1]))
h, p, s = d["attestation"]["signature"].split(".")
raw = base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)).replace(b'"kid":5', b'"kid":"\xff"', 1)
d["attestation"]["signature"] = ".".join([base64.urlsafe_b64encode(raw).rstrip(b"=").decode(), p, s])
json.dump(d, open(sys.argv[2], "w"), indent=2)
PY

SA='"alg":"ML-DSA-65"'
ST='"typ":"application/attest-status+jws"'
status s1-alg-number.json '{"alg":5,"kid":"@KID@",'"$ST"'}'
status s2-kid-number.json '{'"$SA"',"kid":5,'"$ST"'}'
