#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
# =============================================================================
# tests/run.sh — offline acceptance tests for scripts/attest/verify-attestation.sh
#
# A verifier that has only ever printed PASS has told you nothing. Every case
# below mints its own documents with a throwaway ML-DSA-65 key
# (tests/lib/mint.py, which re-implements the issuer side independently of the
# script), runs the verifier, and asserts TWO things:
#
#   1. the exit code (0 verified/good, 1 failed/revoked, 2 could not check,
#      3 revocation status unknown), and
#   2. the line of verifier output that says WHY. A rejection for the wrong
#      reason is a bug too: a tampered document that happens to fail on its age
#      would hide a signature check that no longer works.
#
# The expected lines are quoted from the verifier's own source; grep them there
# before changing one.
#
# It finishes by running the published test vectors (tests/vectors.sh) and the
# signature-disabled mutant check (tests/mutants.sh), and fails if any part
# fails. The mutant check can be skipped locally with VERIFIER_SKIP_MUTANTS=1,
# but CI always runs it and fails if the variable is set there.
#
# Needs: bash >= 4, OpenSSL >= 3.5, python3, jq. No network.
#   bash tests/run.sh                    # the script in this repository
#   VERIFIER=/path/to/copy bash tests/run.sh
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERIFIER="${VERIFIER:-$ROOT/scripts/attest/verify-attestation.sh}"
MINT=(python3 -I "$ROOT/tests/lib/mint.py")

T="$(mktemp -d)"; chmod 700 "$T"
trap 'rm -rf -- "$T"' EXIT

ISS='https://issuer.test'
SLUG='fixture-org'
GEN='2026-01-01T00:00:00.000Z'
EXP='2026-01-01T00:15:00.000Z'
NOW=1767225900            # GEN + 5 min: inside the validity window
NOW_LATE=1767312000       # GEN + 1 day: long expired

PASSED=0; FAILED=0; SKIPPED=0

# expect CODE PATTERN NAME -- verifier args...
expect() {
  local want="$1" pattern="$2" name="$3"; shift 4
  local out="$T/out.$((PASSED + FAILED))" got
  LAST_OUT="$out"
  NO_COLOR=1 bash "$VERIFIER" "$@" > "$out" 2>&1
  got=$?
  if [ "$got" -ne "$want" ]; then
    printf 'not ok - %s (exit %s, expected %s)\n' "$name" "$got" "$want"
    sed 's/^/    # /' "$out"
    FAILED=$((FAILED + 1))
  elif ! grep -qF -- "$pattern" "$out"; then
    printf 'not ok - %s (exit %s as expected, but no line containing: %s)\n' "$name" "$got" "$pattern"
    sed 's/^/    # /' "$out"
    FAILED=$((FAILED + 1))
  else
    printf 'ok - %s (exit %s: %s)\n' "$name" "$got" "$pattern"
    PASSED=$((PASSED + 1))
  fi
}

# lacks PATTERN NAME — the output of the previous expect() has NO line
# containing PATTERN. For verdicts that must not be confused with each other.
lacks() {
  local out="$LAST_OUT"
  if grep -qF -- "$1" "$out"; then
    printf 'not ok - %s (output contains: %s)\n' "$2" "$1"
    sed 's/^/    # /' "$out"
    FAILED=$((FAILED + 1))
  else
    printf 'ok - %s (no line containing: %s)\n' "$2" "$1"
    PASSED=$((PASSED + 1))
  fi
}

# edit IN OUT PYTHON — rewrite a JSON document; `d` is the parsed document.
edit() {
  python3 -I - "$1" "$2" "$3" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
exec(sys.argv[3])
json.dump(d, open(sys.argv[2], "w"), indent=2)
PY
}

# edit_text IN OUT PYTHON — rewrite the raw TEXT of a file; `t` is its content.
# For what a JSON round-trip cannot express, such as duplicate members.
edit_text() {
  python3 -I - "$1" "$2" "$3" <<'PY'
import sys
t = open(sys.argv[1]).read()
exec(sys.argv[3])
open(sys.argv[2], "w").write(t)
PY
}

# --- keys ---------------------------------------------------------------------
"${MINT[@]}" keygen --out "$T/issuer.pem"  --jwks "$T/jwks.json"        >/dev/null
"${MINT[@]}" keygen --out "$T/other.pem"   --jwks "$T/other-jwks.json"  >/dev/null
"${MINT[@]}" keygen --out "$T/status.pem"  --jwks "$T/status-keys.json" >/dev/null
ISSUER_KID="$(jq -r '.keys[0].kid' "$T/jwks.json")"

mint_attest() { "${MINT[@]}" attest --key "$T/issuer.pem" --slug "$SLUG" --iss "$ISS" \
  --generated-at "$GEN" --expires-at "$EXP" \
  --framework iso27001=substantial --framework nis2=basic "$@"; }

mint_attest --out "$T/att.json"
jq -r '.attestation.signature' "$T/att.json" > "$T/att.jws"
jq    '.attestation.claims'    "$T/att.json" > "$T/claims.json"

COMMON=(--jwks "$T/jwks.json" --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$NOW")

echo '# posture attestation'

expect 0 'VERIFIED — this document was signed' 'genuine document verifies' -- \
  --attestation "$T/att.json" "${COMMON[@]}"

expect 0 'VERIFIED — this document was signed' 'genuine document verifies from --jws + --claims' -- \
  --jws "$T/att.jws" --claims "$T/claims.json" "${COMMON[@]}"

edit "$T/att.json" "$T/tampered-field.json" 'd["attestation"]["claims"]["overallBand"] = "advanced"'
expect 1 'SIGNATURE DOES NOT VERIFY' 'a signed field changed after signing is rejected' -- \
  --attestation "$T/tampered-field.json" "${COMMON[@]}"

edit "$T/att.json" "$T/tampered-sig.json" '
h, p, s = d["attestation"]["signature"].split(".")
s = ("B" if s[100] == "A" else "A").join([s[:100], s[101:]])
d["attestation"]["signature"] = ".".join([h, p, s])'
expect 1 'SIGNATURE DOES NOT VERIFY' 'a manipulated signature is rejected' -- \
  --attestation "$T/tampered-sig.json" "${COMMON[@]}"

edit "$T/att.json" "$T/reordered-header.json" '
import base64, json as j
h, p, s = d["attestation"]["signature"].split(".")
hdr = j.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))
h2 = base64.urlsafe_b64encode(j.dumps(dict(reversed(list(hdr.items()))), separators=(",", ":")).encode()).rstrip(b"=").decode()
d["attestation"]["signature"] = ".".join([h2, p, s])'
expect 1 'SIGNATURE DOES NOT VERIFY' 'a re-serialised (reordered) protected header is rejected' -- \
  --attestation "$T/reordered-header.json" "${COMMON[@]}"

"${MINT[@]}" attest --key "$T/issuer.pem" --slug "$SLUG" --iss 'https://other-issuer.test' \
  --generated-at "$GEN" --expires-at "$EXP" --framework iso27001=basic --out "$T/other-iss.json"
expect 1 'issuer_mismatch' 'a document from another issuer is rejected by --expect-issuer' -- \
  --attestation "$T/other-iss.json" "${COMMON[@]}"

"${MINT[@]}" attest --key "$T/issuer.pem" --slug "$SLUG" --iss '' \
  --generated-at "$GEN" --expires-at "$EXP" --framework iso27001=basic --out "$T/empty-iss.json"
expect 1 "iss_empty — iss (E2) is empty" 'a signed but empty iss is a failed check (1) without --expect-issuer' -- \
  --attestation "$T/empty-iss.json" --jwks "$T/jwks.json" --expect-slug "$SLUG" --now "$NOW"
lacks 'VERIFIED —' 'a document with an empty iss never ends VERIFIED'
expect 1 'iss_empty' 'a signed but empty iss is a failed check (1) with --expect-issuer too' -- \
  --attestation "$T/empty-iss.json" "${COMMON[@]}"

expect 1 "not the expected 'another-org'" 'a document for another slug is rejected by --expect-slug' -- \
  --attestation "$T/att.json" --jwks "$T/jwks.json" --expect-slug another-org --expect-issuer "$ISS" --now "$NOW"

expect 1 'EXPIRED' 'an expired document is rejected' -- \
  --attestation "$T/att.json" --jwks "$T/jwks.json" --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$NOW_LATE"

# Expired and tampered both exit 1, but must never read the same (#32): a
# genuine document past its expiry says the signature is valid and how to get
# a new one; a tampered one keeps "Do not rely on this document".
expect 1 "EXPIRED — the signature is valid, but this attestation expired on $EXP." \
  'a genuine expired document says so in its last line (exit 1)' -- \
  --attestation "$T/att.json" --jwks "$T/jwks.json" --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$NOW_LATE"
lacks 'VERIFICATION FAILED' 'a genuine expired document is not reported as a failed verification'
expect 1 "curl -fsS $ISS/api/public/attest/$SLUG -o att.json" \
  'a genuine expired document names the command to fetch a new one' -- \
  --attestation "$T/att.json" --jwks "$T/jwks.json" --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$NOW_LATE"
expect 1 'VERIFICATION FAILED' 'a tampered expired document is still a failed verification (exit 1)' -- \
  --attestation "$T/tampered-field.json" --jwks "$T/jwks.json" --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$NOW_LATE"
lacks 'the signature is valid' 'a tampered expired document never says its signature is valid'
expect 1 'VERIFICATION FAILED' 'an expired document for another slug is a failed verification, not just expired' -- \
  --attestation "$T/att.json" --jwks "$T/jwks.json" --expect-slug another-org --expect-issuer "$ISS" --now "$NOW_LATE"
lacks 'the signature is valid' 'an expired document for another slug never says only that it expired'
expect 1 'EXPIRED — the signature is valid, but this attestation was generated on' \
  'a genuine document older than --max-age-seconds but unexpired says so (exit 1)' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --max-age-seconds 60
lacks 'VERIFICATION FAILED' 'a genuine document that is only too old is not reported as a failed verification'

mint_attest --out "$T/long-ttl.json" --expires-at '2026-01-01T02:00:00.000Z'
expect 1 "above the issuer's" 'a validity window above the 1 h issuer ceiling is rejected' -- \
  --attestation "$T/long-ttl.json" "${COMMON[@]}"
# The ceiling is compared as exact instants: in whole seconds, a window under a
# second over it passed.
mint_attest --out "$T/ttl-frac.json" --expires-at '2026-01-01T01:00:00.500Z'
expect 1 "validity window is 3600.5s (expiresAt - generatedAt), above the issuer's" 'a validity window 0.5 s over the ceiling is rejected' -- \
  --attestation "$T/ttl-frac.json" "${COMMON[@]}"
mint_attest --out "$T/ttl-frac2.json" --generated-at '2026-01-01T00:00:00.900Z' --expires-at '2026-01-01T01:00:00.950Z'
expect 1 "validity window is 3600.05s (expiresAt - generatedAt), above the issuer's" 'a validity window 0.05 s over the ceiling, with a fractional generatedAt, is rejected' -- \
  --attestation "$T/ttl-frac2.json" "${COMMON[@]}"
mint_attest --out "$T/ttl-exact.json" --generated-at '2026-01-01T00:00:00.900Z' --expires-at '2026-01-01T01:00:00.900Z'
expect 0 "validity window 3600s is within the issuer's 3600s ceiling" 'a validity window of exactly the ceiling passes' -- \
  --attestation "$T/ttl-exact.json" "${COMMON[@]}"

expect 1 'not_yet_valid' 'a document dated beyond the 5 min clock-skew allowance is rejected' -- \
  --attestation "$T/att.json" --jwks "$T/jwks.json" --expect-slug "$SLUG" --expect-issuer "$ISS" --now 1767225000
# The skew is compared as exact instants: in whole seconds, a generatedAt up to a
# second beyond it passed. NOW is 00:05:00, so 00:10:00.000 is exactly the skew.
mint_attest --out "$T/ahead-frac.json" --generated-at '2026-01-01T00:10:00.500Z' --expires-at '2026-01-01T00:25:00.500Z'
expect 1 'not_yet_valid — generatedAt is 300.5s in the future' 'a generatedAt 0.5 s beyond the clock-skew allowance is rejected' -- \
  --attestation "$T/ahead-frac.json" "${COMMON[@]}"
mint_attest --out "$T/ahead-exact.json" --generated-at '2026-01-01T00:10:00.000Z' --expires-at '2026-01-01T00:25:00.000Z'
expect 0 'VERIFIED — this document was signed' 'a generatedAt exactly at the clock-skew allowance passes' -- \
  --attestation "$T/ahead-exact.json" "${COMMON[@]}"

mint_attest --out "$T/bad-date.json" --generated-at 'the first of january'
expect 1 "could not parse generatedAt" 'a signed but unparseable generatedAt is rejected, not skipped' -- \
  --attestation "$T/bad-date.json" "${COMMON[@]}"

mint_attest --out "$T/extra-header.json" --header 'x5u=https://keys.example'
expect 1 'header members are' 'a signed protected header outside {alg, kid, typ} is rejected' -- \
  --attestation "$T/extra-header.json" "${COMMON[@]}"

mint_attest --out "$T/nonce.json" --nonce 'challenge-A'
expect 1 'nonce_mismatch' 'a document answering another challenge is rejected' -- \
  --attestation "$T/nonce.json" "${COMMON[@]}" --expect-nonce 'challenge-B'
expect 0 'echoes your challenge verbatim' 'a document answering your challenge verifies' -- \
  --attestation "$T/nonce.json" "${COMMON[@]}" --expect-nonce 'challenge-A'

mint_attest --out "$T/overclaim.json" --overall-band advanced
expect 1 'overall_band_mismatch' 'a signed overallBand stronger than the weakest framework is rejected' -- \
  --attestation "$T/overclaim.json" "${COMMON[@]}"

expect 2 'no key in this JWKS carries kid' 'an unknown kid is "could not check" (2), not a forgery (1)' -- \
  --attestation "$T/att.json" --jwks "$T/other-jwks.json" --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$NOW"

edit "$T/other-jwks.json" "$T/mislabelled-jwks.json" "d['keys'][0]['kid'] = '$ISSUER_KID'"
expect 1 'kid mismatch — header says' 'a key published under a kid its bytes do not derive is rejected' -- \
  --attestation "$T/att.json" --jwks "$T/mislabelled-jwks.json" --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$NOW"

# --expect-kid (#13): pin the key that signed. It is compared with the kid
# recomputed from the key bytes, never with a label. It is a usage error when it
# is not the shape of a kid, and it is not --check-kid (the status-list lookup).
OTHER_KID="$(jq -r '.keys[0].kid' "$T/other-jwks.json")"
expect 0 'one of the kids you pinned with --expect-kid' 'a pinned kid that matches the signing key verifies' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --expect-kid "$ISSUER_KID"
expect 0 'one of the kids you pinned with --expect-kid' 'two pinned kids, the first matching, verify (rotation overlap)' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --expect-kid "$ISSUER_KID" --expect-kid "$OTHER_KID"
expect 0 'one of the kids you pinned with --expect-kid' 'two pinned kids, the second matching, verify (rotation overlap)' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --expect-kid "$OTHER_KID" --expect-kid "$ISSUER_KID"
expect 1 "unexpected_kid — the key bytes derive kid '$ISSUER_KID'" 'a pinned kid that does not match is a failed check (1) that names the kid found' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --expect-kid "$OTHER_KID"
lacks 'one of the kids you pinned' 'a failed pin is never reported as matched'
expect 1 "pinned with --expect-kid: $OTHER_KID AAAAAAAAAAAAAAAAAAAAAA" 'a failed pin lists every kid that was expected' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --expect-kid "$OTHER_KID" --expect-kid AAAAAAAAAAAAAAAAAAAAAA
expect 2 'is not a kid' 'a pinned value too short to be a kid is a usage error (2)' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --expect-kid short
expect 2 'is not a kid' 'a pinned value with characters outside base64url is a usage error (2)' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --expect-kid 'AAAAAAAAAAAAAAAAAAAA+A'
expect 2 'is not a kid' 'a pinned value that no 16-byte digest can encode to is a usage error (2)' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --expect-kid AAAAAAAAAAAAAAAAAAAAAB
expect 2 'is not a kid' 'a malformed pin among valid ones is still a usage error (2)' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --expect-kid "$ISSUER_KID" --expect-kid nope
expect 2 'needs a value' '--expect-kid without a value is a usage error (2)' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --expect-kid
expect 2 'it needs --attestation' '--expect-kid without a document to pin is a usage error, not silently ignored (2)' -- \
  --status-list --status-keys "$T/status-keys.json" --status "$T/list-empty.json" \
  --check-kid "$ISSUER_KID" --expect-kid "$ISSUER_KID" --now "$NOW"
# A key document that publishes the OTHER key under the issuer's kid (the header
# kid of att.json). The existing rule already rejects it (the bytes do not derive
# that label), and a pin cannot rescue it: pinning the label the document claims
# fails on the recomputed kid, and pinning the bytes' real kid still leaves the
# label mismatch. The pin never compares the label.
expect 1 "unexpected_kid — the key bytes derive kid '$OTHER_KID'" 'a key relabelled to the pinned kid does not satisfy the pin (the bytes decide)' -- \
  --attestation "$T/att.json" --jwks "$T/mislabelled-jwks.json" --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$NOW" \
  --expect-kid "$ISSUER_KID"
expect 1 'kid mismatch — header says' 'a relabelled key whose real kid is pinned still fails the existing label rule' -- \
  --attestation "$T/att.json" --jwks "$T/mislabelled-jwks.json" --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$NOW" \
  --expect-kid "$OTHER_KID"

# The 2026-09-29 bypass: an unsigned nested object placed before the genuine
# posture fields used to be what the slug/freshness checks read.
edit "$T/att.json" "$T/decoy-slug.json" '
c = d["attestation"]["claims"]
c["posture"] = {"x": {"slug": "another-org"}, **c["posture"]}'
expect 1 'unsigned_member' 'an unsigned decoy slug does not satisfy --expect-slug' -- \
  --attestation "$T/decoy-slug.json" --jwks "$T/jwks.json" --expect-slug another-org --expect-issuer "$ISS" --now "$NOW"
expect 1 "not the expected 'another-org'" 'the slug check reads the signed slug, not the decoy' -- \
  --attestation "$T/decoy-slug.json" --jwks "$T/jwks.json" --expect-slug another-org --expect-issuer "$ISS" --now "$NOW"

edit "$T/att.json" "$T/decoy-fresh.json" '
c = d["attestation"]["claims"]
c["posture"] = {"x": {"generatedAt": "2026-01-02T00:00:00.000Z", "expiresAt": "2026-01-02T00:10:00.000Z"}, **c["posture"]}'
expect 1 'EXPIRED' 'an unsigned decoy timestamp does not make an expired document fresh' -- \
  --attestation "$T/decoy-fresh.json" --jwks "$T/jwks.json" --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$NOW_LATE"
lacks 'the signature is valid' 'an expired document with an unsigned member is not reported as only expired'

edit "$T/att.json" "$T/extra-top.json" 'd["attestation"]["claims"]["note"] = "not signed"'
expect 1 'claims.note' 'an unsigned top-level claims member is rejected' -- \
  --attestation "$T/extra-top.json" "${COMMON[@]}"

edit "$T/att.json" "$T/extra-fw.json" 'd["attestation"]["claims"]["posture"]["frameworks"][0]["band_note"] = "x"'
expect 1 'posture.frameworks[0].band_note' 'an unsigned framework member is rejected' -- \
  --attestation "$T/extra-fw.json" "${COMMON[@]}"

mint_attest --out "$T/no-expiry.json" --expires-at none
expect 1 'no expiresAt' 'a document without expiresAt is rejected, not treated as never expiring' -- \
  --attestation "$T/no-expiry.json" "${COMMON[@]}"

"${MINT[@]}" attest --key "$T/issuer.pem" --slug "$SLUG" --iss "$ISS" --generated-at "$GEN" \
  --expires-at "$EXP" --visibility gated --framework iso27001=basic --out "$T/gated-leak.json"
expect 1 'redaction_violation' 'a gated posture that still carries coverage is rejected' -- \
  --attestation "$T/gated-leak.json" "${COMMON[@]}"

mint_attest --out "$T/alg-none.json" --header 'alg=none'
expect 1 "alg is 'none'" 'a signed header naming another algorithm is rejected' -- \
  --attestation "$T/alg-none.json" "${COMMON[@]}"

mint_attest --out "$T/crit.json" --header 'crit=x'
expect 1 "header carries 'crit'" 'a signed header with crit is rejected' -- \
  --attestation "$T/crit.json" "${COMMON[@]}"

# A wrapper member inside the claims must not be where the posture is read from.
edit "$T/att.json" "$T/wrapped-decoy.json" '
c = d["attestation"]["claims"]
c["claims"] = {"posture": {**c["posture"], "slug": "another-org"}}'
expect 1 "not the expected 'another-org'" 'a nested claims wrapper does not replace the signed posture' -- \
  --attestation "$T/wrapped-decoy.json" --jwks "$T/jwks.json" --expect-slug another-org --expect-issuer "$ISS" --now "$NOW"

# The attached form: anybody can re-serialise a public detached document as
# attached (no key needed), so it must get every check a detached one gets.
"${MINT[@]}" attach --doc "$T/att.json" --out "$T/attached.jws"
expect 0 'the embedded payload equals the bytes re-derived' 'an attached JWS alone verifies, with its claims decoded' -- \
  --jws "$T/attached.jws" "${COMMON[@]}"
expect 1 "not the expected 'another-org'" 'an attached JWS alone is held to --expect-slug' -- \
  --jws "$T/attached.jws" --jwks "$T/jwks.json" --expect-slug another-org --expect-issuer "$ISS" --now "$NOW"
expect 1 'issuer_mismatch' 'an attached JWS alone is held to --expect-issuer' -- \
  --jws "$T/attached.jws" --jwks "$T/jwks.json" --expect-slug "$SLUG" --expect-issuer https://other-issuer.test --now "$NOW"
expect 1 'nonce_mismatch' 'an attached JWS alone is held to --expect-nonce' -- \
  --jws "$T/attached.jws" "${COMMON[@]}" --expect-nonce 'challenge-B'
expect 1 'EXPIRED' 'an attached JWS alone is held to its expiry' -- \
  --jws "$T/attached.jws" --jwks "$T/jwks.json" --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$NOW_LATE"

edit "$T/att.json" "$T/att-garbage.json" '
h, p, s = d["attestation"]["signature"].split(".")
d["attestation"]["signature"] = ".".join([h, "QUFBQQ", s])'
jq -r '.attestation.signature' "$T/att-garbage.json" > "$T/garbage.jws"
expect 1 'is not a hodei-shield.attest.attestation.v1' 'an attached payload that is not an envelope is a failure (1), not "could not check" (2)' -- \
  --jws "$T/garbage.jws" "${COMMON[@]}"

# Duplicate members. Every parser the script uses keeps the LAST value, which
# is the signed one here, so these were never verdict-changing; the point is
# that a reader who keeps the FIRST would have seen the decoy under a PASS.
jq -c . "$T/att.json" > "$T/att-compact.json"
edit_text "$T/att-compact.json" "$T/dup-posture.json" '
t = t.replace("\"posture\":{", "\"posture\":{\"slug\":\"another-org\",\"expiresAt\":\"2099-01-01T00:00:00.000Z\",", 1)'
expect 1 'duplicate_key' 'a duplicated slug/expiresAt inside posture is rejected' -- \
  --attestation "$T/dup-posture.json" "${COMMON[@]}"
edit_text "$T/att-compact.json" "$T/dup-claims.json" '
t = t.replace("{\"attestation\":{", "{\"attestation\":{\"claims\":{\"iss\":\"x\"},", 1)'
expect 1 'duplicate_key' 'a second claims inside attestation is rejected' -- \
  --attestation "$T/dup-claims.json" "${COMMON[@]}"
edit_text "$T/att-compact.json" "$T/dup-top-claims.json" '
t = "{\"claims\":{\"iss\":\"x\"}," + t[1:]'
expect 1 'duplicate_key' 'a claims member beside attestation at the top level is rejected' -- \
  --attestation "$T/dup-top-claims.json" "${COMMON[@]}"
edit_text "$T/att-compact.json" "$T/dup-attestation.json" '
t = "{\"attestation\":{\"claims\":{}}," + t[1:]'
expect 1 'duplicate_key' 'a duplicated attestation member is rejected' -- \
  --attestation "$T/dup-attestation.json" "${COMMON[@]}"
edit_text "$T/att-compact.json" "$T/dup-band.json" '
t = t.replace("\"band\":", "\"band\":\"advanced\",\"band\":", 1)'
expect 1 'duplicate_key' 'a duplicated framework band is rejected' -- \
  --attestation "$T/dup-band.json" "${COMMON[@]}"
expect 0 'every member of the claims JSON is covered by the signature' 'the same document, compact and without duplicates, verifies' -- \
  --attestation "$T/att-compact.json" "${COMMON[@]}"
jq -c . "$T/claims.json" > "$T/claims-compact.json"
edit_text "$T/claims-compact.json" "$T/dup-claims-file.json" '
t = t.replace("{", "{\"iss\":\"https://other-issuer.test\",", 1)'
expect 1 'duplicate_key' 'a duplicated member in a --claims file is rejected' -- \
  --jws "$T/att.jws" --claims "$T/dup-claims-file.json" "${COMMON[@]}"
jq -c . "$T/jwks.json" > "$T/jwks-compact.json"
edit_text "$T/jwks-compact.json" "$T/dup-jwks.json" '
t = t.replace("\"pub\":", "\"pub\":\"AAAA\",\"pub\":", 1)'
expect 2 'repeats members' 'a key document with duplicated members is "could not check" (2)' -- \
  --attestation "$T/att.json" --jwks "$T/dup-jwks.json" --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$NOW"
# A scanner that crashes must not read as "no duplicates".
edit_text "$T/att-compact.json" "$T/dup-deep.json" '
deep = "[" * 990 + "]" * 990
t = t.replace("\"posture\":{", "\"posture\":{\"slug\":\"another-org\",", 1)
t = t.rstrip()[:-1] + ",\"verification\":" + deep + "}"'
expect 1 'duplicate_key' 'a duplicate beside nesting too deep to walk recursively is still found' -- \
  --attestation "$T/dup-deep.json" "${COMMON[@]}"
edit_text "$T/jwks-compact.json" "$T/jwks-trailing.json" '
t = t + " trailing"'
expect 2 'is not strict JSON' 'a key document with text after the JSON is "could not check" (2)' -- \
  --attestation "$T/att.json" --jwks "$T/jwks-trailing.json" --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$NOW"
mint_attest --out "$T/dup-header.json" --header 'x=1'
edit_text "$T/dup-header.json" "$T/dup-header.json" '
import base64, json as j
d = j.loads(t); h, p, s = d["attestation"]["signature"].split(".")
raw = base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)).decode()
raw = raw.replace("\"x\":\"1\"", "\"typ\":\"application/attest+jws\"")
d["attestation"]["signature"] = ".".join([base64.urlsafe_b64encode(raw.encode()).rstrip(b"=").decode(), p, s])
t = j.dumps(d)'
expect 1 'header members are' 'a protected header with a duplicated member is rejected' -- \
  --attestation "$T/dup-header.json" "${COMMON[@]}"

# The toolchain gate. Shims stand in for an `openssl` that is not ML-DSA
# capable; every other call goes to the real one. LibreSSL >= 3.5 used to pass
# the version check as "ML-DSA capable" and fail later with an unexplained
# message. Both must now say "not ML-DSA capable" and exit 2, never 1.
REAL_OPENSSL="$(command -v openssl)"
mkdir -p "$T/shim-libressl" "$T/shim-no-mldsa"
cat > "$T/shim-libressl/openssl" <<SHIM
#!/usr/bin/env bash
if [ "\${1:-}" = version ]; then echo 'LibreSSL 4.1.2'; exit 0; fi
exec "$REAL_OPENSSL" "\$@"
SHIM
cat > "$T/shim-no-mldsa/openssl" <<SHIM
#!/usr/bin/env bash
if [ "\${1:-}" = list ]; then "$REAL_OPENSSL" "\$@" | grep -vi ml-dsa; exit 0; fi
exec "$REAL_OPENSSL" "\$@"
SHIM
chmod +x "$T/shim-libressl/openssl" "$T/shim-no-mldsa/openssl"
PATH="$T/shim-libressl:$PATH" expect 2 'is not OpenSSL, so it is not ML-DSA capable' \
  'LibreSSL >= 3.5 is "not ML-DSA capable" (2), not a pass' -- \
  --attestation "$T/att.json" "${COMMON[@]}"
lacks 'PASS  OpenSSL' 'LibreSSL >= 3.5 is never reported as an ML-DSA capable OpenSSL'
PATH="$T/shim-no-mldsa:$PATH" expect 2 'does not offer ML-DSA-65, so it is not ML-DSA capable' \
  'an OpenSSL >= 3.5 without ML-DSA-65 is "not ML-DSA capable" (2)' -- \
  --attestation "$T/att.json" "${COMMON[@]}"
lacks 'PASS  OpenSSL' 'an OpenSSL without ML-DSA-65 is never reported as capable'

# The working directory is not code. Without -I, python3 puts the current
# directory first on sys.path, so a json.py where the verifier is run would run
# inside every check. Planted modules that end Python with exit 0 on import must
# change nothing: the tampered-field vector is still signature_invalid (1).
PLANT="$T/planted"; mkdir -p "$PLANT"
for mod in json struct base64 binascii re datetime; do printf 'import os\nos._exit(0)\n' > "$PLANT/$mod.py"; done
VEC="$ROOT/tests/vectors/v1"
PLANT_ARGS=(--attestation "$VEC/attestations/tampered-field.json" --jwks "$VEC/keys/test-only-issuer-jwks.json"
            --expect-slug fixture-org --expect-issuer https://issuer.test --now 1767225900)
( cd "$PLANT" && NO_COLOR=1 bash "$VERIFIER" "${PLANT_ARGS[@]}" ) > "$T/planted.out" 2>&1; got=$?
if [ "$got" -eq 1 ] && grep -qF 'SIGNATURE DOES NOT VERIFY' "$T/planted.out" && ! grep -qF 'VERIFIED —' "$T/planted.out"; then
  printf 'ok - a json.py in the working directory is not imported: tampered-field is still signature_invalid (1)\n'; PASSED=$((PASSED + 1))
else
  printf 'not ok - a json.py in the working directory changed the verdict (exit %s)\n' "$got"; sed 's/^/    # /' "$T/planted.out"; FAILED=$((FAILED + 1))
fi
( cd "$PLANT" && NO_COLOR=1 bash "$VERIFIER" "${PLANT_ARGS[@]}" --json ) > "$T/planted.json" 2>/dev/null; got=$?
if [ "$got" -eq 1 ] && [ "$(python3 -I -c 'import json,sys; o = json.load(open(sys.argv[1])); print(o["reason"], o["exit_code"])' "$T/planted.json" 2>/dev/null)" = 'signature_invalid 1' ]; then
  printf 'ok - with --json too: a planted json.py is not imported (signature_invalid, 1)\n'; PASSED=$((PASSED + 1))
else
  printf 'not ok - with --json, a planted json.py changed the result (exit %s)\n' "$got"; head -c 1500 "$T/planted.json" | sed 's/^/    # /'; FAILED=$((FAILED + 1))
fi

# Each input file is read once, into the work directory. A pipe can be read only
# once, so every input given as <(cat FILE) must still verify; before, the second
# read of the same pipe found it empty.
echo '# inputs are read once'
expect 0 'VERIFIED — this document was signed' '--attestation and --jwks given as pipes (read once) verify' -- \
  --attestation <(cat "$T/att.json") --jwks <(cat "$T/jwks.json") --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$NOW"
expect 0 'VERIFIED — this document was signed' '--jws, --claims and --jwks given as pipes verify' -- \
  --jws <(cat "$T/att.jws") --claims <(cat "$T/claims.json") --jwks <(cat "$T/jwks.json") \
  --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$NOW"
expect 0 'VERIFIED — this document was signed' '--posture (a claims object) given as a pipe verifies' -- \
  --jws <(cat "$T/att.jws") --posture <(cat "$T/claims.json") "${COMMON[@]}"
expect 0 'VERIFIED — this document was signed' 'an attached --jws given as a pipe verifies (its payload is decoded from the copy)' -- \
  --jws <(cat "$T/attached.jws") "${COMMON[@]}"
expect 1 'SIGNATURE DOES NOT VERIFY' 'a tampered document given as a pipe still fails on its signature' -- \
  --attestation <(cat "$T/tampered-field.json") "${COMMON[@]}"
# A file that cannot be read is named as it was given, escaped, never as a copy.
expect 2 'cannot read /nonexistent/att\x1b[31m.json' 'an unreadable --attestation is named as given, escaped (2)' -- \
  --attestation $'/nonexistent/att\e[31m.json' "${COMMON[@]}"
expect 2 'cannot read /nonexistent/jwks.json' 'an unreadable --jwks is named as given (2)' -- \
  --attestation "$T/att.json" --jwks /nonexistent/jwks.json --expect-slug "$SLUG" --now "$NOW"
expect 2 'cannot read /nonexistent/claims.json' 'an unreadable --claims is named as given (2)' -- \
  --jws "$T/att.jws" --claims /nonexistent/claims.json "${COMMON[@]}"
expect 2 'cannot read /nonexistent/a.jws' 'an unreadable --jws is named as given (2)' -- \
  --jws /nonexistent/a.jws --claims "$T/claims.json" "${COMMON[@]}"
expect 2 'could not tell what /nonexistent/posture.json is' 'an unreadable --posture is named as given (2)' -- \
  --jws "$T/att.jws" --posture /nonexistent/posture.json "${COMMON[@]}"
expect 2 "cannot read $T" 'a directory given as --jwks is unreadable (2), and named as given' -- \
  --attestation "$T/att.json" --jwks "$T" --expect-slug "$SLUG" --now "$NOW"
edit "$T/att.json" "$T/no-signature.json" 'del d["attestation"]["signature"]'
expect 2 "$T/no-signature.json carries no \"signature\" member" 'an attestation without a signature is named as given' -- \
  --attestation "$T/no-signature.json" "${COMMON[@]}"
edit "$T/att.json" "$T/no-posture.json" 'del d["attestation"]["claims"]["posture"]'
expect 2 "no usable \`posture\` object: the claims in $T/no-posture.json" 'claims taken from an attestation are named after it' -- \
  --attestation "$T/no-posture.json" "${COMMON[@]}"

echo '# revocation (--status-list)'


LIST_AT='2026-01-01T00:00:00.000Z'
LIST_NEXT='2026-01-01T02:00:00.000Z'
mint_status() { "${MINT[@]}" status --key "$T/status.pem" --iss "$ISS" \
  --issued-at "$LIST_AT" --next-update "$LIST_NEXT" "$@"; }

mint_status --out "$T/list-empty.json" --seq 7
mint_status --out "$T/list-key.json" --seq 8 --revoke-kid="$ISSUER_KID"
mint_status --out "$T/list-subj-after.json" --seq 8 --revoke-subject "$SLUG@2026-01-01T00:10:00.000Z"
mint_status --out "$T/list-subj-before.json" --seq 8 --revoke-subject "$SLUG@2025-12-31T23:00:00.000Z"
"${MINT[@]}" status --key "$T/issuer.pem" --iss "$ISS" --issued-at "$LIST_AT" --next-update "$LIST_NEXT" \
  --out "$T/list-wrong-key.json"

SL=(--status-list --status-keys "$T/status-keys.json" --attestation "$T/att.json" "${COMMON[@]}")

expect 0 'GOOD — not revoked, per a verified status list' 'a genuine document on a list that revokes nothing is good' -- \
  "${SL[@]}" --status "$T/list-empty.json"

expect 1 'REVOKED — via key' 'a document whose signing key is revoked is rejected (Rule K)' -- \
  "${SL[@]}" --status "$T/list-key.json"

expect 1 'REVOKED — via subject' 'a document minted before its subject was withdrawn is rejected (Rule B)' -- \
  "${SL[@]}" --status "$T/list-subj-after.json"

expect 0 'GOOD — not revoked, per a verified status list' 'a document minted after the withdrawal notBefore is good' -- \
  "${SL[@]}" --status "$T/list-subj-before.json"

# --check-subject and --check-generated-at add a subject to Rule B; they never
# replace the document's own signed slug at its own signed generatedAt.
expect 1 'REVOKED — via subject' 'a withdrawn subject is REVOKED even with --check-subject naming another organisation' -- \
  "${SL[@]}" --status "$T/list-subj-after.json" --check-subject other-org
lacks 'GOOD' 'a withdrawn subject is never GOOD under another --check-subject'
expect 1 'REVOKED — via subject' 'a later --check-generated-at does not lift the withdrawal of the document' -- \
  "${SL[@]}" --status "$T/list-subj-after.json" --check-generated-at 2026-01-01T00:20:00.000Z
lacks 'GOOD' 'a withdrawn subject is never GOOD under a later --check-generated-at'
expect 1 'REVOKED — via subject' 'another subject at a later time does not lift the withdrawal either' -- \
  "${SL[@]}" --status "$T/list-subj-after.json" --check-subject other-org --check-generated-at 2026-01-01T00:20:00.000Z
mint_status --out "$T/list-subj-other.json" --seq 8 --revoke-subject "other-org@2026-01-01T00:10:00.000Z"
expect 1 'REVOKED — via subject' 'a withdrawn --check-subject is REVOKED beside a document whose subject is not' -- \
  "${SL[@]}" --status "$T/list-subj-other.json" --check-subject other-org
expect 1 'REVOKED — via subject' 'an earlier --check-generated-at is checked as well' -- \
  "${SL[@]}" --status "$T/list-subj-before.json" --check-generated-at 2025-12-31T22:00:00.000Z
expect 0 'subjects fixture-org, other-org carry no earlier withdrawal' 'the document subject and a --check-subject are both reported as checked' -- \
  "${SL[@]}" --status "$T/list-empty.json" --check-subject other-org
expect 0 'subject fixture-org carries no earlier withdrawal' 'without --check-subject, the document subject alone (unchanged output)' -- \
  "${SL[@]}" --status "$T/list-subj-other.json"
# A standalone query (no document) still checks the --check-subject given.
expect 1 'REVOKED — via subject' 'a standalone --check-subject query still finds a withdrawn subject' -- \
  --status-list --status-keys "$T/status-keys.json" --status "$T/list-subj-after.json" \
  --check-subject "$SLUG" --check-generated-at "$GEN" --now "$NOW"
expect 0 'GOOD — not revoked' 'a standalone --check-subject query after the withdrawal notBefore is good' -- \
  --status-list --status-keys "$T/status-keys.json" --status "$T/list-subj-after.json" \
  --check-subject "$SLUG" --check-generated-at 2026-01-01T00:20:00.000Z --now "$NOW"
expect 3 'IS listed, but no generatedAt was given' 'a standalone --check-subject query without a time is UNKNOWN' -- \
  --status-list --status-keys "$T/status-keys.json" --status "$T/list-subj-after.json" --check-subject "$SLUG" --now "$NOW"
# Nothing is taken from the environment: a standalone query never read a
# document, so an exported GENERATED, SLUG, KID or DERIVED_KID must not stand in
# for one (bash imports every environment variable as a shell variable).
GENERATED=2026-01-01T00:20:00.000Z expect 3 'IS listed, but no generatedAt was given' 'an exported GENERATED is not read as --check-generated-at' -- \
  --status-list --status-keys "$T/status-keys.json" --status "$T/list-subj-after.json" --check-subject "$SLUG" --now "$NOW"
lacks 'GOOD' 'a withdrawn subject is never GOOD through the environment'
KID="$ISSUER_KID" DERIVED_KID="$ISSUER_KID" expect 0 'GOOD — not revoked' 'an exported KID or DERIVED_KID is not looked up in Rule K' -- \
  --status-list --status-keys "$T/status-keys.json" --status "$T/list-key.json" --check-subject other-org \
  --check-generated-at "$GEN" --now "$NOW"
lacks "kid $ISSUER_KID" 'no kid from the environment is reported as checked'
SLUG="$SLUG" GENERATED="$GEN" expect 0 'subject other-org carries no earlier withdrawal' 'an exported SLUG is not added as the subject of a document' -- \
  --status-list --status-keys "$T/status-keys.json" --status "$T/list-subj-after.json" --check-subject other-org \
  --check-generated-at "$GEN" --now "$NOW"
lacks 'fixture-org' 'the exported slug is not checked'

# Rule B compares exact instants, through the same comparator as the retirement
# checks. In whole seconds, a document generated at 00:00:00.000 was not "before"
# a notBefore of 00:00:00.900.
mint_status --out "$T/list-subj-frac.json" --seq 8 --revoke-subject "$SLUG@2026-01-01T00:00:00.900Z"
expect 1 'REVOKED — via subject' 'a document generated 0.9 s before a fractional notBefore is REVOKED' -- \
  "${SL[@]}" --status "$T/list-subj-frac.json"
lacks 'GOOD' 'a document generated under a second before notBefore is never GOOD'
mint_status --out "$T/list-subj-same.json" --seq 8 --revoke-subject "$SLUG@2026-01-01T01:00:00+01:00"
expect 0 'GOOD — not revoked' 'a document generated at notBefore itself (another form of the same instant) is good' -- \
  "${SL[@]}" --status "$T/list-subj-same.json"
mint_status --out "$T/list-subj-bad.json" --seq 8 --revoke-subject "$SLUG@2026-01-01 00:10:00"
expect 3 'could not parse generatedAt/notBefore as RFC 3339' 'a notBefore that is not RFC 3339 leaves the subject UNKNOWN' -- \
  "${SL[@]}" --status "$T/list-subj-bad.json"
# The validity ceiling of a status list is compared exactly too.
"${MINT[@]}" status --key "$T/status.pem" --iss "$ISS" --issued-at "$LIST_AT" \
  --next-update '2026-01-02T00:00:00.500Z' --seq 8 --out "$T/list-validity-frac.json"
expect 3 'validity_exceeded — nextUpdate - issuedAt is 86400.5s, above the' 'a status list valid 0.5 s longer than the ceiling is UNKNOWN' -- \
  "${SL[@]}" --status "$T/list-validity-frac.json"
"${MINT[@]}" status --key "$T/status.pem" --iss "$ISS" --issued-at "$LIST_AT" \
  --next-update '2026-01-02T00:00:00.000Z' --seq 8 --out "$T/list-validity-exact.json"
expect 0 'GOOD — not revoked' 'a status list valid for exactly the ceiling is good' -- \
  "${SL[@]}" --status "$T/list-validity-exact.json"
# And its issuedAt against the clock-skew allowance: NOW is 00:05:00.
"${MINT[@]}" status --key "$T/status.pem" --iss "$ISS" --issued-at '2026-01-01T00:10:00.500Z' \
  --next-update '2026-01-01T02:00:00.000Z' --seq 8 --out "$T/list-ahead-frac.json"
expect 3 'not_yet_valid — issuedAt is in the future' 'a status list issued 0.5 s beyond the clock-skew allowance is UNKNOWN' -- \
  --status-list --status-keys "$T/status-keys.json" --status "$T/list-ahead-frac.json" --check-kid "$ISSUER_KID" --now "$NOW"
"${MINT[@]}" status --key "$T/status.pem" --iss "$ISS" --issued-at '2026-01-01T00:10:00.000Z' \
  --next-update '2026-01-01T02:00:00.000Z' --seq 8 --out "$T/list-ahead-exact.json"
expect 0 'GOOD — not revoked' 'a status list issued exactly at the clock-skew allowance is good' -- \
  --status-list --status-keys "$T/status-keys.json" --status "$T/list-ahead-exact.json" --check-kid "$ISSUER_KID" --now "$NOW"

expect 0 'one of the kids you pinned with --expect-kid' '--expect-kid works beside --status-list on the attestation key' -- \
  "${SL[@]}" --status "$T/list-empty.json" --expect-kid "$ISSUER_KID"
expect 1 'unexpected_kid' '--expect-kid does not look at the status list, only at the attestation key' -- \
  "${SL[@]}" --status "$T/list-empty.json" --expect-kid "$OTHER_KID"

edit "$T/list-key.json" "$T/list-key-stripped.json" 'd["statusList"]["keys"] = []'
expect 3 'bad_signature' 'a list with a revocation removed after signing is UNKNOWN, never good' -- \
  "${SL[@]}" --status "$T/list-key-stripped.json"

expect 3 'unknown_kid' 'a list signed with the ATTESTATION key is UNKNOWN (disjoint key sets)' -- \
  "${SL[@]}" --status "$T/list-wrong-key.json"

expect 3 'stale' 'a list past nextUpdate is UNKNOWN, never good' -- \
  --status-list --status-keys "$T/status-keys.json" --status "$T/list-empty.json" \
  --check-kid "$ISSUER_KID" --now "$NOW_LATE"

expect 3 'rolled_back' 'a list older than one already accepted (--min-seq) is UNKNOWN' -- \
  "${SL[@]}" --status "$T/list-empty.json" --min-seq 8

expect 1 'REVOKED — via subject' 'an attached JWS alone does not dodge a subject withdrawal' -- \
  --status-list --status-keys "$T/status-keys.json" --status "$T/list-subj-after.json" \
  --jws "$T/attached.jws" "${COMMON[@]}"

# The status list and its key set are read once too.
expect 1 'REVOKED — via key' '--status, --status-keys and --attestation given as pipes: REVOKED' -- \
  --status-list --status <(cat "$T/list-key.json") --status-keys <(cat "$T/status-keys.json") \
  --attestation <(cat "$T/att.json") "${COMMON[@]}"
expect 0 'GOOD — not revoked' '--status, --status-keys and --attestation given as pipes: GOOD' -- \
  --status-list --status <(cat "$T/list-empty.json") --status-keys <(cat "$T/status-keys.json") \
  --attestation <(cat "$T/att.json") "${COMMON[@]}"
expect 2 'cannot read /nonexistent/status\x0a.json' 'an unreadable --status is named as given, escaped (2)' -- \
  --status-list --status $'/nonexistent/status\n.json' --status-keys "$T/status-keys.json" --check-kid "$ISSUER_KID" --now "$NOW"

# --check-kid adds a kid to Rule K; it never replaces the document's own kid.
mint_status --out "$T/list-other-key.json" --seq 8 --revoke-kid="$OTHER_KID"
expect 1 'REVOKED — via key' 'a document whose signing key is revoked is REVOKED even with --check-kid naming an unrevoked kid' -- \
  "${SL[@]}" --status "$T/list-key.json" --check-kid "$OTHER_KID"
lacks 'GOOD' 'a revoked signing key is never GOOD under another --check-kid'
expect 1 'REVOKED — via key' 'a --check-kid that is revoked is REVOKED beside a document whose key is not' -- \
  "${SL[@]}" --status "$T/list-other-key.json" --check-kid "$OTHER_KID"
expect 0 "GOOD — kids $ISSUER_KID, $OTHER_KID are not revoked" 'the document kid and a --check-kid are both reported as checked' -- \
  "${SL[@]}" --status "$T/list-empty.json" --check-kid "$OTHER_KID"
expect 0 "GOOD — kid $ISSUER_KID is not revoked" 'without --check-kid, the document kid alone (unchanged output)' -- \
  "${SL[@]}" --status "$T/list-other-key.json"
expect 1 'REVOKED — via key' 'a standalone --check-kid query still finds a revoked kid' -- \
  --status-list --status-keys "$T/status-keys.json" --status "$T/list-key.json" --check-kid "$ISSUER_KID" --now "$NOW"
expect 0 "GOOD — kid $ISSUER_KID is not revoked" 'a standalone --check-kid query still reports an unrevoked kid' -- \
  --status-list --status-keys "$T/status-keys.json" --status "$T/list-other-key.json" --check-kid "$ISSUER_KID" --now "$NOW"

# The options of the status-list mode without --status-list were read by nothing,
# and the run ended VERIFIED. Each is a usage error now.
for sopt in "--status $T/list-key.json" "--status-keys $T/status-keys.json" "--check-kid $ISSUER_KID" \
            "--check-subject $SLUG" "--check-generated-at $GEN" "--min-seq 9"; do
  read -r -a sargs <<< "$sopt"
  expect 2 "error: ${sargs[0]} requires --status-list" "${sargs[0]} without --status-list is a usage error (2)" -- \
    --attestation "$T/att.json" "${COMMON[@]}" "${sargs[@]}"
  lacks 'VERIFIED' "${sargs[0]} without --status-list never ends VERIFIED"
done
expect 0 'GOOD — not revoked' 'the same options with --status-list given after them are accepted' -- \
  --status "$T/list-empty.json" --status-keys "$T/status-keys.json" --attestation "$T/att.json" "${COMMON[@]}" --status-list

edit "$T/list-empty.json" "$T/list-truthy.json" 'd["statusList"]["truncated"] = "yes"'
expect 3 'truncated must be a boolean' 'a list whose truncated flag is not a boolean is UNKNOWN' -- \
  "${SL[@]}" --status "$T/list-truthy.json"

jq -c . "$T/list-key.json" > "$T/list-key-compact.json"
edit_text "$T/list-key-compact.json" "$T/list-dup.json" '
t = t.replace("\"keys\":", "\"keys\":[],\"keys\":", 1)'
expect 3 'duplicate_key' 'a status list with a duplicated member is UNKNOWN' -- \
  "${SL[@]}" --status "$T/list-dup.json"
printf '\xef\xbb\xbf' > "$T/list-bom.json"; cat "$T/list-dup.json" >> "$T/list-bom.json"
expect 3 'is not strict JSON' 'a status list jq accepts but a strict parser does not is UNKNOWN' -- \
  "${SL[@]}" --status "$T/list-bom.json"

# Expired under a good list says so; expired under a revocation reports the
# revocation, because "request a new one" is the wrong advice for a withdrawn
# key or subject.
"${MINT[@]}" status --key "$T/status.pem" --iss "$ISS" --issued-at '2026-01-01T23:00:00.000Z' \
  --next-update '2026-01-02T01:00:00.000Z' --seq 9 --out "$T/list-late-empty.json"
"${MINT[@]}" status --key "$T/status.pem" --iss "$ISS" --issued-at '2026-01-01T23:00:00.000Z' \
  --next-update '2026-01-02T01:00:00.000Z' --seq 9 --revoke-kid="$ISSUER_KID" --out "$T/list-late-key.json"
LATE=(--status-list --status-keys "$T/status-keys.json" --attestation "$T/att.json" --jwks "$T/jwks.json"
      --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$NOW_LATE")
expect 1 "EXPIRED — the signature is valid, but this attestation expired on $EXP." \
  'a genuine expired document under a good list says it expired (exit 1)' -- \
  "${LATE[@]}" --status "$T/list-late-empty.json"
expect 1 'REVOKED — via key' 'a genuine expired document whose key is revoked reports the revocation' -- \
  "${LATE[@]}" --status "$T/list-late-key.json"
lacks 'the signature is valid' 'a revoked expired document is not reported as only expired'

edit "$T/att.json" "$T/decoy-revoked.json" '
c = d["attestation"]["claims"]
c["posture"] = {"x": {"generatedAt": "2026-01-01T00:12:00.000Z"}, **c["posture"]}'
expect 1 'unsigned_member' 'an unsigned decoy generatedAt does not dodge a subject withdrawal' -- \
  --status-list --status-keys "$T/status-keys.json" --status "$T/list-subj-after.json" \
  --attestation "$T/decoy-revoked.json" "${COMMON[@]}"

# Attested content (#14). What a document SAYS (its bands and frameworks) is
# printed only when the run ends VERIFIED/GOOD. A document that does not verify
# shows none of it, even with --raw; it gets one line saying it was withheld.
echo '# attested content'
WITHHELD='attested content withheld: this document did not verify'
# lacks_all NAME STRING... — the previous expect() output has none of the strings.
# A string is matched within one line: grep reads a newline in a pattern as two
# patterns, one of them empty and matching everything, so one is refused (use
# lacks_lines with a ^ anchor to say "never at the start of a line").
lacks_all() {
  local out="$LAST_OUT" name="$1" str bad=0; shift
  for str in "$@"; do
    if [[ "$str" == *$'\n'* ]]; then
      printf 'not ok - %s (the test is wrong: a string with a newline cannot be checked)\n' "$name"; bad=1
    elif grep -qF -- "$str" "$out"; then
      printf 'not ok - %s (output contains: %s)\n' "$name" "$str"; bad=1
    fi
  done
  if [ "$bad" -eq 0 ]; then printf 'ok - %s\n' "$name"; PASSED=$((PASSED + 1)); else FAILED=$((FAILED + 1)); fi
}
# lacks_lines NAME ERE... — no line of the previous expect() output matches any ERE.
lacks_lines() {
  local out="$LAST_OUT" name="$1" re bad=0; shift
  for re in "$@"; do
    if grep -qE -- "$re" "$out"; then
      printf 'not ok - %s (a line matches: %s)\n' "$name" "$re"; grep -nE -- "$re" "$out" | sed 's/^/    # /'; bad=1
    fi
  done
  if [ "$bad" -eq 0 ]; then printf 'ok - %s\n' "$name"; PASSED=$((PASSED + 1)); else FAILED=$((FAILED + 1)); fi
}
SECRETS=(substantial basic advanced ISO27001 iso27001 NIS2 nis2 in_progress)

expect 0 'ISO27001 (iso27001): substantial' 'a verified document shows its frameworks and their bands' -- \
  --attestation "$T/att.json" "${COMMON[@]}"
expect 0 'overallBand: basic' 'a verified document shows its overallBand' -- \
  --attestation "$T/att.json" "${COMMON[@]}"
lacks '"frameworks"' 'a verified document does not print the raw posture JSON without --raw'
expect 0 'subject:     fixture-org  (visibility: public)' 'a verified document shows its subject slug and visibility' -- \
  --attestation "$T/att.json" "${COMMON[@]}"
lacks 'posture (E7' 'the raw posture heading is absent without --raw'
expect 0 '"band": "substantial"' 'with --raw a verified document also prints the raw posture JSON' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --raw
expect 0 'ISO27001 (iso27001): substantial' 'with --raw the readable summary is still there' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --raw
expect 1 "$WITHHELD" 'a tampered document (exit 1) has its content withheld' -- \
  --attestation "$T/tampered-field.json" "${COMMON[@]}"
lacks_all 'a tampered document shows none of its attested values' "${SECRETS[@]}"
expect 1 "$WITHHELD" 'a tampered document has its content withheld even with --raw' -- \
  --attestation "$T/tampered-field.json" "${COMMON[@]}" --raw
lacks_all 'a tampered document shows none of its attested values, even with --raw' "${SECRETS[@]}" '"frameworks"' 'posture (E7'
expect 1 "$WITHHELD" 'a genuine but expired document (exit 1) has its content withheld' -- \
  --attestation "$T/att.json" --jwks "$T/jwks.json" --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$NOW_LATE" --raw
lacks_all 'an expired document shows none of its attested values, even with --raw' "${SECRETS[@]}" '"frameworks"' 'posture (E7'
expect 1 "$WITHHELD" 'a signature-valid document that fails another check has its content withheld' -- \
  --attestation "$T/other-iss.json" "${COMMON[@]}" --raw
lacks_all 'a document from another issuer shows none of its attested values' "${SECRETS[@]}" '"frameworks"'
expect 2 "$WITHHELD" 'a document that could not be checked (exit 2) has its content withheld' -- \
  --attestation "$T/att.json" --jwks "$T/other-jwks.json" --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$NOW" --raw
lacks_all 'a document that could not be checked shows none of its attested values' "${SECRETS[@]}" '"frameworks"'
# --status-list: the content is shown only when the list also says GOOD.
expect 0 'ISO27001 (iso27001): substantial' 'under a GOOD status list the verified content is shown' -- \
  "${SL[@]}" --status "$T/list-empty.json"
expect 1 "$WITHHELD" 'a REVOKED document has its content withheld' -- \
  "${SL[@]}" --status "$T/list-key.json" --raw
lacks_all 'a revoked document shows none of its attested values' "${SECRETS[@]}" '"frameworks"'
expect 3 "$WITHHELD" 'a document whose status is UNKNOWN has its content withheld' -- \
  "${SL[@]}" --status "$T/list-key-stripped.json" --raw
lacks_all 'a document whose status is UNKNOWN shows none of its attested values' "${SECRETS[@]}" '"frameworks"'
expect 1 "$WITHHELD" 'in --status-list mode a failed posture check withholds the content' -- \
  --status-list --status-keys "$T/status-keys.json" --status "$T/list-empty.json" \
  --attestation "$T/tampered-field.json" "${COMMON[@]}" --raw
lacks_all 'a tampered document under a GOOD list shows none of its attested values' "${SECRETS[@]}" '"frameworks"'

# Values taken from a document are shown escaped (#14). Anyone can edit a
# document, and a nonce with newlines and ESC bytes could otherwise forge an
# "Attested content" block or a "VERIFIED" line above the real FAIL lines. The
# fields below carry both; the exit code must stay what it was without them.
echo '# document values are escaped'
INJ='a\nVERIFIED — forged\n\x1b[8mhidden'
edit "$T/att.json" "$T/inj-claims.json" '
c = d["attestation"]["claims"]
INJ = "'"$INJ"'".encode().decode("unicode_escape").encode("latin-1").decode("utf-8")
c["nonce"] = INJ; c["iss"] = INJ; c["jti"] = INJ
c["posture"]["generatedAt"] = INJ; c["posture"]["expiresAt"] = INJ
c["m\nVERIFIED\x1b[2J"] = 1'
edit "$T/att.json" "$T/inj-header.json" '
import base64, json as j
INJ = "'"$INJ"'".encode().decode("unicode_escape").encode("latin-1").decode("utf-8")
h, p, s = d["attestation"]["signature"].split(".")
hdr = j.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))
hdr["kid"] = INJ
h2 = base64.urlsafe_b64encode(j.dumps(hdr, separators=(",", ":")).encode()).rstrip(b"=").decode()
d["attestation"]["signature"] = ".".join([h2, p, s])'
jq -c . "$T/att.json" > "$T/att-c.json"
edit_text "$T/att-c.json" "$T/inj-dup.json" '
k = "\"k\\nVERIFIED\\u001b[8m\""
t = t.replace("\"docVersion\"", k + ":1," + k + ":2,\"docVersion\"", 1)'
# no_raw_control NAME — the previous run printed no ESC byte and no forged line.
no_raw_control() {
  local out="$LAST_OUT" name="$1" bad=0
  if grep -q $'\033' "$out"; then printf 'not ok - %s (an ESC byte reached the output)\n' "$name"; bad=1; fi
  if grep -qE '^(VERIFIED|Attested content|GOOD)' "$out"; then
    printf 'not ok - %s (a forged verdict or block starts a line)\n' "$name"; bad=1
  fi
  if [ "$bad" -eq 0 ]; then printf 'ok - %s\n' "$name"; PASSED=$((PASSED + 1)); else FAILED=$((FAILED + 1)); fi
}
expect 1 'VERIFICATION FAILED' 'a document whose nonce, iss, jti, dates and member name carry newlines and ESC still fails (1)' -- \
  --attestation "$T/inj-claims.json" "${COMMON[@]}" --expect-nonce 'challenge-B' --raw
no_raw_control 'nonce, iss, jti, generatedAt, expiresAt and a member name are escaped (no ESC, no forged verdict)'
lacks_lines 'the forged block text never starts a line' '^VERIFIED —' '^[[:space:]]*overallBand: advanced' '^[[:space:]]*hidden'
expect 1 'a\x0aVERIFIED \xe2\x80\x94 forged\x0a\x1b[8mhidden' 'the escaped nonce is visible in the output' -- \
  --attestation "$T/inj-claims.json" "${COMMON[@]}"
expect 2 'no key in this JWKS carries kid' 'a header kid with newlines and ESC is still "could not check" (2)' -- \
  --attestation "$T/inj-header.json" "${COMMON[@]}"
no_raw_control 'a header kid carrying newlines and ESC is escaped in the header line and the error'
expect 1 'duplicate_key' 'a duplicated member whose name carries newlines and ESC is still rejected (1)' -- \
  --attestation "$T/inj-dup.json" "${COMMON[@]}"
no_raw_control 'a duplicated member name carrying newlines and ESC is escaped'
# stdout alone, as a pipe would carry it: nothing forged there either.
NO_COLOR=1 bash "$VERIFIER" --attestation "$T/inj-claims.json" "${COMMON[@]}" 2>/dev/null > "$T/inj-stdout.txt"
if ! grep -q $'\033' "$T/inj-stdout.txt" && ! grep -qE '^(VERIFIED|Attested content)' "$T/inj-stdout.txt"; then
  printf 'ok - stdout alone carries no ESC byte and no forged verdict\n'; PASSED=$((PASSED + 1))
else
  printf 'not ok - stdout alone carries an ESC byte or a forged verdict\n'; FAILED=$((FAILED + 1))
fi

# Values are compared exactly as signed. $(...) strips trailing newlines, so a
# signed "fixture-org" plus a newline used to satisfy --expect-slug fixture-org,
# and the subject rule hashed the slug without it. A value holding a NUL byte
# (which a shell variable cannot hold) is a failed check, never the value without it.
echo '# values are compared exactly as signed'
mint_attest --out "$T/nl-slug.json" --slug "$SLUG"$'\n'
expect 1 "posture is for slug 'fixture-org\\x0a', not the expected 'fixture-org'" 'a signed slug with a trailing newline does not satisfy --expect-slug (slug_mismatch)' -- \
  --attestation "$T/nl-slug.json" "${COMMON[@]}"
lacks 'VERIFIED' 'a slug with a trailing newline never ends VERIFIED under --expect-slug'
mint_attest --out "$T/nl-nonce.json" --nonce 'challenge-A'$'\n'
expect 1 'nonce_mismatch' 'a signed nonce with a trailing newline does not answer the challenge' -- \
  --attestation "$T/nl-nonce.json" "${COMMON[@]}" --expect-nonce 'challenge-A'
mint_attest --out "$T/nl-iss.json" --iss "$ISS"$'\n'
expect 1 "issuer_mismatch — iss is 'https://issuer.test\\x0a'" 'a signed iss with a trailing newline does not satisfy --expect-issuer' -- \
  --attestation "$T/nl-iss.json" "${COMMON[@]}"
mint_attest --out "$T/nul-slug.json" --escapes --slug 'fixture-org\x00'
expect 1 'nul_byte — slug holds a NUL byte' 'a signed slug holding a NUL byte is a failed check (1)' -- \
  --attestation "$T/nul-slug.json" "${COMMON[@]}"
lacks 'VERIFIED' 'a slug holding a NUL byte never ends VERIFIED'
expect 1 'nul_byte — slug holds a NUL byte' 'a slug holding a NUL byte fails without --expect-slug too' -- \
  --attestation "$T/nul-slug.json" --jwks "$T/jwks.json" --expect-issuer "$ISS" --now "$NOW"
mint_attest --out "$T/nul-iss.json" --escapes --iss 'https://issuer.test\x00'
expect 1 "issuer_mismatch — iss is 'https://issuer.test\\x00'" 'a signed iss holding a NUL byte is shown with it and does not match' -- \
  --attestation "$T/nul-iss.json" "${COMMON[@]}"
# The subject rule hashes the signed slug: a withdrawal of "fixture-org" plus a
# newline applies to a document for exactly that slug.
mint_status --out "$T/list-subj-nl.json" --seq 8 --revoke-subject "$SLUG"$'\n''@2026-01-01T00:10:00.000Z'
expect 1 'REVOKED — via subject' 'a withdrawal of a slug with a trailing newline revokes the document for that slug' -- \
  --status-list --status-keys "$T/status-keys.json" --status "$T/list-subj-nl.json" \
  --attestation "$T/nl-slug.json" --jwks "$T/jwks.json" --expect-issuer "$ISS" --now "$NOW"
# The status list: its iss is compared exactly too.
mint_status --out "$T/list-nl-iss.json" --seq 8 --iss "$ISS"$'\n'
expect 3 "issuer_mismatch — iss is 'https://issuer.test\\x0a'" 'a status list whose iss has a trailing newline does not satisfy --expect-issuer (3)' -- \
  "${SL[@]}" --status "$T/list-nl-iss.json"
lacks 'GOOD' 'a status list with another iss is never GOOD under --expect-issuer'
# A signed but empty slug names no organisation: a failed check (slug_empty), as
# an empty iss is. The subject rule skipped it, so a withdrawal of "" never applied.
mint_attest --out "$T/empty-slug.json" --slug ''
expect 1 "slug_empty — the posture's slug (F2) is empty" 'a signed but empty slug is a failed check (1)' -- \
  --attestation "$T/empty-slug.json" --jwks "$T/jwks.json" --expect-issuer "$ISS" --now "$NOW"
lacks 'VERIFIED —' 'a document with an empty slug never ends VERIFIED'
mint_status --out "$T/list-subj-empty.json" --seq 8 --revoke-subject '@2026-01-01T00:10:00.000Z'
expect 1 'slug_empty' 'a document with an empty slug fails under a list that withdraws the empty subject (1)' -- \
  --status-list --status-keys "$T/status-keys.json" --status "$T/list-subj-empty.json" \
  --attestation "$T/empty-slug.json" --jwks "$T/jwks.json" --expect-issuer "$ISS" --now "$NOW"
lacks 'GOOD' 'a document with an empty slug is never GOOD'
expect 1 'REVOKED — via subject' 'the subject rule runs on the empty slug of the document: the withdrawal of "" applies' -- \
  --status-list --status-keys "$T/status-keys.json" --status "$T/list-subj-empty.json" \
  --attestation "$T/empty-slug.json" --jwks "$T/jwks.json" --expect-issuer "$ISS" --now "$NOW"
expect 1 'slug_empty' 'a document with an empty slug fails under a list that withdraws nothing (1)' -- \
  --status-list --status-keys "$T/status-keys.json" --status "$T/list-empty.json" \
  --attestation "$T/empty-slug.json" --jwks "$T/jwks.json" --expect-issuer "$ISS" --now "$NOW"
lacks 'GOOD — not revoked' 'a document with an empty slug is never GOOD, whatever the list'
mint_status --out "$T/list-nul-iss.json" --seq 8 --escapes --iss 'https://issuer.test\x00'
expect 3 'nul_byte — .iss holds a NUL byte' 'a status list whose iss holds a NUL byte is UNKNOWN (3)' -- \
  "${SL[@]}" --status "$T/list-nul-iss.json"

# A non-ASCII label verifies and is shown. The same document under a Latin-1
# locale is checked in the --json section below (it needs jexpect). This test used
# to set PYTHONIOENCODING=ascii, which python3 -I ignores, so it could not fail;
# the locale is what changed the verdict. The documents carry the label as raw
# UTF-8 bytes, as a server may send it (mint.py writes —; jq writes it raw).
mint_attest --out "$T/label-ascii.json" --framework 'ens—alto=basic'
jq . "$T/label-ascii.json" > "$T/label.json"
jq '.attestation.claims' "$T/label.json" > "$T/label-claims.json"
jq -r '.attestation.signature' "$T/label.json" > "$T/label.jws"
if grep -q $'\xe2\x80\x94' "$T/label.json" && grep -q $'\xe2\x80\x94' "$T/label-claims.json"; then
  printf 'ok - the label documents carry the label as raw UTF-8\n'; PASSED=$((PASSED + 1))
else
  printf 'not ok - the label documents do not carry raw UTF-8; the locale tests would test nothing\n'; FAILED=$((FAILED + 1))
fi
expect 0 'ENS—ALTO (ens—alto): basic' 'a non-ASCII framework label verifies and is shown (0)' -- \
  --attestation "$T/label.json" "${COMMON[@]}"
expect 0 'VERIFIED — this document was signed' 'the same document with --raw reaches its VERIFIED verdict' -- \
  --attestation "$T/label.json" "${COMMON[@]}" --raw
expect 0 'VERIFIED — this document was signed' 'the same document from --jws and a raw UTF-8 --claims verifies' -- \
  --jws "$T/label.jws" --claims "$T/label-claims.json" "${COMMON[@]}"

# --- python3 and the locale (static) --------------------------------------------
# What the embedded Python reads and writes must not depend on the locale: every
# open( in the script is binary ("rb"/"wb") or passes encoding="utf-8" (and no
# errors= that would relax it), and every python3 call is `python3 -I -X utf8`
# (isolated, and UTF-8 for its arguments and standard streams).
LOCALE_SCAN="$(python3 -I - "$VERIFIER" <<'PY'
import re, sys
t = open(sys.argv[1], encoding="utf-8").read()
found, bad = 0, []
for m in re.finditer(r"(?<![A-Za-z0-9_.])open\(", t):
    i, depth = m.end(), 1
    while depth and i < len(t):
        depth += {"(": 1, ")": -1}.get(t[i], 0)
        i += 1
    args = t[m.end():i - 1]
    found += 1
    mode_ok = re.search(r"[\"'](rb|wb)[\"']", args) or 'encoding="utf-8"' in args
    if not mode_ok or "errors=" in args:
        bad.append("line %d: open(%s)" % (t.count("\n", 0, m.start()) + 1, args))
calls = re.findall(r"python3 -[^\n]*", t)
for c in calls:
    if not re.match(r"python3 -I -X utf8(\s|`)", c):
        bad.append("a python3 call that is not python3 -I -X utf8: " + c[:60])
print("%d %d" % (found, len(calls)))
for b in bad: print(b)
PY
)"
read -r LOCALE_OPENS LOCALE_CALLS _ <<< "$LOCALE_SCAN"
if [ "$(printf '%s\n' "$LOCALE_SCAN" | wc -l)" -eq 1 ] && [ "${LOCALE_OPENS:-0}" -ge 15 ] && [ "${LOCALE_CALLS:-0}" -ge 20 ]; then
  printf 'ok - every open( (%s) is binary or UTF-8, and every python3 call (%s) is python3 -I -X utf8\n' "$LOCALE_OPENS" "$LOCALE_CALLS"
  PASSED=$((PASSED + 1))
else
  printf 'not ok - the embedded Python depends on the locale\n'; printf '%s\n' "$LOCALE_SCAN" | sed 's/^/    # /'
  FAILED=$((FAILED + 1))
fi

# --expect-kid is judged in the C locale: an accented letter is not in A-Z (#13).
# A locale with real collation rules is the one that used to accept them.
KID_LOCALE=C
for cand in en_US.utf8 en_GB.utf8 C.utf8; do
  if locale -a 2>/dev/null | grep -qix "$cand"; then KID_LOCALE="$cand"; break; fi
done
LC_ALL="$KID_LOCALE" expect 2 'is not a kid' "an accented letter in --expect-kid is a usage error (2) under $KID_LOCALE" -- \
  --attestation "$T/att.json" "${COMMON[@]}" --expect-kid 'ééééééééééééééééééééé'
LC_ALL="$KID_LOCALE" expect 2 'is not a kid' "an accented letter among valid characters is a usage error (2) under $KID_LOCALE" -- \
  --attestation "$T/att.json" "${COMMON[@]}" --expect-kid 'AAAAAAAAAAAAAAAAAAAAéA'
# The protected header is read in the C locale too: a header kid holding a byte
# that is not valid UTF-8 is read and shown, escaped, under a UTF-8 locale as
# under C (it used to read as an empty kid there).
edit "$T/att.json" "$T/kid-ff.json" '
import base64
h, p, s = d["attestation"]["signature"].split(".")
raw = base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)).replace(b"\"kid\":\"", b"\"kid\":\"\xff", 1)
d["attestation"]["signature"] = ".".join([base64.urlsafe_b64encode(raw).rstrip(b"=").decode(), p, s])'
for kid_loc in C "$KID_LOCALE"; do
  LC_ALL="$kid_loc" expect 2 "no key in this JWKS carries kid '\\xff$ISSUER_KID'" "a header kid with a byte that is not UTF-8 is read the same under $kid_loc (2)" -- \
    --attestation "$T/kid-ff.json" "${COMMON[@]}"
done

# Retired keys (hs_retired_at). The published vectors hold the boundary cases;
# these are the grammar, the key-selection and the escaping cases, which need
# values a fixture file would have to carry byte for byte.
echo '# retired keys'
RET_AT_S='2026-07-31T18:53:58Z'
RET_NOW=1785524038                                   # RET_AT_S as an epoch
mint_attest --out "$T/ret-after.json" --generated-at '2026-07-31T18:53:58.000Z' --expires-at '2026-07-31T19:08:58.000Z'
mint_attest --out "$T/ret-before.json" --generated-at '2026-07-31T18:53:57.999Z' --expires-at '2026-07-31T19:08:57.999Z'
RET_COMMON=(--jwks "$T/jwks-ret.json" --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$RET_NOW")
# set_retired FILE JSON_VALUE — the selected key's hs_retired_at, as raw JSON.
set_retired() { edit "$T/jwks.json" "$T/jwks-ret.json" "d['keys'][0]['hs_retired_at'] = json.loads(r'''$1''')"; }

set_retired '"2026-07-31T18:53:58Z"'
expect 1 "retired_key — this document was generated at 2026-07-31T18:53:58.000Z, at or after the retirement of key $ISSUER_KID at $RET_AT_S" \
  'a document generated at the retirement instant fails retired_key' -- --attestation "$T/ret-after.json" "${RET_COMMON[@]}"
lacks 'EXPIRED' 'retired_key is not reported as a staleness failure'
expect 0 'is retired (at 2026-07-31T18:53:58Z), but this document was generated at 2026-07-31T18:53:57.999Z' \
  'one millisecond before the retirement passes' -- --attestation "$T/ret-before.json" "${RET_COMMON[@]}"
expect 1 'retired_key' '--expect-kid pinned to the retired kid does not rescue a post-retirement document' -- \
  --attestation "$T/ret-after.json" "${RET_COMMON[@]}" --expect-kid "$ISSUER_KID"
expect 0 'VERIFIED — this document was signed' '--pub-b64url has no JWK, so retirement does not apply' -- \
  --attestation "$T/ret-after.json" --pub-b64url "$(jq -r '.keys[0].pub' "$T/jwks.json")" \
  --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$RET_NOW"
# Same retirement, a document generated later on the clock but with a lexically
# smaller string would be the trap of a string comparison; instants are compared.
mint_attest --out "$T/ret-offset.json" --generated-at '2026-07-31T20:53:57.999+02:00' --expires-at '2026-07-31T20:53:58.999+02:00'
expect 0 'before the retirement' 'an offset form of 18:53:57.999Z is compared as an instant' -- \
  --attestation "$T/ret-offset.json" "${RET_COMMON[@]}"

# No claims JSON to read generatedAt from (an attached JWS whose payload is not
# an envelope): a retired key cannot be shown to predate its retirement, so the
# run fails closed (1) with retired_key, besides the failures it already has.
IFS=. read -r UH _ US < <(jq -r '.attestation.signature' "$T/ret-before.json")
printf '%s.AAAA.%s\n' "$UH" "$US" > "$T/ret-undecodable.jws"
set_retired '"2026-07-31T18:53:58Z"'
expect 1 "retired_key — key $ISSUER_KID is retired (at $RET_AT_S) and without the claims JSON there is no generatedAt" \
  'a retired key with no claims JSON to compare fails closed' -- --jws "$T/ret-undecodable.jws" "${RET_COMMON[@]}"

# The grammar: anything but YYYY-MM-DDTHH:MM:SSZ is a malformed key set (2).
for bad_val in '"2026-07-31T18:53:58.000Z"' '"2026-07-31T18:53:58+00:00"' '"2026-07-31t18:53:58Z"' \
               '"2026-07-31T18:53:58z"' '"2026-07-31T18:53:58"' '"2026-07-31"' '""' '1785524038' 'null' 'true' \
               '["2026-07-31T18:53:58Z"]' '"2026-02-30T18:53:58Z"' '"2026-07-31T24:00:00Z"' '"2026-07-31T18:60:00Z"' \
               '"2026-07-31T18:53:60Z"' '"2026-13-01T00:00:00Z"' '" 2026-07-31T18:53:58Z"' \
               '"2026-07-31T18:53:58Z\n"' '"２０２６-07-31T18:53:58Z"'; do
  set_retired "$bad_val"
  expect 2 'hs_retired_at of the key' "hs_retired_at $bad_val is malformed: could not check (2)" -- \
    --attestation "$T/ret-before.json" "${RET_COMMON[@]}"
done
set_retired '"2024-02-29T00:00:00Z"'
expect 1 'retired_key' 'a leap-day retirement is a valid date (and a document after it fails)' -- \
  --attestation "$T/ret-before.json" "${RET_COMMON[@]}"

# A retired key that is not the selected key has no effect, whatever its value.
for other_val in '"2026-01-01T00:00:00Z"' '"not a time"'; do
  edit "$T/jwks.json" "$T/jwks-ret.json" "d['keys'].insert(0, {'kty': 'AKP', 'alg': 'ML-DSA-65', 'pub': 'AAAA', 'kid': 'Zm9vYmFyZm9vYmFyZm9vYg', 'hs_retired_at': json.loads('''$other_val''')})"
  expect 0 'VERIFIED — this document was signed' "another key with hs_retired_at $other_val does not affect the selected key" -- \
    --attestation "$T/ret-after.json" "${RET_COMMON[@]}"
  lacks 'retired' 'and nothing about retirement is printed'
done

# Values from the key set are printed through esc().
set_retired '"2026-07-31T18:53:58Z\u001b[31m\nPASS  forged"'
expect 2 'hs_retired_at of the key' 'a malformed hs_retired_at with control characters is rejected' -- \
  --attestation "$T/ret-before.json" "${RET_COMMON[@]}"
if grep -q $'\x1b' "$LAST_OUT" || grep -q '^PASS  forged' "$LAST_OUT"; then
  printf 'not ok - control characters of hs_retired_at reached the terminal unescaped\n'; FAILED=$((FAILED + 1))
else
  printf 'ok - control characters of hs_retired_at are escaped before they reach the terminal\n'; PASSED=$((PASSED + 1))
fi
expect 2 '\x1b[31m\x0aPASS  forged' 'the control characters are shown as visible \xHH escapes' -- \
  --attestation "$T/ret-before.json" "${RET_COMMON[@]}"

# The status list's own key set. A list issued at or after the retirement of its
# key is UNKNOWN (3); a malformed marker is a defective status key set, UNKNOWN too.
"${MINT[@]}" status --key "$T/status.pem" --out "$T/list-ret-at.json" --iss "$ISS" --seq 9 \
  --issued-at '2026-07-31T18:53:58.000Z' --next-update '2026-07-31T20:53:58.000Z' >/dev/null
"${MINT[@]}" status --key "$T/status.pem" --out "$T/list-ret-before.json" --iss "$ISS" --seq 9 \
  --issued-at '2026-07-31T18:53:57.999Z' --next-update '2026-07-31T20:53:57.999Z' >/dev/null
SKID="$(jq -r '.keys[0].kid' "$T/status-keys.json")"
RETS=(--status-list --attestation "$T/ret-before.json" --jwks "$T/jwks.json" --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$RET_NOW")
edit "$T/status-keys.json" "$T/status-keys-ret.json" "d['keys'][0]['hs_retired_at'] = '$RET_AT_S'"
expect 3 "retired_key — this status list was issued at 2026-07-31T18:53:58.000Z, at or after the retirement of key $SKID at $RET_AT_S" \
  'a status list issued at the retirement of its key is UNKNOWN' -- \
  "${RETS[@]}" --status-keys "$T/status-keys-ret.json" --status "$T/list-ret-at.json"
expect 0 'before the retirement' 'a status list issued one millisecond before the retirement is trusted' -- \
  "${RETS[@]}" --status-keys "$T/status-keys-ret.json" --status "$T/list-ret-before.json"
for bad_val in '2026-07-31T18:53:58.000Z' '2026-07-31t18:53:58Z' '' '2026-02-30T18:53:58Z'; do
  edit "$T/status-keys.json" "$T/status-keys-ret.json" "d['keys'][0]['hs_retired_at'] = '$bad_val'"
  expect 3 'hs_retired_at of the --status-keys entry' "status key hs_retired_at '$bad_val' is malformed: UNKNOWN (3)" -- \
    "${RETS[@]}" --status-keys "$T/status-keys-ret.json" --status "$T/list-ret-before.json"
done
edit "$T/status-keys.json" "$T/status-keys-ret.json" "d['keys'][0]['hs_retired_at'] = 5"
expect 3 'hs_retired_at of the --status-keys entry' 'a non-string status key hs_retired_at is UNKNOWN (3)' -- \
  "${RETS[@]}" --status-keys "$T/status-keys-ret.json" --status "$T/list-ret-before.json"
edit "$T/status-keys.json" "$T/status-keys-ret.json" "d['keys'][0]['hs_retired_at'] = '$RET_AT_S\u001b[31m'"
expect 3 '\x1b[31m' 'a status key hs_retired_at with control characters is printed escaped' -- \
  "${RETS[@]}" --status-keys "$T/status-keys-ret.json" --status "$T/list-ret-before.json"
# The attestation key set's marker does not touch the status list, nor the reverse.
edit "$T/jwks.json" "$T/jwks-ret.json" "d['keys'][0]['hs_retired_at'] = '2000-01-01T00:00:00Z'"
expect 1 'retired_key' 'the attestation key retired long ago still fails a recent document under --status-list' -- \
  --status-list --attestation "$T/ret-before.json" --jwks "$T/jwks-ret.json" --expect-slug "$SLUG" \
  --expect-issuer "$ISS" --now "$RET_NOW" --status-keys "$T/status-keys.json" --status "$T/list-ret-before.json"

# A key set that cannot be read one way: `keys` that is not an array of objects,
# or two keys with the same kid (the first would win, so a marker could be dodged
# by ordering). --jwks: could not check (2). --status-keys: UNKNOWN (3).
for variant in dup-first dup-last keys-object str-entry; do
  case "$variant" in
    dup-first)   PY="k = d['keys'][0]; d['keys'] = [dict(k), dict(k, hs_retired_at='$RET_AT_S')]" ;;
    dup-last)    PY="k = d['keys'][0]; d['keys'] = [dict(k, hs_retired_at='$RET_AT_S'), dict(k)]" ;;
    keys-object) PY="d['keys'] = {'a': dict(d['keys'][0], hs_retired_at='$RET_AT_S')}" ;;
    str-entry)   PY="d['keys'] = ['str', d['keys'][0]]" ;;
  esac
  edit "$T/jwks.json" "$T/jwks-bad.json" "$PY"
  expect 2 'is invalid' "attestation key set, $variant: could not check (2)" -- \
    --attestation "$T/ret-before.json" --jwks "$T/jwks-bad.json" --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$RET_NOW"
  edit "$T/status-keys.json" "$T/status-keys-bad.json" "$PY"
  expect 3 'status-keys.json' "status key set, $variant: UNKNOWN (3), never a crash" -- \
    "${RETS[@]}" --status-keys "$T/status-keys-bad.json" --status "$T/list-ret-at.json"
done

# --pub-b64url and --jwks are two sources for the same key.
expect 2 'cannot be combined with --jwks' '--pub-b64url together with --jwks is a usage error (2)' -- \
  --attestation "$T/ret-before.json" --jwks /nonexistent --pub-b64url "$(jq -r '.keys[0].pub' "$T/jwks.json")" \
  --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$RET_NOW"
expect 2 'cannot be combined with --jwks' '--pub-b64url together with a readable --jwks is a usage error too' -- \
  --attestation "$T/ret-before.json" --jwks "$T/jwks.json" --pub-b64url "$(jq -r '.keys[0].pub' "$T/jwks.json")" \
  --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$RET_NOW"

# --- anchor (--anchor-file), with a cosign test double -------------------------
# The stub only stands in for cosign: a program first on PATH that prints a
# version, records the arguments it was called with, prints what the test tells
# it to on stderr and exits with the code the test tells it to. The verifier
# under test still does the version check, the classification of what cosign
# said, the strict parse of the statement and the membership logic. Real cosign
# and real bundles are exercised by the published vectors (anchor/), which CI
# runs with cosign installed.
echo '# anchor (--anchor-file), cosign test double'
STUB="$T/stub"; mkdir -p "$STUB"
# The verifier calls cosign twice: first with the fixed identity pattern, then
# with the exact identity it read from the certificate. The first call's
# arguments go to COSIGN_STUB_LOG, the second's to COSIGN_STUB_LOG.identity, and
# COSIGN_STUB_RC_IDENTITY makes the second one fail on its own.
cat > "$STUB/cosign" <<'STUBEOF'
#!/usr/bin/env bash
if [ "${1:-}" = version ]; then printf 'GitVersion:    %s\n' "${COSIGN_STUB_VERSION-v3.1.3}"; exit 0; fi
log="${COSIGN_STUB_LOG:-}"; rc="${COSIGN_STUB_RC:-0}"
case " $* " in
  *' --certificate-identity '*) log="${log:+$log.identity}"; rc="${COSIGN_STUB_RC_IDENTITY:-$rc}" ;;
esac
printf '%s\n' "$@" > "${log:-/dev/null}"
[ -z "${COSIGN_STUB_ERR:-}" ] || printf '%b\n' "$COSIGN_STUB_ERR" >&2
exit "$rc"
STUBEOF
chmod +x "$STUB/cosign"
# A PATH with the tools the verifier needs and no cosign.
NOCOSIGN="$T/nocosign"; mkdir -p "$NOCOSIGN"
for tool in bash env openssl python3 jq awk sed grep tr cat head cut wc date mktemp rm cp mkdir chmod sort tee dirname basename xxd uname; do
  tool_path="$(command -v "$tool" 2>/dev/null || true)"
  if [ -n "$tool_path" ] && [ -x "$tool_path" ]; then ln -sf "$tool_path" "$NOCOSIGN/$tool"; fi
done
PATH_BEFORE_STUB="$PATH"
export COSIGN_STUB_LOG="$T/cosign.argv"
ANCHOR_RE='^https://github\.com/Hodeitek/hodeishield-attest-verifier/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$'
ANCHOR_ISSUER_URL='https://token.actions.githubusercontent.com'

# The statement: the issuer, the attestation key and the status-list key of the
# fixtures, minted from their kids as the key sets above are.
ASKID="$(jq -r '.keys[0].kid' "$T/status-keys.json")"
python3 -I - "$T/stmt-base.json" "$ISSUER_KID" "$ASKID" "$ISS" <<'PY'
import json, sys
out, akid, skid, iss = sys.argv[1:5]
json.dump({"schema": "hodeishield.keys.statement.v1", "issuer": iss, "keys": [
    {"kid": akid, "role": "attestation", "status": "active",
     "published_at": iss + "/api/public/attest/keys", "active_since": "2026-01-01"},
    {"kid": skid, "role": "status-list", "status": "active",
     "published_at": iss + "/api/public/attest/status-keys", "active_since": "2026-01-01"}]},
    open(out, "w"), indent=2)
PY
# st OUT PYTHON — a statement derived from the base one; `d` is the document.
st() { edit "$T/stmt-base.json" "$1" "$2"; }
# The bundle the stub "verifies" carries a real (self-signed) certificate whose
# single SAN is the workflow identity at a tag: the verifier reads the release tag
# from it, as it does from the certificate cosign has just verified.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$T/anchor-k.pem" 2>/dev/null
# mint_bundle OUT SAN [REPO] — a Sigstore v0.3 bundle (in shape: the stub verifies
# nothing) whose certificate has this subjectAltName ('' for none) and, as Fulcio
# writes it, the Source Repository Identifier extension (OID
# 1.3.6.1.4.1.57264.1.15): REPO is its value in openssl's ASN1: syntax, by
# default this repository's ID as a UTF8String, or '-' for no extension.
REPO_ID=1340684886
mint_bundle() {
  local ext=() repo="${3:-ASN1:UTF8String:$REPO_ID}"
  rm -f "$T/anchor-c.der"
  if [ -n "$2" ]; then ext=(-addext "subjectAltName=$2"); fi
  if [ "$repo" != - ]; then ext+=(-addext "1.3.6.1.4.1.57264.1.15=$repo"); fi
  openssl req -new -x509 -key "$T/anchor-k.pem" -subj '/CN=anchor-test' -days 2 ${ext[@]+"${ext[@]}"} \
    -outform DER -out "$T/anchor-c.der" 2>/dev/null
  printf '{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{"certificate":{"rawBytes":"%s"},"tlogEntries":[{"logIndex":"1"}],"timestampVerificationData":{}},"messageSignature":{"messageDigest":{"algorithm":"SHA2_256","digest":"AAAA"},"signature":"AAAA"}}\n' \
    "$(openssl base64 -A -in "$T/anchor-c.der")" > "$1"
}
ANCHOR_WF='https://github.com/Hodeitek/hodeishield-attest-verifier/.github/workflows/release.yml@refs/tags/'
VER="$(bash "$VERIFIER" --version | awk '{print $2}')"
ANCHOR_SIGNED="is signed by ${ANCHOR_WF}v${VER}"
mint_bundle "$T/stmt.json.sigstore.json" "URI:${ANCHOR_WF}v${VER}"
cp "$T/stmt-base.json" "$T/stmt.json"
A=(--anchor-file "$T/stmt.json")                         # the bundle: stmt.json.sigstore.json, by default
PUB="$(jq -r '.keys[0].pub' "$T/jwks.json")"

export PATH="$STUB:$PATH_BEFORE_STUB"

rm -f "$COSIGN_STUB_LOG"
expect 0 "the key statement stmt.json ${ANCHOR_SIGNED}" \
  'cosign accepts the statement: the anchor is verified' -- \
  --attestation "$T/att.json" "${COMMON[@]}" "${A[@]}"
expect 0 "lists kid '$ISSUER_KID' as an attestation key" 'the attestation key is listed (anchor_kid_listed)' -- \
  --attestation "$T/att.json" "${COMMON[@]}" "${A[@]}"
expect 0 "iss (E2) is the issuer '$ISS' the signed key statement names" 'the issuer matches the statement (anchor_issuer_matches)' -- \
  --attestation "$T/att.json" "${COMMON[@]}" "${A[@]}"
# What cosign was asked to do: the exact fixed identity pattern and issuer, the
# bundle and the statement, and nothing that could name another identity.
argv_has() {   # ARG DESCRIPTION [LOG]
  local log="${3:-$COSIGN_STUB_LOG}"
  if grep -qxF -- "$1" "$log" 2>/dev/null; then
    printf 'ok - cosign was called with %s\n' "$2"; PASSED=$((PASSED + 1))
  else
    printf 'not ok - cosign was not called with %s\n' "$2"; sed 's/^/    # /' "$log" 2>/dev/null; FAILED=$((FAILED + 1))
  fi
}
argv_has verify-blob 'verify-blob'
argv_has '--certificate-identity-regexp' '--certificate-identity-regexp'
argv_has "$ANCHOR_RE" 'the exact fixed identity pattern'
argv_has '--certificate-oidc-issuer' '--certificate-oidc-issuer'
argv_has "$ANCHOR_ISSUER_URL" 'the GitHub Actions OIDC issuer'
argv_has '--bundle' '--bundle'
argv_has 'b/stmt.json.sigstore.json' 'the bundle next to the statement (the default name), by name only'
argv_has 's/stmt.json' 'the statement, by name only'
if [ "$(wc -l < "$COSIGN_STUB_LOG" | tr -d ' ')" -eq 8 ] && ! grep -qxE -- '--certificate-identity|--certificate|--key|--insecure-ignore-tlog|--trusted-root' "$COSIGN_STUB_LOG"; then
  printf 'ok - cosign was given exactly those 8 arguments and no option that could change the identity\n'; PASSED=$((PASSED + 1))
else
  printf 'not ok - cosign was given other arguments\n'; sed 's/^/    # /' "$COSIGN_STUB_LOG"; FAILED=$((FAILED + 1))
fi
# The second call: the EXACT identity read from the certificate, the same issuer,
# bundle and statement, and no pattern. It binds the tag to what cosign verified.
IDLOG="$COSIGN_STUB_LOG.identity"
argv_has verify-blob 'verify-blob, a second time' "$IDLOG"
argv_has '--certificate-identity' '--certificate-identity (exact), the second time' "$IDLOG"
argv_has "${ANCHOR_WF}v${VER}" 'the exact identity read from the certificate, the second time' "$IDLOG"
argv_has '--certificate-oidc-issuer' '--certificate-oidc-issuer, the second time' "$IDLOG"
argv_has "$ANCHOR_ISSUER_URL" 'the GitHub Actions OIDC issuer, the second time' "$IDLOG"
argv_has 'b/stmt.json.sigstore.json' 'the same bundle, the second time' "$IDLOG"
argv_has 's/stmt.json' 'the same statement, the second time' "$IDLOG"
if [ "$(wc -l < "$IDLOG" | tr -d ' ')" -eq 8 ] && ! grep -qxE -- '--certificate-identity-regexp|--certificate|--key|--insecure-ignore-tlog|--trusted-root' "$IDLOG"; then
  printf 'ok - the second cosign call has exactly 8 arguments and no pattern\n'; PASSED=$((PASSED + 1))
else
  printf 'not ok - the second cosign call was given other arguments\n'; sed 's/^/    # /' "$IDLOG"; FAILED=$((FAILED + 1))
fi
# The second call fails on its own: the certificate the tag is read from is not
# the one cosign verified. Could not check (2), and no tag is reported.
COSIGN_STUB_RC_IDENTITY=1 COSIGN_STUB_ERR='Error: no matching CertificateIdentity found' \
  expect 2 'anchor could not be checked: cosign did not verify the certificate the release tag is read from' \
  'the second, exact-identity cosign call fails: could not check (2)' -- \
  --attestation "$T/att.json" "${COMMON[@]}" "${A[@]}"
lacks 'VERIFIED' 'no verdict on the attestation when the exact identity does not verify'
lacks 'older than this verifier' 'the tag of a certificate cosign did not verify is not used'
# No option and no environment variable changes who may sign the statement.
COSIGN_CERTIFICATE_IDENTITY='x' COSIGN_CERTIFICATE_OIDC_ISSUER='https://evil.test' SIGSTORE_ROOT_FILE='' \
  bash "$VERIFIER" --attestation "$T/att.json" "${COMMON[@]}" "${A[@]}" > /dev/null 2>&1
argv_has "$ANCHOR_RE" 'the same fixed pattern with identity variables set in the environment'
# The statement passed in is not the path cosign saw, and a path is never shown.
mkdir -p "$T/deep/dir"; cp "$T/stmt.json" "$T/deep/dir/stmt.json"; cp "$T/stmt.json.sigstore.json" "$T/deep/dir/stmt.json.sigstore.json"
expect 0 "$ANCHOR_SIGNED" 'a statement given with a directory is accepted' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --anchor-file "$T/deep/dir/stmt.json"
lacks 'deep/dir' 'the directory of the statement is not printed'
lacks "$T" 'no temporary or absolute path is printed on a verified run'

# --- the cosign version ---------------------------------------------------------
for v in v3.1.3 v3.1.4 v3.10.0 v4.0.0 v3.2.0-rc1; do
  COSIGN_STUB_VERSION="$v" expect 0 "$ANCHOR_SIGNED" "cosign $v is new enough (compared numerically)" -- \
    --attestation "$T/att.json" "${COMMON[@]}" "${A[@]}"
done
for v in v2.4.0 v3.1.2 v3.0.9 v2.99.99 v3.1.3-rc1 '' devel v3.1 v3.x.1 v03.1.3x; do
  COSIGN_STUB_VERSION="$v" expect 2 'anchor could not be checked: --anchor-file needs cosign 3.1.3 or later' "cosign '$v' is too old or unreadable: could not check (2)" -- \
    --attestation "$T/att.json" "${COMMON[@]}" "${A[@]}"
done
COSIGN_STUB_VERSION='v2.4.0' expect 2 "this one reports 'v2.4.0'" 'the old version is named in the message' -- \
  --attestation "$T/att.json" "${COMMON[@]}" "${A[@]}"
lacks 'VERIFIED' 'no verdict on the attestation when cosign is too old'
PATH="$NOCOSIGN" expect 2 'anchor could not be checked: --anchor-file needs cosign 3.1.3 or later, and no usable cosign was found' \
  'cosign absent: could not check (2)' -- --attestation "$T/att.json" "${COMMON[@]}" "${A[@]}"
PATH="$NOCOSIGN" expect 0 'VERIFIED — this document was signed' 'cosign is optional: without --anchor-file nothing needs it' -- \
  --attestation "$T/att.json" "${COMMON[@]}"
PATH="$NOCOSIGN" expect 0 'GOOD — not revoked' 'cosign is optional: --status-list without --anchor-file does not need it' -- \
  "${SL[@]}" --status "$T/list-empty.json"

# --- anti-rollback: the release tag of the verified certificate ----------------------
# The tag is read from the certificate of the bundle cosign accepted, strictly, and
# compared with the version of this script numerically. Older: exit 2, before the
# statement is read. Equal or newer: on to the content checks.
IFS=. read -r V_MAJ V_MIN V_PAT <<< "$VER"
tagcase() {   # NAME SAN WANT_EXIT PATTERN
  mint_bundle "$T/tag-bundle.json" "$2"
  expect "$3" "$4" "release tag, $1" -- \
    --attestation "$T/att.json" "${COMMON[@]}" --anchor-file "$T/stmt.json" --anchor-bundle "$T/tag-bundle.json"
}
tagcase 'equal to this version' "URI:${ANCHOR_WF}v${VER}" 0 "$ANCHOR_SIGNED"
tagcase 'a much older tag is refused' "URI:${ANCHOR_WF}v0.0.1" 2 "anchor could not be checked: statement from v0.0.1, older than this verifier v${VER}"
lacks 'VERIFIED' 'no verdict on the attestation when the statement is older'
if [ "$V_MIN" -gt 0 ]; then
  tagcase 'an older minor with a large patch is refused' "URI:${ANCHOR_WF}v${V_MAJ}.$((V_MIN - 1)).999" 2 "statement from v${V_MAJ}.$((V_MIN - 1)).999, older than this verifier"
fi
if [ "$V_PAT" -gt 0 ]; then
  tagcase 'an older patch is refused' "URI:${ANCHOR_WF}v${V_MAJ}.${V_MIN}.$((V_PAT - 1))" 2 "older than this verifier"
fi
tagcase 'a newer patch is accepted' "URI:${ANCHOR_WF}v${V_MAJ}.${V_MIN}.$((V_PAT + 1))" 0 "is signed by ${ANCHOR_WF}v${V_MAJ}.${V_MIN}.$((V_PAT + 1))"
tagcase 'a newer major is accepted' "URI:${ANCHOR_WF}v$((V_MAJ + 1)).0.0" 0 "is signed by ${ANCHOR_WF}v$((V_MAJ + 1)).0.0"
if [ "$V_MAJ" -eq 1 ] && [ "$V_MIN" -lt 10 ]; then
  # 10 > 4 as numbers, and "1.10.0" sorts before "1.4.0" as text.
  tagcase 'v1.10.0 is newer than v1.4.0: the comparison is numeric, not a string comparison' "URI:${ANCHOR_WF}v1.10.0" 0 "is signed by ${ANCHOR_WF}v1.10.0"
fi
# --- the repository, by its numeric ID (the Source Repository Identifier) ----------
# The identity names the repository; the certificate must also carry its numeric
# ID, which a repository that took over the name would not have.
if grep -qxF "ANCHOR_REPOSITORY_ID='$REPO_ID'" "$VERIFIER"; then
  printf 'ok - the script pins the repository ID %s\n' "$REPO_ID"; PASSED=$((PASSED + 1))
else
  printf 'not ok - the script does not pin the repository ID %s\n' "$REPO_ID"; FAILED=$((FAILED + 1))
fi
NOT_REPO='anchor could not be checked: the certificate is not from this repository'
repocase() {   # NAME REPO_EXTENSION
  mint_bundle "$T/repo-bundle.json" "URI:${ANCHOR_WF}v${VER}" "$2"
  expect 2 "$NOT_REPO" "repository ID, $1: could not check (2)" -- \
    --attestation "$T/att.json" "${COMMON[@]}" --anchor-file "$T/stmt.json" --anchor-bundle "$T/repo-bundle.json"
  lacks 'VERIFIED' "repository ID, $1: no verdict on the attestation"
}
repocase 'no Source Repository Identifier' -
repocase 'another repository ID' "ASN1:UTF8String:$((REPO_ID + 1))"
repocase 'the ID with a digit more' "ASN1:UTF8String:${REPO_ID}0"
repocase 'the ID with a digit less' "ASN1:UTF8String:${REPO_ID%?}"
repocase 'the ID as another string type' "ASN1:PRINTABLESTRING:$REPO_ID"
repocase 'the ID as an integer' "ASN1:INTEGER:$REPO_ID"
repocase 'an empty value' 'ASN1:UTF8String:'
mint_bundle "$T/repo-bundle.json" "URI:${ANCHOR_WF}v${VER}"
expect 0 "$ANCHOR_SIGNED" 'repository ID, this repository: accepted' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --anchor-file "$T/stmt.json" --anchor-bundle "$T/repo-bundle.json"

CANNOT='anchor could not be checked: the statement'"'"'s release tag cannot be read'
tagcase 'a pre-release tag' "URI:${ANCHOR_WF}v${VER}-rc1" 2 "$CANNOT"
tagcase 'build metadata' "URI:${ANCHOR_WF}v${VER}+build" 2 "$CANNOT"
tagcase 'a tag with two components' "URI:${ANCHOR_WF}v1.4" 2 "$CANNOT"
tagcase 'a tag with a leading zero' "URI:${ANCHOR_WF}v01.4.0" 2 "$CANNOT"
tagcase 'a tag without the v' "URI:${ANCHOR_WF}1.4.0" 2 "$CANNOT"
tagcase 'a tag with a fourth component' "URI:${ANCHOR_WF}v1.4.0.1" 2 "$CANNOT"
tagcase 'no tag at all' "URI:${ANCHOR_WF}" 2 "$CANNOT"
tagcase 'a branch ref instead of a tag' "URI:https://github.com/Hodeitek/hodeishield-attest-verifier/.github/workflows/release.yml@refs/heads/main" 2 "$CANNOT"
tagcase 'another workflow of the repository' "URI:https://github.com/Hodeitek/hodeishield-attest-verifier/.github/workflows/ci.yml@refs/tags/v${VER}" 2 "$CANNOT"
tagcase 'another repository' "URI:https://github.com/evil/hodeishield-attest-verifier/.github/workflows/release.yml@refs/tags/v${VER}" 2 "$CANNOT"
tagcase 'two identities in the certificate' "URI:${ANCHOR_WF}v${VER},URI:${ANCHOR_WF}v0.0.1" 2 "$CANNOT"
tagcase 'an identity that is not a URI' "email:someone@example.test" 2 "$CANNOT"
tagcase 'a certificate without an identity' "" 2 "$CANNOT"

# --- the bundle is exactly a Sigstore v0.3 bundle, before cosign sees it --------------
# cosign reads a bundle that does not load as v0.3 in its LEGACY format, and then
# verifies the certificate in "cert", not the one the tag is read from. Each of
# these is refused (anchor_bundle_unsupported, exit 2) and cosign is never called.
UNSUPPORTED='anchor could not be checked: the bundle is not a Sigstore v0.3 bundle'
mint_bundle "$T/v03.json" "URI:${ANCHOR_WF}v${VER}"
bundle_case() {   # NAME PYTHON (over `d`, the v0.3 bundle) | NAME --text PYTHON (over `t`)
  if [ "$2" = --text ]; then edit_text "$T/v03.json" "$T/shape-bundle.json" "$3"
  else edit "$T/v03.json" "$T/shape-bundle.json" "$2"; fi
  rm -f "$COSIGN_STUB_LOG" "$COSIGN_STUB_LOG.identity"
  expect 2 "$UNSUPPORTED" "bundle, $1: could not check (2)" -- \
    --attestation "$T/att.json" "${COMMON[@]}" --anchor-file "$T/stmt.json" --anchor-bundle "$T/shape-bundle.json"
  if [ ! -e "$COSIGN_STUB_LOG" ]; then printf 'ok - bundle, %s: cosign is not called\n' "$1"; PASSED=$((PASSED + 1))
  else printf 'not ok - bundle, %s: cosign was called\n' "$1"; FAILED=$((FAILED + 1)); fi
}
# The legacy format: the signature and certificate cosign would verify, beside a
# decoy certificate where this script reads the tag.
bundle_case 'the legacy format beside a v0.3 certificate' '
d.update(base64Signature="AAAA", cert="AAAA", rekorBundle={"SignedEntryTimestamp": "AAAA", "Payload": {}})'
bundle_case 'the legacy format alone' '
d = {"base64Signature": "AAAA", "cert": "AAAA", "rekorBundle": {}, "verificationMaterial": d["verificationMaterial"]}'
bundle_case 'a payload member' 'd["payload"] = "AAAA"'
bundle_case 'an extra member' 'd["note"] = 1'
bundle_case 'a DSSE envelope as well' 'd["dsseEnvelope"] = {"payload": "AAAA", "payloadType": "x", "signatures": []}'
bundle_case 'a DSSE envelope instead of a message signature' 'd["dsseEnvelope"] = d.pop("messageSignature")'
bundle_case 'no mediaType' 'del d["mediaType"]'
bundle_case 'a v0.2 mediaType' 'd["mediaType"] = "application/vnd.dev.sigstore.bundle+json;version=0.2"'
bundle_case 'a v0.1 mediaType' 'd["mediaType"] = "application/vnd.dev.sigstore.bundle+json;version=0.1"'
bundle_case 'a protobuf field name at the top' 'd["verification_material"] = d.pop("verificationMaterial")'
bundle_case 'a certificate chain instead of one certificate' '
m = d["verificationMaterial"]; m["x509CertificateChain"] = {"certificates": [m.pop("certificate")]}'
bundle_case 'a certificate chain beside the certificate' '
m = d["verificationMaterial"]; m["x509CertificateChain"] = {"certificates": [m["certificate"]]}'
bundle_case 'a public key beside the certificate' 'd["verificationMaterial"]["publicKey"] = {"hint": "x"}'
bundle_case 'no tlogEntries' 'del d["verificationMaterial"]["tlogEntries"]'
bundle_case 'empty tlogEntries' 'd["verificationMaterial"]["tlogEntries"] = []'
bundle_case 'a protobuf field name for rawBytes' 'c = d["verificationMaterial"]["certificate"]; c["raw_bytes"] = c.pop("rawBytes")'
bundle_case 'a second member in the certificate' 'd["verificationMaterial"]["certificate"]["x"] = 1'
bundle_case 'a certificate that is not base64' 'd["verificationMaterial"]["certificate"]["rawBytes"] = "not base64!"'
bundle_case 'an empty certificate' 'd["verificationMaterial"]["certificate"]["rawBytes"] = ""'
bundle_case 'a message signature without a signature' 'del d["messageSignature"]["signature"]'
bundle_case 'an extra member in the message signature' 'd["messageSignature"]["x"] = 1'
bundle_case 'a duplicated member (the certificate)' --text '
t = t.replace("\"certificate\":{", "\"certificate\":{\"rawBytes\":\"AAAA\"},\"certificate\":{", 1)'
bundle_case 'a duplicated top-level member' --text 't = t.replace("{", "{\"mediaType\":\"x\",", 1)'
bundle_case 'a byte order mark' --text 't = "﻿" + t'
bundle_case 'not JSON' --text 't = "not a bundle"'
bundle_case 'an empty object' --text 't = "{}"'
bundle_case 'two JSON values' --text 't = t + t'
edit "$T/v03.json" "$T/legacy-named.json" 'd["base64Signature"] = "AAAA"'
expect 2 'its members are not exactly mediaType, verificationMaterial and messageSignature' \
  'the reason a bundle is not v0.3 is named' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --anchor-file "$T/stmt.json" --anchor-bundle "$T/legacy-named.json"
# The genuine shape, with and without timestampVerificationData, is accepted.
expect 0 "$ANCHOR_SIGNED" 'a v0.3 bundle with timestampVerificationData is accepted' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --anchor-file "$T/stmt.json" --anchor-bundle "$T/v03.json"
edit "$T/v03.json" "$T/v03-nots.json" 'del d["verificationMaterial"]["timestampVerificationData"]; del d["messageSignature"]["messageDigest"]'
expect 0 "$ANCHOR_SIGNED" 'a v0.3 bundle without timestampVerificationData or messageDigest is accepted' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --anchor-file "$T/stmt.json" --anchor-bundle "$T/v03-nots.json"

# The tag is checked before the content: an old statement that is also malformed is "older".
st "$T/stmt-old-bad.json" 'd["schema"] = "x"'
mint_bundle "$T/stmt-old-bad.json.sigstore.json" "URI:${ANCHOR_WF}v0.0.1"
expect 2 'statement from v0.0.1, older than this verifier' 'the tag is checked before the statement is parsed' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --anchor-file "$T/stmt-old-bad.json"
lacks 'malformed' 'an old statement is not read, so its content is not reported'
# A status-list run is refused the same way.
expect 2 'statement from v0.0.1, older than this verifier' 'the tag check applies in --status-list mode too' -- \
  "${SL[@]}" --status "$T/list-empty.json" --anchor-file "$T/stmt-old-bad.json"
# The old-statement bundle is not reused below.
rm -f "$T/stmt-old-bad.json.sigstore.json"

# --- cosign says no: always exit 2, with the cause in the text ---------------------
fail_case() {   # NAME EXPECTED_CAUSE STDERR
  COSIGN_STUB_RC=1 COSIGN_STUB_ERR="$3" expect 2 "anchor could not be checked: $2" "cosign fails, $1: could not check (2), never 1" -- \
    --attestation "$T/att.json" "${COMMON[@]}" "${A[@]}"
  lacks 'VERIFIED' "no verdict on the attestation when cosign fails, $1"
}
fail_case 'nothing matched' 'cosign could not verify the statement' ''
fail_case 'unknown message' 'cosign could not verify the statement' 'Error: something nobody has seen'
fail_case 'wrong identity' 'the signing identity does not match the release workflow of this repository' \
  'Error: failed to verify certificate identity: no matching CertificateIdentity found, last error: expected SAN value to match regex "^x$", got "keyless@projectsigstore.iam.gserviceaccount.com"\nerror during command execution: failed to verify certificate identity: no matching CertificateIdentity found'
fail_case 'wrong identity (legacy message)' 'the signing identity does not match the release workflow of this repository' \
  'Error: none of the expected identities matched what was in the certificate, got subjects [x] with issuer y'
fail_case 'altered statement' 'the signature is invalid, or the statement was altered after it was signed' \
  'Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature'
fail_case 'bad bundle signature' 'the signature is invalid, or the statement was altered after it was signed' \
  'Error: error verifying bundle: failed to verify certificate: x509: certificate signed by unknown authority'
fail_case 'trust root' 'the Sigstore trust root could not be obtained' \
  'Error: getting trusted root from TUF for new bundle verification: error creating TUF client: dial tcp: lookup tuf-repo-cdn.sigstore.dev: no such host'
fail_case 'trust root (not found)' 'the Sigstore trust root could not be obtained' \
  'Error: trusted root is required when using new bundle format'
fail_case 'malformed bundle' 'the bundle is unreadable or malformed' 'Error: unexpected end of JSON input'
fail_case 'unreadable bundle' 'the bundle is unreadable or malformed' 'Error: reading stmt.json.sigstore.json: open stmt.json.sigstore.json: no such file or directory'
# cosign is untrusted text: paths are cut to a name and control characters escaped.
COSIGN_STUB_RC=1 COSIGN_STUB_ERR='Error: open /srv/secret-dir/sub/bundle.json: permission denied\nError: see ./relative/dir/file.json and "../up/dir/x.json" at https://example.test/a/b\n\033[31mred\033[0m' \
  expect 2 'cosign: Error: open bundle.json: permission denied' 'a path in what cosign printed is cut to its name' -- \
  --attestation "$T/att.json" "${COMMON[@]}" "${A[@]}"
lacks 'secret-dir' 'a directory of cosign output is not printed'
lacks 'relative/dir' 'a relative directory of cosign output is not printed'
lacks "$T" 'no temporary directory of the verifier is printed on a failed anchor'
if grep -qF 'at https://example.test/a/b' "$LAST_OUT"; then
  printf 'ok - a URL in what cosign printed is kept whole\n'; PASSED=$((PASSED + 1))
else
  printf 'not ok - a URL in what cosign printed was changed\n'; FAILED=$((FAILED + 1))
fi
COSIGN_STUB_RC=1 COSIGN_STUB_ERR='\033[31mred\033[0m' expect 2 '\x1b[31mred\x1b[0m' 'control characters in what cosign printed are escaped' -- \
  --attestation "$T/att.json" "${COMMON[@]}" "${A[@]}"
if grep -q $'\033' "$LAST_OUT"; then
  printf 'not ok - a raw ESC from cosign reached the terminal\n'; FAILED=$((FAILED + 1))
else
  printf 'ok - no raw ESC from cosign reaches the terminal\n'; PASSED=$((PASSED + 1))
fi
# A forged document does not turn a failed anchor into a verdict: the anchor stops the run.
expect 2 'anchor could not be checked' 'a tampered document with a statement that cannot be verified is still exit 2' -- \
  --attestation "$T/tampered-field.json" "${COMMON[@]}" --anchor-file "$T/stmt.json" --anchor-bundle "$T/missing-bundle.json"

# --- files ----------------------------------------------------------------------------
cp "$T/stmt-base.json" "$T/stmt-nobundle.json"
expect 2 'anchor could not be checked: the bundle stmt-nobundle.json.sigstore.json cannot be read' 'no bundle next to the statement (the default name is the statement plus .sigstore.json): could not check (2)' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --anchor-file "$T/stmt-nobundle.json"
expect 2 'anchor could not be checked: the statement nothing.json cannot be read' 'an unreadable statement: could not check (2)' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --anchor-file "$T/nothing.json"
cp "$T/stmt-base.json" "$T/other-name.json"; cp "$T/stmt.json.sigstore.json" "$T/b.bundle"
rm -f "$COSIGN_STUB_LOG"
expect 0 "$ANCHOR_SIGNED" '--anchor-bundle names a bundle that is not next to the statement' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --anchor-file "$T/other-name.json" --anchor-bundle "$T/b.bundle"
argv_has 'b/b.bundle' 'the bundle given with --anchor-bundle, by name only'
expect 2 '--anchor-bundle is the bundle of the statement given with --anchor-file' '--anchor-bundle without --anchor-file is a usage error (2)' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --anchor-bundle "$T/b.bundle"

# --- the statement is read strictly ----------------------------------------------------
# Each of these has a good signature as far as the stub goes: it is the statement
# itself that is wrong. Exit 2 (anchor_malformed), never 1.
bad_statement() {   # NAME PYTHON
  st "$T/stmt-bad.json" "$2"; cp "$T/stmt.json.sigstore.json" "$T/stmt-bad.json.sigstore.json"
  expect 2 'anchor could not be checked: the statement stmt-bad.json is malformed' "malformed statement, $1: could not check (2)" -- \
    --attestation "$T/att.json" "${COMMON[@]}" --anchor-file "$T/stmt-bad.json"
}
bad_statement 'wrong schema' 'd["schema"] = "hodeishield.keys.statement.v2"'
bad_statement 'a member that is not documented' 'd["note"] = "hello"'
bad_statement 'no issuer' 'del d["issuer"]'
bad_statement 'issuer not a string' 'd["issuer"] = 5'
bad_statement 'keys empty' 'd["keys"] = []'
bad_statement 'keys not an array' 'd["keys"] = {"a": 1}'
bad_statement 'a key entry that is not an object' 'd["keys"].append("x")'
bad_statement 'an undocumented key member' 'd["keys"][0]["extra"] = 1'
bad_statement 'a missing key member' 'del d["keys"][0]["published_at"]'
bad_statement 'a kid that is not a kid' 'd["keys"][0]["kid"] = "short"'
bad_statement 'the same kid twice' 'd["keys"].append(dict(d["keys"][0]))'
bad_statement 'a role that is not a role' 'd["keys"][0]["role"] = "admin"'
bad_statement 'a status that is not a status' 'd["keys"][0]["status"] = "gone"'
bad_statement 'a bad active_since' 'd["keys"][0]["active_since"] = "2026-02-30"'
bad_statement 'retired_at on an active key' 'd["keys"][0]["retired_at"] = "2026-07-31T18:53:58Z"'
bad_statement 'a retired key without retired_at' 'd["keys"][0]["status"] = "retired"'
for bad_val in '2026-07-31T18:53:58.000Z' '2026-07-31t18:53:58Z' '2026-07-31T18:53:58+00:00' '2026-02-30T18:53:58Z' '2026-07-31'; do
  bad_statement "retired_at '$bad_val'" "d['keys'][0].update(status='retired', retired_at='$bad_val')"
done
edit_text "$T/stmt-base.json" "$T/stmt-dup.json" 't = t.replace("\"issuer\"", "\"issuer\": \"https://other.test\",\n  \"issuer\"", 1)'
cp "$T/stmt.json.sigstore.json" "$T/stmt-dup.json.sigstore.json"
expect 2 'anchor could not be checked: the statement stmt-dup.json repeats members (issuer)' 'a duplicate member is not accepted: could not check (2)' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --anchor-file "$T/stmt-dup.json"
edit_text "$T/stmt-base.json" "$T/stmt-dupkey.json" 't = t.replace("\"role\": \"attestation\"", "\"role\": \"status-list\", \"role\": \"attestation\"", 1)'
cp "$T/stmt.json.sigstore.json" "$T/stmt-dupkey.json.sigstore.json"
expect 2 'repeats members' 'a duplicate member inside a key entry is not accepted: could not check (2)' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --anchor-file "$T/stmt-dupkey.json"
printf '\xef\xbb\xbf' | cat - "$T/stmt-base.json" > "$T/stmt-bom.json"; cp "$T/stmt.json.sigstore.json" "$T/stmt-bom.json.sigstore.json"
expect 2 'anchor could not be checked: the statement stmt-bom.json is not strict JSON' 'a statement with a BOM is not strict JSON: could not check (2)' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --anchor-file "$T/stmt-bom.json"
printf 'not json\n' > "$T/stmt-text.json"; cp "$T/stmt.json.sigstore.json" "$T/stmt-text.json.sigstore.json"
expect 2 'anchor could not be checked: the statement stmt-text.json is not strict JSON' 'a statement that is not JSON: could not check (2)' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --anchor-file "$T/stmt-text.json"
# A value from the statement is escaped before it is shown.
st "$T/stmt-esc.json" 'd["issuer"] = "https://x.test\u001b[31m"'; cp "$T/stmt.json.sigstore.json" "$T/stmt-esc.json.sigstore.json"
expect 1 'https://x.test\x1b[31m' 'an issuer with control characters is printed escaped (anchor_issuer_mismatch)' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --anchor-file "$T/stmt-esc.json"

# --- membership: the statement verified, and it does not list this key ---------------------
mem() {   # NAME STATEMENT_PYTHON
  st "$T/stmt-$1.json" "$2"; cp "$T/stmt.json.sigstore.json" "$T/stmt-$1.json.sigstore.json"
}
mem nokid 'd["keys"] = d["keys"][1:]'
expect 1 "anchor_kid_absent — the key bytes derive kid '$ISSUER_KID', which the signed key statement does not list" 'a key the statement does not list is a failed check (1)' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --anchor-file "$T/stmt-nokid.json"
lacks 'anchor_kid_listed' 'the kid is not reported as listed'
lacks 'lists kid' 'the kid is not reported as listed (text)'
mem role 'd["keys"][0]["role"] = "status-list"'
expect 1 "anchor_role_mismatch — the signed key statement lists kid '$ISSUER_KID' as 'status-list'" 'the kid listed with another role is a failed check (1)' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --anchor-file "$T/stmt-role.json"
expect 1 "anchor_issuer_mismatch — iss is '', the signed key statement names the issuer '$ISS'" \
  'an empty iss is not skipped by the anchor: anchor_issuer_mismatch (1)' -- \
  --attestation "$T/empty-iss.json" --jwks "$T/jwks.json" --expect-slug "$SLUG" --now "$NOW" "${A[@]}"
lacks "iss (E2) is the issuer" 'an empty iss is never reported as the issuer the statement names'
mem issuer 'd["issuer"] = "https://other.test"'
expect 1 "anchor_issuer_mismatch — iss is '$ISS', the signed key statement names the issuer 'https://other.test'" 'an issuer the statement does not name is a failed check (1)' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --anchor-file "$T/stmt-issuer.json"
# Both issuers are compared exactly as signed: a trailing newline on either side
# is another issuer, and a NUL byte makes the statement malformed.
expect 1 "anchor_issuer_mismatch — iss is 'https://issuer.test\\x0a', the signed key statement names the issuer '$ISS'" \
  'a signed iss with a trailing newline is not the issuer the statement names (1)' -- \
  --attestation "$T/nl-iss.json" --jwks "$T/jwks.json" --expect-slug "$SLUG" --now "$NOW" "${A[@]}"
lacks "iss (E2) is the issuer" 'an iss with a trailing newline is never reported as the issuer the statement names'
mem nliss 'd["issuer"] += "\n"'
expect 1 "anchor_issuer_mismatch — iss is '$ISS', the signed key statement names the issuer 'https://issuer.test\\x0a'" \
  'a statement issuer with a trailing newline is not the iss of the document (1)' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --anchor-file "$T/stmt-nliss.json"
mem nuliss 'd["issuer"] += "\u0000"'
expect 2 'anchor could not be checked: the statement stmt-nuliss.json is malformed: its issuer holds a NUL byte' \
  'a statement issuer holding a NUL byte is malformed (2)' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --anchor-file "$T/stmt-nuliss.json"
# The kid is recomputed from the key bytes: a key set that labels the other key
# with the listed kid is mislabelled (kid_mismatch), and the pin to the kid is
# compared with the recomputed one, so the statement cannot be satisfied by a label.
edit "$T/other-jwks.json" "$T/other-as-issuer.json" "d['keys'][0]['kid'] = '$ISSUER_KID'"
"${MINT[@]}" attest --key "$T/other.pem" --slug "$SLUG" --iss "$ISS" --generated-at "$GEN" --expires-at "$EXP" \
  --framework iso27001=substantial --declare-kid="$ISSUER_KID" --out "$T/att-other-label.json" >/dev/null
expect 1 "anchor_kid_absent" 'a key that names a listed kid but derives another is not admitted by its label' -- \
  --attestation "$T/att-other-label.json" --jwks "$T/other-as-issuer.json" --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$NOW" --anchor-file "$T/stmt.json"

# --- retirement ------------------------------------------------------------------------------
set_retired '"2026-07-31T18:53:58Z"'
cp "$T/jwks-ret.json" "$T/jwks-ret-keep.json"
RETC=(--jwks "$T/jwks-ret-keep.json" --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$RET_NOW")
mem ret "d['keys'][0].update(status='retired', retired_at='$RET_AT_S'); d['keys'][0].pop('active_since')"
expect 0 "is retired (at $RET_AT_S), but this document was generated at 2026-07-31T18:53:57.999Z" \
  'statement and key set agree on the retirement and the document predates it' -- \
  --attestation "$T/ret-before.json" "${RETC[@]}" --anchor-file "$T/stmt-ret.json"
expect 1 "retired_key — this document was generated at 2026-07-31T18:53:58.000Z, at or after the retirement of key $ISSUER_KID at $RET_AT_S" \
  'a retired kid used at the retirement instant fails retired_key (existing code), with the anchor agreeing' -- \
  --attestation "$T/ret-after.json" "${RETC[@]}" --anchor-file "$T/stmt-ret.json"
lacks 'anchor_retired_mismatch' 'agreeing retirements are not a mismatch'
expect 1 "anchor_retired_mismatch — the signed key statement retires kid '$ISSUER_KID' at '' (empty: not retired), the key set says hs_retired_at '$RET_AT_S'" \
  'the key set retires a key the statement does not: a failed check (1)' -- \
  --attestation "$T/ret-before.json" "${RETC[@]}" --anchor-file "$T/stmt.json"
expect 1 "anchor_retired_mismatch — the signed key statement retires kid '$ISSUER_KID' at '$RET_AT_S' (empty: not retired), the key set says hs_retired_at '' (empty: none)" \
  'the statement retires a key the key set does not: a failed check (1)' -- \
  --attestation "$T/ret-before.json" --jwks "$T/jwks.json" --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$RET_NOW" --anchor-file "$T/stmt-ret.json"
expect 1 "retired_key — this document was generated at 2026-07-31T18:53:58.000Z" \
  'the retirement of the statement applies even when the key set has none (retired_key)' -- \
  --attestation "$T/ret-after.json" --jwks "$T/jwks.json" --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$RET_NOW" --anchor-file "$T/stmt-ret.json"
mem ret2 "d['keys'][0].update(status='retired', retired_at='2026-07-31T18:53:59Z'); d['keys'][0].pop('active_since')"
expect 1 "anchor_retired_mismatch — the signed key statement retires kid '$ISSUER_KID' at '2026-07-31T18:53:59Z'" \
  'two different instants are a failed check (1)' -- \
  --attestation "$T/ret-before.json" "${RETC[@]}" --anchor-file "$T/stmt-ret2.json"
expect 1 'retired_key — this document was generated at 2026-07-31T18:53:58.000Z' \
  'the earlier of two different retirements is the one that applies' -- \
  --attestation "$T/ret-after.json" "${RETC[@]}" --anchor-file "$T/stmt-ret2.json"

# --- --pub-b64url: no JWK, but the kid is recomputed from the key bytes ------------------------
expect 0 "lists kid '$ISSUER_KID' as an attestation key" '--pub-b64url with an anchor: the recomputed kid is listed' -- \
  --attestation "$T/att.json" --pub-b64url "$PUB" --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$NOW" "${A[@]}"
expect 1 "anchor_kid_absent — the key bytes derive kid '$ISSUER_KID'" '--pub-b64url with an anchor that does not list the recomputed kid: a failed check (1)' -- \
  --attestation "$T/att.json" --pub-b64url "$PUB" --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$NOW" --anchor-file "$T/stmt-nokid.json"
expect 1 'anchor_role_mismatch' '--pub-b64url with an anchor that lists the kid under another role: a failed check (1)' -- \
  --attestation "$T/att.json" --pub-b64url "$PUB" --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$NOW" --anchor-file "$T/stmt-role.json"
expect 0 'before the retirement' '--pub-b64url with a retired statement entry and a document that predates the retirement' -- \
  --attestation "$T/ret-before.json" --pub-b64url "$PUB" --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$RET_NOW" --anchor-file "$T/stmt-ret.json"
lacks 'anchor_retired_mismatch' '--pub-b64url has no key set, so there is no hs_retired_at to disagree with'
expect 1 'retired_key — this document was generated at 2026-07-31T18:53:58.000Z' '--pub-b64url: the statement retirement applies to a document generated at the retirement' -- \
  --attestation "$T/ret-after.json" --pub-b64url "$PUB" --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$RET_NOW" --anchor-file "$T/stmt-ret.json"

# --- --status-list: the status key is checked the same way, and a failure is UNKNOWN (3) ------------
expect 0 "lists kid '$ASKID' as a status-list key" 'the status-list key is listed (anchor_status_kid_listed)' -- \
  "${SL[@]}" --status "$T/list-empty.json" "${A[@]}"
expect 0 'GOOD — not revoked' 'a listed attestation key and status key: good' -- \
  "${SL[@]}" --status "$T/list-empty.json" "${A[@]}"
mem nostatus 'd["keys"] = d["keys"][:1]'
expect 3 "anchor_status_kid_absent — the status-list key bytes derive kid '$ASKID'" 'a status key the statement does not list leaves the status UNKNOWN (3)' -- \
  "${SL[@]}" --status "$T/list-empty.json" --anchor-file "$T/stmt-nostatus.json"
mem statusrole 'd["keys"][1]["role"] = "attestation"'
expect 3 "anchor_status_role_mismatch — the signed key statement lists kid '$ASKID' as 'attestation'" 'a status key listed as an attestation key is UNKNOWN (3)' -- \
  "${SL[@]}" --status "$T/list-empty.json" --anchor-file "$T/stmt-statusrole.json"
mem statusret "d['keys'][1].update(status='retired', retired_at='$RET_AT_S'); d['keys'][1].pop('active_since')"
expect 3 "anchor_status_retired_mismatch — the signed key statement retires kid '$ASKID' at '$RET_AT_S'" 'a status key retired in the statement only is UNKNOWN (3)' -- \
  "${SL[@]}" --status "$T/list-empty.json" --anchor-file "$T/stmt-statusret.json"
expect 3 'UNKNOWN' 'the status path never turns a failed anchor check into GOOD' -- \
  "${SL[@]}" --status "$T/list-empty.json" --anchor-file "$T/stmt-statusret.json"
lacks 'GOOD' 'no GOOD when the status key is not anchored'
# The attestation key is checked in this mode too, and a failure is exit 1.
expect 1 'anchor_kid_absent' 'in --status-list mode the attestation key must be listed too (1)' -- \
  "${SL[@]}" --status "$T/list-empty.json" --anchor-file "$T/stmt-nokid.json"
# A standalone list query has no attestation key; only the status key is asked about.
expect 0 'GOOD — not revoked' 'a standalone status query: only the status-list key must be listed' -- \
  --status-list --status "$T/list-empty.json" --status-keys "$T/status-keys.json" --check-kid "$ISSUER_KID" --now "$NOW" --anchor-file "$T/stmt-nokid.json"
expect 3 'anchor_status_kid_absent' 'a standalone status query: an unlisted status key is UNKNOWN (3)' -- \
  --status-list --status "$T/list-empty.json" --status-keys "$T/status-keys.json" --check-kid "$ISSUER_KID" --now "$NOW" --anchor-file "$T/stmt-nostatus.json"
# The status key retired in both places agrees; the list is issued before it.
edit "$T/status-keys.json" "$T/status-keys-anchor-ret.json" "d['keys'][0]['hs_retired_at'] = '2027-01-01T00:00:00Z'"
mem statusret2 "d['keys'][1].update(status='retired', retired_at='2027-01-01T00:00:00Z'); d['keys'][1].pop('active_since')"
expect 0 'GOOD — not revoked' 'a status key retired in both places, with a list that predates it, is good' -- \
  --status-list --status "$T/list-empty.json" --status-keys "$T/status-keys-anchor-ret.json" --check-kid "$ISSUER_KID" --now "$NOW" --anchor-file "$T/stmt-statusret2.json"

# --- --json (#38) ----------------------------------------------------------------
# The same runs with --json: stdout is exactly one JSON object (printable ASCII,
# so no control character or ESC byte can reach a terminal raw), stderr is empty,
# and the exit code is the one of the text mode. The object is described in
# docs/security/json-output.md. The cosign test double is still first on PATH.
echo '# --json'
PYBIN="$(command -v python3)"
# jexpect CODE NAME CHECK -- verifier args... — run with --json added; CODE is the
# expected exit code and CHECK a Python expression over the object `o` (and the
# exit code `rc`) that must be true. JTEXT, when set, is a text-mode output file.
# The check is evaluated in parentheses, so that it may span several lines. A
# check that cannot be evaluated (it raises, or it is not an expression) is a
# failure with its traceback, never a pass: the Python exit status is read.
jexpect() {
  local want="$1" name="$2" check="$3"; shift 4
  local out="$T/jout.$((PASSED + FAILED))" got why pyrc
  if [ -n "${JSON_FIRST:-}" ]; then NO_COLOR=1 bash "$VERIFIER" --json "$@" > "$out" 2> "$out.err"
  else NO_COLOR=1 bash "$VERIFIER" "$@" --json > "$out" 2> "$out.err"; fi
  got=$?
  why="$("$PYBIN" -I -X utf8 - "$out" "$out.err" "$got" "$want" "$check" 2>&1 <<'PY'
import json, os, sys
out, err, got, want, check = sys.argv[1:6]
raw = open(out, "rb").read()
if open(err, "rb").read(): print("something on stderr"); sys.exit()
if not raw.endswith(b"\n") or any(b < 0x20 or b > 0x7e for b in raw[:-1]):
    print("stdout is not one line of printable ASCII"); sys.exit()
o = json.loads(raw)
rc = int(got)
if not isinstance(o, dict) or o.get("schema") != "hodeishield.verifier.result.v1": print("not the v1 object"); sys.exit()
if o.get("exit_code") != rc: print("exit_code %r, process exit %d" % (o.get("exit_code"), rc)); sys.exit()
if rc != int(want): print("exit %d, expected %s" % (rc, want)); sys.exit()
env = {"o": o, "rc": rc, "text": open(os.environ["JTEXT"], encoding="utf-8").read() if os.environ.get("JTEXT") else ""}
# eval() on the expression written in this file, never on anything from a document.
if not eval("(" + check + "\n)", env): print("false: " + check)
PY
)"
  pyrc=$?
  if [ "$pyrc" -ne 0 ]; then
    printf 'not ok - json: %s (the check could not be evaluated, python exit %s)\n' "$name" "$pyrc"
    printf '%s\n' "$why" | sed 's/^/    # /'; head -c 1500 "$out" | sed 's/^/    # /'; FAILED=$((FAILED + 1))
  elif [ -z "$why" ]; then printf 'ok - json: %s\n' "$name"; PASSED=$((PASSED + 1))
  else printf 'not ok - json: %s (%s)\n' "$name" "$why"; head -c 1500 "$out" | sed 's/^/    # /'; FAILED=$((FAILED + 1)); fi
}

# The harness itself: a check that raises, or a false check over several lines,
# must be "not ok", and a true one over several lines "ok". Run in a subshell, so
# that the counters of the suite are not touched; only the verdict line is read.
# WANT is the start of the verdict line jexpect must print: each case names its
# exact outcome, so that a check that raises is not passed by any other "not ok".
jexpect_self() {   # NAME WANT CHECK
  local line
  line="$(jexpect 0 "harness self-test" "$3" -- --attestation "$T/att.json" "${COMMON[@]}" | head -1)"
  case "$line" in
    "$2"*) printf 'ok - json harness: %s\n' "$1"; PASSED=$((PASSED + 1)) ;;
    *) printf 'not ok - json harness: %s (got: %s)\n' "$1" "$line"; FAILED=$((FAILED + 1)) ;;
  esac
}
JSELF_RAISES='not ok - json: harness self-test (the check could not be evaluated, python exit '
jexpect_self 'a check that raises is not ok, as could not be evaluated' "$JSELF_RAISES" '1 / 0 == 0'
jexpect_self 'a check that reads a missing member is not ok, as could not be evaluated' "$JSELF_RAISES" 'o["no such member"] == 1'
jexpect_self 'a false check over several lines is not ok, as false' 'not ok - json: harness self-test (false: ' 'o["verdict"] == "verified"
   and o["verdict"] == "failed"'
jexpect_self 'a true check over several lines is ok' 'ok - json: harness self-test' 'o["verdict"] == "verified"
   and o["exit_code"] == 0'
jexpect_self 'a check that is not an expression is not ok, as could not be evaluated' "$JSELF_RAISES" 'import os'

# The verdict does not depend on the locale. Under a Latin-1 locale the embedded
# Python used to decode the claims JSON as Latin-1, so a genuine document with a
# non-ASCII label failed its signature (exit 1), and the attested content could
# differ from what the checks read. Needs the locale en_US.ISO-8859-1, which the
# CI container generates with localedef; skipped, never passed, where it is
# absent, and a failure where VERIFIER_REQUIRE_LATIN1=1 (CI) says it must exist.
# The checks spell the label as an escape, and also compare its code points, so
# that they do not depend on how their own text is decoded: a literal em dash in
# a check was decoded as Latin-1 by the harness, which ran without -X utf8 and so
# read its arguments in the locale. The harness now runs with -X utf8 as well.
# The guard honours LOCPATH, so a locale built with localedef into a directory of
# one's own runs these cases too.
LATIN1=en_US.ISO-8859-1
if [ "$(LC_ALL="$LATIN1" locale charmap 2>/dev/null)" = ISO-8859-1 ]; then
  LC_ALL="$LATIN1" expect 0 'VERIFIED — this document was signed' 'a non-ASCII framework label verifies under a Latin-1 locale (0)' -- \
    --attestation "$T/label.json" "${COMMON[@]}"
  LC_ALL="$LATIN1" expect 0 'VERIFIED — this document was signed' 'a raw UTF-8 --claims verifies under a Latin-1 locale (0)' -- \
    --jws "$T/label.jws" --claims "$T/label-claims.json" "${COMMON[@]}"
  LC_ALL="$LATIN1" jexpect 0 'a raw UTF-8 --claims under a Latin-1 locale: the attested label is the text' \
    'o["verdict"] == "verified" and "ENS\u2014ALTO" in [f["label"] for f in o["attested"]["frameworks"]]
     and any([ord(c) for c in f["label"]] == [69, 78, 83, 0x2014, 65, 76, 84, 79] for f in o["attested"]["frameworks"])' -- \
    --jws "$T/label.jws" --claims "$T/label-claims.json" "${COMMON[@]}"
  LC_ALL="$LATIN1" expect 0 'ENS—ALTO (ens—alto): basic' 'under a Latin-1 locale the label is shown as UTF-8, as written' -- \
    --attestation "$T/label.json" "${COMMON[@]}"
  JTEXT="$LAST_OUT" LC_ALL="$LATIN1" jexpect 0 'under a Latin-1 locale the attested label is the text, and the one the text mode shows' \
    'o["verdict"] == "verified" and "ENS\u2014ALTO" in [f["label"] for f in o["attested"]["frameworks"]]
     and any([ord(c) for c in f["label"]] == [69, 78, 83, 0x2014, 65, 76, 84, 79] for f in o["attested"]["frameworks"])
     and ["%s (%s): %s" % (f["label"], f["code"], f["band"]) for f in o["attested"]["frameworks"]]
         == [l.strip() for l in text.splitlines() if "): " in l and l.startswith("          ")]' -- \
    --attestation "$T/label.json" "${COMMON[@]}"
elif [ "${VERIFIER_REQUIRE_LATIN1:-}" = 1 ]; then
  printf 'not ok - the locale %s is required (VERIFIER_REQUIRE_LATIN1=1) and is not available\n' "$LATIN1"; FAILED=$((FAILED + 1))
else
  printf 'skipped - a non-ASCII label under a Latin-1 locale (needs the locale %s, not available here)\n' "$LATIN1"
  SKIPPED=$((SKIPPED + 1))
fi

# A verified document: the attested content equals the text block.
expect 0 'ISO27001 (iso27001): substantial' 'text reference for the JSON of a verified document' -- \
  --attestation "$T/att.json" "${COMMON[@]}"
JTEXT="$LAST_OUT" jexpect 0 'a verified document: verdict, reason, attested content and the frameworks of the text block' \
  'o["verdict"] == "verified" and o["reason"] == "verified" and o["mode"] == "attestation" and o["verifier"]["version"]
   and o["attested"]["overallBand"] == "basic" and o["attested"]["slug"] == "fixture-org" and o["attested"]["visibility"] == "public"
   and o["attested"]["generatedAt"] == "2026-01-01T00:00:00.000Z" and "posture" not in o["attested"]
   and ["%s (%s): %s" % (f["label"], f["code"], f["band"]) for f in o["attested"]["frameworks"]]
       == [l.strip() for l in text.splitlines() if "): " in l and l.startswith("          ")]
   and o["checks"][-1] == {"code": "verified", "result": "pass", "exit_class": 0} and o["anchor"] is None' -- \
  --attestation "$T/att.json" "${COMMON[@]}"
jexpect 0 'inputs given as pipes: the attested content is read from the copy, at the end of the run' \
  'o["verdict"] == "verified" and o["attested"]["slug"] == "fixture-org" and o["attested"]["posture"]["slug"] == "fixture-org"' -- \
  --jws <(cat "$T/att.jws") --claims <(cat "$T/claims.json") --jwks <(cat "$T/jwks.json") \
  --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$NOW" --raw
jexpect 0 'the same document from --jws and --claims' 'o["verdict"] == "verified" and o["attested"]["frameworks"][0]["code"] == "iso27001"' -- \
  --jws "$T/att.jws" --claims "$T/claims.json" "${COMMON[@]}"
jexpect 0 'with --raw the signed posture is there too' \
  'o["attested"]["posture"]["slug"] == "fixture-org" and o["attested"]["posture"]["frameworks"][0]["band"] == "substantial"' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --raw
jexpect 0 'the envelope values the text mode shows are in "unverified", named as such' \
  'o["unverified"]["iss"] == "https://issuer.test" and o["unverified"]["kid"] == "'"$ISSUER_KID"'" and o["unverified"]["nonce"] is None
   and o["unverified"]["docVersion"] == "attest.attestation.v1" and o["unverified"]["slug"] == "fixture-org" and "attested" in o' -- \
  --attestation "$T/att.json" "${COMMON[@]}"

# Not verified: attested is null, even with --raw, as the text mode withholds it.
jexpect 1 'a tampered document: failed, signature_invalid, attested null even with --raw' \
  'o["verdict"] == "failed" and o["reason"] == "signature_invalid" and o["attested"] is None and "frameworks" not in text' -- \
  --attestation "$T/tampered-field.json" "${COMMON[@]}" --raw
jexpect 1 'a genuine but expired document: expired, attested null' \
  'o["verdict"] == "expired" and o["reason"] == "expired" and o["attested"] is None' -- \
  --attestation "$T/att.json" --jwks "$T/jwks.json" --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$NOW_LATE" --raw
jexpect 2 'a key set that is not the signer: could not check' \
  'o["verdict"] == "could_not_check" and o["reason"] == "unknown_kid" and o["attested"] is None and o["message"]' -- \
  --attestation "$T/att.json" --jwks "$T/other-jwks.json" --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$NOW" --raw

# Control characters and ESC in a document are JSON-escaped; the printable-ASCII
# rule of jexpect already fails a raw ESC byte in stdout.
jexpect 1 'newlines and ESC in the nonce, iss and jti are escaped and survive as the document wrote them' \
  'o["unverified"]["nonce"] == "a\nVERIFIED — forged\n\x1b[8mhidden" and o["unverified"]["jti"] == o["unverified"]["iss"] and o["attested"] is None' -- \
  --attestation "$T/inj-claims.json" "${COMMON[@]}" --expect-nonce 'challenge-B' --raw
jexpect 2 'a header kid with newlines and ESC is only in the message, escaped' 'o["reason"] == "unknown_kid" and "hidden" in o["message"]' -- \
  --attestation "$T/inj-header.json" "${COMMON[@]}"

# The values in "unverified" are the signed ones, exactly: a trailing newline is kept.
jexpect 1 'a slug with a trailing newline: slug_mismatch, and unverified.slug is the signed slug' \
  'o["reason"] == "slug_mismatch" and o["unverified"]["slug"] == "fixture-org\n" and o["attested"] is None' -- \
  --attestation "$T/nl-slug.json" "${COMMON[@]}"
jexpect 0 'without --expect-slug it verifies, and unverified.slug equals attested.slug' \
  'o["verdict"] == "verified" and o["attested"]["slug"] == "fixture-org\n" and o["unverified"]["slug"] == o["attested"]["slug"]' -- \
  --attestation "$T/nl-slug.json" --jwks "$T/jwks.json" --expect-issuer "$ISS" --now "$NOW"
jexpect 1 'a nonce with a trailing newline: nonce_mismatch, unverified.nonce exact' \
  'o["reason"] == "nonce_mismatch" and o["unverified"]["nonce"] == "challenge-A\n"' -- \
  --attestation "$T/nl-nonce.json" "${COMMON[@]}" --expect-nonce 'challenge-A'
jexpect 1 'a slug holding a NUL byte: nul_byte decides, nothing attested' \
  'o["reason"] == "nul_byte" and o["verdict"] == "failed" and o["attested"] is None' -- \
  --attestation "$T/nul-slug.json" --jwks "$T/jwks.json" --expect-issuer "$ISS" --now "$NOW"

# Argument errors are JSON too, wherever --json is, with exit 2.
jexpect 2 'an unknown argument is a usage error' \
  'o["reason"] == "usage" and o["verdict"] == "could_not_check" and o["checks"] == [] and o["attested"] is None
   and o["unverified"] == {} and o["anchor"] is None and o["message"] == "unknown argument: --bogus"' -- --bogus
jexpect 2 'a malformed --expect-kid is a usage error' 'o["reason"] == "usage" and "is not a kid" in o["message"]' -- \
  --attestation "$T/att.json" --expect-kid nope
jexpect 2 'an option with an empty value is a usage error' 'o["reason"] == "usage" and "--jwks needs a value" in o["message"]' -- \
  --attestation "$T/att.json" --jwks ''
jexpect 2 '--min-seq that is not a number is a usage error' 'o["reason"] == "usage"' -- \
  --attestation "$T/att.json" --min-seq x
# Every number given as an option is checked before any arithmetic. "60s" used
# to make a test error, which read as "fresh" (exit 0), and --max-age-days and
# --now were evaluated as bash arithmetic, where a[...] is an array reference.
expect 2 'error: --max-age-seconds must be a whole number of seconds' '--max-age-seconds 60s is a usage error (2)' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --max-age-seconds 60s
lacks 'VERIFIED' '--max-age-seconds 60s never ends VERIFIED'
expect 2 'error: --now must be a Unix time in seconds' '--now 12x is a usage error (2)' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --now 12x
expect 2 'error: --max-age-days must be a whole number of days' "--max-age-days 'a[1]' is a usage error (2)" -- \
  --attestation "$T/att.json" "${COMMON[@]}" --max-age-days 'a[1]'
expect 2 'error: --now must be a Unix time in seconds' "--now 'NOW+1' is a usage error (2), not arithmetic" -- \
  --attestation "$T/att.json" "${COMMON[@]}" --now 'NOW+1'
expect 2 'error: --max-age-seconds must be a whole number of seconds' '--max-age-seconds -1 is a usage error (2)' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --max-age-seconds -1
expect 2 'error: --min-seq must be a non-negative integer' '--min-seq with a non-ASCII digit is a usage error (2)' -- \
  --status-list --status "$T/list-empty.json" --status-keys "$T/status-keys.json" --check-kid "$ISSUER_KID" --now "$NOW" --min-seq '٣'
JSON_FIRST=1 jexpect 2 '--now 12x is a usage error' 'o["reason"] == "usage" and o["message"].startswith("error: --now must be")' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --now 12x
# A leading zero is decimal, not octal: --now 0$NOW is the same time.
expect 0 'VERIFIED — this document was signed' '--now with a leading zero is read as decimal' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --now "0$NOW"
expect 0 'within the 600s freshness window' '--max-age-seconds 0600 is 600 seconds' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --max-age-seconds 0600
expect 1 'EXPIRED' '--max-age-days 0 rejects a document 300 s old (genuine but too old)' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --max-age-days 0
jexpect 2 'a status-list option without --status-list is a usage error' \
  'o["reason"] == "usage" and o["message"] == "error: --status requires --status-list" and o["checks"] == []' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --status "$T/list-key.json"
# --json first or last makes no difference, and a check failure keeps its own code.
out="$T/json-first.out"
NO_COLOR=1 bash "$VERIFIER" --json --attestation "$T/att.json" "${COMMON[@]}" > "$out" 2>&1
if [ "$("$PYBIN" -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["verdict"])' "$out")" = verified ]; then
  printf 'ok - json: --json as the first argument\n'; PASSED=$((PASSED + 1))
else printf 'not ok - json: --json as the first argument\n'; FAILED=$((FAILED + 1)); fi
jexpect 2 'an environment problem is a die: the check, the message' \
  'o["reason"] == "attestation_missing" and o["checks"][-1]["exit_class"] == 2 and "--attestation" in o["message"]' --

# Every option that takes a value: without it, exit 2 and one line, in the text
# mode and with --json; and the next option is never taken as the value.
for opt in --jws --jwks --attestation --claims --posture --pub-b64url --expect-slug --expect-issuer --expect-kid \
           --expect-nonce --max-age-seconds --max-age-days --now --anchor-file --anchor-bundle --status --status-keys \
           --check-kid --check-subject --check-generated-at --min-seq; do
  expect 2 "error: $opt needs a value" "$opt without a value is a usage error (2)" -- "$opt"
  # --json goes first for the options that would take a trailing --json as their value
  JSON_FIRST=1 jexpect 2 "$opt without a value is a usage error" 'o["reason"] == "usage" and o["message"].startswith("error: '"$opt"' needs a value")' -- "$opt"
done
for opt in --jws --jwks --status --expect-slug; do
  expect 2 "error: $opt needs a value" "$opt followed by another option does not take it as its value (2)" -- "$opt" --raw
done
expect 2 "error: --jwks needs a value" '--jwks --json is a usage error, --json is not its value' -- --jwks --json
# Base64url and opaque values can start with --; only an absent value is missing.
KID_DASH='--AAAAAAAAAAAAAAAAAAAA'
expect 1 'unexpected_kid' 'a kid that starts with -- is a value of --expect-kid, not a missing one' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --expect-kid "$KID_DASH"
lacks 'needs a value' '--expect-kid --AAAA... is not reported as a missing value'
expect 2 'is not a kid' 'an option given as the kid fails the kid shape check (2)' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --expect-kid --raw
expect 1 'nonce_mismatch' '--expect-nonce --abc is a nonce, not a missing value' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --expect-nonce --abc
lacks 'needs a value' '--expect-nonce --abc is not reported as a missing value'
expect 2 'public key is 3 bytes' '--pub-b64url with a key that starts with - is a value' -- \
  --attestation "$T/att.json" --pub-b64url -AAA --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$NOW"
lacks 'needs a value' '--pub-b64url -AAA is not reported as a missing value'
expect 0 "GOOD — kid $KID_DASH is not revoked" '--check-kid --AAAA... is a kid to look up, not a missing value' -- \
  --status-list --status "$T/list-empty.json" --status-keys "$T/status-keys.json" --check-kid "$KID_DASH" --now "$NOW"
lacks 'needs a value' '--check-kid --AAAA... is not reported as a missing value'
# --check-kid is held to the shape of a kid: an option given as its value never
# stands in for a kid (it used to replace the document's own kid in Rule K).
expect 2 'error: --check-kid --raw is not a kid' '--check-kid --raw is a usage error (2), not a kid' -- \
  --status-list --status "$T/list-key.json" --status-keys "$T/status-keys.json" --attestation "$T/att.json" "${COMMON[@]}" \
  --check-kid --raw
lacks 'GOOD' '--check-kid --raw never ends GOOD'
expect 2 'error: --check-kid --abc is not a kid' '--check-kid --abc is a usage error (2)' -- \
  --status-list --status "$T/list-empty.json" --status-keys "$T/status-keys.json" --check-kid --abc --now "$NOW"
JSON_FIRST=1 jexpect 2 '--check-kid that is not a kid is a usage error' \
  'o["reason"] == "usage" and o["message"] == "error: --check-kid --raw is not a kid (22 base64url characters)"' -- \
  --status-list --status "$T/list-key.json" --status-keys "$T/status-keys.json" --attestation "$T/att.json" "${COMMON[@]}" \
  --check-kid --raw
expect 0 'VERIFIED — this document was signed' "--expect-nonce '' keeps its meaning: an empty challenge is a value" -- \
  --attestation "$T/att.json" "${COMMON[@]}" --expect-nonce ''

# --help and --version print their usual text, even with --json.
NO_COLOR=1 bash "$VERIFIER" --json --help > "$T/jhelp.out" 2> "$T/jhelp.err"; got=$?
if [ "$got" -eq 0 ] && grep -q '^Exit codes:' "$T/jhelp.out" && [ ! -s "$T/jhelp.err" ] && ! grep -q '^{' "$T/jhelp.out"; then
  printf 'ok - json: --help with --json prints the usual text (exit 0)\n'; PASSED=$((PASSED + 1))
else printf 'not ok - json: --help with --json (exit %s)\n' "$got"; FAILED=$((FAILED + 1)); fi
NO_COLOR=1 bash "$VERIFIER" --version --json > "$T/jver.out" 2> "$T/jver.err"; got=$?
if [ "$got" -eq 0 ] && [ "$(cat "$T/jver.out")" = "verify-attestation.sh $VER" ] && [ ! -s "$T/jver.err" ]; then
  printf 'ok - json: --version with --json prints the usual line (exit 0)\n'; PASSED=$((PASSED + 1))
else printf 'not ok - json: --version with --json (exit %s)\n' "$got"; FAILED=$((FAILED + 1)); fi

# --status-list: good, revoked, unknown.
jexpect 0 'status-list good' \
  'o["mode"] == "status-list" and o["verdict"] == "good" and o["reason"] == "good" and o["attested"]["slug"] == "fixture-org"' -- \
  "${SL[@]}" --status "$T/list-empty.json"
jexpect 1 'status-list revoked (the key): attested null even with --raw' \
  'o["verdict"] == "revoked" and o["reason"] == "revoked_key" and o["attested"] is None' -- \
  "${SL[@]}" --status "$T/list-key.json" --raw
jexpect 1 'status-list revoked (the subject)' 'o["verdict"] == "revoked" and o["reason"] == "revoked_subject"' -- \
  "${SL[@]}" --status "$T/list-subj-after.json"
jexpect 1 'status-list revoked (the subject), --check-subject naming another organisation does not replace it' \
  'o["verdict"] == "revoked" and o["reason"] == "revoked_subject" and o["attested"] is None' -- \
  "${SL[@]}" --status "$T/list-subj-after.json" --check-subject other-org --check-generated-at 2026-01-01T00:20:00.000Z
jexpect 3 'status-list unknown: the list does not verify' \
  'o["verdict"] == "unknown" and o["reason"] == "status_unknown_bad_signature" and o["attested"] is None' -- \
  "${SL[@]}" --status "$T/list-key-stripped.json" --raw
jexpect 0 'a standalone status query: good, nothing attested' \
  'o["verdict"] == "good" and o["attested"] is None and o["unverified"] == {}' -- \
  --status-list --status "$T/list-empty.json" --status-keys "$T/status-keys.json" --check-kid "$ISSUER_KID" --now "$NOW"
GENERATED="$GEN" EXPIRES="$EXP" SLUG="$SLUG" POSTURE_READ=1 jexpect 0 'a standalone status query: nothing from the environment in unverified' \
  'o["verdict"] == "good" and o["unverified"] == {}' -- \
  --status-list --status "$T/list-empty.json" --status-keys "$T/status-keys.json" --check-kid "$ISSUER_KID" --now "$NOW"
jexpect 1 'a tampered document under a good list: failed' 'o["verdict"] == "failed" and o["attested"] is None' -- \
  --status-list --status-keys "$T/status-keys.json" --status "$T/list-empty.json" --attestation "$T/tampered-field.json" "${COMMON[@]}"

# --anchor-file, with the cosign test double.
jexpect 0 'the anchor object: verified, the release tag, the attestation key listed' \
  'o["anchor"]["verified"] is True and o["anchor"]["release_tag"] == "v'"$VER"'"
   and o["anchor"]["kids"] == [{"kid": "'"$ISSUER_KID"'", "role": "attestation", "listed": True}]' -- \
  --attestation "$T/att.json" "${COMMON[@]}" "${A[@]}"
jexpect 0 'the anchor object under --status-list lists both keys' \
  '[k["role"] for k in o["anchor"]["kids"]] == ["attestation", "status-list"] and all(k["listed"] for k in o["anchor"]["kids"])' -- \
  "${SL[@]}" --status "$T/list-empty.json" "${A[@]}"
jexpect 1 'a key the statement does not list: anchor not verified, kid not listed' \
  'o["reason"] == "anchor_kid_absent" and o["anchor"]["verified"] is False and o["anchor"]["kids"][0]["listed"] is False' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --anchor-file "$T/stmt-nokid.json"
COSIGN_STUB_RC=1 COSIGN_STUB_ERR='Error: something nobody has seen' jexpect 2 'cosign says no: could not check, anchor not verified' \
  'o["reason"] == "anchor_unverified" and o["anchor"]["verified"] is False and o["anchor"]["release_tag"] is None and o["anchor"]["kids"] == []' -- \
  --attestation "$T/att.json" "${COMMON[@]}" "${A[@]}"
jexpect 1 'an empty iss: iss_empty and anchor_issuer_mismatch both fail, anchor not verified' \
  '{"iss_empty", "anchor_issuer_mismatch"} <= {c["code"] for c in o["checks"] if c["result"] == "fail"}
   and o["anchor"]["verified"] is False and o["attested"] is None' -- \
  --attestation "$T/empty-iss.json" --jwks "$T/jwks.json" --expect-slug "$SLUG" --now "$NOW" "${A[@]}"
jexpect 1 'an empty iss without the anchor: reason iss_empty' 'o["reason"] == "iss_empty" and o["verdict"] == "failed"' -- \
  --attestation "$T/empty-iss.json" --jwks "$T/jwks.json" --expect-slug "$SLUG" --now "$NOW"
# anchor.verified is true only when every anchor check that applies ran and held.
# A run that stops after the statement verified, before a membership or issuer
# check, is not verified, whatever the statement said.
jexpect 2 'the statement verified but the kid is unknown to the key set: anchor not verified, no kid asked about' \
  'o["reason"] == "unknown_kid" and o["anchor"]["verified"] is False and o["anchor"]["kids"] == []
   and "anchor_verified" in [c["code"] for c in o["checks"]]' -- \
  --attestation "$T/att.json" --jwks "$T/other-jwks.json" --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$NOW" "${A[@]}"
edit "$T/att.json" "$T/att-bad-docversion.json" 'd["attestation"]["claims"]["docVersion"] = "attest.attestation.v0"'
jexpect 2 'the kid is listed but the issuer check never ran (canonicalise_failed): anchor not verified' \
  'o["reason"] == "canonicalise_failed" and o["anchor"]["verified"] is False
   and o["anchor"]["kids"] == [{"kid": "'"$ISSUER_KID"'", "role": "attestation", "listed": True}]
   and "anchor_issuer_matches" not in [c["code"] for c in o["checks"]]' -- \
  --attestation "$T/att-bad-docversion.json" "${COMMON[@]}" "${A[@]}"
jexpect 3 'a status list that fails before its key is asked about: anchor not verified' \
  'o["verdict"] == "unknown" and o["anchor"]["verified"] is False
   and [k["role"] for k in o["anchor"]["kids"]] == ["attestation"]' -- \
  "${SL[@]}" --status "$T/list-wrong-key.json" "${A[@]}"
jexpect 0 'a standalone status query: the status-list key listed is enough' \
  'o["anchor"]["verified"] is True and o["anchor"]["kids"] == [{"kid": "'"$ASKID"'", "role": "status-list", "listed": True}]' -- \
  --status-list --status "$T/list-empty.json" --status-keys "$T/status-keys.json" --check-kid "$ISSUER_KID" --now "$NOW" "${A[@]}"
COSIGN_STUB_RC_IDENTITY=1 jexpect 2 'the exact identity does not verify: could not check, and the tag read is not reported' \
  'o["reason"] == "anchor_unverified" and o["anchor"]["verified"] is False and o["anchor"]["release_tag"] is None' -- \
  --attestation "$T/att.json" "${COMMON[@]}" "${A[@]}"
mint_bundle "$T/repo-bundle.json" "URI:${ANCHOR_WF}v${VER}" "ASN1:UTF8String:$((REPO_ID + 1))"
jexpect 2 'a certificate from another repository ID: anchor_unverified, no tag reported' \
  'o["reason"] == "anchor_unverified" and o["anchor"]["verified"] is False and o["anchor"]["release_tag"] is None
   and "Source Repository Identifier" in o["message"]' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --anchor-file "$T/stmt.json" --anchor-bundle "$T/repo-bundle.json"
jexpect 2 'a bundle in the legacy format: anchor_bundle_unsupported' \
  'o["reason"] == "anchor_bundle_unsupported" and o["anchor"]["verified"] is False and o["anchor"]["release_tag"] is None
   and "not a Sigstore v0.3 bundle" in o["message"]' -- \
  --attestation "$T/att.json" "${COMMON[@]}" --anchor-file "$T/stmt.json" --anchor-bundle "$T/legacy-named.json"

# Two different checks that share a code are two entries: generatedAt and expiresAt
# both unparseable are two date_unparseable failures, at two places in the script.
mint_attest --generated-at 'not-a-date' --expires-at 'also-not' --out "$T/baddates.json"
jexpect 1 'two distinct failures with one code stay two entries' \
  '[c["code"] for c in o["checks"]].count("date_unparseable") == 2 and o["reason"] != "usage"' -- \
  --attestation "$T/baddates.json" --jwks "$T/jwks.json" --expect-slug "$SLUG" --expect-issuer "$ISS" --now "$NOW"
# A warning printed over several lines is one check.
jexpect 0 'a warning printed over two lines is one entry' \
  '[c["code"] for c in o["checks"]].count("issuer_unpinned") == 1' -- \
  --attestation "$T/att.json" --jwks "$T/jwks.json" --expect-slug "$SLUG" --now "$NOW"

# A check recorded in a subshell is not lost. A copy of the script gets two probes
# after its first check: one in ( ), one in $( ) with the same code twice.
PROBE="$T/probe-verifier.sh"
"$PYBIN" -I - "$VERIFIER" "$PROBE" <<'PY'
import sys
t = open(sys.argv[1]).read()
anchor = 'ok openssl_mldsa65_available "OpenSSL ${OSSL_V} offers ML-DSA-65"\n'
assert t.count(anchor) == 1
probe = anchor + '( warn probe_in_subshell "probe" )\np="$(\nbad probe_twice "a"\nbad probe_twice "b"\n)" || true\n'
open(sys.argv[2], "w").write(t.replace(anchor, probe))
PY
VERIFIER_REAL="$VERIFIER"; VERIFIER="$PROBE"
jexpect 0 'a check recorded in a subshell appears, in order, and two same-code checks stay two' \
  '[c["code"] for c in o["checks"]][:4] == ["openssl_mldsa65_available", "probe_in_subshell", "probe_twice", "probe_twice"]
   and o["checks"][1]["result"] == "warn"' -- \
  --attestation "$T/att.json" "${COMMON[@]}"
VERIFIER="$VERIFIER_REAL"

# The writer used without python3 (json_emit_bash) relies on json_str(), the JSON
# string encoder. Section 2 used to define a second json_str() (a header reader)
# that replaced it for the rest of the run. A copy of the script writes the
# object with json_emit_bash right after section 2, from a verified run's state.
PROBE2="$T/probe-header-verifier.sh"
"$PYBIN" -I - "$VERIFIER" "$PROBE2" "$T/probe-header.json" <<'PY'
import sys
t = open(sys.argv[1]).read()
anchor = 'TYP="$(header_field "$WORKDIR/header.json" typ)"\n'
assert t.count(anchor) == 1
open(sys.argv[2], "w").write(t.replace(anchor, anchor + 'json_emit_bash 0 attestation verified > "%s"\n' % sys.argv[3]))
PY
NO_COLOR=1 bash "$PROBE2" --attestation "$T/att.json" "${COMMON[@]}" > /dev/null 2>&1
if [ "$("$PYBIN" -I -c 'import json,sys; o = json.load(open(sys.argv[1])); print(o["schema"], o["verdict"], o["reason"])' "$T/probe-header.json" 2>/dev/null)" \
     = 'hodeishield.verifier.result.v1 verified verified' ]; then
  printf 'ok - json: the writer without python3 still writes JSON after the header section ran\n'; PASSED=$((PASSED + 1))
else
  printf 'not ok - json: the writer without python3 is broken after the header section ran\n'
  head -c 600 "$T/probe-header.json" 2>/dev/null | sed 's/^/    # /'; FAILED=$((FAILED + 1))
fi

# Without python3 a smaller, still valid object is written (nothing attested).
NOPY="$T/nopy"; mkdir -p "$NOPY"
for tool in bash env openssl jq awk sed grep tr cat head cut wc date mktemp rm cp mkdir chmod sort tee dirname basename xxd uname; do
  tool_path="$(command -v "$tool" 2>/dev/null || true)"
  if [ -n "$tool_path" ] && [ -x "$tool_path" ]; then ln -sf "$tool_path" "$NOPY/$tool"; fi
done
PATH="$NOPY" jexpect 2 'without python3: exit 2, a valid object, no attested content' \
  'o["reason"] == "python3_missing" and o["verdict"] == "could_not_check" and o["attested"] is None and o["checks"][-1]["code"] == "python3_missing"' -- \
  --attestation "$T/att.json" "${COMMON[@]}"

export PATH="$PATH_BEFORE_STUB"
unset COSIGN_STUB_LOG

# --- real cosign: a legacy-format bundle cannot lend the tag a certificate -----------
# Needs cosign 3.1.3 or later (CI installs it); skipped, never passed, without it.
# The genuine v1.3.0 bundle is rewritten in cosign's legacy format, which cosign
# falls back to when a bundle does not load as v0.3: its real signature, real
# certificate and real Rekor entry, which cosign verifies, and beside them a
# decoy self-signed certificate at verificationMaterial.certificate whose SAN is
# this repository's release workflow at v99.0.0. Reading the tag from the decoy
# would pass the anti-rollback check and go on to read the statement (an old
# SHA256SUMS, so anchor_malformed). It must stop before: exit 2, not malformed.
#
# What each layer covers, and what no test here can show:
#  1. The shape check (ANCHOR_BUNDLE_PY shape) runs BEFORE cosign. The legacy
#     bundle above is refused by it (anchor_bundle_unsupported), so cosign never
#     sees it: the case proves the shape check on a real legacy bundle, not
#     cosign's legacy fallback. With the shape check first, no bundle that cosign
#     would read in its legacy format gets to cosign, so there is no meaningful
#     real-cosign test of that fallback any more.
#  2. The second cosign call, for the EXACT identity read from the certificate,
#     binds the tag to the certificate cosign verified. With real certificates it
#     cannot be made to fail by a bundle (see the cases below), so real cosign is
#     shown to accept the exact identity of a genuine certificate and, through a
#     recording wrapper that replaces it, to reject another one. The path of the
#     script when that call fails is covered by the cosign test double above
#     (COSIGN_STUB_RC_IDENTITY), with the arguments of both calls recorded.
#  3. The repository ID and the anti-rollback check read that same certificate:
#     the genuine v1.3.0 bundle reaches anchor_statement_older, with its tag.
echo '# anchor, real cosign'
real_cosign_ok=0
if command -v cosign >/dev/null 2>&1; then
  real_cosign_v="$(cosign version 2>/dev/null | awk '$1 == "GitVersion:" { print $2; exit }' || true)"
  if python3 -I -c '
import re, sys
m = re.fullmatch(r"v?([0-9]{1,6})\.([0-9]{1,6})\.([0-9]{1,6})(-.*)?", sys.argv[1])
n = tuple(int(x) for x in m.groups()[:3]) if m else (0, 0, 0)
sys.exit(0 if n > (3, 1, 3) or (n == (3, 1, 3) and not m.group(4)) else 1)
' "$real_cosign_v"; then real_cosign_ok=1; fi
fi
if [ "$real_cosign_ok" -eq 1 ]; then
  RELB="$ROOT/tests/vectors/v1/anchor/release-v1.3.0"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$T/decoy-k.pem" 2>/dev/null
  openssl req -new -x509 -key "$T/decoy-k.pem" -subj '/CN=decoy' -days 2 \
    -addext "subjectAltName=URI:${ANCHOR_WF}v99.0.0" -outform DER -out "$T/decoy.der" 2>/dev/null
  python3 -I - "$RELB/SHA256SUMS.sigstore.json" "$T/decoy.der" "$T/legacy.sigstore.json" <<'PY'
import base64, json, sys, textwrap
b = json.load(open(sys.argv[1], encoding="utf-8"))
decoy = open(sys.argv[2], "rb").read()
m = b["verificationMaterial"]; e = m["tlogEntries"][0]
der = base64.b64decode(m["certificate"]["rawBytes"])
pem = ("-----BEGIN CERTIFICATE-----\n" + "\n".join(textwrap.wrap(base64.b64encode(der).decode(), 64))
       + "\n-----END CERTIFICATE-----\n")
legacy = {
    "base64Signature": b["messageSignature"]["signature"],
    "cert": base64.b64encode(pem.encode()).decode(),
    "rekorBundle": {
        "SignedEntryTimestamp": e["inclusionPromise"]["signedEntryTimestamp"],
        "Payload": {"body": e["canonicalizedBody"], "integratedTime": int(e["integratedTime"]),
                    "logIndex": int(e["logIndex"]), "logID": base64.b64decode(e["logId"]["keyId"]).hex()}},
    "verificationMaterial": {"certificate": {"rawBytes": base64.b64encode(decoy).decode()}},
}
json.dump(legacy, open(sys.argv[3], "w", encoding="utf-8"))
PY
  jexpect 2 'real cosign: a legacy bundle with a decoy v99.0.0 certificate stops before the statement is read' \
    'o["exit_code"] == 2 and o["reason"] == "anchor_bundle_unsupported"
     and all(c["code"] != "anchor_malformed" for c in o["checks"]) and o["anchor"]["release_tag"] is None' -- \
    --attestation "$T/att.json" "${COMMON[@]}" --anchor-file "$RELB/SHA256SUMS" --anchor-bundle "$T/legacy.sigstore.json"

  # The second, exact-identity cosign call, against real cosign. A real v0.3
  # bundle has one certificate, the one cosign verifies and the tag is read
  # from, so no bundle with real certificates can make that call fail on its
  # own. Instead a wrapper first on PATH records each call and runs the real
  # cosign, and for one case replaces the identity of the second call, as a
  # script that read the identity from another certificate would pass it.
  REALWRAP="$T/realwrap"; mkdir -p "$REALWRAP"
  REAL_COSIGN="$(command -v cosign)"
  cat > "$REALWRAP/cosign" <<WRAP
#!/usr/bin/env bash
args=("\$@")
case " \$* " in
  *' --certificate-identity '*)
    printf '%s\n' "\$@" > "$T/realwrap.identity.argv"
    if [ -n "\${COSIGN_WRAP_IDENTITY:-}" ]; then
      for i in "\${!args[@]}"; do
        if [ "\${args[i]}" = --certificate-identity ]; then args[i + 1]="\$COSIGN_WRAP_IDENTITY"; fi
      done
    fi ;;
esac
exec "$REAL_COSIGN" "\${args[@]}"
WRAP
  chmod +x "$REALWRAP/cosign"
  rm -f "$T/realwrap.identity.argv"
  PATH="$REALWRAP:$PATH" jexpect 2 'real cosign: the genuine v1.3.0 bundle passes both cosign calls, and its tag is read (older than this verifier)' \
    'o["reason"] == "anchor_statement_older" and o["anchor"]["release_tag"] == "v1.3.0"' -- \
    --attestation "$T/att.json" "${COMMON[@]}" --anchor-file "$RELB/SHA256SUMS" --anchor-bundle "$RELB/SHA256SUMS.sigstore.json"
  argv_has "${ANCHOR_WF}v1.3.0" 'the exact identity of the genuine certificate, the second time (real cosign)' "$T/realwrap.identity.argv"
  COSIGN_WRAP_IDENTITY="${ANCHOR_WF}v1.3.1" PATH="$REALWRAP:$PATH" jexpect 2 \
    'real cosign: an exact identity that is not the verified certificate'"'"'s is rejected, and no tag is reported' \
    'o["reason"] == "anchor_unverified" and o["anchor"]["release_tag"] is None
     and "cosign did not verify the certificate the release tag is read from" in o["message"]' -- \
    --attestation "$T/att.json" "${COMMON[@]}" --anchor-file "$RELB/SHA256SUMS" --anchor-bundle "$RELB/SHA256SUMS.sigstore.json"
else
  printf 'skipped - real cosign: a legacy bundle with a decoy certificate (needs cosign 3.1.3 or later, not available here)\n'
  printf 'skipped - real cosign: the second, exact-identity call (needs cosign 3.1.3 or later, not available here)\n'
  SKIPPED=$((SKIPPED + 2))
fi

# --- version consistency (tests/version-consistency.sh) --------------------------
# VERIFIER_VERSION is what --anchor-file compares the statement's release tag with,
# so it must be the version the script is released as.
echo '# version consistency'
VC="$ROOT/tests/version-consistency.sh"
vc_case() {   # NAME WANT_EXIT VERSION CHANGELOG_BODY [TAG]
  printf '#!/usr/bin/env bash\nVERIFIER_VERSION="%s"\n' "$3" > "$T/vc-script.sh"
  printf '# Changelog\n\n## Compatibility\n\ntext\n\n%b' "$4" > "$T/vc-changelog.md"
  local args=(--script "$T/vc-script.sh" --changelog "$T/vc-changelog.md")
  if [ -n "${5:-}" ]; then args+=(--tag "$5"); fi
  local out="$T/out.$((PASSED + FAILED))" got
  LAST_OUT="$out"
  bash "$VC" "${args[@]}" > "$out" 2>&1; got=$?
  if [ "$got" -eq "$2" ]; then printf 'ok - version: %s (exit %s)\n' "$1" "$got"; PASSED=$((PASSED + 1))
  else printf 'not ok - version: %s (exit %s, expected %s)\n' "$1" "$got" "$2"; sed 's/^/    # /' "$out"; FAILED=$((FAILED + 1)); fi
}
U='## Unreleased\n\n### Added\n- x\n\n'
D13='## v1.3.0 - 2026-10-08\n\ntext\n\n## v1.2.1 - 2026-10-06\n\ntext\n'
vc_case 'Unreleased above v1.3.0, version 1.4.0 (the state on dev)' 0 1.4.0 "$U$D13"
vc_case 'Unreleased, version equal to the newest release' 1 1.3.0 "$U$D13"
vc_case 'Unreleased, version older than the newest release' 1 1.2.0 "$U$D13"
vc_case 'Unreleased, version 1.10.0 above v1.9.0 (numeric)' 0 1.10.0 '## Unreleased\n\n## v1.9.0 - 2026-01-01\n'
vc_case 'a dated top section, version equal' 0 1.3.0 "$D13"
vc_case 'a dated top section, version different' 1 1.4.0 "$D13"
vc_case 'a version that is not N.N.N' 1 1.4 "$U$D13"
vc_case 'a version with a leading zero' 1 01.4.0 "$U$D13"
vc_case 'a pre-release version' 1 1.4.0-rc1 "$U$D13"
vc_case 'a release: tag equals the version, dated heading present' 0 1.3.0 "$D13" v1.3.0
vc_case 'a release: the tag differs from the version' 1 1.4.0 "$U$D13" v1.5.0
vc_case 'a release: the heading is not dated yet (Unreleased)' 1 1.4.0 "$U$D13" v1.4.0
vc_case 'a release: the version was not bumped' 1 1.3.0 "$D13" v1.4.0
vc_case 'a release: the tag is not N.N.N' 1 1.4.0 "$U$D13" v1.4.0-rc1
vc_case 'no dated heading at all' 1 1.4.0 "$U"
printf '#!/usr/bin/env bash\n' > "$T/vc-script.sh"
printf '# Changelog\n\n%b' "$U$D13" > "$T/vc-changelog.md"
bash "$VC" --script "$T/vc-script.sh" --changelog "$T/vc-changelog.md" > "$T/vc.out" 2>&1; got=$?
if [ "$got" -ne 0 ]; then printf 'ok - version: a script without VERIFIER_VERSION fails (exit %s)\n' "$got"; PASSED=$((PASSED + 1))
else printf 'not ok - version: a script without VERIFIER_VERSION passed\n'; FAILED=$((FAILED + 1)); fi
bash "$VC" > "$T/vc.out" 2>&1; got=$?
if [ "$got" -eq 0 ]; then printf 'ok - version: this tree is consistent (%s)\n' "$(cat "$T/vc.out")"; PASSED=$((PASSED + 1))
else printf 'not ok - version: this tree is not consistent\n'; sed 's/^/    # /' "$T/vc.out"; FAILED=$((FAILED + 1)); fi
expect 0 "verify-attestation.sh $VER" '--version prints one line with the version and exits 0' -- --version
if [ "$(wc -l < "$LAST_OUT" | tr -d ' ')" -eq 1 ]; then printf 'ok - --version is one line\n'; PASSED=$((PASSED + 1))
else printf 'not ok - --version is not one line\n'; FAILED=$((FAILED + 1)); fi

# --help (#15): a short usage, not the header comment. It must exit 0, stay
# under 40 lines, carry the exit codes, and list EVERY option the argument
# parser accepts. The options are read from the parser's own `case` patterns, so
# an option added later without help text fails here.
echo '# --help'
expect 0 'Exit codes:' '--help exits 0 and prints the exit codes' -- --help
HELP_OUT="$LAST_OUT"
HELP_LINES="$(wc -l < "$HELP_OUT" | tr -d ' ')"
if [ "$HELP_LINES" -le 40 ]; then
  printf 'ok - --help is %s lines (at most 40)\n' "$HELP_LINES"; PASSED=$((PASSED + 1))
else
  printf 'not ok - --help is %s lines, expected at most 40\n' "$HELP_LINES"; FAILED=$((FAILED + 1))
fi
for code in 0 1 2 3; do
  if grep -qE "^  $code  " "$HELP_OUT"; then
    printf 'ok - --help documents exit code %s\n' "$code"; PASSED=$((PASSED + 1))
  else
    printf 'not ok - --help has no line for exit code %s\n' "$code"; FAILED=$((FAILED + 1))
  fi
done
lacks 'set -euo pipefail' '--help is the usage text, not the header comment of the script'
# The parser's patterns: from `while [ $# -gt 0 ]` to its `done`, the lines that
# open a case arm, e.g. `    --jws)` or `    -h|--help)`.
mapfile -t PARSER_OPTS < <(sed -n '/^while \[ \$# -gt 0 \]; do$/,/^done$/p' "$VERIFIER" \
  | sed -nE 's/^    (-[-A-Za-z0-9|]+)\).*/\1/p' | tr '|' '\n' | grep -E '^--[a-z]' | sort -u)
if [ "${#PARSER_OPTS[@]}" -ge 19 ]; then
  printf 'ok - found %d options in the argument parser\n' "${#PARSER_OPTS[@]}"; PASSED=$((PASSED + 1))
else
  printf 'not ok - read only %d options from the argument parser; did its shape change?\n' "${#PARSER_OPTS[@]}"
  FAILED=$((FAILED + 1))
fi
for opt in "${PARSER_OPTS[@]}"; do
  if grep -qE -- "(^|[^-A-Za-z])${opt}([^-A-Za-z]|\$)" "$HELP_OUT"; then
    printf 'ok - --help lists %s\n' "$opt"; PASSED=$((PASSED + 1))
  else
    printf 'not ok - --help does not list %s\n' "$opt"; FAILED=$((FAILED + 1))
  fi
done

# Nothing the verifier prints may send the reader to a document that is not
# public (#34). Every run above left its stdout and stderr in $T/out.N, the
# --status-list runs that end UNKNOWN among them.
expect 3 'attest-verification.md' 'an UNKNOWN verdict points to the public verification document' -- \
  "${SL[@]}" --status "$T/list-key-stripped.json"
expect 3 '"Unknown is not good"' 'an UNKNOWN verdict cites the public paragraph that explains it' -- \
  "${SL[@]}" --status "$T/list-key-stripped.json"
mapfile -t leaks < <(grep -lE 'docs/architecture|design doc' "$T"/out.* 2>/dev/null || true)
runs=("$T"/out.*)
if [ "${#leaks[@]}" -eq 0 ]; then
  printf 'ok - no run printed a reference to a non-public design document (%d runs)\n' "${#runs[@]}"
  PASSED=$((PASSED + 1))
else
  printf 'not ok - output refers to a non-public design document:\n'
  grep -nE 'docs/architecture|design doc' "${leaks[@]}" | sed 's/^/    # /'
  FAILED=$((FAILED + 1))
fi

# --- one definition per function (static) ---------------------------------------
# A second definition of a function silently replaces the first from the point
# where it runs, for every caller (json_str() was defined twice). Every form bash
# accepts is read: name(), name (), function name, function name() and
# function name ().
fn_names() {   # FILE — the name of each function definition, one per line, in order
  sed -nE 's/^[[:space:]]*function[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)([[:space:]]*\(\))?([[:space:]]|\{|$).*/\1/p; t
           s/^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*\(\)([[:space:]]|\{|$).*/\1/p' "$1"
}
# The reader itself, on every form, a call and a duplicate of each kind.
cat > "$T/fn-forms.sh" <<'FNS'
a() { :; }
b () { :; }
function c { :; }
function d() { :; }
  function  e  () {
    x="$(g)"; h a
  }
  f()   {
    :
  }
a () { :; }
function b { :; }
FNS
if [ "$(fn_names "$T/fn-forms.sh" | tr '\n' ' ')" = 'a b c d e f a b ' ] \
   && [ "$(fn_names "$T/fn-forms.sh" | sort | uniq -d | tr '\n' ' ')" = 'a b ' ]; then
  printf 'ok - the duplicate-function reader finds every form of definition, and a duplicate of each\n'; PASSED=$((PASSED + 1))
else
  printf 'not ok - the duplicate-function reader misses a form: %s\n' "$(fn_names "$T/fn-forms.sh" | tr '\n' ' ')"; FAILED=$((FAILED + 1))
fi
mapfile -t all_fns < <(fn_names "$VERIFIER")
mapfile -t dup_fns < <(printf '%s\n' "${all_fns[@]}" | sort | uniq -d)
if [ "${#all_fns[@]}" -ge 30 ] && [ "${#dup_fns[@]}" -eq 0 ]; then
  printf 'ok - every function of the script is defined once (%d functions)\n' "${#all_fns[@]}"; PASSED=$((PASSED + 1))
else
  printf 'not ok - functions defined more than once: %s (%d read)\n' "${dup_fns[*]}" "${#all_fns[@]}"; FAILED=$((FAILED + 1))
fi

# --- no global is taken from the environment (static) ----------------------------
# Bash imports every environment variable as a shell variable. A global that the
# script reads with a default (${VAR:-}, ${VAR+x}, ...) must be set at the top
# level before the first line that reads it, or the caller's environment decides
# its value (an exported GENERATED did, for a standalone --status-list query).
# Function locals and NO_COLOR (read from the environment on purpose) are exempt.
GLOBALS_SCAN="$(python3 -I - "$VERIFIER" <<'PY'
import re, sys
lines = open(sys.argv[1], encoding="utf-8").read().split("\n")
locals_ = set()
for ln in lines:
    m = re.match(r"\s*local\s+(.*)", ln)
    if m:
        locals_ |= set(re.findall(r"(?:^|\s)([A-Za-z_][A-Za-z0-9_]*)(?==|\s|$)", m.group(1)))
first_use, first_set = {}, {}
for n, ln in enumerate(lines, 1):
    if ln.lstrip().startswith("#"): continue   # a comment is not a read
    for v in re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?[-+?])", ln):
        first_use.setdefault(v, n)
    if not ln[:1].isspace():
        for v in re.findall(r"(?:^|;\s*)([A-Za-z_][A-Za-z0-9_]*)=", ln):
            first_set.setdefault(v, n)
exempt = locals_ | {"NO_COLOR", "FUNCNAME", "BASH_LINENO"}
bad = sorted("%s (read at line %d, set at %s)" % (v, n, first_set.get(v, "no top-level line"))
             for v, n in first_use.items() if v not in exempt and not first_set.get(v, n + 1) < n)
print(len(first_use))
for b in bad: print(b)
PY
)"
if [ "$(printf '%s\n' "$GLOBALS_SCAN" | wc -l)" -eq 1 ] && [ "$GLOBALS_SCAN" -ge 15 ]; then
  printf 'ok - every global read with a default (%s) is set at the top level before it is read\n' "$GLOBALS_SCAN"; PASSED=$((PASSED + 1))
else
  printf 'not ok - globals that the environment can set:\n'; printf '%s\n' "$GLOBALS_SCAN" | sed 's/^/    # /'; FAILED=$((FAILED + 1))
fi

# --- reason codes (static) ----------------------------------------------------
# Every check carries a machine reason code (docs/security/reason-codes.md). This
# reads the script, the document and the vectors manifest as text and runs no
# document: each code the script uses is documented, each documented code is
# one the script can emit, and each expect.code the manifest asserts is one the
# script can emit.
RC_DOC="$ROOT/docs/security/reason-codes.md"
RC_SCRIPT="$T/rc.script"; RC_DOCS="$T/rc.docs"; RC_MANIFEST="$T/rc.manifest"
{
  grep -oE '(^|[^A-Za-z_])(ok|warn|warn_unknown|bad|stale|stat_bad|die) [a-z][a-z0-9_]* "' "$VERIFIER" \
    | sed -E 's/^[^a-z]*[a-z_]+ ([a-z0-9_]+) "$/\1/'
  grep -oE 'record [a-z][a-z0-9_]* (pass|warn|fail) [0-3]' "$VERIFIER" | awk '{print $2}'
  grep -oE '[A-Z_]+_CODE=[a-z][a-z0-9_]*' "$VERIFIER" | sed 's/^.*=//'
} | sort -u > "$RC_SCRIPT"
# A table row starts with the code between two backticks (any character below).
sed -nE 's/^\| [^A-Za-z0-9 ]([a-z][a-z0-9_]*)[^A-Za-z0-9 ] \|.*/\1/p' "$RC_DOC" | sort -u > "$RC_DOCS"
python3 -I -c 'import json,sys
for c in json.load(open(sys.argv[1]))["cases"]: print(c["expect"]["code"])' \
  "$ROOT/tests/vectors/v1/vectors.json" | sort -u > "$RC_MANIFEST"
rc_missing="$(comm -23 "$RC_SCRIPT" "$RC_DOCS" | tr '\n' ' ')"
rc_stale="$(comm -13 "$RC_SCRIPT" "$RC_DOCS" | tr '\n' ' ')"
rc_unknown="$(comm -13 "$RC_SCRIPT" "$RC_MANIFEST" | tr '\n' ' ')"
if [ -s "$RC_SCRIPT" ] && [ -z "$rc_missing" ] && [ -z "$rc_stale" ] && [ -z "$rc_unknown" ]; then
  printf 'ok - reason codes: %d in the script, all documented; every vectors expect.code is emitted\n' "$(wc -l < "$RC_SCRIPT")"
  PASSED=$((PASSED + 1))
else
  printf 'not ok - reason codes\n'
  [ -z "$rc_missing" ] || printf '    # used by the script, not in reason-codes.md: %s\n' "$rc_missing"
  [ -z "$rc_stale" ]   || printf '    # in reason-codes.md, never emitted by the script: %s\n' "$rc_stale"
  [ -z "$rc_unknown" ] || printf '    # expect.code in vectors.json that the script cannot emit: %s\n' "$rc_unknown"
  FAILED=$((FAILED + 1))
fi

echo
printf '# %d passed, %d failed, %d skipped\n' "$PASSED" "$FAILED" "$SKIPPED"

# The published vectors (tests/vectors/v1) are part of the same gate, and so
# is the proof that they catch a verifier whose signature check does nothing.
echo
VECTORS_RC=0
VERIFIER="$VERIFIER" bash "$ROOT/tests/vectors.sh" || VECTORS_RC=$?
echo
VERIFIER="$VERIFIER" bash "$ROOT/tests/vectors.sh" --json || VECTORS_RC=$?
echo
MUTANTS_RC=0
if [ "${VERIFIER_SKIP_MUTANTS:-}" = "1" ]; then
  if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    echo "# mutants: VERIFIER_SKIP_MUTANTS is not honoured in CI"
    MUTANTS_RC=1
  else
    echo "# mutants: skipped (VERIFIER_SKIP_MUTANTS=1); CI runs them"
    MUTANTS_RC=0
  fi
else
  VERIFIER="$VERIFIER" bash "$ROOT/tests/mutants.sh" || MUTANTS_RC=$?
fi
[ "$FAILED" -eq 0 ] && [ "$VECTORS_RC" -eq 0 ] && [ "$MUTANTS_RC" -eq 0 ]
