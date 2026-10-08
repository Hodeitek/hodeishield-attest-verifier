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
MINT=(python3 "$ROOT/tests/lib/mint.py")

T="$(mktemp -d)"; chmod 700 "$T"
trap 'rm -rf -- "$T"' EXIT

ISS='https://issuer.test'
SLUG='fixture-org'
GEN='2026-01-01T00:00:00.000Z'
EXP='2026-01-01T00:15:00.000Z'
NOW=1767225900            # GEN + 5 min: inside the validity window
NOW_LATE=1767312000       # GEN + 1 day: long expired

PASSED=0; FAILED=0

# expect CODE PATTERN NAME -- verifier args...
expect() {
  local want="$1" pattern="$2" name="$3"; shift 4
  local out="$T/out.$((PASSED + FAILED))" got
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
  local out="$T/out.$((PASSED + FAILED - 1))"
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
  python3 - "$1" "$2" "$3" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
exec(sys.argv[3])
json.dump(d, open(sys.argv[2], "w"), indent=2)
PY
}

# edit_text IN OUT PYTHON — rewrite the raw TEXT of a file; `t` is its content.
# For what a JSON round-trip cannot express, such as duplicate members.
edit_text() {
  python3 - "$1" "$2" "$3" <<'PY'
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

expect 1 'not_yet_valid' 'a document dated beyond the 5 min clock-skew allowance is rejected' -- \
  --attestation "$T/att.json" --jwks "$T/jwks.json" --expect-slug "$SLUG" --expect-issuer "$ISS" --now 1767225000

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
lacks_all() {
  local out="$T/out.$((PASSED + FAILED - 1))" name="$1" str bad=0; shift
  for str in "$@"; do
    if grep -qF -- "$str" "$out"; then
      printf 'not ok - %s (output contains: %s)\n' "$name" "$str"; bad=1
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
  local out="$T/out.$((PASSED + FAILED - 1))" name="$1" bad=0
  if grep -q $'\033' "$out"; then printf 'not ok - %s (an ESC byte reached the output)\n' "$name"; bad=1; fi
  if grep -qE '^(VERIFIED|Attested content|GOOD)' "$out"; then
    printf 'not ok - %s (a forged verdict or block starts a line)\n' "$name"; bad=1
  fi
  if [ "$bad" -eq 0 ]; then printf 'ok - %s\n' "$name"; PASSED=$((PASSED + 1)); else FAILED=$((FAILED + 1)); fi
}
expect 1 'VERIFICATION FAILED' 'a document whose nonce, iss, jti, dates and member name carry newlines and ESC still fails (1)' -- \
  --attestation "$T/inj-claims.json" "${COMMON[@]}" --expect-nonce 'challenge-B' --raw
no_raw_control 'nonce, iss, jti, generatedAt, expiresAt and a member name are escaped (no ESC, no forged verdict)'
lacks_all 'the forged block text never starts a line' $'\nVERIFIED —' $'\n        overallBand: advanced'
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

# A display problem must never change a verdict (#14): the summary is written as
# UTF-8 bytes, so a non-UTF-8 stdout does not turn a verified document into an error.
mint_attest --out "$T/label.json" --framework 'ens—alto=basic'
PYTHONIOENCODING=ascii expect 0 'ENS—ALTO (ens—alto): basic' 'a non-ASCII framework label under an ASCII Python stdout still verifies (0)' -- \
  --attestation "$T/label.json" "${COMMON[@]}"
PYTHONIOENCODING=ascii expect 0 'VERIFIED — this document was signed' 'the same document still reaches its VERIFIED verdict' -- \
  --attestation "$T/label.json" "${COMMON[@]}" --raw

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
if grep -q $'\x1b' "$T/out.$((PASSED + FAILED - 1))" || grep -q '^PASS  forged' "$T/out.$((PASSED + FAILED - 1))"; then
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

# --help (#15): a short usage, not the header comment. It must exit 0, stay
# under 40 lines, carry the exit codes, and list EVERY option the argument
# parser accepts. The options are read from the parser's own `case` patterns, so
# an option added later without help text fails here.
echo '# --help'
expect 0 'Exit codes:' '--help exits 0 and prints the exit codes' -- --help
HELP_OUT="$T/out.$((PASSED + FAILED - 1))"
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

echo
printf '# %d passed, %d failed\n' "$PASSED" "$FAILED"

# The published vectors (tests/vectors/v1) are part of the same gate, and so
# is the proof that they catch a verifier whose signature check does nothing.
echo
VECTORS_RC=0
VERIFIER="$VERIFIER" bash "$ROOT/tests/vectors.sh" || VECTORS_RC=$?
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
