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
# fails.
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
  | sed -nE 's/^    (-[-A-Za-z|]+)\).*/\1/p' | tr '|' '\n' | grep -E '^--[a-z]' | sort -u)
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
VERIFIER="$VERIFIER" bash "$ROOT/tests/mutants.sh" || MUTANTS_RC=$?
[ "$FAILED" -eq 0 ] && [ "$VECTORS_RC" -eq 0 ] && [ "$MUTANTS_RC" -eq 0 ]
