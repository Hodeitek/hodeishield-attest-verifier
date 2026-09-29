#!/usr/bin/env bash
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

# edit IN OUT PYTHON — rewrite a JSON document; `d` is the parsed document.
edit() {
  python3 - "$1" "$2" "$3" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
exec(sys.argv[3])
json.dump(d, open(sys.argv[2], "w"), indent=2)
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

echo '# revocation (--status-list)'

LIST_AT='2026-01-01T00:00:00.000Z'
LIST_NEXT='2026-01-01T02:00:00.000Z'
mint_status() { "${MINT[@]}" status --key "$T/status.pem" --iss "$ISS" \
  --issued-at "$LIST_AT" --next-update "$LIST_NEXT" "$@"; }

mint_status --out "$T/list-empty.json" --seq 7
mint_status --out "$T/list-key.json" --seq 8 --revoke-kid "$ISSUER_KID"
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

edit "$T/att.json" "$T/decoy-revoked.json" '
c = d["attestation"]["claims"]
c["posture"] = {"x": {"generatedAt": "2026-01-01T00:12:00.000Z"}, **c["posture"]}'
expect 1 'unsigned_member' 'an unsigned decoy generatedAt does not dodge a subject withdrawal' -- \
  --status-list --status-keys "$T/status-keys.json" --status "$T/list-subj-after.json" \
  --attestation "$T/decoy-revoked.json" "${COMMON[@]}"

echo
printf '# %d passed, %d failed\n' "$PASSED" "$FAILED"
[ "$FAILED" -eq 0 ]
