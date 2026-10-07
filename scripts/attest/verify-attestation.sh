#!/usr/bin/env bash
# shellcheck disable=SC2317,SC2329 # cleanup() is invoked only indirectly via
# `trap cleanup EXIT`, not by a direct call shellcheck can see, so it
# misreads the function body as unreachable. File-wide, one rule (SC2329 is its name from ShellCheck 0.11), documented.
# =============================================================================
# verify-attestation.sh — verify a HodeiShield posture attestation OFFLINE.
#
# Written for third parties. It depends on bash (>= 4 — this is bash, not POSIX
# sh), OpenSSL >= 3.5, and python3. python3 is NOT optional on the path the
# endpoint actually serves: `GET /api/public/attest/<slug>` returns a DETACHED
# JWS, so the canonical bytes must be re-derived from the claims JSON, and that
# needs a JSON parser. `--status-list` additionally needs jq, and curl if you
# hand it URLs rather than files. Everything else is coreutils. No npm, no Node,
# no HodeiShield code, no network access at verification time. If you can read this script you can audit
# the whole check; docs/security/attest-verification.md §4 spells out the same
# commands by hand so you can satisfy yourself the script does nothing else.
#
# WHAT IS SIGNED — read this first, it is the one thing people get wrong.
#
#   The signature covers the ATTESTATION ENVELOPE
#   `hodei-shield.attest.attestation.v1` (fields E1..E7), NOT the bare posture.
#   The posture you can read is nested VERBATIM inside it as field E7, as the
#   frozen `hodei-shield.attest.posture.v1` bytes (fields F1..F8). So there are
#   two encoders below and you need BOTH: the inner one produces E7, the outer
#   one produces the bytes the ML-DSA-65 signature is actually over.
#
#   Practically: the whole `claims` object is the signed document. The posture
#   alone is NOT enough to verify — `iss`, `jti`, `nonce` and `overallBand` are
#   inside the signature too, and `jti` is a random UUID nobody can reconstruct.
#   Give this script `--attestation` (the endpoint response) or `--claims`.
#
# TWO SERIALISATIONS, both supported:
#
#   ATTACHED   protected.payload.signature
#              The canonical ENVELOPE bytes travel inside the token. Without
#              --claims, they are decoded back into the claims they encode, and
#              those get every check a detached document gets (python3 needed).
#
#   DETACHED   protected..signature        (RFC 7515 Appendix F)
#              The payload segment is EMPTY; you are handed the claims as JSON
#              and re-derive the canonical bytes yourself. That re-derivation is
#              the point: you check the JSON you can read, not bytes you cannot.
#              Needs python3 for the canonical encoders (embedded below,
#              reimplemented from the published wire formats).
#
# USAGE
#   verify-attestation.sh --attestation FILE --jwks FILE
#                         [--expect-slug SLUG] [--expect-nonce STR]
#                         [--expect-issuer ORIGIN] [--pub-b64url STR]
#                         [--max-age-seconds N] [--now EPOCH]
#
#   verify-attestation.sh --jws FILE --claims FILE --jwks FILE [...]
#
#   --attestation      the whole document, exactly as `GET /api/public/attest/
#                      <slug>` serves it: {"attestation":{"claims",...,
#                      "signature",...}}. A bare {"claims","signature"} is
#                      accepted too. This is the no-jq path — the signature and
#                      the claims are pulled out of the one file for you.
#   --jws              the compact JWS, attached or detached. Only needed when
#                      the signature travels separately from the claims;
#                      --attestation carries both.
#   --claims           the `claims` object alone (docVersion/iss/kid/jti/nonce/
#                      overallBand/posture). THIS is the signed document.
#   --jwks             publisher key document (RFC 9964 "AKP" keys)
#   --pub-b64url       a single base64url public key instead of --jwks
#   --posture          DEPRECATED as a verification input, and refused when it
#                      holds a bare posture: the signature does not cover those
#                      bytes, so accepting it could only ever produce a false
#                      FAIL on a genuine document. A full claims object passed
#                      here is accepted (it is what --claims wants).
#   --expect-slug      fail unless the posture is for this trust-center slug
#   --expect-nonce     fail unless claims.nonce equals this challenge VERBATIM.
#                      A nonce you do not compare is decoration — this is the
#                      comparison, and only you can make it.
#   --expect-issuer    fail unless claims.iss equals this origin
#   --expect-kid       fail unless the key that signed is one of these kids; repeat
#                      it to pin two through a rotation overlap. Compared with the
#                      kid RECOMPUTED from the key bytes, never with a label. Not
#                      --check-kid, and it does not apply to the status-list key.
#   --raw              also print the full signed posture JSON, but only when the
#                      document verified (what it says is never shown otherwise)
#   --max-age-seconds  staleness tolerance on `generatedAt` (default 3600 = 1 h)
#   --max-age-days     deprecated alias, converted to seconds
#   --now              override "now" (Unix seconds), for reproducible testing
#
# REVOCATION STATUS-LIST MODE (`--status-list`)
#   A SEPARATE document, `hodei-shield.attest.statuslist.v1`, signed by a key
#   DISJOINT from the attestation key above and published at a DIFFERENT
#   endpoint. See docs/architecture/specs/2026-07-30-attest-revocation-design.md
#   for the full argument (§4.2 on why the key sets must be disjoint) — this
#   mode is the "complete independent implementation" its §6.4 describes, wired
#   into this same offline tool rather than left as a markdown code block a
#   reader has to hand-copy.
#
#   verify-attestation.sh --status-list --status SRC --status-keys SRC
#                         [--attestation FILE | --jws FILE --claims FILE]
#                         [--check-kid KID] [--check-subject SLUG]
#                         [--check-generated-at RFC3339] [--min-seq N]
#                         [--expect-issuer ISS] [--now EPOCH]
#
#   --status            the status-list document: GET /api/public/attest/status
#                        response, exactly as served — a FILE PATH or an
#                        http(s):// URL this script fetches itself (`curl`).
#                        Cleartext http:// warns: the list is signed, so on-path
#                        tampering shows up as `unknown`, never as a false `good`.
#   --status-keys        the STATUS key set: GET /api/public/attest/status-keys
#                        response — FILE PATH or an https:// URL. NEVER the
#                        attestation `--jwks`; the two sets are disjoint by design
#                        and resolving a status `kid` against the attestation set
#                        would defeat the whole scheme.
#                        A cleartext http:// URL is REFUSED for this one (except
#                        loopback): it is the trust anchor every check in section
#                        8 is performed *with*, so an on-path swap produces a
#                        self-consistent GOOD/REVOKED of the attacker's choosing
#                        and nothing downstream can notice. Fetch it yourself and
#                        pass the file if you must take that risk knowingly.
#   --check-kid          the attestation `kid` to test against the list (Rule K,
#                        unconditional — revokedAt is never compared). Defaults
#                        to the `--jws` header kid when one is given.
#   --check-subject      the trust-center slug to test (Rule B — reads the
#                        timestamp, because this branch presumes the key is NOT
#                        compromised). Defaults to the verified document's slug.
#   --check-generated-at the attestation's `generatedAt`, needed to evaluate
#                        Rule B. Defaults to the verified document's generatedAt.
#   --min-seq            reject a list whose `seq` is lower than this — the
#                        rollback bound for a verifier with memory (§7 of the
#                        design doc). A cold verifier omits it and relies on
#                        `nextUpdate` alone.
#   --expect-issuer      fail unless the list's `iss` equals this origin. (The
#                        same flag also checks the ATTESTATION's `iss` when a
#                        document is supplied — one origin, checked wherever it
#                        appears.)
#
#   Combine with `--attestation` (or `--jws` + `--claims`) to run the full
#   posture check FIRST and then apply the list to the resulting
#   `kid`/slug/generatedAt — the §6.2 procedure end to end. Omit the document for
#   a standalone list query: verify the list alone and answer
#   good/revoked/unknown for an explicit --check-kid or --check-subject you
#   already hold from elsewhere.
#
#   OUTCOME. Per §6.1 of the design doc, ANY failure verifying the list itself
#   (bad signature, stale, wrong `typ`, rolled back, self-revoking, ...) yields
#   `unknown` — never `good` and never `revoked`. `unknown` is printed and
#   exits distinctly from `revoked` (see EXIT CODES): a verifier that cannot
#   reach or cannot verify the list has NOT learned "not revoked".
#
# WHY THE DEFAULT IS ONE HOUR
#   The issuer clamps every attestation to a 1-hour lifetime (MAX_TTL_SECONDS in
#   app/src/lib/attest/posture.ts) and issues 15 minutes by default. A reference
#   verifier that tolerated more than the issuer can produce would accept, with a
#   PASS, documents the issuer's own verifier rejects — which is the one failure
#   mode a published third-party verifier must not have. This default is pinned
#   to that ceiling deliberately; raise it only if you know why you are doing it.
#
# EXIT CODES
#   Posture mode (default):    0 verified | 1 verification failed | 2 environment/usage problem
#   A genuine document that is only too old or expired is still 1, but its last
#   line says so ("EXPIRED — the signature is valid ...") instead of the line a
#   tampered or invalid document gets, and names the command to fetch a new one.
#   --status-list mode:        0 good | 1 revoked | 2 environment/usage problem | 3 unknown
#   `unknown` (3) is deliberately its own code, distinct from `revoked` (1): a
#   list that was obtained but could not be verified is NOT evidence the subject is
#   fine (one that could not be fetched at all is exit 2), and a caller scripting against this tool must not be able to conflate
#   the two by checking `$? -ne 0`.
# =============================================================================
set -euo pipefail

JWS_FILE=''; JWKS_FILE=''; POSTURE_FILE=''; PUB_B64URL=''
ATTESTATION_FILE=''; CLAIMS_FILE=''
EXPECT_SLUG=''; EXPECT_NONCE_SET=0; EXPECT_NONCE=''
MAX_AGE_SECONDS=3600; NOW_OVERRIDE=''
SHOW_RAW=0
# --expect-kid, repeatable: the kids the attestation's signing key may have. Empty
# means no pin. Not --check-kid, which looks a kid up in a status list.
EXPECT_KIDS=()

# --- status-list mode (--status-list) ---------------------------------------
STATUS_LIST_MODE=0
STATUS_SRC=''; STATUS_KEYS_SRC=''
RETIRED_AT=''   # hs_retired_at of the selected attestation key, when it has one
CHECK_KID=''; CHECK_SUBJECT=''; CHECK_GENERATED_AT=''
MIN_SEQ=''; EXPECT_ISSUER=''

# The issuer's hard TTL ceiling (posture.ts MAX_TTL_SECONDS). `expiresAt` further
# from `generatedAt` than this is above anything a conforming issuer can mint, so
# it is a rejection regardless of how good the signature is.
MAX_TTL_SECONDS=3600

# How far in the future `generatedAt` may sit before the document is rejected as
# `not_yet_valid` (posture.ts DEFAULT_CLOCK_SKEW_MS / 1000, the house NTP
# allowance). Without it, a document dated a year ahead stays "fresh" all year.
POSTURE_CLOCK_SKEW_SECONDS=300

# The verifier-side ceiling on a status list's own `nextUpdate - issuedAt`
# (status-list.ts MAX_STATUS_LIST_VALIDITY_SECONDS). Re-checked here for the
# same reason posture.ts's ttl_exceeded is re-checked above: a producer-side
# clamp a compromised signer can simply not apply is not a bound at all.
MAX_STATUS_LIST_VALIDITY_SECONDS=86400

# House NTP allowance (status-list.ts DEFAULT_CLOCK_SKEW_MS / 1000).
STATUS_CLOCK_SKEW_SECONDS=300

# The text --help prints. The header comment above is for whoever reads or audits
# this script; this is for whoever runs it. Every option the parser below accepts
# is listed here, and tests/run.sh fails if one is not.
usage() {
  cat <<'USAGE'
Usage:
  verify-attestation.sh --attestation att.json --jwks jwks.json [options]
  verify-attestation.sh --status-list --status S --status-keys K \
                        (--attestation att.json --jwks jwks.json | --check-kid KID) [options]

Attestation mode (the default):
  --attestation FILE     the document as the endpoint serves it
  --jws FILE             a compact JWS, with --claims FILE or attached
  --claims FILE          the claims object that the JWS signs
  --posture FILE         a full claims object (a bare posture is refused)
  --jwks FILE            the attestation key set
  --pub-b64url KEY       the raw public key, instead of --jwks
  --expect-slug SLUG     require this organisation slug
  --expect-issuer URL    require this issuer (iss)
  --expect-nonce VALUE   require this challenge ('' requires none)
  --expect-kid KID       require the signing key to have this kid; repeat for a rotation overlap
  --max-age-seconds N    reject a document older than N seconds (default 3600)
  --max-age-days N       the same, in days
  --raw                  also print the full signed posture JSON (verified documents only)
  --now EPOCH            take this Unix time as now (for testing)

Status-list mode (revocation):
  --status-list          check a signed revocation status list
  --status FILE|URL      the status list
  --status-keys FILE|URL the status list's own key set (never --jwks)
  --check-kid KID        look this kid up in the list (not --expect-kid, which pins)
  --check-subject SLUG   look this organisation up in the list
  --check-generated-at T the document time to compare with the subject entry
  --min-seq N            reject a list older than sequence N (rollback)

Common:
  -h, --help             this text

Exit codes:
  0  verified (good, in --status-list mode)
  1  a check failed (revoked, in --status-list mode)
  2  could not check, or a usage error
  3  unknown, in --status-list mode only: not evidence either way

Documentation: README.md and docs/security/attest-verification.md
USAGE
}

# esc VALUE — print VALUE with every byte that is not printable ASCII shown as a
# visible \xHH escape. EVERY value that comes from a document, a key set or a
# status list goes through this before it reaches the terminal: anyone can edit
# a document, and an unescaped newline or ESC inside a nonce could forge lines
# (an "Attested content" block, a VERIFIED verdict) or hide text, whether or not
# the signature verifies. The C locale makes it count bytes, so a multi-byte
# character cannot slip through as one "printable" unit.
esc() {
  local LC_ALL=C
  local s="$1" out='' c='' i=0 n=${#1}
  local plain='^[ -~]*$' one='^[ -~]$'
  if [[ "$s" =~ $plain ]]; then printf '%s' "$s"; return 0; fi
  for (( i = 0; i < n; i++ )); do
    c="${s:i:1}"
    if [[ "$c" =~ $one ]]; then out+="$c"; else printf -v c '\\x%02x' "'$c"; out+="$c"; fi
  done
  printf '%s' "$out"
}
# Whether $1 has the shape of a kid. In the C locale, so that a range such as
# A-Z cannot match an accented letter under a UTF-8 locale.
is_kid_shape() {
  local LC_ALL=C
  local shape='^[A-Za-z0-9_-]{21}[AQgw]$'
  [[ "$1" =~ $shape ]]
}

while [ $# -gt 0 ]; do
  case "$1" in
    --jws)          JWS_FILE="${2:?}"; shift 2 ;;
    --jwks)         JWKS_FILE="${2:?}"; shift 2 ;;
    --attestation)  ATTESTATION_FILE="${2:?}"; shift 2 ;;
    --claims)       CLAIMS_FILE="${2:?}"; shift 2 ;;
    --posture)      POSTURE_FILE="${2:?}"; shift 2 ;;
    --pub-b64url)   PUB_B64URL="${2:?}"; shift 2 ;;
    --expect-slug)  EXPECT_SLUG="${2:?}"; shift 2 ;;
    # Presence is tracked separately from the value: `--expect-nonce ''` is a
    # meaningful assertion ("this document must carry NO challenge"), and an
    # empty string must not silently mean "do not check".
    --expect-nonce)
      [ $# -ge 2 ] || { printf 'error: --expect-nonce needs a value (use '"''"' for "no challenge")\n' >&2; exit 2; }
      EXPECT_NONCE_SET=1; EXPECT_NONCE="$2"; shift 2 ;;
    --max-age-seconds) MAX_AGE_SECONDS="${2:?}"; shift 2 ;;
    --max-age-days) MAX_AGE_SECONDS=$(( ${2:?} * 86400 )); shift 2 ;;
    --now)          NOW_OVERRIDE="${2:?}"; shift 2 ;;
    --raw)          SHOW_RAW=1; shift ;;
    # Repeatable, so that two kids can be pinned through a key rotation overlap.
    # A kid is BASE64URL of 16 bytes: 21 characters of the alphabet, then one of
    # A Q g w (the last character carries only 2 bits). Anything else can never
    # equal a derived kid, so it is a usage error, not a check that always fails.
    --expect-kid)
      [ $# -ge 2 ] || { printf 'error: --expect-kid needs a value\n' >&2; exit 2; }
      is_kid_shape "$2" \
        || { printf 'error: --expect-kid %s is not a kid (22 base64url characters)\n' "$(esc "$2")" >&2; exit 2; }
      EXPECT_KIDS+=("$2"); shift 2 ;;
    --status-list)         STATUS_LIST_MODE=1; shift ;;
    --status)               STATUS_SRC="${2:?}"; shift 2 ;;
    --status-keys)          STATUS_KEYS_SRC="${2:?}"; shift 2 ;;
    --check-kid)            CHECK_KID="${2:?}"; shift 2 ;;
    --check-subject)        CHECK_SUBJECT="${2:?}"; shift 2 ;;
    --check-generated-at)   CHECK_GENERATED_AT="${2:?}"; shift 2 ;;
    --min-seq)              MIN_SEQ="${2:?}"; shift 2
      [[ "$MIN_SEQ" =~ ^[0-9]{1,18}$ ]] || { printf 'error: --min-seq must be a non-negative integer\n' >&2; exit 2; } ;;
    --expect-issuer)        EXPECT_ISSUER="${2:?}"; shift 2 ;;
    -h|--help)      usage; exit 0 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done

CONTENT_WITHHELD='attested content withheld: this document did not verify'
RED=''; GREEN=''; YELLOW=''; BOLD=''; RESET=''
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
fi
ok()   { printf '  %sPASS%s  %s\n' "$GREEN" "$RESET" "$*"; }
warn() { printf '  %sWARN%s  %s\n' "$YELLOW" "$RESET" "$*"; }
# WITHHOLD_ON_DIE is set once a document is being read (after the banner below):
# a run that stops there never established the document, so it shows none of it.
WITHHOLD_ON_DIE=0
die()  {
  printf '%serror:%s %s\n' "$RED" "$RESET" "$*" >&2
  [ "$WITHHOLD_ON_DIE" -eq 0 ] || printf '%s\n' "$CONTENT_WITHHELD" >&2
  exit 2
}
bad()  { printf '  %sFAIL%s  %s\n' "$RED" "$RESET" "$*" >&2; FAILURES=$((FAILURES+1)); }
# Like bad(), but for the STATUS LIST's own verification (§6.1 of the design
# doc). Deliberately a SEPARATE counter from $FAILURES: a status-list failure
# means the list is `unknown`, which is a different outcome from a posture
# attestation's signature not verifying, and the two must not be summed into
# one number that then can't tell a caller which document was the problem.
STATUS_FAILURES=0
stat_bad() { printf '  %sFAIL%s  %s\n' "$RED" "$RESET" "$*" >&2; STATUS_FAILURES=$((STATUS_FAILURES+1)); }

# Placeholder printed for a claim that is absent. Held in a variable rather than
# spelled out inline in each parameter-expansion default, because Semgrep's bash
# parser reads a literal `<` inside such a default as a redirection and drops the
# whole line from the scan — silently, still reporting "~100.0% parsed". Same
# output, byte for byte; the only difference is that the line can now be
# analysed at all.
MISSING_LABEL='<missing>'

FAILURES=0
# The subset of FAILURES that are only about age: too old for --max-age-seconds,
# or past expiresAt. When every failure is one of these AND the signature
# verified, the document is genuine but stale, and the verdict says that
# instead of the line a tampered document gets (#32). Same exit code, 1: an
# expired attestation is still not one to rely on.
STALE_FAILURES=0; STALE_EXPIRED=0; SIGNATURE_VERIFIED=0
stale() { bad "$@"; STALE_FAILURES=$((STALE_FAILURES+1)); }
WORKDIR=''
cleanup() { if [ -n "$WORKDIR" ]; then rm -rf -- "$WORKDIR"; fi; return 0; }
trap cleanup EXIT

# Is a posture attestation being checked at all? `--attestation` carries its own
# signature, so it stands in for `--jws` everywhere below.
HAVE_ATTESTATION=0
if [ -n "$JWS_FILE" ] || [ -n "$ATTESTATION_FILE" ]; then HAVE_ATTESTATION=1; fi

if [ "$STATUS_LIST_MODE" -eq 1 ]; then
  [ -n "$STATUS_SRC" ] || die "--status-list requires --status <file-or-url>."
  [ -n "$STATUS_KEYS_SRC" ] || die "--status-list requires --status-keys <file-or-url>. \
Never the attestation --jwks — the two key sets are disjoint by design."
  [ "$HAVE_ATTESTATION" -eq 1 ] || [ -n "$CHECK_KID" ] || [ -n "$CHECK_SUBJECT" ] \
    || die "--status-list needs something to check: pass --attestation or --jws (check its \
kid/slug), or --check-kid, or --check-subject. Run with --help."
fi
[ "${#EXPECT_KIDS[@]}" -eq 0 ] || [ "$HAVE_ATTESTATION" -eq 1 ] \
  || die "--expect-kid pins the key that signed an attestation, so it needs --attestation (or --jws). \
To look a kid up in a status list, use --check-kid."
if [ "$HAVE_ATTESTATION" -eq 1 ] || [ "$STATUS_LIST_MODE" -eq 0 ]; then
  [ "$HAVE_ATTESTATION" -eq 1 ] || die "missing --attestation (or --jws). Run with --help."
  [ -z "$JWS_FILE" ] || [ -r "$JWS_FILE" ] || die "cannot read ${JWS_FILE}"
  [ -z "$ATTESTATION_FILE" ] || [ -r "$ATTESTATION_FILE" ] || die "cannot read ${ATTESTATION_FILE}"
  [ -n "$JWKS_FILE" ] || [ -n "$PUB_B64URL" ] || die "need --jwks or --pub-b64url."
fi
[ -z "$CLAIMS_FILE" ] || [ -r "$CLAIMS_FILE" ] || die "cannot read ${CLAIMS_FILE}"

# Refused rather than resolved by precedence. Two sources for the same document
# is exactly the situation where a verifier reads one and reports on the other.
if [ -n "$POSTURE_FILE" ] && { [ -n "$CLAIMS_FILE" ] || [ -n "$ATTESTATION_FILE" ]; }; then
  die "--posture cannot be combined with --claims or --attestation: they are two sources for \
the same document, and the signature covers only one of them. Drop --posture."
fi

if [ "$STATUS_LIST_MODE" -eq 1 ]; then
  printf '\n%sHodeiShield ATTEST revocation status list — offline verification%s\n\n' "$BOLD" "$RESET"
else
  printf '\n%sHodeiShield posture attestation — offline verification%s\n\n' "$BOLD" "$RESET"
fi
if [ "$HAVE_ATTESTATION" -eq 1 ]; then WITHHOLD_ON_DIE=1; fi

# --- 0. Environment ----------------------------------------------------------
printf '%s[0] Environment%s\n' "$BOLD" "$RESET"
command -v openssl >/dev/null 2>&1 || die "openssl not found. Need OpenSSL >= 3.5 for ML-DSA."
OSSL_LINE="$(openssl version)"
# The version number alone says nothing about ML-DSA: LibreSSL (macOS, and
# Homebrew's 4.x) prints a version >= 3.5 and has no ML-DSA at all. Before this
# check it passed as "ML-DSA capable" and only failed later, as an unexplained
# "OpenSSL rejected the reconstructed public key". Still exit 2, but the reader
# was told the opposite of the truth on the way there.
case "$OSSL_LINE" in
  'OpenSSL '*) ;;
  *) die "'openssl' here is not OpenSSL, so it is not ML-DSA capable: ${OSSL_LINE}
       ML-DSA (FIPS 204) needs OpenSSL >= 3.5. LibreSSL has no ML-DSA, whatever its
       version number. Use OpenSSL >= 3.5, or the container route in the README.
       This is a tooling limit, not evidence against the attestation." ;;
esac
OSSL_V="$(printf '%s' "$OSSL_LINE" | awk '{print $2}')"
OSSL_MAJ="${OSSL_V%%.*}"; OSSL_R="${OSSL_V#*.}"; OSSL_MIN="${OSSL_R%%.*}"
# Written multi-line on purpose. Semgrep's bash parser cannot parse a
# single-line `case ... in ... esac`; it drops the construct AND a chunk of what
# follows, then still reports "~100.0% parsed" and exits 0 — i.e. the code is
# silently never scanned. Semantics are identical either way, so the shape that
# a SAST tool can actually read is the one worth having. (This does NOT mean the
# file is fully covered: a parse gate in our CI checks that separately.)
case "$OSSL_MAJ$OSSL_MIN" in
  *[!0-9]*|'') die "cannot parse OpenSSL version from: ${OSSL_LINE}" ;;
esac
if [ "$OSSL_MAJ" -lt 3 ] || { [ "$OSSL_MAJ" -eq 3 ] && [ "$OSSL_MIN" -lt 5 ]; }; then
  die "OpenSSL ${OSSL_V} is too old — ML-DSA (FIPS 204) needs >= 3.5.
       Found: ${OSSL_LINE}
       This is a tooling limit, not evidence against the attestation."
fi
# Ask OpenSSL itself, instead of inferring it from the version: a build or a
# provider configuration (a FIPS-only provider, say) can lack ML-DSA-65 on 3.5+.
if ! openssl list -signature-algorithms 2>/dev/null | grep -qi 'ML-DSA-65'; then
  die "OpenSSL ${OSSL_V} does not offer ML-DSA-65, so it is not ML-DSA capable here.
       Found: ${OSSL_LINE}
       'openssl list -signature-algorithms' does not list ML-DSA-65 (check the
       providers it loads). This is a tooling limit, not evidence against the attestation."
fi
ok "OpenSSL ${OSSL_V} offers ML-DSA-65"

if [ -n "$ATTESTATION_FILE" ] || [ -n "$CLAIMS_FILE" ] || [ -n "$POSTURE_FILE" ]; then
  command -v python3 >/dev/null 2>&1 \
    || die "python3 is needed to read the claims JSON and re-derive the canonical envelope bytes."
fi

if [ "$STATUS_LIST_MODE" -eq 1 ]; then
  command -v python3 >/dev/null 2>&1 || die "python3 is needed for the status-list canonical encoder."
  command -v jq >/dev/null 2>&1 || die "jq is needed for --status-list — the document nests arrays \
(keys[], subjects[]) that plain sed cannot safely extract."
  ok "python3 and jq present"
  case "$STATUS_SRC$STATUS_KEYS_SRC" in
    *http://*|*https://*) command -v curl >/dev/null 2>&1 || die "curl is needed to fetch --status/--status-keys URLs." ;;
  esac
fi

# The 22-byte ML-DSA-65 SPKI prefix has to be turned from hex into bytes. `xxd`
# is the obvious tool and is NOT installed on minimal Debian/Ubuntu images or
# most containers, so it is not assumed: python3 is the fallback, and if neither
# is present you get a sentence rather than `xxd: command not found` from the
# middle of section 3.
hex_to_bin() {
  if command -v xxd >/dev/null 2>&1; then
    xxd -r -p
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import sys,binascii;sys.stdout.buffer.write(binascii.unhexlify(sys.stdin.read().strip()))'
  else
    die "need either xxd or python3 to build the SPKI header (22 constant bytes of the algorithm)."
  fi
}

WORKDIR="$(mktemp -d)"; chmod 700 "$WORKDIR"

b64url_decode() {
  local s="${1//-/+}"
  s="${s//_//}"
  # Multi-line for the same parser reason as the `case` above: as a one-liner
  # this construct was the largest SAST blind spot in the file, taking the whole
  # of fetch_or_read() down with it.
  #
  # The length is taken in its own assignment rather than written inline as
  # `case $(( ${#s} % 4 ))`, because that inline form makes Semgrep's
  # unquoted-expansion rule fire on an arithmetic context where no word
  # splitting can occur — a false positive, and suppressing one would have been
  # the wrong trade when a plain assignment says the same thing and is honest.
  local pad=0
  pad=${#s}
  pad=$(( pad % 4 ))
  case "$pad" in
    2) s="${s}==" ;;
    3) s="${s}=" ;;
    1) return 1 ;;
  esac
  printf '%s' "$s" | openssl base64 -d -A
}
b64url_encode() { openssl base64 -A -in "$1" | tr '+/' '-_' | tr -d '='; }

# RFC 3339 -> Unix seconds, or empty on a bad string. Global: needed by the
# posture freshness check (section 6) AND the status-list freshness check
# (section 8), and the latter can run without the former ever having run.
# GNU `date -u -d` first (fast, and what most Linux boxes have); python3 second,
# which is portable and is already a hard requirement on the --attestation path;
# BSD/macOS `date -u -j -f` last. Returning '' on a bad string is the contract,
# and EVERY caller must treat '' as "could not check" — never as "check passed".
# See section 6: an unparseable expiresAt is a FAIL there, not a silent pass.
epoch_of() {
  local out
  out="$(date -u -d "$1" +%s 2>/dev/null)" && [ -n "$out" ] && { printf '%s' "$out"; return; }
  if command -v python3 >/dev/null 2>&1; then
    out="$(printf '%s' "$1" | python3 -c '
import sys, datetime
s = sys.stdin.read().strip().replace("Z", "+00:00")
try:
    print(int(datetime.datetime.fromisoformat(s).timestamp()))
except Exception:
    pass
' 2>/dev/null)" && [ -n "$out" ] && { printf '%s' "$out"; return; }
  fi
  out="$(date -u -j -f '%Y-%m-%dT%H:%M:%S' "${1%%.*}" +%s 2>/dev/null)" \
    && [ -n "$out" ] && { printf '%s' "$out"; return; }
  printf ''
}

# Fetch (http(s):// URL, via curl) or read (anything else, as a file path) SRC
# into OUT, labelling it ROLE for the messages below. Used by --status-list for
# --status/--status-keys, which accept either the raw `curl -o` output of the
# endpoints or the endpoints directly.
#
# TRANSPORT MATTERS DIFFERENTLY FOR THE TWO DOCUMENTS, and this function is the
# only place that can tell them apart:
#
#   --status     (the list)    is SIGNED. Cleartext transport degrades it to
#                              `unknown` — tamper with it and the signature stops
#                              verifying — so it is allowed, with a warning.
#   --status-keys (the KEYS)   is the TRUST ANCHOR. Nothing downstream checks it;
#                              every signature check below is performed *with* it.
#                              Over cleartext an on-path attacker swaps in their
#                              own key set, signs a list of their choosing with the
#                              matching private key, and this script prints GOOD or
#                              REVOKED with every check "passing". That is not a
#                              degraded answer, it is a chosen one, so plaintext
#                              http:// is REFUSED here rather than warned about.
#
# The refusal is not a wall: fetch the key set yourself and pass the file
# (`curl -fsS http://… -o keys.json` → `--status-keys keys.json`). What that buys
# is that the risk is taken deliberately by a human, not silently by this script.
# Loopback is exempt — there is no on-path attacker on 127.0.0.1, and local
# end-to-end testing of the endpoints has to stay possible.
#
# WHAT THIS DOES NOT GUARANTEE. HTTPS here means "curl's default verification
# against the system trust store" — it does not pin a certificate, does not know
# which origin *should* be authoritative for a given `iss` (that is --expect-issuer's
# job, and only if you pass it), and says nothing about whether the key set served
# is the right one. Redirects are deliberately NOT followed (no `-L`), so a
# redirect to a file:// or an internal address cannot be chased; a redirecting
# endpoint fails closed instead. There is also no response-size bound beyond
# --max-time 15, so a hostile endpoint can stream into the (0700, mktemp -d)
# work directory for up to 15 seconds.
fetch_or_read() {
  local src="$1" out="$2" role="${3:-document}"
  case "$src" in
    https://*)
      curl -fsS --max-time 15 --max-filesize 5000000 -o "$out" "$src" || die "failed to fetch ${src}"
      ;;
    http://localhost|http://localhost/*|http://localhost:*|\
    http://127.0.0.1|http://127.0.0.1/*|http://127.0.0.1:*|\
    "http://[::1]"|"http://[::1]/"*|"http://[::1]:"*)
      warn "fetching the ${role} over cleartext HTTP from loopback: ${src}"
      curl -fsS --max-time 15 --max-filesize 5000000 -o "$out" "$src" || die "failed to fetch ${src}"
      ;;
    http://*)
      if [ "$role" = 'status key set' ]; then
        die "refusing to fetch the STATUS KEY SET over cleartext HTTP: ${src}

       The key set is the trust anchor for everything section 8 checks. Fetched
       over http://, anyone on the path can replace it with keys they hold and
       have this script report a signed, self-consistent GOOD or REVOKED that
       they chose. No later check can catch that — they are all performed with
       this document.

       Use https://, or fetch it yourself and pass the file, which makes the
       decision yours rather than this script's:
         curl -fsS ${src} -o status-keys.json
         verify-attestation.sh --status-list --status-keys status-keys.json ..."
      fi
      warn "fetching the ${role} over cleartext HTTP: ${src}"
      warn "the list is signed, so tampering shows up as a failed signature (=> unknown),"
      warn "but use https:// — a downgrade you did not notice is not a threat model."
      curl -fsS --max-time 15 --max-filesize 5000000 -o "$out" "$src" || die "failed to fetch ${src}"
      ;;
    *)
      [ -r "$src" ] || die "cannot read ${src}"
      cp -- "$src" "$out"
      ;;
  esac
}

# The canonical ATTESTATION encoder, reimplemented from the two published wire
# formats — `hodei-shield.attest.attestation.v1` (the ENVELOPE, fields E1..E7;
# app/src/lib/attest/posture.ts) wrapping `hodei-shield.attest.posture.v1` (the
# frozen posture, fields F1..F8; app/src/lib/attest/canonical.ts). Both are in
# §4.4 of the verification doc. Independent of HodeiShield code on purpose: if
# this reproduces the bytes the platform signed, the format is genuinely
# specified rather than defined-by-implementation.
#
# THE SIGNATURE IS OVER THE ENVELOPE. The posture encoder is not the payload
# encoder — it produces field E7 of the payload, and it is also what §4.9's
# badge commitment hashes. Emitting the wrong one of these two is precisely the
# defect this script shipped with: it re-derived 517 posture bytes for a
# document whose signature covered 715 envelope bytes, and reported a genuine
# attestation as forged.
#
#   argv[1]  claims JSON (the whole `claims` object)
#   argv[2]  "envelope" -> E1..E7 bytes (what is signed)
#            "posture"  -> F1..F8 bytes of the nested posture (E7's contents)
CANON_PY='
import json, struct, sys
ENVELOPE_DOMAIN = b"hodei-shield.attest.attestation.v1"
POSTURE_DOMAIN  = b"hodei-shield.attest.posture.v1"
MAX_FIELD_BYTES = 4096          # R6 / envelope MAX_FIELD_BYTES
MAX_FRAMEWORKS  = 64
def u64be(n): return struct.pack(">Q", n)
def bs(b):    return u64be(len(b)) + b
def st(s, label="field"):
    if not isinstance(s, str): raise SystemExit("canonical: %s must be a string" % label)
    b = s.encode("utf-8", "strict")             # R5/E-rules: reject unpaired surrogates
    if len(b) > MAX_FIELD_BYTES: raise SystemExit("canonical: %s exceeds %d bytes" % (label, MAX_FIELD_BYTES))
    return bs(b)
def opt(s, label="field"): return b"\x00" if s is None else b"\x01" + st(s, label)
def u64(n):   return bs(u64be(n))

def posture_bytes(p):
    if not isinstance(p, dict): raise SystemExit("canonical: posture must be an object")
    if p.get("version") != "attest.posture.v1": raise SystemExit("canonical: unsupported posture version")
    if p.get("visibility") not in ("public", "gated"): raise SystemExit("canonical: bad visibility")
    fw = sorted(p["frameworks"], key=lambda f: f["code"].encode("utf-8"))   # R2: UTF-8 byte order
    if len(fw) > MAX_FRAMEWORKS: raise SystemExit("canonical: too many frameworks")   # R6
    codes = [f["code"] for f in fw]
    if len(set(codes)) != len(codes): raise SystemExit("canonical: duplicate framework code")  # R3
    out = [POSTURE_DOMAIN, st(p["version"], "version"), st(p["slug"], "slug"),
           st(p["orgName"], "orgName"), st(p["visibility"], "visibility"),
           st(p["generatedAt"], "generatedAt"), opt(p.get("expiresAt"), "expiresAt"),
           opt(p.get("lastCheckedAt"), "lastCheckedAt"), u64(len(fw))]
    for f in fw: out += [st(f["code"], "code"), st(f["label"], "label"), st(f["band"], "band")]
    return b"".join(out)

def envelope_bytes(c):
    if not isinstance(c, dict): raise SystemExit("canonical: claims must be an object")
    if c.get("docVersion") != "attest.attestation.v1":
        raise SystemExit("canonical: claims.docVersion must be attest.attestation.v1")
    nested = posture_bytes(c.get("posture"))    # E7 first: refuse a bad posture before anything else
    return b"".join([ENVELOPE_DOMAIN,
                     st(c["docVersion"], "docVersion"), st(c["iss"], "iss"), st(c["kid"], "kid"),
                     opt(c.get("jti"), "jti"), opt(c.get("nonce"), "nonce"),
                     opt(c.get("overallBand"), "overallBand"),
                     bs(nested)])

claims = json.load(open(sys.argv[1]))
what = sys.argv[2] if len(sys.argv) > 2 else "envelope"
if   what == "envelope": sys.stdout.buffer.write(envelope_bytes(claims))
elif what == "posture":  sys.stdout.buffer.write(posture_bytes(claims.get("posture")))
else: raise SystemExit("canonical: unknown target %r" % what)
'

# The inverse of CANON_PY's envelope encoder, for an ATTACHED JWS handed over
# without its claims JSON. Before 2026-09-29 that path verified the signature
# and then skipped freshness, --expect-slug, --expect-issuer, --expect-nonce and
# the subject-revocation rule, because there was no JSON to read them from; any
# public detached document could be re-wrapped as attached to reach it. Now the
# payload is decoded into the claims it encodes, strictly (every byte consumed),
# and those claims go through exactly the same checks as a detached document.
# Section 4 then re-encodes them and requires the result to equal the payload.
#   argv[1]  the decoded payload bytes;  stdout: the claims JSON
DECODE_PY='
import json, struct, sys
b = open(sys.argv[1], "rb").read()
pos = 0
def take(n):
    global pos
    if n < 0 or pos + n > len(b): raise SystemExit("decode: truncated payload")
    out = b[pos:pos + n]; pos += n; return out
def lit(x):
    if take(len(x)) != x: raise SystemExit("decode: wrong domain separator")
def u64be(): return struct.unpack(">Q", take(8))[0]
def raw():
    n = u64be()
    if n > len(b): raise SystemExit("decode: length out of range")
    return take(n)
def st(): return raw().decode("utf-8", "strict")
def opt():
    t = take(1)
    if t == b"\x00": return None
    if t == b"\x01": return st()
    raise SystemExit("decode: bad option tag")
def u64():
    v = raw()
    if len(v) != 8: raise SystemExit("decode: bad u64")
    return struct.unpack(">Q", v)[0]
lit(b"hodei-shield.attest.attestation.v1")
c = {"docVersion": st(), "iss": st(), "kid": st(), "jti": opt(), "nonce": opt(), "overallBand": opt()}
nested = raw()
if pos != len(b): raise SystemExit("decode: trailing bytes after the envelope")
b, pos = nested, 0
lit(b"hodei-shield.attest.posture.v1")
p = {"version": st(), "slug": st(), "orgName": st(), "visibility": st(), "generatedAt": st(),
     "expiresAt": opt(), "lastCheckedAt": opt()}
n = u64()
if n > 64: raise SystemExit("decode: too many frameworks")
p["frameworks"] = [{"code": st(), "label": st(), "band": st()} for _ in range(n)]
if pos != len(b): raise SystemExit("decode: trailing bytes after the posture")
c["posture"] = p
json.dump(c, sys.stdout, indent=2)
'

# Duplicate object members, anywhere in a JSON file: one path per line, nothing
# when there are none. Every python json.load in this script keeps the LAST of
# a duplicated member and so does jq, which is why the verdict was never
# decided by a duplicate. But a reader or another program that keeps the FIRST
# sees a value nobody signed, printed under this script's own PASS lines. RFC
# 8259 leaves duplicates undefined, so a signed document must not carry any.
#
# It parses STRICTLY (UTF-8, no BOM, nothing after the value) and walks without
# recursion. If it cannot do either it exits non-zero, and every caller treats
# that as a malformed document, never as "no duplicates found".
DUPKEY_PY='
import json, sys
class Obj(list): pass
with open(sys.argv[1], "rb") as fh: raw = fh.read()
doc = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=Obj)
out = []
stack = [(doc, "")]
while stack:
    v, path = stack.pop()
    if isinstance(v, Obj):
        seen = set()
        for k, x in v:
            here = path + "." + k if path else k
            if k in seen: out.append(here)
            seen.add(k)
            stack.append((x, here))
    elif isinstance(v, list):
        stack.extend((x, "%s[%d]" % (path, i)) for i, x in enumerate(v))
# The same member at two levels is the same ambiguity: a document that carries
# "claims" (or "signature") both beside and inside "attestation" offers two.
if isinstance(doc, Obj):
    top = [k for k, _ in doc]
    if "attestation" in top:
        out += [k + " (beside and inside attestation)" for k in ("claims", "signature") if k in top]
def vis(t):
    return "".join(c if c.isprintable() else ("\\x%02x" % ord(c) if ord(c) < 256 else "\\u%04x" % ord(c)) for c in str(t))
# Member names come from the document; they are shown, so they are escaped here.
sys.stdout.write("\n".join(sorted(set(vis(x) for x in out))))
'

# Retirement of a signing key (the JWK member `hs_retired_at`). One reader for
# both key sets, so the grammar, the instant arithmetic and the verdicts exist
# once.
#
#   argv[1] = "key"  argv[2] = key file  argv[3] = kid
#       line 1: absent | ok | malformed (the first entry with that kid and a
#       string `pub`, the one the caller selects); then the member's value.
#       A string is written raw (the caller escapes it before it is shown); any
#       other JSON value is written as JSON text.
#   argv[1] = "cmp"  argv[2] = instant of the document  argv[3] = hs_retired_at
#       at_or_after | before | unparseable
#
# The grammar is exactly YYYY-MM-DDTHH:MM:SSZ with a real calendar date and
# time: no fraction, no offset, no lowercase t or z, no leap second. Instants
# are compared exactly (a `generatedAt` carries milliseconds), never as strings.
RETIRED_PY='
import calendar, datetime, fractions, json, re, sys
RETIRED = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", re.ASCII)
INSTANT = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?(?:Z|([+-])([0-9]{2}):([0-9]{2}))", re.ASCII)
def strict(v):
    return isinstance(v, str) and RETIRED.fullmatch(v) is not None and instant(v) is not None
def instant(v):
    m = INSTANT.fullmatch(v)
    if m is None: return None
    y, mo, d, h, mi, s = (int(m.group(i)) for i in range(1, 7))
    try: datetime.datetime(y, mo, d, h, mi, s)
    except ValueError: return None
    off = 0
    if m.group(8):
        oh, om = int(m.group(9)), int(m.group(10))
        if oh > 23 or om > 59: return None
        off = (oh * 3600 + om * 60) * (1 if m.group(8) == "+" else -1)
    frac = fractions.Fraction(int(m.group(7)[1:]), 10 ** (len(m.group(7)) - 1)) if m.group(7) else 0
    return calendar.timegm((y, mo, d, h, mi, s)) - off + frac
out = sys.stdout.buffer
if sys.argv[1] == "key":
    status, val = "absent", b""
    doc = json.load(open(sys.argv[2], "rb"))
    for k in (doc.get("keys") or []) if isinstance(doc, dict) else []:
        if isinstance(k, dict) and k.get("kid") == sys.argv[3] and isinstance(k.get("pub"), str):
            if "hs_retired_at" in k:
                v = k["hs_retired_at"]
                status = "ok" if strict(v) else "malformed"
                val = (v if isinstance(v, str) else json.dumps(v)).encode("utf-8", "surrogatepass")
            break
    out.write(status.encode() + b"\n" + val)
else:
    a, b = instant(sys.argv[2]), instant(sys.argv[3])
    out.write(b"unparseable" if a is None or b is None else b"at_or_after" if a >= b else b"before")
'

# Document surgery: pull the pieces out of whatever JSON the caller handed us.
# Kept separate from the encoders above so the code that decides WHICH bytes to
# hash stays readable, and so no JSON-shaped convenience can leak into the
# canonical encoder itself.
#
#   argv[2] = "split"   argv[1] is a /api/public/attest/<slug> response (or a
#                       bare {claims, signature}); writes argv[3]=claims.json
#                       and prints the compact JWS on stdout.
#   argv[2] = "shape"   prints "claims" | "posture" | "unknown" for argv[1].
#   argv[2] = "posture" writes the nested posture object to argv[3], so the
#                       freshness/claims sections keep reading a plain posture.
#   argv[2] = "field"   prints one top-level claims field (argv[3]), or nothing
#                       when it is JSON null/absent.
#   argv[2] = "has"     prints 1 when that field is present and not null, else 0
#                       — so "absent" and "the empty string" stay distinguishable
#                       (they are different assertions for `nonce`).
DOCX_PY='
import json, sys
doc = json.load(open(sys.argv[1]))
mode = sys.argv[2]
def claims_of(d):
    if not isinstance(d, dict): raise SystemExit("document: expected a JSON object")
    if "attestation" in d and isinstance(d["attestation"], dict): d = d["attestation"]
    return d
if mode == "shape":
    if not isinstance(doc, dict): print("unknown")
    elif doc.get("docVersion") == "attest.attestation.v1" or "claims" in doc or "attestation" in doc: print("claims")
    elif doc.get("version") == "attest.posture.v1": print("posture")
    else: print("unknown")
elif mode == "split":
    d = claims_of(doc)
    c = d.get("claims", d)
    sig = d.get("signature")
    if not isinstance(c, dict): raise SystemExit("document: no claims object found")
    json.dump(c, open(sys.argv[3], "w"), indent=2)
    if isinstance(sig, str): sys.stdout.write(sig)
elif mode == "posture":
    # The SAME member the canonical encoder reads (claims["posture"]), never a
    # "claims"/"attestation" wrapper found inside the claims: those are not
    # what the signature covers.
    p = doc.get("posture") if isinstance(doc, dict) else None
    if not isinstance(p, dict): raise SystemExit("document: claims.posture is missing")
    json.dump(p, open(sys.argv[3], "w"), indent=2)
elif mode == "field":
    v = doc.get(sys.argv[3])
    # Bytes, not text: a non-UTF-8 stdout (PYTHONIOENCODING) must not make a
    # value unreadable and so change a verdict.
    if isinstance(v, str): sys.stdout.buffer.write(v.encode("utf-8", "surrogatepass"))
    elif v is not None: sys.stdout.write(json.dumps(v))
elif mode == "has":
    sys.stdout.write("0" if doc.get(sys.argv[3]) is None else "1")
elif mode == "unsigned":
    # Every member the canonical encoders do NOT read, one path per line. Those
    # bytes are outside the signature, so a document carrying them is showing
    # you facts nobody signed.
    SIGNED_CLAIMS    = {"docVersion", "iss", "kid", "jti", "nonce", "overallBand", "posture"}
    SIGNED_POSTURE   = {"version", "slug", "orgName", "visibility", "generatedAt",
                        "expiresAt", "lastCheckedAt", "frameworks"}
    SIGNED_FRAMEWORK = {"code", "label", "band"}
    extra = ["claims." + k for k in doc if k not in SIGNED_CLAIMS]
    p = doc.get("posture")
    if isinstance(p, dict):
        extra += ["posture." + k for k in p if k not in SIGNED_POSTURE]
        for i, f in enumerate(p.get("frameworks") or []):
            if isinstance(f, dict):
                extra += ["posture.frameworks[%d].%s" % (i, k) for k in f if k not in SIGNED_FRAMEWORK]
    def vis(t):
        return "".join(c if c.isprintable() else ("\\x%02x" % ord(c) if ord(c) < 256 else "\\u%04x" % ord(c)) for c in str(t))
    sys.stdout.write("\n".join(vis(x) for x in extra))
elif mode == "summary":
    # What the signature covers, for a human: only members the canonical encoders
    # read. Control characters are shown as ? so a value cannot drive the terminal.
    def clean(v): return "".join(ch if ch.isprintable() else "?" for ch in str(v))
    def show(v): return "null" if v is None else clean(v)
    p = doc.get("posture") or {}
    lines = ["        overallBand: " + show(doc.get("overallBand")),
             "        subject:     %s  (visibility: %s)" % (show(p.get("slug")), show(p.get("visibility"))),
             "        generatedAt: " + show(p.get("generatedAt")),
             "        lastCheckedAt: %s" % ("null  (no monitoring heartbeat is claimed)" if p.get("lastCheckedAt") is None
                else clean(p["lastCheckedAt"]) + "  (freshness of the underlying data, can be older than generatedAt)")]
    fw = p.get("frameworks") or []
    lines.append("        frameworks:  " + ("none attested" if not fw else "%d attested" % len(fw)))
    for f in fw: lines.append("          %s (%s): %s" % (clean(f.get("label")), clean(f.get("code")), clean(f.get("band"))))
    # Written as UTF-8 bytes whatever the terminal encoding: a label such as
    # "ens—alto" must not turn a verified document into an error.
    sys.stdout.buffer.write(("\n".join(lines) + "\n").encode("utf-8", "backslashreplace"))
else: raise SystemExit("document: unknown mode %r" % mode)
'

# The canonical STATUS-LIST encoder, reimplemented from the published wire
# format `hodei-shield.attest.statuslist.v1`
# (app/src/lib/attest/status-list.ts, and §5-6.4 of
# docs/architecture/specs/2026-07-30-attest-revocation-design.md). This is the
# "complete independent implementation" §6.4 promises the shell verifier
# embeds; byte-for-byte the same encoder pinned as a golden vector in
# app/src/lib/attest/__tests__/status-list.test.ts, so it cannot drift from
# the doc without that test failing.
CANON_STATUS_PY='
import json, struct, sys
DOMAIN  = b"hodei-shield.attest.statuslist.v1"
REASONS = {"key_compromise","superseded","issuer_error","subject_withdrawn","unspecified"}
def u64be(n): return struct.pack(">Q", n)
def bs(b):    return u64be(len(b)) + b
def st(s):
    if not isinstance(s, str): raise SystemExit("canonical: field must be a string")
    s.encode("utf-8", "strict")                                # S5
    return bs(s.encode("utf-8"))
def u64(n):   return bs(u64be(n))
def rs(s):
    if s not in REASONS: raise SystemExit("canonical: unknown reason: %s" % s)   # S7
    return st(s)

L = json.load(open(sys.argv[1]))
if L.get("docVersion") != "attest.statuslist.v1": raise SystemExit("canonical: unsupported docVersion")
# Typed strictly, because sections 8-9 read these with jq and bash: a truncated
# flag that is truthy but not true would skip the truncated => unknown rule, and
# a seq that bash cannot compare would skip the --min-seq rollback check.
if not isinstance(L.get("truncated"), bool): raise SystemExit("canonical: truncated must be a boolean")
if type(L.get("seq")) is not int or not 0 <= L["seq"] < 2**63: raise SystemExit("canonical: seq must be an integer in [0, 2^63)")
ke = sorted(L["keys"],     key=lambda e: e["kid"].encode("utf-8"))          # S2
se = sorted(L["subjects"], key=lambda e: e["subjectHash"].encode("utf-8"))  # S2
if len({e["kid"] for e in ke}) != len(ke):         raise SystemExit("canonical: duplicate kid")       # S3
if len({e["subjectHash"] for e in se}) != len(se): raise SystemExit("canonical: duplicate subject")   # S3

out = [DOMAIN, st(L["docVersion"]), st(L["iss"]), st(L["kid"]), u64(L["seq"]),
       st(L["issuedAt"]), st(L["nextUpdate"]), u64(1 if L["truncated"] else 0),
       u64(len(ke))]
for e in ke: out += [st(e["kid"]), rs(e["reason"]), st(e["revokedAt"])]
out += [u64(len(se))]
for e in se: out += [st(e["subjectHash"]), rs(e["reason"]), st(e["notBefore"]), st(e["expiresAt"])]
sys.stdout.buffer.write(b"".join(out))
'

# --- Document resolution -----------------------------------------------------
# Normalise whatever the caller passed into (a) a file holding the compact JWS,
# (b) a file holding the CLAIMS object — the signed document — and (c) a file
# holding just the nested posture, which sections 6 and 7 read.
if [ -n "$ATTESTATION_FILE" ]; then
  python3 -c "$DOCX_PY" "$ATTESTATION_FILE" split "$WORKDIR/claims.json" > "$WORKDIR/att.jws" \
    || die "could not read ${ATTESTATION_FILE} as an attestation document.
       Expected what GET /api/public/attest/<slug> serves:
       {\"attestation\": {\"claims\": {...}, \"signature\": \"...\"}}"
  [ -n "$CLAIMS_FILE" ] || CLAIMS_FILE="$WORKDIR/claims.json"
  if [ -z "$JWS_FILE" ]; then
    [ -s "$WORKDIR/att.jws" ] || die "${ATTESTATION_FILE} carries no \"signature\" member. \
Pass the signature with --jws if you hold it separately."
    JWS_FILE="$WORKDIR/att.jws"
  fi
fi

# `--posture` used to be THE verification input, back when this script wrongly
# believed the bare posture was what got signed. It is not. A full claims object
# passed here still works (people will do it, and it is unambiguous); a bare
# posture is REFUSED — with a usage error, never a FAIL, because "you gave me
# one field of the document" is not evidence against the document.
if [ -n "$POSTURE_FILE" ] && [ -z "$CLAIMS_FILE" ]; then
  case "$(python3 -c "$DOCX_PY" "$POSTURE_FILE" shape 2>/dev/null || printf 'unknown')" in
    claims)
      CLAIMS_FILE="$POSTURE_FILE"
      ;;
    posture)
      die "--posture was given a bare posture object, and the signature does not cover those bytes.

       The signature is over the ATTESTATION ENVELOPE (hodei-shield.attest.attestation.v1),
       which nests the posture as field E7 alongside iss, kid, jti, nonce and overallBand.
       You cannot verify from a bare posture: jti alone is a random UUID nobody
       can reconstruct.

       Pass the whole document instead:
         curl -fsS https://<origin>/api/public/attest/<slug> -o att.json
         verify-attestation.sh --attestation att.json --jwks jwks.json
       or, if you are splitting it yourself:
         jq -r '.attestation.signature' att.json > att.jws
         jq   '.attestation.claims'     att.json > att.claims.json
         verify-attestation.sh --jws att.jws --claims att.claims.json --jwks jwks.json"
      ;;
    *)
      die "could not tell what ${POSTURE_FILE} is. Pass --attestation or --claims."
      ;;
  esac
fi

# An attached JWS with no claims JSON: decode its payload into claims (see
# DECODE_PY). A payload that does not decode as the envelope is evidence
# against the document, not a tooling problem: section 4 FAILS it (exit 1), and
# it is never verified as opaque bytes.
ATTACHED_UNDECODABLE=''
if [ -n "$JWS_FILE" ] && [ -z "$CLAIMS_FILE" ]; then
  ATT_PAYLOAD="$(tr -d '[:space:]' < "$JWS_FILE" | cut -d. -f2)"
  if [ -n "$ATT_PAYLOAD" ]; then
    command -v python3 >/dev/null 2>&1 \
      || die "python3 is needed to decode the attached payload into the claims it signs."
    if b64url_decode "$ATT_PAYLOAD" > "$WORKDIR/attached-payload.bin" 2>/dev/null \
       && python3 -c "$DECODE_PY" "$WORKDIR/attached-payload.bin" > "$WORKDIR/claims.json" \
            2>"$WORKDIR/decode_err"; then
      CLAIMS_FILE="$WORKDIR/claims.json"
    else
      ATTACHED_UNDECODABLE="$(cat "$WORKDIR/decode_err" 2>/dev/null || true)"
      : "${ATTACHED_UNDECODABLE:=payload segment is not valid base64url}"
    fi
  fi
fi

# Duplicate members in the document as the caller handed it over — the raw
# file, before any re-serialisation hides them. Section 7 FAILS on them.
DUPLICATE_KEYS=''
for dup_src in "$ATTESTATION_FILE" "$CLAIMS_FILE"; do
  [ -n "$dup_src" ] || continue
  dup_found="$(python3 -c "$DUPKEY_PY" "$dup_src" 2>/dev/null)" \
    || dup_found="(the file could not be parsed strictly: $dup_src)"
  [ -z "$dup_found" ] || DUPLICATE_KEYS="${DUPLICATE_KEYS:+$DUPLICATE_KEYS
}$dup_found"
done

# One posture view for sections 6 and 7, always sliced out of the claims we are
# about to verify — never a second file the caller supplied, which could differ
# from the one inside the signature.
POSTURE_FILE=''
if [ -n "$CLAIMS_FILE" ]; then
  python3 -c "$DOCX_PY" "$CLAIMS_FILE" posture "$WORKDIR/posture.json" \
    || die "claims JSON has no usable \`posture\` object: ${CLAIMS_FILE}"
  POSTURE_FILE="$WORKDIR/posture.json"
fi

# Sections 1-7 verify the POSTURE ATTESTATION (`--jws`/`--attestation`). They run
# whenever a document was given — unconditionally in the default mode (required
# above), and optionally in `--status-list` mode when the caller wants the full
# §6.2 procedure (verify the attestation, THEN apply the list to it) rather than
# a standalone list query against an explicit --check-kid/--check-subject.
if [ -n "$JWS_FILE" ]; then

# --- 1. Structure ------------------------------------------------------------
printf '\n%s[1] Structure%s\n' "$BOLD" "$RESET"
JWS="$(tr -d '[:space:]' < "$JWS_FILE")"
case "$JWS" in
  *.*.*) : ;;
  *) die "not a compact JWS (expected two dots): ${JWS_FILE}" ;;
esac
H="${JWS%%.*}"; REST="${JWS#*.}"; P="${REST%%.*}"; S="${REST#*.}"
case "$S" in
  *.*) die "too many dots — is this a JSON-serialised JWS?" ;;
esac

if [ -z "$P" ]; then
  FORM='detached'
  ok "detached JWS (RFC 7515 Appendix F): payload segment is empty"
  [ -n "$CLAIMS_FILE" ] || die "a detached JWS carries no payload, so the bytes it signed must be \
re-derived from the claims JSON.
       Pass --attestation <the endpoint response>, or --claims <the claims object>."
else
  FORM='attached'
  ok "attached JWS: payload segment carries the canonical envelope bytes"
fi

b64url_decode "$H" > "$WORKDIR/header.json" || die "header is not valid base64url"
b64url_decode "$S" > "$WORKDIR/sig.bin"     || die "signature is not valid base64url"
SIG_LEN="$(wc -c < "$WORKDIR/sig.bin" | tr -d ' ')"
if [ "$SIG_LEN" -eq 3309 ]; then
  ok "signature is 3309 bytes — the ML-DSA-65 size"
else
  bad "signature is ${SIG_LEN} bytes, expected 3309 for ML-DSA-65"
fi

# --- 2. Header ---------------------------------------------------------------
printf '\n%s[2] Header%s\n' "$BOLD" "$RESET"
json_str() { sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$1" | head -1; }
ALG="$(json_str "$WORKDIR/header.json" alg)"
KID="$(json_str "$WORKDIR/header.json" kid)"
TYP="$(json_str "$WORKDIR/header.json" typ)"
printf '        %s\n' "$(esc "$(cat "$WORKDIR/header.json")")"

# Never dispatch on `alg` — compare it as a constant. The verification primitive
# below is ML-DSA-65 unconditionally, so `alg: none` is a non-event.
if [ "$ALG" = 'ML-DSA-65' ]; then
  ok "alg is ML-DSA-65 (RFC 9964, IANA-permanent)"
else
  bad "alg is '$(esc "${ALG}")', expected 'ML-DSA-65'. Refusing to verify under a substituted algorithm."
fi
if [ "$TYP" = 'application/attest+jws' ]; then
  ok "typ is application/attest+jws — cannot be replayed into another JWS surface"
else
  bad "typ is '$(esc "${TYP}")', expected 'application/attest+jws'"
fi
if grep -q '"crit"' "$WORKDIR/header.json"; then
  bad "header carries 'crit' — RFC 7515 §4.1.11 requires rejection of extensions we do not implement"
else
  ok "no 'crit' header extension"
fi
# The same closed set the platform verifier (jws.ts ALLOWED_HEADER_MEMBERS) and
# section 8 below enforce: a member nothing examines must not be able to carry
# meaning. Not a JSON object at all counts as a mismatch too.
command -v python3 >/dev/null 2>&1 || die "python3 is needed to check the protected header's member set."
HEADER_MEMBERS="$(python3 -c '
import json, sys
pairs = []
h = json.load(open(sys.argv[1]), object_pairs_hook=lambda p: (pairs.append([k for k, _ in p]), dict(p))[1])
dups = sorted({k for ks in pairs for k in ks if ks.count(k) > 1})
if dups: print("duplicated: " + ",".join(dups))
else: print(",".join(sorted(h)) if isinstance(h, dict) else "(not a JSON object)")
' "$WORKDIR/header.json" 2>/dev/null || printf '(not JSON)')"
if [ "$HEADER_MEMBERS" = 'alg,kid,typ' ]; then
  ok "header is the closed set {alg, kid, typ}"
else
  bad "malformed_document — header members are '$(esc "${HEADER_MEMBERS}")', expected exactly alg,kid,typ"
fi

# --- 3. Public key -----------------------------------------------------------
printf '\n%s[3] Public key%s\n' "$BOLD" "$RESET"
if [ -z "$PUB_B64URL" ]; then
  [ -r "$JWKS_FILE" ] || die "cannot read ${JWKS_FILE}"
  # A key document with a duplicated member is malformed: which `pub` or `kid`
  # counts would depend on the parser. Not evidence against the attestation,
  # so exit 2, like the unknown-kid stop below.
  JWKS_DUPS="$(python3 -c "$DUPKEY_PY" "$JWKS_FILE" 2>/dev/null)" \
    || die "the key document ${JWKS_FILE} is not strict JSON (UTF-8, no BOM, one value).
       Re-fetch it; do not edit it by hand."
  [ -z "$JWKS_DUPS" ] || die "the key document ${JWKS_FILE} repeats members ($(printf '%s' "$JWKS_DUPS" | tr '\n' ' ')).
       Which key it names depends on the parser. Re-fetch it; do not edit it by hand."
  # Selected as JSON: the entry of `keys` whose `kid` is the header kid, and its
  # `pub` — never the first line of text that looks like one. `|| true` is
  # load-bearing under `set -euo pipefail`: with no match the assignment must
  # not abort the script (a silent exit 1, indistinguishable from a failed
  # signature), so that the unknown-kid diagnosis below can run.
  PUB_B64URL="$(python3 -c '
import json, sys
for k in json.load(open(sys.argv[1])).get("keys") or []:
    if isinstance(k, dict) and k.get("kid") == sys.argv[2] and isinstance(k.get("pub"), str):
        sys.stdout.write(k["pub"]); break
' "$JWKS_FILE" "$KID" 2>/dev/null || true)"
  if [ -z "$PUB_B64URL" ]; then
    # A HARD stop, never a fallback to keys[0] — the same rule the status-list
    # path applies to an unknown kid, and for the same reason. Guessing a key
    # can only turn "I am holding the wrong key document" into a signature
    # failure that reads like a forged document. Those are different findings
    # and a verifier must not conflate them.
    die "no key in this JWKS carries kid '$(esc "${KID}")'.
       This is NOT evidence that the document is forged — it means you are
       holding the wrong or a stale key document. Re-fetch the JWKS and retry;
       a retired key stays in the published set, marked with hs_retired_at."
  else
    ok "selected the JWKS key whose kid is '$(esc "${KID}")'"
    # The retirement marker of the selected key (checked against generatedAt in
    # section 6). A marker that is not exactly an RFC 3339 UTC second is an
    # invalid key set, not evidence about the document: exit 2.
    RETIRED_OUT="$(LC_ALL=C python3 -c "$RETIRED_PY" key "$JWKS_FILE" "$KID" 2>/dev/null; printf x)"
    RETIRED_OUT="${RETIRED_OUT%x}"
    case "${RETIRED_OUT%%$'\n'*}" in
      absent) ;;
      ok) RETIRED_AT="${RETIRED_OUT#*$'\n'}" ;;
      *) die "the key document ${JWKS_FILE} is invalid: hs_retired_at of the key '$(esc "${KID}")' is
       '$(esc "${RETIRED_OUT#*$'\n'}")', not an RFC 3339 UTC time with seconds (YYYY-MM-DDTHH:MM:SSZ).
       Re-fetch the key document; do not edit it by hand." ;;
    esac
  fi
fi

b64url_decode "$PUB_B64URL" > "$WORKDIR/pub.raw" || die "public key is not valid base64url"
PUB_LEN="$(wc -c < "$WORKDIR/pub.raw" | tr -d ' ')"
if [ "$PUB_LEN" -eq 1952 ]; then
  ok "public key is 1952 bytes — the ML-DSA-65 size"
else
  bad "public key is ${PUB_LEN} bytes, expected 1952"
fi

# The kid is CHECKED, not trusted: it must be derivable from the key bytes, so a
# JWK cannot claim to be a key it is not.
#   kid = BASE64URL( SHA-256( UTF8("hodei-shield.attest.kid.v1") || pub )[0..16] )
{ printf 'hodei-shield.attest.kid.v1'; cat "$WORKDIR/pub.raw"; } > "$WORKDIR/kidinput.bin"
openssl dgst -sha256 -binary -out "$WORKDIR/kiddigest.bin" "$WORKDIR/kidinput.bin"
head -c 16 "$WORKDIR/kiddigest.bin" > "$WORKDIR/kid16.bin"
DERIVED_KID="$(b64url_encode "$WORKDIR/kid16.bin")"
if [ "$DERIVED_KID" = "$KID" ]; then
  ok "kid '$(esc "${KID}")' is derivable from these key bytes"
else
  bad "kid mismatch — header says '$(esc "${KID}")', the key bytes derive '${DERIVED_KID}'.
          The key document is mislabelled or you are holding the wrong key."
fi

# --expect-kid: the pin is compared with the kid RECOMPUTED from the key bytes
# above, never with the label the header or the JWKS carries. A mislabelled key
# therefore cannot satisfy a pin by naming itself after the kid you pinned. (A
# mismatch between that label and the key already failed above; this is the
# separate question of whether the key is one you meant to trust.)
if [ "${#EXPECT_KIDS[@]}" -gt 0 ]; then
  PIN_MATCH=0
  for pinned_kid in "${EXPECT_KIDS[@]}"; do
    if [ "$pinned_kid" = "$DERIVED_KID" ]; then PIN_MATCH=1; fi
  done
  if [ "$PIN_MATCH" -eq 1 ]; then
    ok "the key bytes derive kid '${DERIVED_KID}', one of the kids you pinned with --expect-kid"
  else
    bad "unexpected_kid — the key bytes derive kid '${DERIVED_KID}', which is not one of the kids you
          pinned with --expect-kid: ${EXPECT_KIDS[*]}"
  fi
fi

# OpenSSL loads SubjectPublicKeyInfo; the JWK carries the bare FIPS 204 key.
# 22-byte SPKI prefix for ML-DSA-65 (OID 2.16.840.1.101.3.4.3.12):
printf '308207b2300b0609608648016503040312038207a100' | hex_to_bin > "$WORKDIR/pub.der"
cat "$WORKDIR/pub.raw" >> "$WORKDIR/pub.der"
openssl pkey -pubin -inform DER -in "$WORKDIR/pub.der" -out "$WORKDIR/pub.pem" 2>"$WORKDIR/err" \
  || die "OpenSSL rejected the reconstructed public key: $(esc "$(cat "$WORKDIR/err")")"
ok "loaded as an ML-DSA-65 public key"

# --- 4. Payload — the signing envelope ---------------------------------------
# The payload is `hodei-shield.attest.attestation.v1` (E1..E7), NOT the bare
# posture. The posture is E7, nested verbatim. Re-deriving only the posture is
# how this script used to report genuine documents as forged.
printf '\n%s[4] Payload — attestation envelope (E1..E7)%s\n' "$BOLD" "$RESET"
CLAIMS_KID=''
if [ -n "$CLAIMS_FILE" ]; then
  [ -r "$CLAIMS_FILE" ] || die "cannot read ${CLAIMS_FILE}"
  command -v python3 >/dev/null 2>&1 || die "python3 is needed to re-derive canonical bytes from the claims JSON."
  python3 -c "$CANON_PY" "$CLAIMS_FILE" envelope > "$WORKDIR/canon.bin" \
    || die "could not canonicalise ${CLAIMS_FILE}"
  python3 -c "$CANON_PY" "$CLAIMS_FILE" posture > "$WORKDIR/canon-posture.bin" \
    || die "could not canonicalise the nested posture of ${CLAIMS_FILE}"
  CANON_LEN="$(wc -c < "$WORKDIR/canon.bin" | tr -d ' ')"
  NESTED_LEN="$(wc -c < "$WORKDIR/canon-posture.bin" | tr -d ' ')"
  ok "re-derived ${CANON_LEN} canonical envelope bytes from the claims JSON you can read"
  printf '        of which E7 nests %s bytes of hodei-shield.attest.posture.v1 (the posture itself)\n' "$NESTED_LEN"
  printf '        sha-256: %s\n' "$(openssl dgst -sha256 -hex "$WORKDIR/canon.bin" | awk '{print $NF}')"
  printf '        (compare with attestation.digest as the endpoint published it — a content id,\n'
  printf '         never an authentication check: the signature below is the check)\n'
  PAYLOAD_B64="$(b64url_encode "$WORKDIR/canon.bin")"
  if [ "$FORM" = 'attached' ]; then
    if [ "$PAYLOAD_B64" = "$P" ]; then
      ok "the embedded payload equals the bytes re-derived from your claims JSON"
    else
      bad "the embedded payload does NOT match the claims JSON you supplied —
          the JSON you can read is not the document that was signed"
    fi
  fi

  # The body names a key; the header names a key. They must be the same key, or
  # the document is lying about which key vouches for it. (This is the platform
  # verifier's `kid_mismatch`, and it only became checkable here once the whole
  # envelope was in view — E3 is inside the signature, the header kid is inside
  # the signing input, and both must agree.)
  CLAIMS_KID="$(python3 -c "$DOCX_PY" "$CLAIMS_FILE" field kid)"
  if [ "$CLAIMS_KID" = "$KID" ]; then
    ok "claims.kid (E3) equals the protected-header kid — one key, named twice, agreeing"
  else
    bad "kid_mismatch — the header says '$(esc "${KID}")', the signed body says '$(esc "${CLAIMS_KID}")'.
          A document cannot name one key in its body and be signed by another."
  fi
elif [ -n "$ATTACHED_UNDECODABLE" ]; then
  bad "malformed_document — the attached payload is not a hodei-shield.attest.attestation.v1
          envelope ($(esc "${ATTACHED_UNDECODABLE}")). There are no claims to check, so nothing here verifies."
  PAYLOAD_B64="$P"
else
  ok "using the payload embedded in the attached JWS"
  b64url_decode "$P" > "$WORKDIR/canon.bin" || die "payload segment is not valid base64url"
  PAYLOAD_B64="$P"
  warn "no --attestation/--claims given: you are verifying opaque bytes. Supply the"
  warn "claims JSON so the facts you read are provably the facts that were signed."
fi

# --- 5. Signature ------------------------------------------------------------
printf '\n%s[5] Signature%s\n' "$BOLD" "$RESET"
# Signing input is ASCII(BASE64URL(protected) || '.' || BASE64URL(payload)).
# The protected segment goes in EXACTLY as received — never re-serialised from
# the parsed header, or a sender could reorder the header JSON and have us
# verify over different bytes than were signed.
# The ML-DSA context string is EMPTY: OpenSSL's default, and what RFC 9964 mandates.
printf '%s.%s' "$H" "$PAYLOAD_B64" > "$WORKDIR/signing_input.bin"
if openssl pkeyutl -verify -pubin -inkey "$WORKDIR/pub.pem" -rawin \
     -in "$WORKDIR/signing_input.bin" -sigfile "$WORKDIR/sig.bin" >/dev/null 2>&1; then
  ok "ML-DSA-65 signature verifies over protected.payload"
  SIGNATURE_VERIFIED=1
else
  bad "SIGNATURE DOES NOT VERIFY — the document was altered, or it was not signed by this key"
fi

# --- 6. Freshness ------------------------------------------------------------
printf '\n%s[6] Freshness%s\n' "$BOLD" "$RESET"
NOW="${NOW_OVERRIDE:-$(date -u +%s)}"
if [ -n "$POSTURE_FILE" ]; then
  # Read as JSON, by TOP-LEVEL member — never with json_str(). json_str() takes
  # the FIRST line anywhere in the file that looks like `"slug": "..."`, nested
  # objects included, and the canonical encoder ignores members it does not
  # read. Before 2026-09-29 that meant an unsigned nested member could decide
  # the slug, freshness and subject-revocation checks while the signature still
  # verified over the genuine fields. Section 7 now also refuses any member the
  # signature does not cover; tests/run.sh holds the rejection cases.
  GENERATED="$(python3 -c "$DOCX_PY" "$POSTURE_FILE" field generatedAt)"
  EXPIRES="$(python3 -c "$DOCX_PY" "$POSTURE_FILE" field expiresAt)"
  SLUG="$(python3 -c "$DOCX_PY" "$POSTURE_FILE" field slug)"

  # epoch_of() is defined globally (near b64url_encode) so --status-list mode
  # can use it too without a --jws having run.

  G=''
  if [ -n "$GENERATED" ]; then
    G="$(epoch_of "$GENERATED")"
    if [ -n "$G" ]; then
      AGE=$(( NOW - G ))
      printf '        generatedAt: %s  (age %ss)\n' "$(esc "$GENERATED")" "$AGE"
      if [ $(( G - POSTURE_CLOCK_SKEW_SECONDS )) -gt "$NOW" ]; then
        bad "not_yet_valid — generatedAt is $(( G - NOW ))s in the future, beyond the
          ${POSTURE_CLOCK_SKEW_SECONDS}s clock-skew allowance"
      elif [ "$AGE" -gt "$MAX_AGE_SECONDS" ]; then
        stale "posture is ${AGE}s old, beyond --max-age-seconds ${MAX_AGE_SECONDS}"
      else
        ok "within the ${MAX_AGE_SECONDS}s freshness window"
      fi
    else
      # A FAIL, as posture.ts rejects it (`malformed_document`): a document whose
      # age cannot be read has not had its age checked, and until 2026-09-29 this
      # was a warning that let it through with freshness unchecked.
      bad "could not parse generatedAt '$(esc "${GENERATED}")' — freshness was NOT checked.
          Do not read this as 'fresh'. Upgrade date(1) or install python3."
    fi
  else
    bad "no generatedAt — every genuine HodeiShield attestation carries one"
  fi

  # A retired key: the document must predate the retirement. The signed
  # generatedAt, the value the freshness check above uses, compared as exact
  # instants. Not a staleness failure: a fresh copy of the same document would
  # not help, so this is a plain FAIL (VERIFICATION FAILED, not EXPIRED).
  if [ -n "$RETIRED_AT" ] && [ -n "$GENERATED" ]; then
    case "$(LC_ALL=C python3 -c "$RETIRED_PY" cmp "$GENERATED" "$RETIRED_AT" 2>/dev/null)" in
      at_or_after)
        bad "retired_key — this document was generated at $(esc "$GENERATED"), at or after the retirement of key $(esc "$KID") at $(esc "$RETIRED_AT")" ;;
      before)
        ok "key $(esc "$KID") is retired (at $(esc "$RETIRED_AT")), but this document was generated at $(esc "$GENERATED"), before the retirement" ;;
      *)
        bad "date_unparseable — generatedAt '$(esc "$GENERATED")' is not an RFC 3339 time, so it cannot be
          compared with the retirement of key $(esc "$KID") at $(esc "$RETIRED_AT")" ;;
    esac
  fi

  if [ -n "$EXPIRES" ]; then
    E="$(epoch_of "$EXPIRES")"
    printf '        expiresAt:   %s\n' "$(esc "$EXPIRES")"
    if [ -z "$E" ]; then
      # NOT a pass and NOT a warning. Before 2026-08-20 this branch fell through
      # to `ok "not expired"`, so on any host whose date(1) could not parse the
      # string — BSD, macOS — an EXPIRED document reported PASS. A verifier that
      # cannot read the expiry has not checked the expiry, and the whole point
      # of this tool is that it never says otherwise.
      bad "could not parse expiresAt '$(esc "${EXPIRES}")' — the expiry was NOT checked.
          Do not read this as 'not expired'. Upgrade date(1) or install python3."
    elif [ "$NOW" -gt "$E" ]; then
      stale "EXPIRED $(( NOW - E ))s ago — re-fetch, do not accept"
      STALE_EXPIRED=1
    else
      ok "not expired"
    fi
    # The TTL CEILING. A window wider than the issuer can mint means the document
    # did not come from a conforming issuer, however well it verifies. The
    # platform's own verifier rejects this as `ttl_exceeded`; so does this one.
    if [ -n "$E" ] && [ -n "$G" ]; then
      TTL=$(( E - G ))
      if [ "$TTL" -gt "$MAX_TTL_SECONDS" ]; then
        bad "validity window is ${TTL}s (expiresAt - generatedAt), above the issuer's
          ${MAX_TTL_SECONDS}s ceiling — no conforming issuer can mint this"
      else
        ok "validity window ${TTL}s is within the issuer's ${MAX_TTL_SECONDS}s ceiling"
      fi
    fi
  else
    # NOT a warning. We always set expiresAt, so a document without one is not
    # ours, and "no expiry" must never be read as "never expires".
    bad "no expiresAt — every genuine HodeiShield attestation carries one.
          Reject this document; do not substitute a tolerance of your own."
  fi

  if [ -n "$EXPECT_SLUG" ]; then
    if [ "$SLUG" = "$EXPECT_SLUG" ]; then
      ok "posture is for slug '$(esc "${SLUG}")', as expected"
    else
      bad "posture is for slug '$(esc "${SLUG}")', not the expected '${EXPECT_SLUG}' —
          this attestation belongs to a different organisation"
    fi
  fi
else
  warn "no claims JSON: freshness cannot be checked from opaque canonical bytes"
  if [ -n "$RETIRED_AT" ]; then
    warn "key $(esc "$KID") is retired (at $(esc "$RETIRED_AT")) and there is no generatedAt to compare with it"
  fi
fi

# --- 7. Claims ---------------------------------------------------------------
# A good signature over bad content is a rejection. These are the envelope-level
# invariants the platform's own verifier enforces after the signature checks out
# (verifyPostureAttestation in app/src/lib/attest/posture.ts) — re-implemented
# here so a third party reaches the same verdict without asking us.
printf '\n%s[7] Attested claims%s\n' "$BOLD" "$RESET"
if [ -n "$CLAIMS_FILE" ]; then
  CLAIMS_DOCVERSION="$(python3 -c "$DOCX_PY" "$CLAIMS_FILE" field docVersion)"
  CLAIMS_ISS="$(python3 -c "$DOCX_PY" "$CLAIMS_FILE" field iss)"
  CLAIMS_JTI="$(python3 -c "$DOCX_PY" "$CLAIMS_FILE" field jti)"
  CLAIMS_NONCE="$(python3 -c "$DOCX_PY" "$CLAIMS_FILE" field nonce)"
  CLAIMS_NONCE_PRESENT="$(python3 -c "$DOCX_PY" "$CLAIMS_FILE" has nonce)"
  CLAIMS_BAND="$(python3 -c "$DOCX_PY" "$CLAIMS_FILE" field overallBand)"
  CLAIMS_BAND_PRESENT="$(python3 -c "$DOCX_PY" "$CLAIMS_FILE" has overallBand)"

  printf '        docVersion:  %s\n' "$(esc "${CLAIMS_DOCVERSION:-$MISSING_LABEL}")"
  printf '        iss:         %s\n' "$(esc "${CLAIMS_ISS:-$MISSING_LABEL}")"
  printf '        kid:         %s\n' "$(esc "${CLAIMS_KID:-$MISSING_LABEL}")"
  printf '        jti:         %s\n' "$(esc "${CLAIMS_JTI:-$MISSING_LABEL}")"
  if [ "$CLAIMS_NONCE_PRESENT" = '1' ]; then
    printf '        nonce:       %s\n' "$(esc "$CLAIMS_NONCE")"
  else
    printf '        nonce:       null  (no challenge — see --expect-nonce)\n'
  fi

  if [ "$CLAIMS_DOCVERSION" = 'attest.attestation.v1' ]; then
    ok "docVersion (E1) is attest.attestation.v1 — and it is inside the signature, so it cannot be rewritten on the wire"
  else
    bad "unsupported_version — docVersion is '$(esc "${CLAIMS_DOCVERSION:-$MISSING_LABEL}")'"
  fi

  # The canonical encoders read a CLOSED set of members and silently skip the
  # rest, so anything else in the JSON verifies without being signed. Such a
  # member is not harmless noise: it is exactly how a decoy `slug` or
  # `generatedAt` got in front of sections 6 and 9 (see section 6).
  if [ -n "$DUPLICATE_KEYS" ]; then
    bad "duplicate_key — the document repeats these members:
          $(printf '%s' "$DUPLICATE_KEYS" | tr '\n' ' ')
          Only one of each can be the signed value, and which one a reader sees depends on
          the reader. Reject the document."
  fi
  UNSIGNED_MEMBERS="$(python3 -c "$DOCX_PY" "$CLAIMS_FILE" unsigned)"
  if [ -z "$UNSIGNED_MEMBERS" ] && [ -z "$DUPLICATE_KEYS" ]; then
    ok "every member of the claims JSON is covered by the signature"
  elif [ -z "$UNSIGNED_MEMBERS" ]; then
    :
  else
    bad "unsigned_member — the claims JSON carries members the signature does not cover:
          $(printf '%s' "$UNSIGNED_MEMBERS" | tr '\n' ' ')
          Nobody signed them. Someone added them after signing; reject the document."
  fi

  # `iss` is who VOUCHES. It decides which key set is authoritative, so a
  # verifier that never pins it can be handed a perfectly valid document signed
  # by somebody else's HodeiShield deployment.
  if [ -n "$EXPECT_ISSUER" ]; then
    if [ "$CLAIMS_ISS" = "$EXPECT_ISSUER" ]; then
      ok "iss (E2) is '$(esc "${CLAIMS_ISS}")', as expected"
    else
      bad "issuer_mismatch — iss is '$(esc "${CLAIMS_ISS}")', not the expected '${EXPECT_ISSUER}'"
    fi
  else
    warn "no --expect-issuer: iss is '$(esc "${CLAIMS_ISS}")' and nothing pinned it. The key set you"
    warn "verified against must be the one THAT origin publishes, or this proves nothing."
  fi

  # THE NONCE. Only the party that invented the challenge can check it, and a
  # nonce nobody compares is decoration (§4.8 of the verification doc).
  if [ "$EXPECT_NONCE_SET" -eq 1 ]; then
    if [ -z "$EXPECT_NONCE" ]; then
      if [ "$CLAIMS_NONCE_PRESENT" = '0' ]; then
        ok "nonce (E5) is null, as required by --expect-nonce ''"
      else
        bad "nonce_mismatch — you required no challenge, the document carries '$(esc "${CLAIMS_NONCE}")'"
      fi
    elif [ "$CLAIMS_NONCE_PRESENT" = '1' ] && [ "$CLAIMS_NONCE" = "$EXPECT_NONCE" ]; then
      ok "nonce (E5) echoes your challenge verbatim — this document was minted for you, now"
    else
      bad "nonce_mismatch — you challenged with '${EXPECT_NONCE}', the document carries \
'$(esc "${CLAIMS_NONCE:-null}")'. A replayed or substituted document, however well it verifies."
    fi
  elif [ "$CLAIMS_NONCE_PRESENT" = '1' ]; then
    warn "the document carries a nonce but you did not pass --expect-nonce, so nothing"
    warn "compared it. Only the party that invented the challenge can check it."
  fi

  # overallBand is DERIVED — the weakest attested band — so a verifier can
  # recompute it and reject a document that overclaims while agreeing with its
  # own coverage list nowhere.
  DERIVED_BAND="$(python3 - "$CLAIMS_FILE" <<'PY'
import json, sys
STRENGTH = ["in_progress", "basic", "substantial", "advanced"]
p = json.load(open(sys.argv[1])).get("posture") or {}
ranks = [STRENGTH.index(f["band"]) for f in p.get("frameworks", []) if f.get("band") in STRENGTH]
sys.stdout.write(STRENGTH[min(ranks)] if ranks else "")
PY
)"
  if [ "$CLAIMS_BAND" = "$DERIVED_BAND" ]; then
    if [ -z "$DERIVED_BAND" ]; then
      ok "overallBand (E6) is null and nothing is attested — consistent"
    else
      ok "overallBand (E6) equals the weakest attested band — recomputed, not trusted"
    fi
  else
    bad "overall_band_mismatch — the document's overallBand is not the weakest band in its
          own coverage list"
  fi

  # The gated-redaction contract, enforced at the RELYING PARTY: a `gated`
  # posture that still carries coverage, a heartbeat or an overall band is a
  # leak, and a signature must not make a leak look authoritative.
  VISIBILITY="$(python3 -c "$DOCX_PY" "$POSTURE_FILE" field visibility)"
  if [ "$VISIBILITY" = 'gated' ]; then
    FW_COUNT="$(python3 - "$POSTURE_FILE" <<'PY'
import json, sys
sys.stdout.write(str(len(json.load(open(sys.argv[1])).get("frameworks", []))))
PY
)"
    CHECKED_PRESENT="$(python3 -c "$DOCX_PY" "$POSTURE_FILE" has lastCheckedAt)"
    if [ "$FW_COUNT" -eq 0 ] && [ "$CHECKED_PRESENT" = '0' ] && [ "$CLAIMS_BAND_PRESENT" = '0' ]; then
      ok "gated posture is redacted as it must be: no coverage, no heartbeat, no overall band"
    else
      bad "redaction_violation — a 'gated' posture is carrying coverage,
          a heartbeat or an overall band. Reject it: a signature must not make a leak authoritative."
    fi
  fi
else
  printf '        (canonical bytes only; supply --attestation or --claims to read the claims)\n'
fi

fi # [ -n "$JWS_FILE" ] — end of posture-attestation sections 1-7

# --- 8. Status list ------------------------------------------------------------
# Verifier algorithm per design-doc §6.1: signature and every document invariant
# FIRST; content is read only at the very end. ANY failure below yields UNKNOWN,
# never GOOD and never REVOKED — tracked in $STATUS_FAILURES, deliberately a
# counter separate from the posture $FAILURES above (see stat_bad()).
if [ "$STATUS_LIST_MODE" -eq 1 ]; then

printf '\n%s[8] Status list — hodei-shield.attest.statuslist.v1%s\n' "$BOLD" "$RESET"
printf '        (how to check revocation yourself: docs/security/attest-verification.md §7.1)\n'

STATUS_JWS=''; SH=''; SP=''; SS=''
STATUS_DOC_VERSION=''; STATUS_LIST_KID=''; SALG=''; STYP=''
STATUS_PUB_B64URL=''; STATUS_DERIVED_KID=''; STATUS_RETIRED_AT=''
LIST_KID=''; LIST_ISS=''
STATUS_LIST_VALID=0

fetch_or_read "$STATUS_SRC" "$WORKDIR/status.json" 'status list'
fetch_or_read "$STATUS_KEYS_SRC" "$WORKDIR/status-keys.json" 'status key set'

for dup_src in status.json status-keys.json; do
  if ! dup_found="$(python3 -c "$DUPKEY_PY" "$WORKDIR/$dup_src" 2>/dev/null)"; then
    stat_bad "malformed_document — ${dup_src} is not strict JSON (UTF-8, no BOM, one value)"
  elif [ -n "$dup_found" ]; then
    stat_bad "duplicate_key — ${dup_src} repeats members: \
$(printf '%s' "$dup_found" | tr '\n' ' ')— which value counts depends on the parser"
  fi
done

if [ "$STATUS_FAILURES" -eq 0 ] && jq -e 'type=="object" and has("statusList") and has("signature")' "$WORKDIR/status.json" >/dev/null 2>&1; then
  ok "status document has the expected {statusList, signature} shape"
  jq '.statusList' "$WORKDIR/status.json" > "$WORKDIR/list.json"
  STATUS_JWS="$(jq -r '.signature' "$WORKDIR/status.json")"
else
  stat_bad "malformed_document — expected {statusList, signature, ...}, exactly what \
GET /api/public/attest/status serves"
fi

if [ "$STATUS_FAILURES" -eq 0 ]; then
  STATUS_DOC_VERSION="$(jq -r '.docVersion // empty' "$WORKDIR/list.json")"
  if [ "$STATUS_DOC_VERSION" = 'attest.statuslist.v1' ]; then
    ok "docVersion is attest.statuslist.v1"
  else
    stat_bad "unsupported_version — statusList.docVersion is '$(esc "${STATUS_DOC_VERSION:-$MISSING_LABEL}")', \
expected 'attest.statuslist.v1'"
  fi
fi

# --- envelope: split, detached form, closed header set ---
if [ "$STATUS_FAILURES" -eq 0 ]; then
  case "$STATUS_JWS" in
    *.*.*) SH="${STATUS_JWS%%.*}"; SREST="${STATUS_JWS#*.}"; SP="${SREST%%.*}"; SS="${SREST#*.}" ;;
    *) stat_bad "malformed_document — .signature is not a 3-segment compact JWS" ;;
  esac
fi
if [ "$STATUS_FAILURES" -eq 0 ]; then
  case "$SS" in
    *.*) stat_bad "malformed_document — too many dots in .signature" ;;
  esac
fi
if [ "$STATUS_FAILURES" -eq 0 ]; then
  if [ -n "$SP" ]; then
    stat_bad "malformed_document — status-list signature must be detached (RFC 7515 Appendix F: \
empty payload segment)"
  else
    ok "detached JWS: payload segment is empty, as the status envelope requires"
  fi
fi
if [ "$STATUS_FAILURES" -eq 0 ] && ! b64url_decode "$SH" > "$WORKDIR/status_header.json" 2>/dev/null; then
  stat_bad "malformed_document — protected header is not valid base64url"
fi
if [ "$STATUS_FAILURES" -eq 0 ] && ! b64url_decode "$SS" > "$WORKDIR/status_sig.bin" 2>/dev/null; then
  stat_bad "malformed_document — signature segment is not valid base64url"
fi
if [ "$STATUS_FAILURES" -eq 0 ]; then
  SSIG_LEN="$(wc -c < "$WORKDIR/status_sig.bin" | tr -d ' ')"
  if [ "$SSIG_LEN" -eq 3309 ]; then
    ok "signature is 3309 bytes — the ML-DSA-65 size"
  else
    stat_bad "signature is ${SSIG_LEN} bytes, expected 3309 for ML-DSA-65"
  fi
fi
if [ "$STATUS_FAILURES" -eq 0 ] && ! jq -e 'type=="object"' "$WORKDIR/status_header.json" >/dev/null 2>&1; then
  stat_bad "malformed_document — protected header did not decode to a JSON object"
fi
if [ "$STATUS_FAILURES" -eq 0 ]; then
  if ! SHDR_DUPS="$(python3 -c "$DUPKEY_PY" "$WORKDIR/status_header.json" 2>/dev/null)"; then
    stat_bad "malformed_document — protected header is not strict JSON"
  elif [ -n "$SHDR_DUPS" ]; then
    stat_bad "duplicate_key — protected header repeats: $(printf '%s' "$SHDR_DUPS" | tr '\n' ' ')"
  fi
fi
if [ "$STATUS_FAILURES" -eq 0 ]; then
  if jq -e 'has("crit")' "$WORKDIR/status_header.json" >/dev/null 2>&1; then
    stat_bad "unsupported_crit — header carries 'crit' (RFC 7515 §4.1.11 requires rejection)"
  else
    ok "no 'crit' header extension"
  fi
fi
if [ "$STATUS_FAILURES" -eq 0 ]; then
  HEADER_MEMBERS="$(jq -r 'keys_unsorted | sort | join(",")' "$WORKDIR/status_header.json")"
  if [ "$HEADER_MEMBERS" = 'alg,kid,typ' ]; then
    ok "header is the closed set {alg, kid, typ} — nothing unexamined can carry meaning"
  else
    stat_bad "malformed_document — header members are '$(esc "${HEADER_MEMBERS}")', expected exactly alg,kid,typ"
  fi
fi
if [ "$STATUS_FAILURES" -eq 0 ]; then
  SALG="$(jq -r '.alg' "$WORKDIR/status_header.json")"
  STYP="$(jq -r '.typ' "$WORKDIR/status_header.json")"
  STATUS_LIST_KID="$(jq -r '.kid' "$WORKDIR/status_header.json")"
  # Never dispatch on alg — constant comparison only, exactly as jws.ts does.
  if [ "$SALG" = 'ML-DSA-65' ]; then
    ok "alg is ML-DSA-65"
  else
    stat_bad "unsupported_alg — alg is '$(esc "${SALG}")', expected 'ML-DSA-65'"
  fi
  if [ "$STYP" = 'application/attest-status+jws' ]; then
    ok "typ is application/attest-status+jws — cannot be replayed as a posture attestation"
  else
    stat_bad "unexpected_typ — typ is '$(esc "${STYP}")', expected 'application/attest-status+jws'"
  fi
fi

# --- key resolution: against --status-keys ONLY, never --jwks ---
if [ "$STATUS_FAILURES" -eq 0 ]; then
  STATUS_PUB_B64URL="$(jq -r --arg kid "$STATUS_LIST_KID" \
    '.keys[]? | select(.kid==$kid) | .pub' "$WORKDIR/status-keys.json" | head -1)"
  if [ -n "$STATUS_PUB_B64URL" ]; then
    ok "selected the --status-keys entry whose kid is '$(esc "${STATUS_LIST_KID}")'"
    # The retirement marker of this key (checked against issuedAt below). A
    # defective status key set already leaves the list UNKNOWN (not strict JSON,
    # a repeated member, an unknown kid), so a malformed marker does too.
    STATUS_RETIRED_OUT="$(LC_ALL=C python3 -c "$RETIRED_PY" key "$WORKDIR/status-keys.json" "$STATUS_LIST_KID" 2>/dev/null; printf x)"
    STATUS_RETIRED_OUT="${STATUS_RETIRED_OUT%x}"
    case "${STATUS_RETIRED_OUT%%$'\n'*}" in
      absent) ;;
      ok) STATUS_RETIRED_AT="${STATUS_RETIRED_OUT#*$'\n'}" ;;
      *) stat_bad "malformed_document — hs_retired_at of the --status-keys entry '$(esc "${STATUS_LIST_KID}")' is \
'$(esc "${STATUS_RETIRED_OUT#*$'\n'}")', not an RFC 3339 UTC time with seconds (YYYY-MM-DDTHH:MM:SSZ)" ;;
    esac
  else
    stat_bad "unknown_kid — '$(esc "${STATUS_LIST_KID}")' is not in --status-keys. Unresolvable is a \
rejection, never a fallback to another key — and never a fallback to the attestation --jwks, \
which is a disjoint set by design (status-keys.ts)."
  fi
fi
if [ "$STATUS_FAILURES" -eq 0 ] && ! b64url_decode "$STATUS_PUB_B64URL" > "$WORKDIR/status_pub.raw" 2>/dev/null; then
  stat_bad "public key is not valid base64url"
fi
if [ "$STATUS_FAILURES" -eq 0 ]; then
  SPUB_LEN="$(wc -c < "$WORKDIR/status_pub.raw" | tr -d ' ')"
  if [ "$SPUB_LEN" -eq 1952 ]; then
    ok "public key is 1952 bytes — the ML-DSA-65 size"
  else
    stat_bad "public key is ${SPUB_LEN} bytes, expected 1952"
  fi
fi
if [ "$STATUS_FAILURES" -eq 0 ]; then
  # kid = BASE64URL(SHA-256("hodei-shield.attest.kid.v1" || pub)[0..16]) — the
  # SAME domain separator as the attestation key set (keys.ts:deriveAttestKid).
  { printf 'hodei-shield.attest.kid.v1'; cat "$WORKDIR/status_pub.raw"; } > "$WORKDIR/status_kidinput.bin"
  openssl dgst -sha256 -binary -out "$WORKDIR/status_kiddigest.bin" "$WORKDIR/status_kidinput.bin"
  head -c 16 "$WORKDIR/status_kiddigest.bin" > "$WORKDIR/status_kid16.bin"
  STATUS_DERIVED_KID="$(b64url_encode "$WORKDIR/status_kid16.bin")"
  if [ "$STATUS_DERIVED_KID" = "$STATUS_LIST_KID" ]; then
    ok "kid '$(esc "${STATUS_LIST_KID}")' is derivable from these key bytes"
  else
    stat_bad "kid mismatch — status-keys entry claims '$(esc "${STATUS_LIST_KID}")', its bytes derive \
'${STATUS_DERIVED_KID}'"
  fi
fi
if [ "$STATUS_FAILURES" -eq 0 ]; then
  # 22-byte SPKI prefix for ML-DSA-65 (OID 2.16.840.1.101.3.4.3.12) — identical
  # to the one used for the attestation key above; the algorithm is the same.
  printf '308207b2300b0609608648016503040312038207a100' | hex_to_bin > "$WORKDIR/status_pub.der"
  cat "$WORKDIR/status_pub.raw" >> "$WORKDIR/status_pub.der"
  if openssl pkey -pubin -inform DER -in "$WORKDIR/status_pub.der" -out "$WORKDIR/status_pub.pem" \
       2>"$WORKDIR/status_err"; then
    ok "loaded as an ML-DSA-65 public key"
  else
    stat_bad "OpenSSL rejected the reconstructed status public key: $(esc "$(cat "$WORKDIR/status_err")")"
  fi
fi

# --- canonical bytes (the independent §6.4 encoder) + signature ---
if [ "$STATUS_FAILURES" -eq 0 ]; then
  if python3 -c "$CANON_STATUS_PY" "$WORKDIR/list.json" > "$WORKDIR/status_canon.bin" \
       2>"$WORKDIR/status_canon_err"; then
    SCANON_LEN="$(wc -c < "$WORKDIR/status_canon.bin" | tr -d ' ')"
    ok "re-derived ${SCANON_LEN} canonical bytes from statusList (independent encoder)"
  else
    stat_bad "encoding_failed — canonical encoder refused the document: $(esc "$(cat "$WORKDIR/status_canon_err")")"
  fi
fi
if [ "$STATUS_FAILURES" -eq 0 ]; then
  printf '        sha-256: %s\n' "$(openssl dgst -sha256 -hex "$WORKDIR/status_canon.bin" | awk '{print $NF}')"
  SPAYLOAD_B64="$(b64url_encode "$WORKDIR/status_canon.bin")"
  printf '%s.%s' "$SH" "$SPAYLOAD_B64" > "$WORKDIR/status_signing_input.bin"
  if openssl pkeyutl -verify -pubin -inkey "$WORKDIR/status_pub.pem" -rawin \
       -in "$WORKDIR/status_signing_input.bin" -sigfile "$WORKDIR/status_sig.bin" >/dev/null 2>&1; then
    ok "ML-DSA-65 signature verifies over protected.payload"
  else
    stat_bad "bad_signature — SIGNATURE DOES NOT VERIFY. The list was altered, or was not signed \
by this key."
  fi
fi

# --- claims.kid == header kid ---
if [ "$STATUS_FAILURES" -eq 0 ]; then
  LIST_KID="$(jq -r '.kid' "$WORKDIR/list.json")"
  if [ "$LIST_KID" = "$STATUS_LIST_KID" ]; then
    ok "claims.kid equals the JWS header kid (signed twice, deliberately)"
  else
    stat_bad "kid_mismatch — statusList.kid ('$(esc "${LIST_KID}")') != JWS header kid ('$(esc "${STATUS_LIST_KID}")')"
  fi
fi

if [ "$STATUS_FAILURES" -eq 0 ] && [ -n "$EXPECT_ISSUER" ]; then
  LIST_ISS="$(jq -r '.iss' "$WORKDIR/list.json")"
  if [ "$LIST_ISS" = "$EXPECT_ISSUER" ]; then
    ok "iss is '$(esc "${LIST_ISS}")', as expected"
  else
    stat_bad "issuer_mismatch — iss is '$(esc "${LIST_ISS}")', expected '${EXPECT_ISSUER}'"
  fi
fi

# --- freshness: issuedAt, nextUpdate, validity ceiling (design doc §7) ---
if [ "$STATUS_FAILURES" -eq 0 ]; then
  SNOW="${NOW_OVERRIDE:-$(date -u +%s)}"
  SISSUEDAT="$(jq -r '.issuedAt' "$WORKDIR/list.json")"
  SNEXTUPDATE="$(jq -r '.nextUpdate' "$WORKDIR/list.json")"
  SIAT="$(epoch_of "$SISSUEDAT")"
  SNUP="$(epoch_of "$SNEXTUPDATE")"
  printf '        issuedAt:   %s\n' "$(esc "$SISSUEDAT")"
  printf '        nextUpdate: %s\n' "$(esc "$SNEXTUPDATE")"
  if [ -z "$SIAT" ] || [ -z "$SNUP" ]; then
    stat_bad "malformed_document — could not parse issuedAt/nextUpdate as RFC 3339"
  else
    if [ $(( SIAT - STATUS_CLOCK_SKEW_SECONDS )) -gt "$SNOW" ]; then
      stat_bad "not_yet_valid — issuedAt is in the future beyond the ${STATUS_CLOCK_SKEW_SECONDS}s skew allowance"
    else
      ok "issuedAt is not in the future (beyond skew)"
    fi
    # No skew here: both instants are inside the signed bytes, so no clock is
    # involved — exactly as posture.ts checks ttl_exceeded above.
    if [ $(( SNUP - SIAT )) -gt "$MAX_STATUS_LIST_VALIDITY_SECONDS" ]; then
      stat_bad "validity_exceeded — nextUpdate - issuedAt is $(( SNUP - SIAT ))s, above the \
${MAX_STATUS_LIST_VALIDITY_SECONDS}s ceiling any conforming issuer can produce"
    else
      ok "nextUpdate - issuedAt is within the ${MAX_STATUS_LIST_VALIDITY_SECONDS}s ceiling"
    fi
    if [ $(( SNUP + STATUS_CLOCK_SKEW_SECONDS )) -lt "$SNOW" ]; then
      stat_bad "stale — nextUpdate is $(( SNOW - SNUP ))s in the past, beyond the \
${STATUS_CLOCK_SKEW_SECONDS}s skew allowance. Re-fetch — do not rely on this list."
    else
      ok "not stale (nextUpdate has not passed, allowing for skew)"
    fi
  fi
fi

# --- a list issued at or after the retirement of its own key is not trusted ---
if [ "$STATUS_FAILURES" -eq 0 ] && [ -n "$STATUS_RETIRED_AT" ]; then
  case "$(LC_ALL=C python3 -c "$RETIRED_PY" cmp "$SISSUEDAT" "$STATUS_RETIRED_AT" 2>/dev/null)" in
    at_or_after)
      stat_bad "retired_key — this status list was issued at $(esc "$SISSUEDAT"), at or after the retirement of \
key $(esc "$STATUS_LIST_KID") at $(esc "$STATUS_RETIRED_AT")" ;;
    before)
      ok "key $(esc "$STATUS_LIST_KID") is retired (at $(esc "$STATUS_RETIRED_AT")), but this list was issued at $(esc "$SISSUEDAT"), before the retirement" ;;
    *)
      stat_bad "malformed_document — issuedAt '$(esc "$SISSUEDAT")' cannot be compared with the retirement of key \
$(esc "$STATUS_LIST_KID") at $(esc "$STATUS_RETIRED_AT")" ;;
  esac
fi

if [ "$STATUS_FAILURES" -eq 0 ] && [ -n "$MIN_SEQ" ]; then
  SSEQ="$(jq -r '.seq' "$WORKDIR/list.json")"
  if [ "$SSEQ" -lt "$MIN_SEQ" ] 2>/dev/null; then
    stat_bad "rolled_back — seq $(esc "${SSEQ}") is lower than the highest previously accepted (${MIN_SEQ})"
  else
    ok "seq $(esc "${SSEQ}") >= previously accepted ${MIN_SEQ} — not a rollback"
  fi
fi

# --- Rule S: a list may not revoke its own signer ---
if [ "$STATUS_FAILURES" -eq 0 ]; then
  if jq -e --arg kid "$LIST_KID" '.keys[]? | select(.kid==$kid)' "$WORKDIR/list.json" >/dev/null 2>&1; then
    stat_bad "self_revocation — the list revokes its own signing key ('$(esc "${LIST_KID}")')"
  else
    ok "the list does not name its own signing key among the revoked keys (Rule S)"
  fi
fi

if [ "$STATUS_FAILURES" -eq 0 ]; then
  STATUS_LIST_VALID=1
  printf '        %s revoked key(s), %s revoked subject(s), truncated=%s, seq=%s, iss=%s\n' \
    "$(jq '.keys | length' "$WORKDIR/list.json")" "$(jq '.subjects | length' "$WORKDIR/list.json")" \
    "$(jq -r '.truncated' "$WORKDIR/list.json")" "$(esc "$(jq -r '.seq' "$WORKDIR/list.json")")" \
    "$(esc "$(jq -r '.iss' "$WORKDIR/list.json")")"
  printf '\n%s%sthe status list itself verifies.%s\n' "$GREEN" "$BOLD" "$RESET"
else
  printf '\n%s%sthe status list does NOT verify%s (%d check(s) failed) — its content is UNKNOWN,\n' \
    "$YELLOW" "$BOLD" "$RESET" "$STATUS_FAILURES"
  printf 'not "not revoked". Any failure here yields unknown, never good, never revoked.%s\n' "$RESET"
fi

fi # STATUS_LIST_MODE — section 8

# --- 9. Revocation check -------------------------------------------------------
# Apply an ALREADY-VERIFIED list to a kid/subject (design doc §6.2/§6.3).
if [ "$STATUS_LIST_MODE" -eq 1 ]; then

printf '\n%s[9] Revocation check%s\n' "$BOLD" "$RESET"

# §6.3's "unknown_kid upgrade": when --jws was verified, its header kid is used
# here EVEN IF the posture check above already failed on it — safe to do with an
# unverified field because the only reachable effect is a rejection (revoked, or
# the signature simply does not verify under the claimed key). It can never turn
# a bad document good.
EFFECTIVE_KID="${CHECK_KID:-${KID:-}}"
EFFECTIVE_SLUG="${CHECK_SUBJECT:-${SLUG:-}}"
EFFECTIVE_GENAT="${CHECK_GENERATED_AT:-${GENERATED:-}}"

REVOCATION_STATUS=''
REVOCATION_REASON=''
REVOCATION_VIA=''
REVOCATION_UNKNOWN_BECAUSE=''

if [ "$STATUS_LIST_VALID" -ne 1 ]; then
  REVOCATION_STATUS='unknown'; REVOCATION_UNKNOWN_BECAUSE='list_unverified'
  warn "cannot apply an unverified list — status is UNKNOWN, never 'good'"
elif [ -z "$EFFECTIVE_KID" ] && [ -z "$EFFECTIVE_SLUG" ]; then
  REVOCATION_STATUS='unknown'; REVOCATION_UNKNOWN_BECAUSE='no_subject'
  warn "nothing to check (no kid or subject given) — list contents printed above only"
else
  # Rule K — UNCONDITIONAL. revokedAt is deliberately never compared: it is a
  # field the compromised key itself could sign, so a rule over it is decoration.
  if [ -n "$EFFECTIVE_KID" ]; then
    KEY_HIT_REASON="$(jq -r --arg kid "$EFFECTIVE_KID" \
      '.keys[]? | select(.kid==$kid) | .reason' "$WORKDIR/list.json" | head -1)"
    if [ -n "$KEY_HIT_REASON" ]; then
      REVOCATION_STATUS='revoked'; REVOCATION_REASON="$KEY_HIT_REASON"; REVOCATION_VIA='key'
    fi
  fi

  # Rule B — reads the timestamp; legitimate only because this branch presumes
  # the key is NOT compromised (Rule K above would already have fired if it were).
  if [ "$REVOCATION_STATUS" != 'revoked' ] && [ -n "$EFFECTIVE_SLUG" ]; then
    { printf 'hodei-shield.attest.subject.v1'; printf '%s' "$EFFECTIVE_SLUG"; } \
      | openssl dgst -sha256 -binary > "$WORKDIR/subject_hash.bin"
    SUBJECT_HASH="$(b64url_encode "$WORKDIR/subject_hash.bin")"
    printf '        subjectHash(%s) = %s\n' "$(esc "$EFFECTIVE_SLUG")" "$SUBJECT_HASH"

    SUBJ_ENTRY="$(jq -c --arg h "$SUBJECT_HASH" \
      '.subjects[]? | select(.subjectHash==$h)' "$WORKDIR/list.json" | head -1)"
    if [ -n "$SUBJ_ENTRY" ]; then
      SUBJ_NOTBEFORE="$(printf '%s' "$SUBJ_ENTRY" | jq -r '.notBefore')"
      SUBJ_REASON="$(printf '%s' "$SUBJ_ENTRY" | jq -r '.reason')"
      if [ -z "$EFFECTIVE_GENAT" ]; then
        REVOCATION_STATUS='unknown'; REVOCATION_UNKNOWN_BECAUSE='list_unverified'
        warn "subject '$(esc "${EFFECTIVE_SLUG}")' IS listed, but no generatedAt was given \
(--check-generated-at, or --attestation/--claims) to compare against notBefore='$(esc "${SUBJ_NOTBEFORE}")' \
— cannot \
decide, so UNKNOWN, never 'good'"
      else
        SGEN="$(epoch_of "$EFFECTIVE_GENAT")"
        SNB="$(epoch_of "$SUBJ_NOTBEFORE")"
        if [ -z "$SGEN" ] || [ -z "$SNB" ]; then
          REVOCATION_STATUS='unknown'; REVOCATION_UNKNOWN_BECAUSE='list_unverified'
          warn "could not parse generatedAt/notBefore as RFC 3339 — UNKNOWN, never 'good'"
        elif [ "$SGEN" -lt "$SNB" ]; then
          REVOCATION_STATUS='revoked'; REVOCATION_REASON="$SUBJ_REASON"; REVOCATION_VIA='subject'
        fi
      fi
    else
      SLIST_TRUNCATED="$(jq -r '.truncated' "$WORKDIR/list.json")"
      if [ "$SLIST_TRUNCATED" = 'true' ]; then
        REVOCATION_STATUS='unknown'; REVOCATION_UNKNOWN_BECAUSE='truncated'
        warn "subject not found, but truncated=true: entries were dropped for the cap, so \
'not found' does not mean 'not listed' — UNKNOWN on the subject dimension, fail-safe"
      fi
    fi
  fi

  [ -n "$REVOCATION_STATUS" ] || REVOCATION_STATUS='good'
fi

case "$REVOCATION_STATUS" in
  good)
    printf '\n%s%sGOOD%s' "$GREEN" "$BOLD" "$RESET"
    [ -n "$(esc "$EFFECTIVE_KID")" ]  && printf ' — kid %s is not revoked' "$(esc "$EFFECTIVE_KID")"
    [ -n "$(esc "$EFFECTIVE_SLUG")" ] && printf ', subject %s carries no earlier withdrawal' "$(esc "$EFFECTIVE_SLUG")"
    printf ' (list seq %s).\n' "$(esc "$(jq -r '.seq' "$WORKDIR/list.json" 2>/dev/null || printf '?')")"
    ;;
  revoked)
    printf '\n%s%sREVOKED%s — via %s, reason "%s".\n' "$RED" "$BOLD" "$RESET" "$REVOCATION_VIA" "$(esc "$REVOCATION_REASON")"
    ;;
  unknown)
    printf '\n%s%sUNKNOWN%s (%s). Neither good nor revoked — do not treat this as "not revoked".\n' \
      "$YELLOW" "$BOLD" "$RESET" "$REVOCATION_UNKNOWN_BECAUSE"
    ;;
esac

fi # STATUS_LIST_MODE — section 9

# --- Attested content --------------------------------------------------------
# What the document SAYS is shown only once the whole run has established it:
# every posture check held and, in --status-list mode, the list also says GOOD.
# A document that is tampered, expired, revoked or of unknown status shows none
# of it, so nothing unproven sits on the screen beside a PASS. Section 7 above
# prints only the envelope fields the checks compare (docVersion, iss, kid, jti,
# nonce); the posture and its bands are printed here, last, or not at all.
if [ -n "$JWS_FILE" ]; then
  if [ "$FAILURES" -eq 0 ] && { [ "$STATUS_LIST_MODE" -eq 0 ] || [ "${REVOCATION_STATUS:-}" = good ]; }; then
    if [ -n "$CLAIMS_FILE" ]; then
      printf '\n%sAttested content%s (covered by the signature, and the document verified)\n' "$BOLD" "$RESET"
      # A display failure must never change the verdict.
      python3 -c "$DOCX_PY" "$CLAIMS_FILE" summary || printf '        (the summary could not be rendered)\n'
      if [ "$SHOW_RAW" -eq 1 ]; then
        printf '\n        posture (E7, the frozen v1 bytes):\n'
        if command -v jq >/dev/null 2>&1; then
          jq . < "$POSTURE_FILE" | sed 's/^/        /'
        else
          sed 's/^/        /' "$POSTURE_FILE"
        fi
      fi
    fi
  else
    printf '\n%s\n' "$CONTENT_WITHHELD"
  fi
fi

# --- Verdict -----------------------------------------------------------------
printf '\n'

# Genuine but stale: the signature verified and the only failures are age or
# expiry. Exit 1 like any failure, with a last line that cannot be confused
# with the one a tampered document gets.
stale_only() {
  [ "$SIGNATURE_VERIFIED" -eq 1 ] && [ "$FAILURES" -gt 0 ] && [ "$FAILURES" -eq "$STALE_FAILURES" ]
}
stale_verdict() {
  if [ "$STALE_EXPIRED" -eq 1 ]; then
    printf '%s%sEXPIRED%s — the signature is valid, but this attestation expired on %s.\n' \
      "$RED" "$BOLD" "$RESET" "$(esc "${EXPIRES:-}")" >&2
  else
    printf '%s%sEXPIRED%s — the signature is valid, but this attestation was generated on %s,\n' \
      "$RED" "$BOLD" "$RESET" "$(esc "${GENERATED:-}")" >&2
    printf 'more than the %ss you allow (--max-age-seconds) ago.\n' "$MAX_AGE_SECONDS" >&2
  fi
  printf 'It was not altered, but it no longer says anything about the organisation now:\n' >&2
  printf 'do not rely on it. Request a new one, or fetch a fresh copy from the link you\n' >&2
  printf 'were given and verify that instead.\n' >&2
  # The command is built from the signed iss and slug only when both have the
  # shape of an origin and a slug, so nothing odd is ever printed as a command.
  if [[ "${CLAIMS_ISS:-}" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?$ ]] \
     && [[ "${SLUG:-}" =~ ^[a-z0-9][a-z0-9-]*$ ]]; then
    printf '\n  curl -fsS %s/api/public/attest/%s -o att.json\n' "$(esc "$CLAIMS_ISS")" "$(esc "$SLUG")" >&2
  fi
  printf '\n' >&2
  exit 1
}

if [ "$STATUS_LIST_MODE" -eq 1 ]; then
  # A posture signature that does not verify is a harder failure than a
  # revocation-check outcome and takes precedence, exactly as it would for a
  # caller composing the two checks itself: an attestation that is not even
  # authentic is not rescued by its kid also being absent from a status list.
  # A revoked key or subject outranks staleness: "request a new one" would be
  # the wrong advice for a document whose signer or subject was withdrawn.
  if [ -n "$JWS_FILE" ] && stale_only && [ "$REVOCATION_STATUS" != revoked ]; then
    stale_verdict
  fi
  if [ -n "$JWS_FILE" ] && [ "$FAILURES" -ne 0 ] && ! stale_only; then
    printf '%s%sVERIFICATION FAILED%s — %d posture check(s) did not hold. Do not rely on this document.\n\n' \
      "$RED" "$BOLD" "$RESET" "$FAILURES" >&2
    exit 1
  fi
  case "$REVOCATION_STATUS" in
    good)
      printf '%s%sGOOD%s — not revoked, per a verified status list.\n\n' "$GREEN" "$BOLD" "$RESET"
      printf '%sThat is all it proves.%s It does not prove the claims inside are true, that the key\n' "$BOLD" "$RESET"
      printf 'belongs to who you think, or that nothing else about the document is wrong. Read\n'
      printf 'docs/security/attest-verification.md §6 and §7 before relying on it.\n\n'
      exit 0
      ;;
    revoked)
      printf '%s%sREVOKED%s — reason "%s". Do not rely on this document.\n\n' "$RED" "$BOLD" "$RESET" "$(esc "$REVOCATION_REASON")" >&2
      exit 1
      ;;
    *)
      printf '%s%sUNKNOWN%s (%s) — neither good nor revoked. A status list that was obtained but does\n' \
        "$YELLOW" "$BOLD" "$RESET" "${REVOCATION_UNKNOWN_BECAUSE:-unverified}" >&2
      printf 'not verify, or that cannot settle this subject, has NOT told you the subject is fine; treat\n' >&2
      printf 'this exactly as you would treat an unreachable revocation authority. docs/security/attest-verification.md\n' >&2
      printf '§7.1, "Unknown is not good", explains why this is a distinct outcome from both\n' >&2
      printf '"good" and "revoked", not a synonym for either.\n\n' >&2
      exit 3
      ;;
  esac
fi

if [ "$FAILURES" -eq 0 ]; then
  printf '%s%sVERIFIED%s — this document was signed by the holder of the key above and\n' "$GREEN" "$BOLD" "$RESET"
  printf 'has not been altered since.\n\n'
  printf '%sThat is all it proves.%s It does not prove the claims inside are true, that\n' "$BOLD" "$RESET"
  printf 'the key belongs to who you think, or that the document was meant to exist.\n'
  printf 'Read docs/security/attest-verification.md §6 before relying on it.\n\n'
  exit 0
fi
if stale_only; then
  stale_verdict
fi
printf '%s%sVERIFICATION FAILED%s — %d check(s) did not hold. Do not rely on this document.\n\n' \
  "$RED" "$BOLD" "$RESET" "$FAILURES" >&2
exit 1
