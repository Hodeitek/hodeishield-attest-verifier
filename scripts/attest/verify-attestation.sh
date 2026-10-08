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
#                         [--anchor-file STATEMENT [--anchor-bundle FILE]]
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
#   --anchor-file      a key statement (keys-statement.json, schema
#                      hodeishield.keys.statement.v1) from a release of this
#                      repository. The script runs `cosign verify-blob` on it with
#                      the bundle given by --anchor-bundle (default: the statement's
#                      name plus .sigstore.json), under an identity FIXED in this
#                      script (the release workflow of this repository at a tag
#                      vN.N.N, issued by GitHub Actions); there is no option and no
#                      environment variable to change it. The bundle must be exactly
#                      a Sigstore bundle v0.3 (anything else is exit 2), and cosign
#                      is asked a second time for the exact identity read from its
#                      certificate, which must carry this repository's numeric ID
#                      (Fulcio's Source Repository Identifier) and whose release
#                      tag must not be older than this script. It then requires the key
#                      that signed to be listed, under the right role, with a
#                      retirement that agrees with hs_retired_at. cosign is an
#                      OPTIONAL dependency, needed only here, version 3.1.3 or later.
#                      cosign may contact the Sigstore TUF repository to refresh its
#                      trust root. A statement that cannot be verified is exit 2
#                      ("anchor could not be checked"), never 1: it is not evidence
#                      against the attestation, as a wrong key document is not. A
#                      statement that verifies but does not list the key is exit 1
#                      (exit 3 for the status-list key in --status-list mode).
#                      With --pub-b64url the kid is still recomputed from the key
#                      bytes, so membership is checked; there is no key set, so there
#                      is no hs_retired_at to compare.
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
#   --check-kid          an attestation `kid` to test against the list (Rule K,
#                        unconditional — revokedAt is never compared). It must
#                        have the shape of a kid (a usage error otherwise). With
#                        a document, the document's own kid (recomputed from the
#                        key bytes, and its header kid) is ALWAYS tested too:
#                        --check-kid adds a kid, it never replaces that one.
#
#   Every option of this mode (--status, --status-keys, --check-kid,
#   --check-subject, --check-generated-at, --min-seq) without --status-list is a
#   usage error, exit 2: it would otherwise be read by nothing.
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

# The version this script is released as. --anchor-file refuses a key statement
# from an older release than this (anti-rollback); tests/version-consistency.sh
# keeps it in step with CHANGELOG.md and, on a release, with the tag.
VERIFIER_VERSION="1.4.0"

JWS_FILE=''; JWKS_FILE=''; POSTURE_FILE=''; PUB_B64URL=''
ATTESTATION_FILE=''; CLAIMS_FILE=''
EXPECT_SLUG=''; EXPECT_NONCE_SET=0; EXPECT_NONCE=''
MAX_AGE_SECONDS=3600; NOW_OVERRIDE=''
SHOW_RAW=0
# --anchor-file / --anchor-bundle (see the header). The identity and the issuer
# below are FIXED: nothing the caller passes can change who may sign the statement.
ANCHOR_FILE=''; ANCHOR_BUNDLE=''
ANCHOR_MIN_COSIGN='3.1.3'   # the version release.yml pins
ANCHOR_IDENTITY_RE='^https://github\.com/Hodeitek/hodeishield-attest-verifier/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$'
ANCHOR_OIDC_ISSUER='https://token.actions.githubusercontent.com'
# The identity above names this repository by NAME, which a deleted or renamed
# repository gives up to whoever takes the name next. Fulcio also writes the
# repository's numeric GitHub ID, which is never reused, into every certificate it
# issues to a workflow: the Source Repository Identifier extension, OID
# 1.3.6.1.4.1.57264.1.15. The certificate cosign verified must carry this one.
ANCHOR_REPOSITORY_ID='1340684886'
ANCHOR_READY=0; ANCHOR_STMT=''; ANCHOR_ISSUER=''
# --expect-kid, repeatable: the kids the attestation's signing key may have. Empty
# means no pin. Not --check-kid, which looks a kid up in a status list.
EXPECT_KIDS=()

# --- status-list mode (--status-list) ---------------------------------------
STATUS_LIST_MODE=0
STATUS_SRC=''; STATUS_KEYS_SRC=''
RETIRED_AT=''   # hs_retired_at of the selected attestation key, when it has one
CHECK_KID=''; CHECK_SUBJECT=''; CHECK_GENERATED_AT=''
MIN_SEQ=''; EXPECT_ISSUER=''
STATUS_OPT=''   # the first status-list option given, for the usage error without --status-list

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
  --jws FILE, --claims FILE  a compact JWS, and the claims object that it signs (or attached)
  --posture FILE         a full claims object (a bare posture is refused)
  --jwks FILE            the attestation key set
  --pub-b64url KEY       the raw public key, instead of --jwks
  --expect-slug SLUG     require this organisation slug
  --expect-issuer URL    require this issuer (iss)
  --expect-nonce VALUE   require this challenge ('' requires none)
  --expect-kid KID       require the signing key to have this kid; repeat for a rotation overlap
  --max-age-seconds N    reject a document older than N seconds, default 3600 (--max-age-days N: days)
  --raw                  also print the full signed posture JSON (verified documents only)
  --now EPOCH            take this Unix time as now (for testing)

Status-list mode (revocation):
  --status-list          check a signed revocation status list
  --status FILE|URL      the status list, and --status-keys FILE|URL its own key set (never --jwks)
  --check-kid KID        look this kid up in the list (not --expect-kid, which pins)
  --check-subject SLUG   look this organisation up in the list
  --check-generated-at T the document time to compare with the subject entry
  --min-seq N            reject a list older than sequence N (rollback)

Common:
  --anchor-file FILE     check the signing key against a signed key statement (needs cosign >= 3.1.3)
  --anchor-bundle FILE   the statement's Sigstore bundle (default: FILE.sigstore.json)
  --json                 print one JSON object on stdout and nothing else (the exit codes do not change)
  --version, -h, --help  print the version of this script, or this text

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

# --- --json ------------------------------------------------------------------
# With --json anywhere in the arguments (found here, before they are parsed, so
# that an argument error is reported as JSON too) the run prints ONE JSON object
# on stdout and nothing else: the human text is sent to /dev/null on both stdout
# and stderr, and the object is written to the real stdout (fd 3) when the run
# ends, whatever way it ends. The exit codes are the ones of the text mode.
# docs/security/json-output.md describes the object.
#
# Every string reaches the object through JSON encoding (python3 json.dumps with
# ensure_ascii), so a control character or an escape sequence in a document can
# never reach the terminal raw. Without python3 a smaller object is written by
# json_emit_bash (see there).
JSON_MODE=0; JSON_EMIT=1
for json_arg in "$@"; do
  if [ "$json_arg" = --json ]; then JSON_MODE=1; fi
done
unset json_arg
# State that the object reports; set where the text mode prints the same thing.
VERDICT=''          # verified, expired, failed, could_not_check, good, revoked, unknown
USAGE_ERR=0; USAGE_CODE=usage; USAGE_MSG=''   # an argument error, before any check
DIE_MSG=''          # the message of the die() that ended the run
ATTESTED_OK=0       # the "Attested content" block was shown
CLAIMS_SHOWN=0      # the envelope values of section 7 were shown
if [ "$JSON_MODE" -eq 1 ]; then exec 3>&1 >/dev/null 2>&1; fi

# An argument error: the text is the one the text mode prints, exit 2.
arg_die() {
  USAGE_ERR=1; USAGE_MSG="$1"
  printf '%s\n' "$1" >&2
  exit 2
}
# --help and --version print their usual text even with --json (and exit 0).
plain_output() {
  JSON_EMIT=0
  if [ "$JSON_MODE" -eq 1 ]; then exec 1>&3; fi
}

JSON_PY='
import json, sys
kv = {}
parts = sys.stdin.buffer.read().split(b"\0")
for i in range(0, len(parts) - 1, 2):
    kv[parts[i].decode("ascii", "replace")] = parts[i + 1].decode("utf-8", "replace")
rc = int(kv["rc"])
verdict = kv["verdict"]
usage = kv.get("usage") == "1"

# The checks, in the order they ran. A run of consecutive entries from one call
# site with one code is one check (a warning printed over several lines).
checks = []
seen = None
lines = []
if not usage and kv.get("checks_file"):
    try:
        lines = open(kv["checks_file"], encoding="utf-8", errors="replace").read().split("\n")
    except OSError:
        lines = []
for ln in lines:
    f = ln.split("|")
    if len(f) != 4 or f[3] not in ("0", "1", "2", "3"):
        continue
    if (f[0], f[1]) == seen:
        continue
    seen = (f[0], f[1])
    checks.append({"code": f[1], "result": f[2], "exit_class": int(f[3])})

def reason():
    if usage:
        return kv["usage_code"]
    if rc == 0:
        return verdict
    # The verdicts that are decided by a particular check: a withdrawal, an expiry.
    wanted = {"revoked": ("revoked_key", "revoked_subject"), "expired": ("expired",)}.get(verdict, ())
    for c in reversed(checks):
        if c["code"] in wanted and c["result"] == "fail":
            return c["code"]
    # A failure that is not about age is what decided "failed"; too_old and
    # expired decide only "expired".
    skip = ("too_old", "expired") if verdict == "failed" else ()
    for want in ("fail", None):
        for c in checks:
            if c["exit_class"] == rc and c["code"] not in skip and (want is None or c["result"] == want):
                return c["code"]
    return None

def val(name):
    v = kv.get(name)
    return v if v else None

# What the signature covers, only when the run verified the document.
attested = None
if kv.get("attested") == "1" and rc == 0:
    try:
        doc = json.load(open(kv["claims_file"], encoding="utf-8"))
        p = doc.get("posture") or {}
        attested = {
            "overallBand": doc.get("overallBand"),
            "slug": p.get("slug"),
            "visibility": p.get("visibility"),
            "generatedAt": p.get("generatedAt"),
            "lastCheckedAt": p.get("lastCheckedAt"),
            "frameworks": [{"label": f.get("label"), "code": f.get("code"), "band": f.get("band")}
                           for f in (p.get("frameworks") or []) if isinstance(f, dict)],
        }
        if kv.get("raw_posture_file"):
            attested["posture"] = json.load(open(kv["raw_posture_file"], encoding="utf-8"))
    except Exception:
        attested = None

# What the document says, read but not established unless the exit code is 0.
unverified = {}
if kv.get("claims_shown") == "1":
    unverified["docVersion"] = val("u_docVersion")
    unverified["iss"] = val("u_iss")
    unverified["kid"] = val("u_kid")
    unverified["jti"] = val("u_jti")
    unverified["nonce"] = kv.get("u_nonce") if kv.get("u_nonce_present") == "1" else None
for name in ("generatedAt", "expiresAt", "slug"):
    if "u_" + name in kv:
        unverified[name] = val("u_" + name)

anchor = None
if kv.get("anchor") == "1":
    kids = []
    for role, kidkey, listed_code, codes in (
            ("attestation", "anchor_kid_att", "anchor_kid_listed",
             ("anchor_kid_listed", "anchor_kid_absent", "anchor_role_mismatch", "anchor_retired_mismatch")),
            ("status-list", "anchor_kid_stat", "anchor_status_kid_listed",
             ("anchor_status_kid_listed", "anchor_status_kid_absent", "anchor_status_role_mismatch",
              "anchor_status_retired_mismatch"))):
        ran = [c for c in checks if c["code"] in codes]
        if ran:
            kids.append({"kid": val(kidkey), "role": role, "listed": any(c["code"] == listed_code for c in ran)})
    # Verified only when every anchor check that applies RAN and held: the
    # statement itself, then, with a document, the membership of its key and the
    # issuer; in --status-list mode, the membership of the status-list key. A run
    # that stopped before one of them (an unknown kid, a document that cannot be
    # canonicalised, a status list that failed first) is not verified.
    required = set()
    if kv.get("anchor_doc") == "1":
        required |= {"anchor_kid_listed", "anchor_issuer_matches"}
    if kv["mode"] == "status-list":
        required.add("anchor_status_kid_listed")
    passed = {c["code"] for c in checks if c["result"] == "pass"}
    anchor = {
        "verified": kv.get("anchor_ready") == "1" and "anchor_verified" in passed and required <= passed and not any(
            c["code"].startswith("anchor_") and c["result"] == "fail" for c in checks),
        "release_tag": val("anchor_tag"),
        "kids": kids,
    }

obj = {
    "schema": "hodeishield.verifier.result.v1",
    "verifier": {"version": kv["version"]},
    "mode": kv["mode"],
    "exit_code": rc,
    "verdict": verdict,
    "reason": reason(),
    "checks": checks,
    "attested": attested,
    "unverified": {} if usage else unverified,
    "anchor": None if usage else anchor,
}
if "message" in kv:
    obj["message"] = kv["message"]
sys.stdout.write(json.dumps(obj, ensure_ascii=True, sort_keys=False) + "\n")
'

# The same object without python3, which is then the very thing that is missing:
# no attested content, no unverified values, no anchor. A byte outside printable
# ASCII becomes \u00XX (so a non-ASCII message is not exact, but it is safe).
json_str() {
  local LC_ALL=C s="$1" out='' c='' i=0 n=${#1} bs=$'\\'
  for (( i = 0; i < n; i++ )); do
    c="${s:i:1}"
    case "$c" in
      '"')  out+="$bs\"" ;;
      \\)  out+="$bs$bs" ;;
      [[:print:]]) out+="$c" ;;
      *)    printf -v c '\\u%04x' "'$c"; out+="$c" ;;
    esac
  done
  printf '"%s"' "$out"
}
json_emit_bash() {
  local rc="$1" mode="$2" verdict="$3" site='' code='' result='' cls='' seen='' items='' reason='' any=''
  if [ "$USAGE_ERR" -eq 1 ]; then
    reason="$USAGE_CODE"
  elif [ "$rc" -eq 0 ]; then
    reason="$verdict"
  elif [ -n "${CHECKS_FILE:-}" ] && [ -r "$CHECKS_FILE" ]; then
    while IFS='|' read -r site code result cls; do
      [ -n "$cls" ] || continue
      if [ "$site|$code" != "$seen" ]; then
        items+="${items:+,}{\"code\":$(json_str "$code"),\"result\":$(json_str "$result"),\"exit_class\":$cls}"
      fi
      seen="$site|$code"
      if [ "$cls" = "$rc" ]; then
        if [ "$result" = fail ] && [ -z "$reason" ]; then reason="$code"; fi
        if [ -z "$any" ]; then any="$code"; fi
      fi
    done < "$CHECKS_FILE"
    if [ -z "$reason" ]; then reason="$any"; fi
  fi
  printf '{"schema":"hodeishield.verifier.result.v1","verifier":{"version":%s},"mode":%s,"exit_code":%s,"verdict":%s,' \
    "$(json_str "$VERIFIER_VERSION")" "$(json_str "$mode")" "$rc" "$(json_str "$verdict")"
  if [ -n "$reason" ]; then printf '"reason":%s,' "$(json_str "$reason")"; else printf '"reason":null,'; fi
  printf '"checks":[%s],"attested":null,"unverified":{},"anchor":null' "$items"
  if [ "$USAGE_ERR" -eq 1 ]; then printf ',"message":%s' "$(json_str "$USAGE_MSG")"
  elif [ -n "$DIE_MSG" ]; then printf ',"message":%s' "$(json_str "$DIE_MSG")"; fi
  printf '}\n'
}

# json_emit RC — write the object for a run that ends with exit status RC.
json_emit() {
  local rc="$1" mode=attestation verdict="$VERDICT"
  if [ "$STATUS_LIST_MODE" -eq 1 ]; then mode=status-list; fi
  if [ -z "$verdict" ]; then
    case "$rc" in
      0) if [ "$mode" = attestation ]; then verdict=verified; else verdict=good; fi ;;
      1) verdict=failed ;;
      3) verdict=unknown ;;
      *) verdict=could_not_check ;;
    esac
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    json_emit_bash "$rc" "$mode" "$verdict"
    return 0
  fi
  {
    printf 'version\0%s\0mode\0%s\0rc\0%s\0verdict\0%s\0' "$VERIFIER_VERSION" "$mode" "$rc" "$verdict"
    printf 'checks_file\0%s\0' "${CHECKS_FILE:-}"
    if [ "$USAGE_ERR" -eq 1 ]; then printf 'usage\0%s\0usage_code\0%s\0message\0%s\0' 1 "$USAGE_CODE" "$USAGE_MSG"
    elif [ -n "$DIE_MSG" ]; then printf 'message\0%s\0' "$DIE_MSG"; fi
    if [ "$CLAIMS_SHOWN" -eq 1 ]; then
      printf 'claims_shown\0%s\0u_docVersion\0%s\0u_iss\0%s\0u_kid\0%s\0u_jti\0%s\0' 1 \
        "${CLAIMS_DOCVERSION:-}" "${CLAIMS_ISS:-}" "${CLAIMS_KID:-}" "${CLAIMS_JTI:-}"
      printf 'u_nonce_present\0%s\0u_nonce\0%s\0' "${CLAIMS_NONCE_PRESENT:-0}" "${CLAIMS_NONCE:-}"
    fi
    if [ -n "${GENERATED+x}" ]; then printf 'u_generatedAt\0%s\0' "$GENERATED"; fi
    if [ -n "${EXPIRES+x}" ]; then printf 'u_expiresAt\0%s\0' "$EXPIRES"; fi
    if [ -n "${SLUG+x}" ]; then printf 'u_slug\0%s\0' "$SLUG"; fi
    if [ "$ATTESTED_OK" -eq 1 ]; then
      printf 'attested\0%s\0claims_file\0%s\0' 1 "$CLAIMS_FILE"
      if [ "$SHOW_RAW" -eq 1 ]; then printf 'raw_posture_file\0%s\0' "$POSTURE_FILE"; fi
    fi
    if [ -n "$ANCHOR_FILE" ]; then
      printf 'anchor\0%s\0anchor_ready\0%s\0anchor_kid_att\0%s\0anchor_kid_stat\0%s\0anchor_doc\0%s\0' 1 "$ANCHOR_READY" \
        "${DERIVED_KID:-}" "${STATUS_DERIVED_KID:-}" "${HAVE_ATTESTATION:-0}"
      if [ "${anchor_tag_ok:-0}" -eq 1 ]; then printf 'anchor_tag\0%s\0' "$anchor_tag"; fi
    fi
  } | python3 -I -c "$JSON_PY"
}

# The work directory and what happens when the run ends, however it ends.
WORKDIR=''
cleanup() { if [ -n "$WORKDIR" ]; then rm -rf -- "$WORKDIR"; fi; return 0; }
on_exit() {
  local rc=$?
  set +e
  if [ "$JSON_MODE" -eq 1 ] && [ "$JSON_EMIT" -eq 1 ]; then json_emit "$rc" >&3 2>/dev/null; fi
  cleanup
  exit "$rc"
}
trap on_exit EXIT

while [ $# -gt 0 ]; do
  # An option that takes a value, given without one, is a usage error (exit 2) in
  # every mode. One rule per kind of value:
  #  - a file, a URL, a slug, a number or a time: missing when absent, empty or
  #    the next option (starting with --), which is never taken in its place;
  #  - a kid, a key or a nonce is base64url or opaque, where - is an ordinary
  #    character and a genuine value can start with --: missing only when absent
  #    (or empty, for --check-kid and --pub-b64url). --expect-kid and
  #    --expect-nonce check their own value below.
  case "$1" in
    --jws|--jwks|--attestation|--claims|--posture|--expect-slug|--max-age-seconds|--max-age-days|--now|\
    --anchor-file|--anchor-bundle|--status|--status-keys|--check-subject|--check-generated-at|--min-seq|--expect-issuer)
      if [ $# -lt 2 ] || [ -z "$2" ] || [[ "$2" == --* ]]; then arg_die "error: $1 needs a value"; fi ;;
    --check-kid|--pub-b64url)
      if [ $# -lt 2 ] || [ -z "$2" ]; then arg_die "error: $1 needs a value"; fi ;;
  esac
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
      [ $# -ge 2 ] || arg_die "error: --expect-nonce needs a value (use '' for \"no challenge\")"
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
      [ $# -ge 2 ] || arg_die 'error: --expect-kid needs a value'
      is_kid_shape "$2" \
        || arg_die "error: --expect-kid $(esc "$2") is not a kid (22 base64url characters)"
      EXPECT_KIDS+=("$2"); shift 2 ;;
    --anchor-file)          ANCHOR_FILE="${2:?}"; shift 2 ;;
    --anchor-bundle)        ANCHOR_BUNDLE="${2:?}"; shift 2 ;;
    --status-list)         STATUS_LIST_MODE=1; shift ;;
    --status)               STATUS_SRC="${2:?}"; STATUS_OPT="${STATUS_OPT:-$1}"; shift 2 ;;
    --status-keys)          STATUS_KEYS_SRC="${2:?}"; STATUS_OPT="${STATUS_OPT:-$1}"; shift 2 ;;
    # A kid has one shape (see --expect-kid). Anything else, an option given as
    # the value among them, is a usage error: it could never be found in a list,
    # and it must not stand in for the kid of a document.
    --check-kid)
      is_kid_shape "$2" \
        || arg_die "error: --check-kid $(esc "$2") is not a kid (22 base64url characters)"
      CHECK_KID="$2"; STATUS_OPT="${STATUS_OPT:-$1}"; shift 2 ;;
    --check-subject)        CHECK_SUBJECT="${2:?}"; STATUS_OPT="${STATUS_OPT:-$1}"; shift 2 ;;
    --check-generated-at)   CHECK_GENERATED_AT="${2:?}"; STATUS_OPT="${STATUS_OPT:-$1}"; shift 2 ;;
    --min-seq)              MIN_SEQ="${2:?}"; STATUS_OPT="${STATUS_OPT:-$1}"; shift 2
      [[ "$MIN_SEQ" =~ ^[0-9]{1,18}$ ]] || arg_die 'error: --min-seq must be a non-negative integer' ;;
    --expect-issuer)        EXPECT_ISSUER="${2:?}"; shift 2 ;;
    --json)         shift ;;
    --version)      plain_output; printf 'verify-attestation.sh %s\n' "$VERIFIER_VERSION"; exit 0 ;;
    -h|--help)      plain_output; usage; exit 0 ;;
    *) arg_die "unknown argument: $1" ;;
  esac
done
# An option of the status-list mode without --status-list would be read by
# nothing, and the run would end VERIFIED as if it had been checked.
if [ -n "$STATUS_OPT" ] && [ "$STATUS_LIST_MODE" -eq 0 ]; then
  arg_die "error: $STATUS_OPT requires --status-list"
fi

CONTENT_WITHHELD='attested content withheld: this document did not verify'
RED=''; GREEN=''; YELLOW=''; BOLD=''; RESET=''
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
fi
# REASON CODES. Every check below names itself with a stable machine code, the
# first argument of ok/warn/bad/stale/stat_bad/die (docs/security/reason-codes.md
# lists them; they are only ever added, never renamed). record() keeps one entry
# per call as "site|code|result|exit-class": result is pass, warn or fail, and
# the class is the exit code that check leads to (0, 1, 2 or 3). The site is the
# function and line that made the check (internal; never printed), so two
# different checks that share a code stay two entries.
#
# Entries are appended to a file in the private work directory, not only held
# in a variable: a check recorded inside $(...) or any other subshell would
# otherwise be lost with it. Until the work directory exists they wait in
# CHECKS and are written out when it is created (see record_flush).
CHECKS=()
CHECKS_FILE=''
record() {
  local i=1 site='' entry=''
  # The site is the first frame outside the helpers that wrap record().
  while :; do
    case "${FUNCNAME[i]:-main}" in
      ok|warn|warn_unknown|die|bad|stale|stat_bad|record) i=$((i + 1)) ;;
      *) break ;;
    esac
  done
  site="${FUNCNAME[i]:-main}:${BASH_LINENO[i-1]:-0}"
  entry="$site|$1|$2|$3"
  if [ -n "$CHECKS_FILE" ]; then printf '%s\n' "$entry" >> "$CHECKS_FILE"; else CHECKS+=("$entry"); fi
}
record_flush() {
  local e=''
  for e in "${CHECKS[@]+"${CHECKS[@]}"}"; do printf '%s\n' "$e" >> "$CHECKS_FILE"; done
  CHECKS=()
}
ok()   { record "$1" pass 0; shift; printf '  %sPASS%s  %s\n' "$GREEN" "$RESET" "$*"; }
warn() { record "$1" warn 0; shift; printf '  %sWARN%s  %s\n' "$YELLOW" "$RESET" "$*"; }
# The further lines of a warning that one warn() began: printed, not recorded.
warn_more() { printf '  %sWARN%s  %s\n' "$YELLOW" "$RESET" "$*"; }
# A warning in section 9 that leaves the revocation status UNKNOWN (exit 3).
warn_unknown() { record "$1" warn 3; shift; printf '  %sWARN%s  %s\n' "$YELLOW" "$RESET" "$*"; }
# WITHHOLD_ON_DIE is set once a document is being read (after the banner below):
# a run that stops there never established the document, so it shows none of it.
WITHHOLD_ON_DIE=0
die()  {
  record "$1" fail 2; shift
  VERDICT=could_not_check; DIE_MSG="$*"
  printf '%serror:%s %s\n' "$RED" "$RESET" "$*" >&2
  [ "$WITHHOLD_ON_DIE" -eq 0 ] || printf '%s\n' "$CONTENT_WITHHELD" >&2
  exit 2
}
bad()  { record "$1" fail 1; shift; printf '  %sFAIL%s  %s\n' "$RED" "$RESET" "$*" >&2; FAILURES=$((FAILURES+1)); }
# Like bad(), but for the STATUS LIST's own verification (§6.1 of the design
# doc). Deliberately a SEPARATE counter from $FAILURES: a status-list failure
# means the list is `unknown`, which is a different outcome from a posture
# attestation's signature not verifying, and the two must not be summed into
# one number that then can't tell a caller which document was the problem.
STATUS_FAILURES=0
stat_bad() { record "$1" fail 3; shift; printf '  %sFAIL%s  %s\n' "$RED" "$RESET" "$*" >&2; STATUS_FAILURES=$((STATUS_FAILURES+1)); }

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
# Created before the first check can run, so that every check lands in CHECKS_FILE.
WORKDIR="$(mktemp -d)"; chmod 700 "$WORKDIR"
CHECKS_FILE="$WORKDIR/checks"; : > "$CHECKS_FILE"
record_flush

# Every input file is read ONCE, here, into the private work directory, and from
# then on only the copy is read: a file that changes while the checks run is
# still checked as one document, and a pipe such as <(curl ...), which can be
# read only once, works. The name given is kept for the messages, always shown
# through esc(). A file that cannot be read leaves a path that does not exist,
# so the checks below report it, under its given name, where they always did.
# (The --anchor-file statement and bundle are copied the same way in section 0b;
# a --status or --status-keys URL is fetched once in section 8.)
JWS_NAME="$JWS_FILE"; ATTESTATION_NAME="$ATTESTATION_FILE"; CLAIMS_NAME="$CLAIMS_FILE"
POSTURE_NAME="$POSTURE_FILE"; JWKS_NAME="$JWKS_FILE"
STATUS_NAME="$STATUS_SRC"; STATUS_KEYS_NAME="$STATUS_KEYS_SRC"
mkdir "$WORKDIR/in"
read_input() {   # SRC DEST — print the path to read from now on
  if [ -r "$1" ] && [ ! -d "$1" ] && { cat < "$1" > "$2"; } 2>/dev/null; then
    printf '%s' "$2"
  else
    rm -f -- "$2"; printf '%s' "$2.unreadable"
  fi
}
[ -z "$JWS_FILE" ]         || JWS_FILE="$(read_input "$JWS_FILE" "$WORKDIR/in/jws")"
[ -z "$ATTESTATION_FILE" ] || ATTESTATION_FILE="$(read_input "$ATTESTATION_FILE" "$WORKDIR/in/attestation.json")"
[ -z "$CLAIMS_FILE" ]      || CLAIMS_FILE="$(read_input "$CLAIMS_FILE" "$WORKDIR/in/claims.json")"
[ -z "$POSTURE_FILE" ]     || POSTURE_FILE="$(read_input "$POSTURE_FILE" "$WORKDIR/in/posture.json")"
[ -z "$JWKS_FILE" ]        || JWKS_FILE="$(read_input "$JWKS_FILE" "$WORKDIR/in/jwks.json")"
case "$STATUS_SRC" in
  ''|http://*|https://*) ;;
  *) STATUS_SRC="$(read_input "$STATUS_SRC" "$WORKDIR/in/status.json")" ;;
esac
case "$STATUS_KEYS_SRC" in
  ''|http://*|https://*) ;;
  *) STATUS_KEYS_SRC="$(read_input "$STATUS_KEYS_SRC" "$WORKDIR/in/status-keys.json")" ;;
esac

# Is a posture attestation being checked at all? `--attestation` carries its own
# signature, so it stands in for `--jws` everywhere below.
HAVE_ATTESTATION=0
if [ -n "$JWS_FILE" ] || [ -n "$ATTESTATION_FILE" ]; then HAVE_ATTESTATION=1; fi

if [ "$STATUS_LIST_MODE" -eq 1 ]; then
  [ -n "$STATUS_SRC" ] || die status_source_missing "--status-list requires --status <file-or-url>."
  [ -n "$STATUS_KEYS_SRC" ] || die status_keys_source_missing "--status-list requires --status-keys <file-or-url>. \
Never the attestation --jwks — the two key sets are disjoint by design."
  [ "$HAVE_ATTESTATION" -eq 1 ] || [ -n "$CHECK_KID" ] || [ -n "$CHECK_SUBJECT" ] \
    || die status_list_nothing_to_check "--status-list needs something to check: pass --attestation or --jws (check its \
kid/slug), or --check-kid, or --check-subject. Run with --help."
fi
[ "${#EXPECT_KIDS[@]}" -eq 0 ] || [ "$HAVE_ATTESTATION" -eq 1 ] \
  || die expect_kid_needs_attestation "--expect-kid pins the key that signed an attestation, so it needs --attestation (or --jws). \
To look a kid up in a status list, use --check-kid."
if [ "$HAVE_ATTESTATION" -eq 1 ] || [ "$STATUS_LIST_MODE" -eq 0 ]; then
  [ "$HAVE_ATTESTATION" -eq 1 ] || die attestation_missing "missing --attestation (or --jws). Run with --help."
  [ -z "$JWS_FILE" ] || [ -r "$JWS_FILE" ] || die jws_unreadable "cannot read $(esc "$JWS_NAME")"
  [ -z "$ATTESTATION_FILE" ] || [ -r "$ATTESTATION_FILE" ] || die attestation_unreadable "cannot read $(esc "$ATTESTATION_NAME")"
  [ -n "$JWKS_FILE" ] || [ -n "$PUB_B64URL" ] || die key_source_missing "need --jwks or --pub-b64url."
fi
[ -z "$CLAIMS_FILE" ] || [ -r "$CLAIMS_FILE" ] || die claims_unreadable "cannot read $(esc "$CLAIMS_NAME")"

# The same rule for the key: a --jwks next to a --pub-b64url would be read by
# neither the kid check nor the retirement check, and the run would report on a
# key set it never looked at.
if [ -n "$JWKS_FILE" ] && [ -n "$PUB_B64URL" ]; then
  die pub_b64url_with_jwks "--pub-b64url cannot be combined with --jwks: they are two sources for the signing key, and a \
raw key has no kid, no retirement marker and no key set to look them up in. Drop one."
fi

[ -z "$ANCHOR_BUNDLE" ] || [ -n "$ANCHOR_FILE" ] \
  || die anchor_bundle_without_file "--anchor-bundle is the bundle of the statement given with --anchor-file, so it needs --anchor-file."

# Refused rather than resolved by precedence. Two sources for the same document
# is exactly the situation where a verifier reads one and reports on the other.
if [ -n "$POSTURE_FILE" ] && { [ -n "$CLAIMS_FILE" ] || [ -n "$ATTESTATION_FILE" ]; }; then
  die posture_with_claims "--posture cannot be combined with --claims or --attestation: they are two sources for \
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
command -v openssl >/dev/null 2>&1 || die openssl_missing "openssl not found. Need OpenSSL >= 3.5 for ML-DSA."
OSSL_LINE="$(openssl version)"
# The version number alone says nothing about ML-DSA: LibreSSL (macOS, and
# Homebrew's 4.x) prints a version >= 3.5 and has no ML-DSA at all. Before this
# check it passed as "ML-DSA capable" and only failed later, as an unexplained
# "OpenSSL rejected the reconstructed public key". Still exit 2, but the reader
# was told the opposite of the truth on the way there.
case "$OSSL_LINE" in
  'OpenSSL '*) ;;
  *) die openssl_not_openssl "'openssl' here is not OpenSSL, so it is not ML-DSA capable: ${OSSL_LINE}
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
  *[!0-9]*|'') die openssl_version_unparseable "cannot parse OpenSSL version from: ${OSSL_LINE}" ;;
esac
if [ "$OSSL_MAJ" -lt 3 ] || { [ "$OSSL_MAJ" -eq 3 ] && [ "$OSSL_MIN" -lt 5 ]; }; then
  die openssl_too_old "OpenSSL ${OSSL_V} is too old — ML-DSA (FIPS 204) needs >= 3.5.
       Found: ${OSSL_LINE}
       This is a tooling limit, not evidence against the attestation."
fi
# Ask OpenSSL itself, instead of inferring it from the version: a build or a
# provider configuration (a FIPS-only provider, say) can lack ML-DSA-65 on 3.5+.
if ! openssl list -signature-algorithms 2>/dev/null | grep -qi 'ML-DSA-65'; then
  die openssl_mldsa65_missing "OpenSSL ${OSSL_V} does not offer ML-DSA-65, so it is not ML-DSA capable here.
       Found: ${OSSL_LINE}
       'openssl list -signature-algorithms' does not list ML-DSA-65 (check the
       providers it loads). This is a tooling limit, not evidence against the attestation."
fi
ok openssl_mldsa65_available "OpenSSL ${OSSL_V} offers ML-DSA-65"

if [ -n "$ATTESTATION_FILE" ] || [ -n "$CLAIMS_FILE" ] || [ -n "$POSTURE_FILE" ] || [ -n "$ANCHOR_FILE" ]; then
  command -v python3 >/dev/null 2>&1 \
    || die python3_missing "python3 is needed to read the claims JSON and re-derive the canonical envelope bytes."
fi

if [ "$STATUS_LIST_MODE" -eq 1 ]; then
  command -v python3 >/dev/null 2>&1 || die python3_missing "python3 is needed for the status-list canonical encoder."
  command -v jq >/dev/null 2>&1 || die jq_missing "jq is needed for --status-list — the document nests arrays \
(keys[], subjects[]) that plain sed cannot safely extract."
  ok tools_present "python3 and jq present"
  case "$STATUS_SRC$STATUS_KEYS_SRC" in
    *http://*|*https://*) command -v curl >/dev/null 2>&1 || die curl_missing "curl is needed to fetch --status/--status-keys URLs." ;;
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
    python3 -I -c 'import sys,binascii;sys.stdout.buffer.write(binascii.unhexlify(sys.stdin.read().strip()))'
  else
    die spki_tool_missing "need either xxd or python3 to build the SPKI header (22 constant bytes of the algorithm)."
  fi
}

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
    out="$(printf '%s' "$1" | python3 -I -c '
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
  local src="$1" out="$2" role="${3:-document}" name="${4:-$1}"
  case "$src" in
    https://*)
      curl -fsS --max-time 15 --max-filesize 5000000 -o "$out" "$src" || die fetch_failed "failed to fetch ${src}"
      ;;
    http://localhost|http://localhost/*|http://localhost:*|\
    http://127.0.0.1|http://127.0.0.1/*|http://127.0.0.1:*|\
    "http://[::1]"|"http://[::1]/"*|"http://[::1]:"*)
      warn fetch_cleartext_loopback "fetching the ${role} over cleartext HTTP from loopback: ${src}"
      curl -fsS --max-time 15 --max-filesize 5000000 -o "$out" "$src" || die fetch_failed "failed to fetch ${src}"
      ;;
    http://*)
      if [ "$role" = 'status key set' ]; then
        die status_keys_cleartext_refused "refusing to fetch the STATUS KEY SET over cleartext HTTP: ${src}

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
      warn fetch_cleartext_http "fetching the ${role} over cleartext HTTP: ${src}"
      warn_more "the list is signed, so tampering shows up as a failed signature (=> unknown),"
      warn_more "but use https:// — a downgrade you did not notice is not a threat model."
      curl -fsS --max-time 15 --max-filesize 5000000 -o "$out" "$src" || die fetch_failed "failed to fetch ${src}"
      ;;
    *)
      [ -r "$src" ] || die file_unreadable "cannot read $(esc "$name")"
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

# Key selection and retirement of a signing key (the JWK member
# `hs_retired_at`). One reader for both key sets, so which entry is selected,
# the grammar, the instant arithmetic and the verdicts exist once.
#
#   argv[1] = "key"  argv[2] = key file  argv[3] = kid  argv[4] = file for `pub`
#       line 1: invalid (`keys` is not an array of objects) | duplicate (two
#       entries carry the same kid, so which one counts would depend on the
#       order) | none (no entry with that kid and a string `pub`) | absent |
#       ok | malformed (the selected entry has no marker / a valid marker / a
#       bad one); then the member's value. A string is written raw (the caller
#       escapes it before it is shown); any other JSON value as JSON text. The
#       selected entry's `pub` is written to argv[4].
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
    status, val, pub = "none", b"", b""
    doc = json.load(open(sys.argv[2], "rb"))
    keys = doc.get("keys") if isinstance(doc, dict) else None
    if not isinstance(keys, list) or not all(isinstance(k, dict) for k in keys):
        status = "invalid"
    else:
        kids = [k.get("kid") for k in keys if isinstance(k.get("kid"), str)]
        if len(kids) != len(set(kids)):
            status = "duplicate"
        else:
            for k in keys:
                if k.get("kid") == sys.argv[3] and isinstance(k.get("pub"), str):
                    pub = k["pub"].encode("utf-8", "surrogatepass")
                    status = "absent"
                    if "hs_retired_at" in k:
                        v = k["hs_retired_at"]
                        status = "ok" if strict(v) else "malformed"
                        val = (v if isinstance(v, str) else json.dumps(v)).encode("utf-8", "surrogatepass")
                    break
    open(sys.argv[4], "wb").write(pub)
    out.write(status.encode() + b"\n" + val)
elif sys.argv[1] == "cmp":
    a, b = instant(sys.argv[2]), instant(sys.argv[3])
    out.write(b"unparseable" if a is None or b is None else b"at_or_after" if a >= b else b"before")
else:
    # The key statement (--anchor-file). The file has already been read strictly
    # (UTF-8, one value, no duplicate member) by the caller.
    #   argv[1] = "statement"  argv[2] = file
    #       line 1: ok | bad; then the issuer (ok) or a fixed reason (bad)
    #   argv[1] = "lookup"     argv[2] = file  argv[3] = kid
    #       line 1: absent | found; then the role and the retired_at ("" if none)
    KID = re.compile(r"[A-Za-z0-9_-]{21}[AQgw]", re.ASCII)
    DAY = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", re.ASCII)
    def day(v):
        try: datetime.date(int(v[0:4]), int(v[5:7]), int(v[8:10]))
        except ValueError: return False
        return True
    def why(d):
        if not isinstance(d, dict) or set(d) != {"schema", "issuer", "keys"}:
            return "its members are not exactly schema, issuer and keys"
        if d["schema"] != "hodeishield.keys.statement.v1": return "its schema is not hodeishield.keys.statement.v1"
        if not isinstance(d["issuer"], str) or not d["issuer"]: return "its issuer is not a string"
        ks = d["keys"]
        if not isinstance(ks, list) or not ks: return "its keys are not a non-empty array"
        seen = set()
        for k in ks:
            if not isinstance(k, dict): return "a key entry is not an object"
            if not {"kid", "role", "status", "published_at"} <= set(k) <= {"kid", "role", "status", "published_at", "active_since", "retired_at"}:
                return "a key entry lacks a documented member or has one that is not documented"
            if not (isinstance(k["kid"], str) and KID.fullmatch(k["kid"])): return "a kid is not the shape of a kid"
            if k["kid"] in seen: return "a kid is listed twice"
            seen.add(k["kid"])
            if not (isinstance(k["role"], str) and k["role"] in ("attestation", "status-list")): return "a role is neither attestation nor status-list"
            if not (isinstance(k["status"], str) and k["status"] in ("active", "retired")): return "a status is neither active nor retired"
            if not isinstance(k["published_at"], str): return "a published_at is not a string"
            if "active_since" in k:
                v = k["active_since"]
                if not (isinstance(v, str) and DAY.fullmatch(v) and day(v)): return "an active_since is not a date, YYYY-MM-DD"
            if (k["status"] == "retired") != ("retired_at" in k): return "retired_at is not present exactly for the retired keys"
            if "retired_at" in k and not strict(k["retired_at"]): return "a retired_at is not an RFC 3339 UTC time with seconds (YYYY-MM-DDTHH:MM:SSZ)"
        return None
    doc = json.load(open(sys.argv[2], "rb"))
    if sys.argv[1] == "statement":
        r = why(doc)
        out.write(b"bad\n" + r.encode() if r else b"ok\n" + doc["issuer"].encode("utf-8", "surrogatepass"))
    else:
        hit = [k for k in doc["keys"] if k["kid"] == sys.argv[3]]
        out.write(b"absent" if not hit else ("found\n%s\n%s" % (hit[0]["role"], hit[0].get("retired_at", ""))).encode())
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

# --- 0b. The anchor (--anchor-file) -------------------------------------------
# A signed key statement from a release of this repository, checked with cosign
# before any document is read. See the header and docs/security/key-anchor.md.
# Every way the statement cannot be verified ends here, with exit 2: a statement
# that does not verify is not evidence that the attestation is forged, in the
# same way a wrong key document is not. Membership of the key (a failed check,
# exit 1 or 3) is decided later, once the key has been selected and its kid
# recomputed from the key bytes.

# Whether the cosign version $1 (GitVersion, e.g. v3.1.3) is at least
# $ANCHOR_MIN_COSIGN. Numeric, in the C locale; a pre-release of the minimum
# itself does not count.
anchor_cosign_new_enough() {
  local LC_ALL=C v="${1#v}" i=0 have=() want=() pre=''
  local re='^([0-9]{1,6})\.([0-9]{1,6})\.([0-9]{1,6})(-[0-9A-Za-z.+-]*)?$'
  [[ "$v" =~ $re ]] || return 1
  have=("${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}")
  pre="${BASH_REMATCH[4]}"
  IFS=. read -r -a want <<< "$ANCHOR_MIN_COSIGN"
  for i in 0 1 2; do
    if [ $(( 10#${have[i]} )) -gt "${want[i]}" ]; then return 0; fi
    if [ $(( 10#${have[i]} )) -lt "${want[i]}" ]; then return 1; fi
  done
  [ -z "$pre" ]
}

# Whether the certificate (DER) $1 carries the Source Repository Identifier
# extension exactly once, as a top-level extension of the certificate, with a
# value that is exactly the DER UTF8String of ANCHOR_REPOSITORY_ID (as Fulcio
# encodes it). Read with `openssl asn1parse`, which prints the extension's OID and
# then its value as a hex dump; nothing else is accepted, not another string
# type, not a critical flag in between, not a longer or shorter number.
anchor_repository_id_ok() {
  local LC_ALL=C id_hex='' h='' i=0 line='' after=0 lines=()
  local oid_re=':d=5 +hl=[0-9]+ +l= *[0-9]+ +prim: +OBJECT +:1\.3\.6\.1\.4\.1\.57264\.1\.15$'
  local val_re=':d=5 +hl=[0-9]+ +l= *[0-9]+ +prim: +OCTET STRING +\[HEX DUMP\]:([0-9A-F]+)$'
  printf -v id_hex '0C%02X' "${#ANCHOR_REPOSITORY_ID}"
  for (( i = 0; i < ${#ANCHOR_REPOSITORY_ID}; i++ )); do
    printf -v h '%02X' "'${ANCHOR_REPOSITORY_ID:i:1}"; id_hex+="$h"
  done
  # Each occurrence of the OID, and the line that follows it.
  while IFS= read -r line; do
    if [ "$after" -eq 1 ]; then lines+=("$line"); after=0; fi
    if [[ "$line" =~ $oid_re ]]; then lines+=(OID); after=1; fi
  done < <(openssl asn1parse -inform DER -in "$1" 2>/dev/null || true)
  [ "${#lines[@]}" -eq 2 ] && [ "${lines[0]}" = OID ] && [[ "${lines[1]}" =~ $val_re ]] \
    && [ "${BASH_REMATCH[1]}" = "$id_hex" ]
}

# cosign's own diagnostics, for the reader: directories taken off every path
# (a name only, never a temporary or an absolute path), every line through esc(),
# indented. URLs are left alone: the pattern needs a path to start after a space,
# a quote or a bracket.
anchor_diagnostics() {
  local line='' n=0
  while IFS= read -r line && [ "$n" -lt 12 ]; do
    line="$(printf '%s' "$line" | LC_ALL=C sed -E 's#(^|[ "(])(\.{0,2}/)?[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*/([A-Za-z0-9._-]+)#\1\4#g')"
    printf '         cosign: %s\n' "$(esc "${line:0:400}")"
    n=$((n + 1))
  done < "$1"
}

# The bundle, read by this script (it has already been read strictly: UTF-8, no
# BOM, one value, no duplicate member).
#
#   argv[1] = "shape"  argv[2] = bundle
#       ok | bad, then a fixed reason. The bundle must be EXACTLY a Sigstore
#       bundle v0.3 with a message signature and one leaf certificate. cosign
#       falls back to its LEGACY bundle format (base64Signature, cert,
#       rekorBundle) when a bundle does not load as a v0.3 one, and then it
#       verifies the certificate in "cert", not the one this script reads. So no
#       member is accepted that a v0.3 bundle does not have, at the levels read
#       here; the names a protobuf JSON parser would also accept
#       (verification_material, raw_bytes, ...) are refused with the rest.
#   argv[1] = "cert"   argv[2] = bundle  argv[3] = out
#       writes the leaf certificate (DER) to argv[3].
ANCHOR_BUNDLE_PY='
import base64, binascii, json, sys
b = json.load(open(sys.argv[2], "rb"))
def why(b):
    if not isinstance(b, dict) or set(b) != {"mediaType", "verificationMaterial", "messageSignature"}:
        return "its members are not exactly mediaType, verificationMaterial and messageSignature"
    if b["mediaType"] != "application/vnd.dev.sigstore.bundle.v0.3+json":
        return "its mediaType is not application/vnd.dev.sigstore.bundle.v0.3+json"
    m = b["verificationMaterial"]
    if not isinstance(m, dict) or not {"certificate", "tlogEntries"} <= set(m) <= {"certificate", "tlogEntries", "timestampVerificationData"}:
        return "its verificationMaterial is not one certificate, tlogEntries and (optionally) timestampVerificationData"
    c = m["certificate"]
    if not isinstance(c, dict) or set(c) != {"rawBytes"} or not isinstance(c["rawBytes"], str) or not c["rawBytes"]:
        return "its certificate is not exactly one rawBytes"
    try:
        base64.b64decode(c["rawBytes"], validate=True)
    except (binascii.Error, ValueError):
        return "its certificate is not base64"
    t = m["tlogEntries"]
    if not isinstance(t, list) or not t or not all(isinstance(e, dict) for e in t):
        return "its tlogEntries are not a non-empty array of objects"
    s = b["messageSignature"]
    if not isinstance(s, dict) or not {"signature"} <= set(s) <= {"messageDigest", "signature"} or not isinstance(s["signature"], str):
        return "its messageSignature is not a signature and (optionally) a messageDigest"
    return None
if sys.argv[1] == "shape":
    r = why(b)
    sys.stdout.write("bad\n" + r if r else "ok\n")
else:
    if why(b): raise SystemExit("bundle: not a v0.3 bundle")
    open(sys.argv[3], "wb").write(base64.b64decode(b["verificationMaterial"]["certificate"]["rawBytes"], validate=True))
'

if [ -n "$ANCHOR_FILE" ]; then
  [ -n "$ANCHOR_BUNDLE" ] || ANCHOR_BUNDLE="${ANCHOR_FILE}.sigstore.json"
  anchor_sn="$(basename -- "$ANCHOR_FILE")"; anchor_bn="$(basename -- "$ANCHOR_BUNDLE")"
  printf '        anchor: %s, bundle %s\n' "$(esc "$anchor_sn")" "$(esc "$anchor_bn")"
  anchor_v=''
  if command -v cosign >/dev/null 2>&1; then
    anchor_v="$(cosign version 2>/dev/null | awk '$1 == "GitVersion:" { print $2; exit }' || true)"
  fi
  if ! anchor_cosign_new_enough "$anchor_v"; then
    if [ -z "$anchor_v" ]; then anchor_found='no usable cosign was found'
    else anchor_found="this one reports '$(esc "${anchor_v:0:40}")'"; fi
    die anchor_cosign_unavailable "anchor could not be checked: --anchor-file needs cosign ${ANCHOR_MIN_COSIGN} or later, and ${anchor_found}.
       cosign is needed for this option only. This is a tooling limit, not evidence against the attestation."
  fi
  if [ ! -r "$ANCHOR_FILE" ] || [ ! -f "$ANCHOR_FILE" ]; then
    die anchor_unverified "anchor could not be checked: the statement $(esc "$anchor_sn") cannot be read.
       This is not evidence against the attestation."
  fi
  if [ ! -r "$ANCHOR_BUNDLE" ] || [ ! -f "$ANCHOR_BUNDLE" ]; then
    die anchor_unverified "anchor could not be checked: the bundle $(esc "$anchor_bn") cannot be read (pass it with --anchor-bundle).
       This is not evidence against the attestation."
  fi
  # cosign checks, and this script reads, one private copy of the statement: the
  # file cannot change between the two. Names that are not plain are replaced.
  case "$anchor_sn" in
    ''|.|..|*[!A-Za-z0-9._-]*) anchor_fs='statement.json' ;;
    *) anchor_fs="$anchor_sn" ;;
  esac
  case "$anchor_bn" in
    ''|.|..|*[!A-Za-z0-9._-]*) anchor_fb='bundle.json' ;;
    *) anchor_fb="$anchor_bn" ;;
  esac
  mkdir -p "$WORKDIR/anchor/s" "$WORKDIR/anchor/b"
  cp -- "$ANCHOR_FILE" "$WORKDIR/anchor/s/$anchor_fs"
  cp -- "$ANCHOR_BUNDLE" "$WORKDIR/anchor/b/$anchor_fb"
  ANCHOR_STMT="$WORKDIR/anchor/s/$anchor_fs"
  # The bundle must be exactly a Sigstore v0.3 bundle (see ANCHOR_BUNDLE_PY),
  # read strictly, BEFORE cosign sees it: a bundle cosign reads in its legacy
  # format carries a certificate other than the one this script reads the tag from.
  anchor_bundle_bad=''
  if ! anchor_bdups="$(python3 -I -c "$DUPKEY_PY" "$WORKDIR/anchor/b/$anchor_fb" 2>/dev/null)"; then
    anchor_bundle_bad='it is not strict JSON (UTF-8, no BOM, one value)'
  elif [ -n "$anchor_bdups" ]; then
    anchor_bundle_bad="it repeats members ($(printf '%s' "$anchor_bdups" | tr '\n' ' '))"
  else
    anchor_bshape="$(python3 -I -c "$ANCHOR_BUNDLE_PY" shape "$WORKDIR/anchor/b/$anchor_fb" 2>/dev/null || printf 'bad\nit could not be read')"
    if [ "${anchor_bshape%%$'\n'*}" != ok ]; then anchor_bundle_bad="${anchor_bshape#*$'\n'}"; fi
  fi
  if [ -n "$anchor_bundle_bad" ]; then
    die anchor_bundle_unsupported "anchor could not be checked: the bundle is not a Sigstore v0.3 bundle.
       The bundle $(esc "$anchor_bn"): $(esc "$anchor_bundle_bad").
       Use the .sigstore.json file published with the release. This is not evidence against the attestation."
  fi
  # cosign may contact the Sigstore TUF repository here to refresh its trust root.
  anchor_rc=0
  ( cd "$WORKDIR/anchor" && cosign verify-blob --bundle "b/$anchor_fb" \
      --certificate-identity-regexp "$ANCHOR_IDENTITY_RE" \
      --certificate-oidc-issuer "$ANCHOR_OIDC_ISSUER" "s/$anchor_fs" ) \
    > "$WORKDIR/anchor/cosign.out" 2>&1 < /dev/null || anchor_rc=$?
  if [ "$anchor_rc" -ne 0 ]; then
    # cosign says exit 1 for all of these; the cause is read from what it printed.
    # It changes the explanation only: every one of them is exit 2.
    anchor_why='cosign could not verify the statement'
    if grep -qiE 'no matching CertificateIdentity|none of the expected identities|failed to verify certificate identity|expected (SAN|issuer) value' "$WORKDIR/anchor/cosign.out"; then
      anchor_why='the signing identity does not match the release workflow of this repository'
    elif grep -qiE 'failed to verify signature|invalid signature|error verifying bundle|cert verification failed|failed to verify (leaf )?certificate|failed to verify log inclusion|does not match digest|digest does not match|could not verify (message|envelope)' "$WORKDIR/anchor/cosign.out"; then
      anchor_why='the signature is invalid, or the statement was altered after it was signed'
    elif grep -qiE 'trusted root|TUF|dial tcp|no such host|i/o timeout|connection refused|deadline exceeded|network is unreachable|TLS handshake' "$WORKDIR/anchor/cosign.out"; then
      anchor_why='the Sigstore trust root could not be obtained (cosign may contact the Sigstore TUF repository: check the network)'
    elif grep -qiE 'unexpected end of JSON|invalid character|proto:|validation error|unsupported media type|invalid bundle|missing (verification material|bundle content)|empty protobuf|no such file|reading |unmarshal' "$WORKDIR/anchor/cosign.out"; then
      anchor_why='the bundle is unreadable or malformed'
    fi
    die anchor_unverified "anchor could not be checked: ${anchor_why}.
       This is not evidence that the attestation is forged. The run ends without a verdict on it: re-fetch the statement and
       its bundle from the release you trust, or drop --anchor-file.
$(anchor_diagnostics "$WORKDIR/anchor/cosign.out")"
  fi
  # ANTI-ROLLBACK. The release tag comes from the certificate cosign has just
  # verified (its single SAN, the workflow identity), read from the same private
  # copy of the bundle. Any older, genuinely signed statement would otherwise be
  # accepted, so a statement from a release older than this script is refused,
  # BEFORE its content is read. An unreadable or unusual tag is refused too.
  anchor_id=''; anchor_tag=''
  python3 -I -c "$ANCHOR_BUNDLE_PY" cert "$WORKDIR/anchor/b/$anchor_fb" "$WORKDIR/anchor/cert.der" 2>/dev/null \
    || : > "$WORKDIR/anchor/cert.der"
  anchor_san="$(openssl x509 -inform DER -in "$WORKDIR/anchor/cert.der" -noout -ext subjectAltName 2>/dev/null || true)"
  mapfile -t anchor_san_lines <<< "$anchor_san"
  anchor_prefix='https://github.com/Hodeitek/hodeishield-attest-verifier/.github/workflows/release.yml@refs/tags/'
  anchor_tag_re='^v(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$'
  # anchor_tag_ok is set only once the tag is bound to what cosign verified (below).
  anchor_tag_ok=0; anchor_tag_shape=0
  if [ "${#anchor_san_lines[@]}" -eq 2 ] && [[ "${anchor_san_lines[1]}" =~ ^[[:space:]]*URI:([^[:space:],]+)$ ]]; then
    anchor_id="${BASH_REMATCH[1]}"
    anchor_tag="${anchor_id#"$anchor_prefix"}"
    if [ "$anchor_tag" != "$anchor_id" ] && [[ "$anchor_tag" =~ $anchor_tag_re ]]; then anchor_tag_shape=1; fi
  fi
  if [ "$anchor_tag_shape" -ne 1 ]; then
    die anchor_tag_unreadable "anchor could not be checked: the statement's release tag cannot be read.
       The signing identity of the bundle is not this repository's release workflow at a tag vN.N.N (no pre-release, no
       build metadata, no leading zeros). This is not evidence against the attestation."
  fi
  # The certificate read above must be the one cosign verified: cosign is asked a
  # second time, now for that EXACT identity (not a pattern). A bundle whose
  # certificate cosign did not verify cannot pass, so the tag is bound to it.
  anchor_rc=0
  ( cd "$WORKDIR/anchor" && cosign verify-blob --bundle "b/$anchor_fb" \
      --certificate-identity "$anchor_id" \
      --certificate-oidc-issuer "$ANCHOR_OIDC_ISSUER" "s/$anchor_fs" ) \
    > "$WORKDIR/anchor/cosign-identity.out" 2>&1 < /dev/null || anchor_rc=$?
  if [ "$anchor_rc" -ne 0 ]; then
    die anchor_unverified "anchor could not be checked: cosign did not verify the certificate the release tag is read from.
       The identity read from the bundle, $(esc "$anchor_id"), is not the one cosign verified.
       This is not evidence that the attestation is forged. The run ends without a verdict on it: re-fetch the statement and
       its bundle from the release you trust, or drop --anchor-file.
$(anchor_diagnostics "$WORKDIR/anchor/cosign-identity.out")"
  fi
  # The same verified certificate must be from THIS repository, by its numeric ID.
  if ! anchor_repository_id_ok "$WORKDIR/anchor/cert.der"; then
    die anchor_unverified "anchor could not be checked: the certificate is not from this repository.
       Its Source Repository Identifier (OID 1.3.6.1.4.1.57264.1.15) is not ${ANCHOR_REPOSITORY_ID}, the numeric GitHub ID
       of Hodeitek/hodeishield-attest-verifier. A repository that took over the name would have another ID.
       This is not evidence against the attestation."
  fi
  anchor_tag_ok=1
  IFS=. read -r -a anchor_tv <<< "${anchor_tag#v}"
  IFS=. read -r -a anchor_vv <<< "$VERIFIER_VERSION"
  for i in 0 1 2; do
    if [ $(( 10#${anchor_tv[i]} )) -lt $(( 10#${anchor_vv[i]} )) ]; then
      die anchor_statement_older "anchor could not be checked: statement from ${anchor_tag}, older than this verifier v${VERIFIER_VERSION}.
       A statement from an older release may not list the current key, and accepting it would let an old, genuinely
       signed statement stand in for the current one. Download the statement from the latest release.
       This is not evidence against the attestation."
    fi
    if [ $(( 10#${anchor_tv[i]} )) -gt $(( 10#${anchor_vv[i]} )) ]; then break; fi
  done
  # The statement, strictly: UTF-8, no BOM, one value, no duplicate member; then
  # the schema, the documented members only, the grammar of retired_at.
  anchor_dups="$(python3 -I -c "$DUPKEY_PY" "$ANCHOR_STMT" 2>/dev/null)" \
    || die anchor_malformed "anchor could not be checked: the statement $(esc "$anchor_sn") is not strict JSON (UTF-8, no BOM, one value)."
  [ -z "$anchor_dups" ] \
    || die anchor_malformed "anchor could not be checked: the statement $(esc "$anchor_sn") repeats members ($(esc "$(printf '%s' "$anchor_dups" | tr '\n' ' ')"))."
  anchor_st="$(LC_ALL=C python3 -I -c "$RETIRED_PY" statement "$ANCHOR_STMT" 2>/dev/null || printf 'bad\nit could not be read\n')"
  if [ "${anchor_st%%$'\n'*}" != ok ]; then
    die anchor_malformed "anchor could not be checked: the statement $(esc "$anchor_sn") is malformed: $(esc "${anchor_st#*$'\n'}")."
  fi
  ANCHOR_ISSUER="${anchor_st#*$'\n'}"
  ANCHOR_READY=1
  ok anchor_verified "the key statement $(esc "$anchor_sn") is signed by $(esc "$anchor_id") (issuer ${ANCHOR_OIDC_ISSUER})"
fi

# --- Document resolution -----------------------------------------------------
# Normalise whatever the caller passed into (a) a file holding the compact JWS,
# (b) a file holding the CLAIMS object — the signed document — and (c) a file
# holding just the nested posture, which sections 6 and 7 read.
if [ -n "$ATTESTATION_FILE" ]; then
  python3 -I -c "$DOCX_PY" "$ATTESTATION_FILE" split "$WORKDIR/claims.json" > "$WORKDIR/att.jws" \
    || die attestation_unparseable "could not read $(esc "$ATTESTATION_NAME") as an attestation document.
       Expected what GET /api/public/attest/<slug> serves:
       {\"attestation\": {\"claims\": {...}, \"signature\": \"...\"}}"
  if [ -z "$CLAIMS_FILE" ]; then
    CLAIMS_FILE="$WORKDIR/claims.json"; CLAIMS_NAME="the claims in $ATTESTATION_NAME"
  fi
  if [ -z "$JWS_FILE" ]; then
    [ -s "$WORKDIR/att.jws" ] || die attestation_signature_missing "$(esc "$ATTESTATION_NAME") carries no \"signature\" member. \
Pass the signature with --jws if you hold it separately."
    JWS_FILE="$WORKDIR/att.jws"; JWS_NAME="the signature in $ATTESTATION_NAME"
  fi
fi

# `--posture` used to be THE verification input, back when this script wrongly
# believed the bare posture was what got signed. It is not. A full claims object
# passed here still works (people will do it, and it is unambiguous); a bare
# posture is REFUSED — with a usage error, never a FAIL, because "you gave me
# one field of the document" is not evidence against the document.
if [ -n "$POSTURE_FILE" ] && [ -z "$CLAIMS_FILE" ]; then
  case "$(python3 -I -c "$DOCX_PY" "$POSTURE_FILE" shape 2>/dev/null || printf 'unknown')" in
    claims)
      CLAIMS_FILE="$POSTURE_FILE"; CLAIMS_NAME="$POSTURE_NAME"
      ;;
    posture)
      die posture_bare_refused "--posture was given a bare posture object, and the signature does not cover those bytes.

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
      die posture_unrecognised "could not tell what $(esc "$POSTURE_NAME") is. Pass --attestation or --claims."
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
      || die python3_missing "python3 is needed to decode the attached payload into the claims it signs."
    if b64url_decode "$ATT_PAYLOAD" > "$WORKDIR/attached-payload.bin" 2>/dev/null \
       && python3 -I -c "$DECODE_PY" "$WORKDIR/attached-payload.bin" > "$WORKDIR/claims.json" \
            2>"$WORKDIR/decode_err"; then
      CLAIMS_FILE="$WORKDIR/claims.json"; CLAIMS_NAME="the claims decoded from $JWS_NAME"
    else
      ATTACHED_UNDECODABLE="$(cat "$WORKDIR/decode_err" 2>/dev/null || true)"
      : "${ATTACHED_UNDECODABLE:=payload segment is not valid base64url}"
    fi
  fi
fi

# Duplicate members in the document as the caller handed it over — the raw
# file, before any re-serialisation hides them. Section 7 FAILS on them.
DUPLICATE_KEYS=''
for dup_which in attestation claims; do
  if [ "$dup_which" = attestation ]; then dup_src="$ATTESTATION_FILE"; dup_name="$ATTESTATION_NAME"
  else dup_src="$CLAIMS_FILE"; dup_name="$CLAIMS_NAME"; fi
  [ -n "$dup_src" ] || continue
  dup_found="$(python3 -I -c "$DUPKEY_PY" "$dup_src" 2>/dev/null)" \
    || dup_found="(the file could not be parsed strictly: $(esc "$dup_name"))"
  [ -z "$dup_found" ] || DUPLICATE_KEYS="${DUPLICATE_KEYS:+$DUPLICATE_KEYS
}$dup_found"
done

# One posture view for sections 6 and 7, always sliced out of the claims we are
# about to verify — never a second file the caller supplied, which could differ
# from the one inside the signature.
POSTURE_FILE=''
if [ -n "$CLAIMS_FILE" ]; then
  python3 -I -c "$DOCX_PY" "$CLAIMS_FILE" posture "$WORKDIR/posture.json" \
    || die claims_posture_missing "claims JSON has no usable \`posture\` object: $(esc "$CLAIMS_NAME")"
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
  *) die jws_not_compact "not a compact JWS (expected two dots): $(esc "$JWS_NAME")" ;;
esac
H="${JWS%%.*}"; REST="${JWS#*.}"; P="${REST%%.*}"; S="${REST#*.}"
case "$S" in
  *.*) die jws_too_many_dots "too many dots — is this a JSON-serialised JWS?" ;;
esac

if [ -z "$P" ]; then
  FORM='detached'
  ok jws_detached "detached JWS (RFC 7515 Appendix F): payload segment is empty"
  [ -n "$CLAIMS_FILE" ] || die jws_detached_needs_claims "a detached JWS carries no payload, so the bytes it signed must be \
re-derived from the claims JSON.
       Pass --attestation <the endpoint response>, or --claims <the claims object>."
else
  FORM='attached'
  ok jws_attached "attached JWS: payload segment carries the canonical envelope bytes"
fi

b64url_decode "$H" > "$WORKDIR/header.json" || die header_not_base64url "header is not valid base64url"
b64url_decode "$S" > "$WORKDIR/sig.bin"     || die signature_not_base64url "signature is not valid base64url"
SIG_LEN="$(wc -c < "$WORKDIR/sig.bin" | tr -d ' ')"
if [ "$SIG_LEN" -eq 3309 ]; then
  ok signature_size_valid "signature is 3309 bytes — the ML-DSA-65 size"
else
  bad signature_size_invalid "signature is ${SIG_LEN} bytes, expected 3309 for ML-DSA-65"
fi

# --- 2. Header ---------------------------------------------------------------
printf '\n%s[2] Header%s\n' "$BOLD" "$RESET"
header_field() { sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$1" | head -1; }
ALG="$(header_field "$WORKDIR/header.json" alg)"
KID="$(header_field "$WORKDIR/header.json" kid)"
TYP="$(header_field "$WORKDIR/header.json" typ)"
printf '        %s\n' "$(esc "$(cat "$WORKDIR/header.json")")"

# Never dispatch on `alg` — compare it as a constant. The verification primitive
# below is ML-DSA-65 unconditionally, so `alg: none` is a non-event.
if [ "$ALG" = 'ML-DSA-65' ]; then
  ok header_alg_valid "alg is ML-DSA-65 (RFC 9964, IANA-permanent)"
else
  bad header_alg_invalid "alg is '$(esc "${ALG}")', expected 'ML-DSA-65'. Refusing to verify under a substituted algorithm."
fi
if [ "$TYP" = 'application/attest+jws' ]; then
  ok header_typ_valid "typ is application/attest+jws — cannot be replayed into another JWS surface"
else
  bad header_typ_invalid "typ is '$(esc "${TYP}")', expected 'application/attest+jws'"
fi
if grep -q '"crit"' "$WORKDIR/header.json"; then
  bad header_not_allowed "header carries 'crit' — RFC 7515 §4.1.11 requires rejection of extensions we do not implement"
else
  ok header_crit_absent "no 'crit' header extension"
fi
# The same closed set the platform verifier (jws.ts ALLOWED_HEADER_MEMBERS) and
# section 8 below enforce: a member nothing examines must not be able to carry
# meaning. Not a JSON object at all counts as a mismatch too.
command -v python3 >/dev/null 2>&1 || die python3_missing "python3 is needed to check the protected header's member set."
HEADER_MEMBERS="$(python3 -I -c '
import json, sys
pairs = []
h = json.load(open(sys.argv[1]), object_pairs_hook=lambda p: (pairs.append([k for k, _ in p]), dict(p))[1])
dups = sorted({k for ks in pairs for k in ks if ks.count(k) > 1})
if dups: print("duplicated: " + ",".join(dups))
else: print(",".join(sorted(h)) if isinstance(h, dict) else "(not a JSON object)")
' "$WORKDIR/header.json" 2>/dev/null || printf '(not JSON)')"
if [ "$HEADER_MEMBERS" = 'alg,kid,typ' ]; then
  ok header_members_valid "header is the closed set {alg, kid, typ}"
else
  bad header_not_allowed "malformed_document — header members are '$(esc "${HEADER_MEMBERS}")', expected exactly alg,kid,typ"
fi

# --- 3. Public key -----------------------------------------------------------
printf '\n%s[3] Public key%s\n' "$BOLD" "$RESET"
if [ -z "$PUB_B64URL" ]; then
  [ -r "$JWKS_FILE" ] || die jwks_unreadable "cannot read $(esc "$JWKS_NAME")"
  # A key document with a duplicated member is malformed: which `pub` or `kid`
  # counts would depend on the parser. Not evidence against the attestation,
  # so exit 2, like the unknown-kid stop below.
  JWKS_DUPS="$(python3 -I -c "$DUPKEY_PY" "$JWKS_FILE" 2>/dev/null)" \
    || die not_strict_json "the key document $(esc "$JWKS_NAME") is not strict JSON (UTF-8, no BOM, one value).
       Re-fetch it; do not edit it by hand."
  [ -z "$JWKS_DUPS" ] || die jwks_duplicate_key "the key document $(esc "$JWKS_NAME") repeats members ($(printf '%s' "$JWKS_DUPS" | tr '\n' ' ')).
       Which key it names depends on the parser. Re-fetch it; do not edit it by hand."
  # Selected as JSON: the entry of `keys` whose `kid` is the header kid, and its
  # `pub` — never the first line of text that looks like one. The same reader
  # gives the retirement marker of that entry. `|| true` is load-bearing under
  # `set -euo pipefail`: a reader that fails must not abort the script (a
  # silent exit 1, indistinguishable from a failed signature).
  RETIRED_OUT="$(LC_ALL=C python3 -I -c "$RETIRED_PY" key "$JWKS_FILE" "$KID" "$WORKDIR/jwks-pub.txt" 2>/dev/null || printf 'invalid\n'; printf x)"
  RETIRED_OUT="${RETIRED_OUT%x}"
  case "${RETIRED_OUT%%$'\n'*}" in
    invalid) die jwks_keys_not_array "the key document $(esc "$JWKS_NAME") is invalid: \`keys\` is not an array of objects.
       Re-fetch it; do not edit it by hand." ;;
    duplicate) die jwks_duplicate_kid "the key document $(esc "$JWKS_NAME") is invalid: two of its keys carry the same kid, so
       which one counts would depend on the order. Re-fetch it; do not edit it by hand." ;;
  esac
  PUB_B64URL="$(cat "$WORKDIR/jwks-pub.txt" 2>/dev/null || true)"
  if [ -z "$PUB_B64URL" ]; then
    # A HARD stop, never a fallback to keys[0] — the same rule the status-list
    # path applies to an unknown kid, and for the same reason. Guessing a key
    # can only turn "I am holding the wrong key document" into a signature
    # failure that reads like a forged document. Those are different findings
    # and a verifier must not conflate them.
    die unknown_kid "no key in this JWKS carries kid '$(esc "${KID}")'.
       This is NOT evidence that the document is forged — it means you are
       holding the wrong or a stale key document. Re-fetch the JWKS and retry.
       By policy, a retired key stays published and is marked with hs_retired_at."
  else
    ok jwks_key_selected "selected the JWKS key whose kid is '$(esc "${KID}")'"
    # A marker that is not exactly an RFC 3339 UTC second is an invalid key
    # set, not evidence about the document: exit 2. Checked against generatedAt
    # in section 6.
    case "${RETIRED_OUT%%$'\n'*}" in
      absent) ;;
      ok) RETIRED_AT="${RETIRED_OUT#*$'\n'}" ;;
      *) die jwks_retired_at_malformed "the key document $(esc "$JWKS_NAME") is invalid: hs_retired_at of the key '$(esc "${KID}")' is
       '$(esc "${RETIRED_OUT#*$'\n'}")', not an RFC 3339 UTC time with seconds (YYYY-MM-DDTHH:MM:SSZ).
       Re-fetch the key document; do not edit it by hand." ;;
    esac
  fi
fi

b64url_decode "$PUB_B64URL" > "$WORKDIR/pub.raw" || die public_key_not_base64url "public key is not valid base64url"
PUB_LEN="$(wc -c < "$WORKDIR/pub.raw" | tr -d ' ')"
if [ "$PUB_LEN" -eq 1952 ]; then
  ok public_key_size_valid "public key is 1952 bytes — the ML-DSA-65 size"
else
  bad public_key_size_invalid "public key is ${PUB_LEN} bytes, expected 1952"
fi

# The kid is CHECKED, not trusted: it must be derivable from the key bytes, so a
# JWK cannot claim to be a key it is not.
#   kid = BASE64URL( SHA-256( UTF8("hodei-shield.attest.kid.v1") || pub )[0..16] )
{ printf 'hodei-shield.attest.kid.v1'; cat "$WORKDIR/pub.raw"; } > "$WORKDIR/kidinput.bin"
openssl dgst -sha256 -binary -out "$WORKDIR/kiddigest.bin" "$WORKDIR/kidinput.bin"
head -c 16 "$WORKDIR/kiddigest.bin" > "$WORKDIR/kid16.bin"
DERIVED_KID="$(b64url_encode "$WORKDIR/kid16.bin")"
if [ "$DERIVED_KID" = "$KID" ]; then
  ok kid_derivable "kid '$(esc "${KID}")' is derivable from these key bytes"
else
  bad kid_mismatch "kid mismatch — header says '$(esc "${KID}")', the key bytes derive '${DERIVED_KID}'.
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
    ok kid_pinned "the key bytes derive kid '${DERIVED_KID}', one of the kids you pinned with --expect-kid"
  else
    bad unexpected_kid "unexpected_kid — the key bytes derive kid '${DERIVED_KID}', which is not one of the kids you
          pinned with --expect-kid: ${EXPECT_KIDS[*]}"
  fi
fi

# --anchor-file: is this key one the signed statement lists? Asked of the kid
# RECOMPUTED from the key bytes above, never of a label, so a mislabelled key
# cannot be admitted by naming itself after a listed kid. (With --pub-b64url
# there is no JWK, but the kid is still recomputed, so this still works; there is
# no key set either, so there is no hs_retired_at to compare.) Each failure is a
# failed check, exit 1: the statement verified, and it does not list this key.
if [ "$ANCHOR_READY" -eq 1 ]; then
  ANCHOR_OK=1
  ANCHOR_ENTRY="$(LC_ALL=C python3 -I -c "$RETIRED_PY" lookup "$ANCHOR_STMT" "$DERIVED_KID" 2>/dev/null || printf 'absent')"
  mapfile -t ANCHOR_E <<< "$ANCHOR_ENTRY"
  if [ "${ANCHOR_E[0]:-absent}" != found ]; then
    ANCHOR_OK=0
    bad anchor_kid_absent "anchor_kid_absent — the key bytes derive kid '${DERIVED_KID}', which the signed key statement does not list"
  else
    if [ "${ANCHOR_E[1]:-}" != attestation ]; then
      ANCHOR_OK=0
      bad anchor_role_mismatch "anchor_role_mismatch — the signed key statement lists kid '${DERIVED_KID}' as '$(esc "${ANCHOR_E[1]:-}")', not as an attestation key"
    fi
    # The statement's retirement and the key set's must be the same instant (both
    # have the strict grammar, so equal instants are equal strings), or both absent.
    if [ -n "$JWKS_FILE" ] && [ "${ANCHOR_E[2]:-}" != "$RETIRED_AT" ]; then
      ANCHOR_OK=0
      bad anchor_retired_mismatch "anchor_retired_mismatch — the signed key statement retires kid '${DERIVED_KID}' at '$(esc "${ANCHOR_E[2]:-}")' (empty: not retired), the key set says hs_retired_at '$(esc "$RETIRED_AT")' (empty: none)"
    fi
    # A retirement the statement carries applies even when the key set carries
    # none (or a later one): the earlier instant is used by the retired_key check
    # in section 6.
    if [ -n "${ANCHOR_E[2]:-}" ]; then
      if [ -z "$RETIRED_AT" ] || [ "$(LC_ALL=C python3 -I -c "$RETIRED_PY" cmp "${ANCHOR_E[2]}" "$RETIRED_AT" 2>/dev/null)" = before ]; then
        RETIRED_AT="${ANCHOR_E[2]}"
      fi
    fi
  fi
  if [ "$ANCHOR_OK" -eq 1 ]; then
    ok anchor_kid_listed "the signed key statement lists kid '${DERIVED_KID}' as an attestation key"
  fi
fi

# OpenSSL loads SubjectPublicKeyInfo; the JWK carries the bare FIPS 204 key.
# 22-byte SPKI prefix for ML-DSA-65 (OID 2.16.840.1.101.3.4.3.12):
printf '308207b2300b0609608648016503040312038207a100' | hex_to_bin > "$WORKDIR/pub.der"
cat "$WORKDIR/pub.raw" >> "$WORKDIR/pub.der"
openssl pkey -pubin -inform DER -in "$WORKDIR/pub.der" -out "$WORKDIR/pub.pem" 2>"$WORKDIR/err" \
  || die public_key_rejected "OpenSSL rejected the reconstructed public key: $(esc "$(cat "$WORKDIR/err")")"
ok public_key_loaded "loaded as an ML-DSA-65 public key"

# --- 4. Payload — the signing envelope ---------------------------------------
# The payload is `hodei-shield.attest.attestation.v1` (E1..E7), NOT the bare
# posture. The posture is E7, nested verbatim. Re-deriving only the posture is
# how this script used to report genuine documents as forged.
printf '\n%s[4] Payload — attestation envelope (E1..E7)%s\n' "$BOLD" "$RESET"
CLAIMS_KID=''
if [ -n "$CLAIMS_FILE" ]; then
  [ -r "$CLAIMS_FILE" ] || die claims_unreadable "cannot read $(esc "$CLAIMS_NAME")"
  command -v python3 >/dev/null 2>&1 || die python3_missing "python3 is needed to re-derive canonical bytes from the claims JSON."
  python3 -I -c "$CANON_PY" "$CLAIMS_FILE" envelope > "$WORKDIR/canon.bin" \
    || die canonicalise_failed "could not canonicalise $(esc "$CLAIMS_NAME")"
  python3 -I -c "$CANON_PY" "$CLAIMS_FILE" posture > "$WORKDIR/canon-posture.bin" \
    || die canonicalise_posture_failed "could not canonicalise the nested posture of $(esc "$CLAIMS_NAME")"
  CANON_LEN="$(wc -c < "$WORKDIR/canon.bin" | tr -d ' ')"
  NESTED_LEN="$(wc -c < "$WORKDIR/canon-posture.bin" | tr -d ' ')"
  ok canonical_rederived "re-derived ${CANON_LEN} canonical envelope bytes from the claims JSON you can read"
  printf '        of which E7 nests %s bytes of hodei-shield.attest.posture.v1 (the posture itself)\n' "$NESTED_LEN"
  printf '        sha-256: %s\n' "$(openssl dgst -sha256 -hex "$WORKDIR/canon.bin" | awk '{print $NF}')"
  printf '        (compare with attestation.digest as the endpoint published it — a content id,\n'
  printf '         never an authentication check: the signature below is the check)\n'
  PAYLOAD_B64="$(b64url_encode "$WORKDIR/canon.bin")"
  if [ "$FORM" = 'attached' ]; then
    if [ "$PAYLOAD_B64" = "$P" ]; then
      ok payload_matches_claims "the embedded payload equals the bytes re-derived from your claims JSON"
    else
      bad payload_claims_mismatch "the embedded payload does NOT match the claims JSON you supplied —
          the JSON you can read is not the document that was signed"
    fi
  fi

  # The body names a key; the header names a key. They must be the same key, or
  # the document is lying about which key vouches for it. (This is the platform
  # verifier's `kid_mismatch`, and it only became checkable here once the whole
  # envelope was in view — E3 is inside the signature, the header kid is inside
  # the signing input, and both must agree.)
  CLAIMS_KID="$(python3 -I -c "$DOCX_PY" "$CLAIMS_FILE" field kid)"
  # --anchor-file: the statement names the issuer origin; the signed iss must be it.
  if [ "$ANCHOR_READY" -eq 1 ]; then
    # Never skipped: an empty iss is not the issuer the statement names (which is
    # never empty), so it fails here too, besides iss_empty in section 7.
    ANCHOR_CLAIMS_ISS="$(python3 -I -c "$DOCX_PY" "$CLAIMS_FILE" field iss)"
    if [ "$ANCHOR_CLAIMS_ISS" = "$ANCHOR_ISSUER" ]; then
      ok anchor_issuer_matches "iss (E2) is the issuer '$(esc "$ANCHOR_CLAIMS_ISS")' the signed key statement names"
    else
      bad anchor_issuer_mismatch "anchor_issuer_mismatch — iss is '$(esc "$ANCHOR_CLAIMS_ISS")', the signed key statement names the issuer '$(esc "$ANCHOR_ISSUER")'"
    fi
  fi
  if [ "$CLAIMS_KID" = "$KID" ]; then
    ok claims_kid_matches "claims.kid (E3) equals the protected-header kid — one key, named twice, agreeing"
  else
    bad kid_mismatch "kid_mismatch — the header says '$(esc "${KID}")', the signed body says '$(esc "${CLAIMS_KID}")'.
          A document cannot name one key in its body and be signed by another."
  fi
elif [ -n "$ATTACHED_UNDECODABLE" ]; then
  bad payload_not_envelope "malformed_document — the attached payload is not a hodei-shield.attest.attestation.v1
          envelope ($(esc "${ATTACHED_UNDECODABLE}")). There are no claims to check, so nothing here verifies."
  PAYLOAD_B64="$P"
else
  ok payload_embedded "using the payload embedded in the attached JWS"
  b64url_decode "$P" > "$WORKDIR/canon.bin" || die payload_not_base64url "payload segment is not valid base64url"
  PAYLOAD_B64="$P"
  warn opaque_bytes "no --attestation/--claims given: you are verifying opaque bytes. Supply the"
  warn_more "claims JSON so the facts you read are provably the facts that were signed."
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
  ok signature_valid "ML-DSA-65 signature verifies over protected.payload"
  SIGNATURE_VERIFIED=1
else
  bad signature_invalid "SIGNATURE DOES NOT VERIFY — the document was altered, or it was not signed by this key"
fi

# --- 6. Freshness ------------------------------------------------------------
printf '\n%s[6] Freshness%s\n' "$BOLD" "$RESET"
NOW="${NOW_OVERRIDE:-$(date -u +%s)}"
if [ -n "$POSTURE_FILE" ]; then
  # Read as JSON, by TOP-LEVEL member — never with header_field(). header_field() takes
  # the FIRST line anywhere in the file that looks like `"slug": "..."`, nested
  # objects included, and the canonical encoder ignores members it does not
  # read. Before 2026-09-29 that meant an unsigned nested member could decide
  # the slug, freshness and subject-revocation checks while the signature still
  # verified over the genuine fields. Section 7 now also refuses any member the
  # signature does not cover; tests/run.sh holds the rejection cases.
  GENERATED="$(python3 -I -c "$DOCX_PY" "$POSTURE_FILE" field generatedAt)"
  EXPIRES="$(python3 -I -c "$DOCX_PY" "$POSTURE_FILE" field expiresAt)"
  SLUG="$(python3 -I -c "$DOCX_PY" "$POSTURE_FILE" field slug)"

  # epoch_of() is defined globally (near b64url_encode) so --status-list mode
  # can use it too without a --jws having run.

  G=''
  if [ -n "$GENERATED" ]; then
    G="$(epoch_of "$GENERATED")"
    if [ -n "$G" ]; then
      AGE=$(( NOW - G ))
      printf '        generatedAt: %s  (age %ss)\n' "$(esc "$GENERATED")" "$AGE"
      if [ $(( G - POSTURE_CLOCK_SKEW_SECONDS )) -gt "$NOW" ]; then
        bad not_yet_valid "not_yet_valid — generatedAt is $(( G - NOW ))s in the future, beyond the
          ${POSTURE_CLOCK_SKEW_SECONDS}s clock-skew allowance"
      elif [ "$AGE" -gt "$MAX_AGE_SECONDS" ]; then
        stale too_old "posture is ${AGE}s old, beyond --max-age-seconds ${MAX_AGE_SECONDS}"
      else
        ok fresh "within the ${MAX_AGE_SECONDS}s freshness window"
      fi
    else
      # A FAIL, as posture.ts rejects it (`malformed_document`): a document whose
      # age cannot be read has not had its age checked, and until 2026-09-29 this
      # was a warning that let it through with freshness unchecked.
      bad date_unparseable "could not parse generatedAt '$(esc "${GENERATED}")' — freshness was NOT checked.
          Do not read this as 'fresh'. Upgrade date(1) or install python3."
    fi
  else
    bad generated_at_missing "no generatedAt — every genuine HodeiShield attestation carries one"
  fi

  # A retired key: the document must predate the retirement. The signed
  # generatedAt, the value the freshness check above uses, compared as exact
  # instants. Not a staleness failure: a fresh copy of the same document would
  # not help, so this is a plain FAIL (VERIFICATION FAILED, not EXPIRED).
  if [ -n "$RETIRED_AT" ] && [ -n "$GENERATED" ]; then
    case "$(LC_ALL=C python3 -I -c "$RETIRED_PY" cmp "$GENERATED" "$RETIRED_AT" 2>/dev/null)" in
      at_or_after)
        bad retired_key "retired_key — this document was generated at $(esc "$GENERATED"), at or after the retirement of key $(esc "$KID") at $(esc "$RETIRED_AT")" ;;
      before)
        ok retired_key_document_predates "key $(esc "$KID") is retired (at $(esc "$RETIRED_AT")), but this document was generated at $(esc "$GENERATED"), before the retirement" ;;
      *)
        bad date_unparseable "date_unparseable — generatedAt '$(esc "$GENERATED")' is not an RFC 3339 time, so it cannot be
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
      bad date_unparseable "could not parse expiresAt '$(esc "${EXPIRES}")' — the expiry was NOT checked.
          Do not read this as 'not expired'. Upgrade date(1) or install python3."
    elif [ "$NOW" -gt "$E" ]; then
      stale expired "EXPIRED $(( NOW - E ))s ago — re-fetch, do not accept"
      STALE_EXPIRED=1
    else
      ok not_expired "not expired"
    fi
    # The TTL CEILING. A window wider than the issuer can mint means the document
    # did not come from a conforming issuer, however well it verifies. The
    # platform's own verifier rejects this as `ttl_exceeded`; so does this one.
    if [ -n "$E" ] && [ -n "$G" ]; then
      TTL=$(( E - G ))
      if [ "$TTL" -gt "$MAX_TTL_SECONDS" ]; then
        bad ttl_exceeded "validity window is ${TTL}s (expiresAt - generatedAt), above the issuer's
          ${MAX_TTL_SECONDS}s ceiling — no conforming issuer can mint this"
      else
        ok ttl_within_ceiling "validity window ${TTL}s is within the issuer's ${MAX_TTL_SECONDS}s ceiling"
      fi
    fi
  else
    # NOT a warning. We always set expiresAt, so a document without one is not
    # ours, and "no expiry" must never be read as "never expires".
    bad missing_expiry "no expiresAt — every genuine HodeiShield attestation carries one.
          Reject this document; do not substitute a tolerance of your own."
  fi

  if [ -n "$EXPECT_SLUG" ]; then
    if [ "$SLUG" = "$EXPECT_SLUG" ]; then
      ok slug_match "posture is for slug '$(esc "${SLUG}")', as expected"
    else
      bad slug_mismatch "posture is for slug '$(esc "${SLUG}")', not the expected '${EXPECT_SLUG}' —
          this attestation belongs to a different organisation"
    fi
  fi
else
  warn freshness_unchecked "no claims JSON: freshness cannot be checked from opaque canonical bytes"
  if [ -n "$RETIRED_AT" ]; then
    # Fail closed: retirement is only satisfied by showing the document predates it.
    bad retired_key "retired_key — key $(esc "$KID") is retired (at $(esc "$RETIRED_AT")) and without the claims JSON there is no generatedAt to show this document predates the retirement; supply the claims JSON"
  fi
fi

# --- 7. Claims ---------------------------------------------------------------
# A good signature over bad content is a rejection. These are the envelope-level
# invariants the platform's own verifier enforces after the signature checks out
# (verifyPostureAttestation in app/src/lib/attest/posture.ts) — re-implemented
# here so a third party reaches the same verdict without asking us.
printf '\n%s[7] Attested claims%s\n' "$BOLD" "$RESET"
if [ -n "$CLAIMS_FILE" ]; then
  CLAIMS_DOCVERSION="$(python3 -I -c "$DOCX_PY" "$CLAIMS_FILE" field docVersion)"
  CLAIMS_ISS="$(python3 -I -c "$DOCX_PY" "$CLAIMS_FILE" field iss)"
  CLAIMS_JTI="$(python3 -I -c "$DOCX_PY" "$CLAIMS_FILE" field jti)"
  CLAIMS_NONCE="$(python3 -I -c "$DOCX_PY" "$CLAIMS_FILE" field nonce)"
  CLAIMS_NONCE_PRESENT="$(python3 -I -c "$DOCX_PY" "$CLAIMS_FILE" has nonce)"
  CLAIMS_BAND="$(python3 -I -c "$DOCX_PY" "$CLAIMS_FILE" field overallBand)"
  CLAIMS_BAND_PRESENT="$(python3 -I -c "$DOCX_PY" "$CLAIMS_FILE" has overallBand)"

  printf '        docVersion:  %s\n' "$(esc "${CLAIMS_DOCVERSION:-$MISSING_LABEL}")"
  printf '        iss:         %s\n' "$(esc "${CLAIMS_ISS:-$MISSING_LABEL}")"
  printf '        kid:         %s\n' "$(esc "${CLAIMS_KID:-$MISSING_LABEL}")"
  printf '        jti:         %s\n' "$(esc "${CLAIMS_JTI:-$MISSING_LABEL}")"
  if [ "$CLAIMS_NONCE_PRESENT" = '1' ]; then
    printf '        nonce:       %s\n' "$(esc "$CLAIMS_NONCE")"
  else
    printf '        nonce:       null  (no challenge — see --expect-nonce)\n'
  fi
  CLAIMS_SHOWN=1

  if [ "$CLAIMS_DOCVERSION" = 'attest.attestation.v1' ]; then
    ok doc_version_valid "docVersion (E1) is attest.attestation.v1 — and it is inside the signature, so it cannot be rewritten on the wire"
  else
    bad unsupported_version "unsupported_version — docVersion is '$(esc "${CLAIMS_DOCVERSION:-$MISSING_LABEL}")'"
  fi

  # The canonical encoders read a CLOSED set of members and silently skip the
  # rest, so anything else in the JSON verifies without being signed. Such a
  # member is not harmless noise: it is exactly how a decoy `slug` or
  # `generatedAt` got in front of sections 6 and 9 (see section 6).
  if [ -n "$DUPLICATE_KEYS" ]; then
    bad duplicate_key "duplicate_key — the document repeats these members:
          $(printf '%s' "$DUPLICATE_KEYS" | tr '\n' ' ')
          Only one of each can be the signed value, and which one a reader sees depends on
          the reader. Reject the document."
  fi
  UNSIGNED_MEMBERS="$(python3 -I -c "$DOCX_PY" "$CLAIMS_FILE" unsigned)"
  if [ -z "$UNSIGNED_MEMBERS" ] && [ -z "$DUPLICATE_KEYS" ]; then
    ok members_signed "every member of the claims JSON is covered by the signature"
  elif [ -z "$UNSIGNED_MEMBERS" ]; then
    :
  else
    bad unsigned_member "unsigned_member — the claims JSON carries members the signature does not cover:
          $(printf '%s' "$UNSIGNED_MEMBERS" | tr '\n' ' ')
          Nobody signed them. Someone added them after signing; reject the document."
  fi

  # `iss` is who VOUCHES. It decides which key set is authoritative, so a
  # verifier that never pins it can be handed a perfectly valid document signed
  # by somebody else's HodeiShield deployment. An EMPTY iss names nobody: it is a
  # failed check, whether or not --expect-issuer is given. (An absent or null iss
  # never gets here: the canonical encoder refuses it in section 4.)
  if [ -z "$CLAIMS_ISS" ]; then
    bad iss_empty "iss_empty — iss (E2) is empty: the document names no issuer, so nothing says whose key set
          should verify it. Every genuine HodeiShield attestation names its issuer origin."
  fi
  if [ -n "$EXPECT_ISSUER" ]; then
    if [ "$CLAIMS_ISS" = "$EXPECT_ISSUER" ]; then
      ok issuer_match "iss (E2) is '$(esc "${CLAIMS_ISS}")', as expected"
    else
      bad issuer_mismatch "issuer_mismatch — iss is '$(esc "${CLAIMS_ISS}")', not the expected '${EXPECT_ISSUER}'"
    fi
  else
    warn issuer_unpinned "no --expect-issuer: iss is '$(esc "${CLAIMS_ISS}")' and nothing pinned it. The key set you"
    warn_more "verified against must be the one THAT origin publishes, or this proves nothing."
  fi

  # THE NONCE. Only the party that invented the challenge can check it, and a
  # nonce nobody compares is decoration (§4.8 of the verification doc).
  if [ "$EXPECT_NONCE_SET" -eq 1 ]; then
    if [ -z "$EXPECT_NONCE" ]; then
      if [ "$CLAIMS_NONCE_PRESENT" = '0' ]; then
        ok nonce_match "nonce (E5) is null, as required by --expect-nonce ''"
      else
        bad nonce_mismatch "nonce_mismatch — you required no challenge, the document carries '$(esc "${CLAIMS_NONCE}")'"
      fi
    elif [ "$CLAIMS_NONCE_PRESENT" = '1' ] && [ "$CLAIMS_NONCE" = "$EXPECT_NONCE" ]; then
      ok nonce_match "nonce (E5) echoes your challenge verbatim — this document was minted for you, now"
    else
      bad nonce_mismatch "nonce_mismatch — you challenged with '${EXPECT_NONCE}', the document carries \
'$(esc "${CLAIMS_NONCE:-null}")'. A replayed or substituted document, however well it verifies."
    fi
  elif [ "$CLAIMS_NONCE_PRESENT" = '1' ]; then
    warn nonce_unchecked "the document carries a nonce but you did not pass --expect-nonce, so nothing"
    warn_more "compared it. Only the party that invented the challenge can check it."
  fi

  # overallBand is DERIVED — the weakest attested band — so a verifier can
  # recompute it and reject a document that overclaims while agreeing with its
  # own coverage list nowhere.
  DERIVED_BAND="$(python3 -I - "$CLAIMS_FILE" <<'PY'
import json, sys
STRENGTH = ["in_progress", "basic", "substantial", "advanced"]
p = json.load(open(sys.argv[1])).get("posture") or {}
ranks = [STRENGTH.index(f["band"]) for f in p.get("frameworks", []) if f.get("band") in STRENGTH]
sys.stdout.write(STRENGTH[min(ranks)] if ranks else "")
PY
)"
  if [ "$CLAIMS_BAND" = "$DERIVED_BAND" ]; then
    if [ -z "$DERIVED_BAND" ]; then
      ok overall_band_valid "overallBand (E6) is null and nothing is attested — consistent"
    else
      ok overall_band_valid "overallBand (E6) equals the weakest attested band — recomputed, not trusted"
    fi
  else
    bad overall_band_mismatch "overall_band_mismatch — the document's overallBand is not the weakest band in its
          own coverage list"
  fi

  # The gated-redaction contract, enforced at the RELYING PARTY: a `gated`
  # posture that still carries coverage, a heartbeat or an overall band is a
  # leak, and a signature must not make a leak look authoritative.
  VISIBILITY="$(python3 -I -c "$DOCX_PY" "$POSTURE_FILE" field visibility)"
  if [ "$VISIBILITY" = 'gated' ]; then
    FW_COUNT="$(python3 -I - "$POSTURE_FILE" <<'PY'
import json, sys
sys.stdout.write(str(len(json.load(open(sys.argv[1])).get("frameworks", []))))
PY
)"
    CHECKED_PRESENT="$(python3 -I -c "$DOCX_PY" "$POSTURE_FILE" has lastCheckedAt)"
    if [ "$FW_COUNT" -eq 0 ] && [ "$CHECKED_PRESENT" = '0' ] && [ "$CLAIMS_BAND_PRESENT" = '0' ]; then
      ok redaction_valid "gated posture is redacted as it must be: no coverage, no heartbeat, no overall band"
    else
      bad redaction_violation "redaction_violation — a 'gated' posture is carrying coverage,
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

fetch_or_read "$STATUS_SRC" "$WORKDIR/status.json" 'status list' "$STATUS_NAME"
fetch_or_read "$STATUS_KEYS_SRC" "$WORKDIR/status-keys.json" 'status key set' "$STATUS_KEYS_NAME"

for dup_src in status.json status-keys.json; do
  if ! dup_found="$(python3 -I -c "$DUPKEY_PY" "$WORKDIR/$dup_src" 2>/dev/null)"; then
    stat_bad status_unknown_not_strict_json "malformed_document — ${dup_src} is not strict JSON (UTF-8, no BOM, one value)"
  elif [ -n "$dup_found" ]; then
    stat_bad status_unknown_duplicate_key "duplicate_key — ${dup_src} repeats members: \
$(printf '%s' "$dup_found" | tr '\n' ' ')— which value counts depends on the parser"
  fi
done

if [ "$STATUS_FAILURES" -eq 0 ] && jq -e 'type=="object" and has("statusList") and has("signature")' "$WORKDIR/status.json" >/dev/null 2>&1; then
  ok status_shape_valid "status document has the expected {statusList, signature} shape"
  jq '.statusList' "$WORKDIR/status.json" > "$WORKDIR/list.json"
  STATUS_JWS="$(jq -r '.signature' "$WORKDIR/status.json")"
else
  stat_bad status_unknown_malformed_document "malformed_document — expected {statusList, signature, ...}, exactly what \
GET /api/public/attest/status serves"
fi

if [ "$STATUS_FAILURES" -eq 0 ]; then
  STATUS_DOC_VERSION="$(jq -r '.docVersion // empty' "$WORKDIR/list.json")"
  if [ "$STATUS_DOC_VERSION" = 'attest.statuslist.v1' ]; then
    ok status_doc_version_valid "docVersion is attest.statuslist.v1"
  else
    stat_bad status_unknown_unsupported_version "unsupported_version — statusList.docVersion is '$(esc "${STATUS_DOC_VERSION:-$MISSING_LABEL}")', \
expected 'attest.statuslist.v1'"
  fi
fi

# --- envelope: split, detached form, closed header set ---
if [ "$STATUS_FAILURES" -eq 0 ]; then
  case "$STATUS_JWS" in
    *.*.*) SH="${STATUS_JWS%%.*}"; SREST="${STATUS_JWS#*.}"; SP="${SREST%%.*}"; SS="${SREST#*.}" ;;
    *) stat_bad status_unknown_not_compact_jws "malformed_document — .signature is not a 3-segment compact JWS" ;;
  esac
fi
if [ "$STATUS_FAILURES" -eq 0 ]; then
  case "$SS" in
    *.*) stat_bad status_unknown_too_many_dots "malformed_document — too many dots in .signature" ;;
  esac
fi
if [ "$STATUS_FAILURES" -eq 0 ]; then
  if [ -n "$SP" ]; then
    stat_bad status_unknown_signature_not_detached "malformed_document — status-list signature must be detached (RFC 7515 Appendix F: \
empty payload segment)"
  else
    ok status_jws_detached "detached JWS: payload segment is empty, as the status envelope requires"
  fi
fi
if [ "$STATUS_FAILURES" -eq 0 ] && ! b64url_decode "$SH" > "$WORKDIR/status_header.json" 2>/dev/null; then
  stat_bad status_unknown_header_not_base64url "malformed_document — protected header is not valid base64url"
fi
if [ "$STATUS_FAILURES" -eq 0 ] && ! b64url_decode "$SS" > "$WORKDIR/status_sig.bin" 2>/dev/null; then
  stat_bad status_unknown_signature_not_base64url "malformed_document — signature segment is not valid base64url"
fi
if [ "$STATUS_FAILURES" -eq 0 ]; then
  SSIG_LEN="$(wc -c < "$WORKDIR/status_sig.bin" | tr -d ' ')"
  if [ "$SSIG_LEN" -eq 3309 ]; then
    ok status_signature_size_valid "signature is 3309 bytes — the ML-DSA-65 size"
  else
    stat_bad status_unknown_signature_size "signature is ${SSIG_LEN} bytes, expected 3309 for ML-DSA-65"
  fi
fi
if [ "$STATUS_FAILURES" -eq 0 ] && ! jq -e 'type=="object"' "$WORKDIR/status_header.json" >/dev/null 2>&1; then
  stat_bad status_unknown_header_not_object "malformed_document — protected header did not decode to a JSON object"
fi
if [ "$STATUS_FAILURES" -eq 0 ]; then
  if ! SHDR_DUPS="$(python3 -I -c "$DUPKEY_PY" "$WORKDIR/status_header.json" 2>/dev/null)"; then
    stat_bad status_unknown_header_not_strict_json "malformed_document — protected header is not strict JSON"
  elif [ -n "$SHDR_DUPS" ]; then
    stat_bad status_unknown_header_duplicate_key "duplicate_key — protected header repeats: $(printf '%s' "$SHDR_DUPS" | tr '\n' ' ')"
  fi
fi
if [ "$STATUS_FAILURES" -eq 0 ]; then
  if jq -e 'has("crit")' "$WORKDIR/status_header.json" >/dev/null 2>&1; then
    stat_bad status_unknown_unsupported_crit "unsupported_crit — header carries 'crit' (RFC 7515 §4.1.11 requires rejection)"
  else
    ok status_header_crit_absent "no 'crit' header extension"
  fi
fi
if [ "$STATUS_FAILURES" -eq 0 ]; then
  HEADER_MEMBERS="$(jq -r 'keys_unsorted | sort | join(",")' "$WORKDIR/status_header.json")"
  if [ "$HEADER_MEMBERS" = 'alg,kid,typ' ]; then
    ok status_header_members_valid "header is the closed set {alg, kid, typ} — nothing unexamined can carry meaning"
  else
    stat_bad status_unknown_header_not_allowed "malformed_document — header members are '$(esc "${HEADER_MEMBERS}")', expected exactly alg,kid,typ"
  fi
fi
if [ "$STATUS_FAILURES" -eq 0 ]; then
  SALG="$(jq -r '.alg' "$WORKDIR/status_header.json")"
  STYP="$(jq -r '.typ' "$WORKDIR/status_header.json")"
  STATUS_LIST_KID="$(jq -r '.kid' "$WORKDIR/status_header.json")"
  # Never dispatch on alg — constant comparison only, exactly as jws.ts does.
  if [ "$SALG" = 'ML-DSA-65' ]; then
    ok status_header_alg_valid "alg is ML-DSA-65"
  else
    stat_bad status_unknown_unsupported_alg "unsupported_alg — alg is '$(esc "${SALG}")', expected 'ML-DSA-65'"
  fi
  if [ "$STYP" = 'application/attest-status+jws' ]; then
    ok status_header_typ_valid "typ is application/attest-status+jws — cannot be replayed as a posture attestation"
  else
    stat_bad status_unknown_unexpected_typ "unexpected_typ — typ is '$(esc "${STYP}")', expected 'application/attest-status+jws'"
  fi
fi

# --- key resolution: against --status-keys ONLY, never --jwks ---
if [ "$STATUS_FAILURES" -eq 0 ]; then
  STATUS_RETIRED_OUT="$(LC_ALL=C python3 -I -c "$RETIRED_PY" key "$WORKDIR/status-keys.json" "$STATUS_LIST_KID" "$WORKDIR/status-pub.txt" 2>/dev/null || printf 'invalid\n'; printf x)"
  STATUS_RETIRED_OUT="${STATUS_RETIRED_OUT%x}"
  STATUS_PUB_B64URL="$(cat "$WORKDIR/status-pub.txt" 2>/dev/null || true)"
  case "${STATUS_RETIRED_OUT%%$'\n'*}" in
    invalid) stat_bad status_unknown_keys_not_array "malformed_document — status-keys.json: \`keys\` is not an array of objects" ;;
    duplicate) stat_bad status_unknown_duplicate_kid "duplicate_key — status-keys.json has two keys with the same kid — which one counts depends on the order" ;;
  esac
  if [ "$STATUS_FAILURES" -ne 0 ]; then
    :  # already UNKNOWN: the key set is defective
  elif [ -n "$STATUS_PUB_B64URL" ]; then
    ok status_key_selected "selected the --status-keys entry whose kid is '$(esc "${STATUS_LIST_KID}")'"
    # The retirement marker of this key (checked against issuedAt below). A
    # defective status key set already leaves the list UNKNOWN (not strict JSON,
    # a repeated member, an unknown kid), so a malformed marker does too.
    case "${STATUS_RETIRED_OUT%%$'\n'*}" in
      absent) ;;
      ok) STATUS_RETIRED_AT="${STATUS_RETIRED_OUT#*$'\n'}" ;;
      *) stat_bad status_unknown_retired_at_malformed "malformed_document — hs_retired_at of the --status-keys entry '$(esc "${STATUS_LIST_KID}")' is \
'$(esc "${STATUS_RETIRED_OUT#*$'\n'}")', not an RFC 3339 UTC time with seconds (YYYY-MM-DDTHH:MM:SSZ)" ;;
    esac
  else
    stat_bad status_unknown_unknown_kid "unknown_kid — '$(esc "${STATUS_LIST_KID}")' is not in --status-keys. Unresolvable is a \
rejection, never a fallback to another key — and never a fallback to the attestation --jwks, \
which is a disjoint set by design (status-keys.ts)."
  fi
fi
if [ "$STATUS_FAILURES" -eq 0 ] && ! b64url_decode "$STATUS_PUB_B64URL" > "$WORKDIR/status_pub.raw" 2>/dev/null; then
  stat_bad status_unknown_public_key_not_base64url "public key is not valid base64url"
fi
if [ "$STATUS_FAILURES" -eq 0 ]; then
  SPUB_LEN="$(wc -c < "$WORKDIR/status_pub.raw" | tr -d ' ')"
  if [ "$SPUB_LEN" -eq 1952 ]; then
    ok status_public_key_size_valid "public key is 1952 bytes — the ML-DSA-65 size"
  else
    stat_bad status_unknown_public_key_size "public key is ${SPUB_LEN} bytes, expected 1952"
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
    ok status_kid_derivable "kid '$(esc "${STATUS_LIST_KID}")' is derivable from these key bytes"
  else
    stat_bad status_unknown_kid_mismatch "kid mismatch — status-keys entry claims '$(esc "${STATUS_LIST_KID}")', its bytes derive \
'${STATUS_DERIVED_KID}'"
  fi
fi
# --anchor-file: the same membership question for the status-list key, asked of
# the recomputed kid and with the role status-list. A failure leaves the status
# UNKNOWN (exit 3), as every failure to establish the list does.
if [ "$ANCHOR_READY" -eq 1 ] && [ "$STATUS_FAILURES" -eq 0 ]; then
  ANCHOR_SOK=1
  ANCHOR_SENTRY="$(LC_ALL=C python3 -I -c "$RETIRED_PY" lookup "$ANCHOR_STMT" "$STATUS_DERIVED_KID" 2>/dev/null || printf 'absent')"
  mapfile -t ANCHOR_SE <<< "$ANCHOR_SENTRY"
  if [ "${ANCHOR_SE[0]:-absent}" != found ]; then
    ANCHOR_SOK=0
    stat_bad anchor_status_kid_absent "anchor_status_kid_absent — the status-list key bytes derive kid '${STATUS_DERIVED_KID}', which the signed key statement does not list"
  else
    if [ "${ANCHOR_SE[1]:-}" != status-list ]; then
      ANCHOR_SOK=0
      stat_bad anchor_status_role_mismatch "anchor_status_role_mismatch — the signed key statement lists kid '${STATUS_DERIVED_KID}' as '$(esc "${ANCHOR_SE[1]:-}")', not as a status-list key"
    fi
    if [ "${ANCHOR_SE[2]:-}" != "$STATUS_RETIRED_AT" ]; then
      ANCHOR_SOK=0
      stat_bad anchor_status_retired_mismatch "anchor_status_retired_mismatch — the signed key statement retires kid '${STATUS_DERIVED_KID}' at '$(esc "${ANCHOR_SE[2]:-}")' (empty: not retired), the status key set says hs_retired_at '$(esc "$STATUS_RETIRED_AT")' (empty: none)"
    fi
    if [ -n "${ANCHOR_SE[2]:-}" ]; then
      if [ -z "$STATUS_RETIRED_AT" ] || [ "$(LC_ALL=C python3 -I -c "$RETIRED_PY" cmp "${ANCHOR_SE[2]}" "$STATUS_RETIRED_AT" 2>/dev/null)" = before ]; then
        STATUS_RETIRED_AT="${ANCHOR_SE[2]}"
      fi
    fi
  fi
  if [ "$ANCHOR_SOK" -eq 1 ]; then
    ok anchor_status_kid_listed "the signed key statement lists kid '${STATUS_DERIVED_KID}' as a status-list key"
  fi
fi
if [ "$STATUS_FAILURES" -eq 0 ]; then
  # 22-byte SPKI prefix for ML-DSA-65 (OID 2.16.840.1.101.3.4.3.12) — identical
  # to the one used for the attestation key above; the algorithm is the same.
  printf '308207b2300b0609608648016503040312038207a100' | hex_to_bin > "$WORKDIR/status_pub.der"
  cat "$WORKDIR/status_pub.raw" >> "$WORKDIR/status_pub.der"
  if openssl pkey -pubin -inform DER -in "$WORKDIR/status_pub.der" -out "$WORKDIR/status_pub.pem" \
       2>"$WORKDIR/status_err"; then
    ok status_public_key_loaded "loaded as an ML-DSA-65 public key"
  else
    stat_bad status_unknown_public_key_rejected "OpenSSL rejected the reconstructed status public key: $(esc "$(cat "$WORKDIR/status_err")")"
  fi
fi

# --- canonical bytes (the independent §6.4 encoder) + signature ---
if [ "$STATUS_FAILURES" -eq 0 ]; then
  if python3 -I -c "$CANON_STATUS_PY" "$WORKDIR/list.json" > "$WORKDIR/status_canon.bin" \
       2>"$WORKDIR/status_canon_err"; then
    SCANON_LEN="$(wc -c < "$WORKDIR/status_canon.bin" | tr -d ' ')"
    ok status_canonical_rederived "re-derived ${SCANON_LEN} canonical bytes from statusList (independent encoder)"
  else
    case "$(cat "$WORKDIR/status_canon_err")" in
      *'truncated must be a boolean'*) STATUS_ENCODE_CODE=status_unknown_truncated_invalid ;;
      *) STATUS_ENCODE_CODE=status_unknown_encoding_failed ;;
    esac
    stat_bad "$STATUS_ENCODE_CODE" "encoding_failed — canonical encoder refused the document: $(esc "$(cat "$WORKDIR/status_canon_err")")"
  fi
fi
if [ "$STATUS_FAILURES" -eq 0 ]; then
  printf '        sha-256: %s\n' "$(openssl dgst -sha256 -hex "$WORKDIR/status_canon.bin" | awk '{print $NF}')"
  SPAYLOAD_B64="$(b64url_encode "$WORKDIR/status_canon.bin")"
  printf '%s.%s' "$SH" "$SPAYLOAD_B64" > "$WORKDIR/status_signing_input.bin"
  if openssl pkeyutl -verify -pubin -inkey "$WORKDIR/status_pub.pem" -rawin \
       -in "$WORKDIR/status_signing_input.bin" -sigfile "$WORKDIR/status_sig.bin" >/dev/null 2>&1; then
    ok status_signature_valid "ML-DSA-65 signature verifies over protected.payload"
  else
    stat_bad status_unknown_bad_signature "bad_signature — SIGNATURE DOES NOT VERIFY. The list was altered, or was not signed \
by this key."
  fi
fi

# --- claims.kid == header kid ---
if [ "$STATUS_FAILURES" -eq 0 ]; then
  LIST_KID="$(jq -r '.kid' "$WORKDIR/list.json")"
  if [ "$LIST_KID" = "$STATUS_LIST_KID" ]; then
    ok status_kid_matches "claims.kid equals the JWS header kid (signed twice, deliberately)"
  else
    stat_bad status_unknown_kid_mismatch "kid_mismatch — statusList.kid ('$(esc "${LIST_KID}")') != JWS header kid ('$(esc "${STATUS_LIST_KID}")')"
  fi
fi

if [ "$STATUS_FAILURES" -eq 0 ] && [ -n "$EXPECT_ISSUER" ]; then
  LIST_ISS="$(jq -r '.iss' "$WORKDIR/list.json")"
  if [ "$LIST_ISS" = "$EXPECT_ISSUER" ]; then
    ok status_issuer_match "iss is '$(esc "${LIST_ISS}")', as expected"
  else
    stat_bad status_unknown_issuer_mismatch "issuer_mismatch — iss is '$(esc "${LIST_ISS}")', expected '${EXPECT_ISSUER}'"
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
    stat_bad status_unknown_date_unparseable "malformed_document — could not parse issuedAt/nextUpdate as RFC 3339"
  else
    if [ $(( SIAT - STATUS_CLOCK_SKEW_SECONDS )) -gt "$SNOW" ]; then
      stat_bad status_unknown_not_yet_valid "not_yet_valid — issuedAt is in the future beyond the ${STATUS_CLOCK_SKEW_SECONDS}s skew allowance"
    else
      ok status_not_future "issuedAt is not in the future (beyond skew)"
    fi
    # No skew here: both instants are inside the signed bytes, so no clock is
    # involved — exactly as posture.ts checks ttl_exceeded above.
    if [ $(( SNUP - SIAT )) -gt "$MAX_STATUS_LIST_VALIDITY_SECONDS" ]; then
      stat_bad status_unknown_validity_exceeded "validity_exceeded — nextUpdate - issuedAt is $(( SNUP - SIAT ))s, above the \
${MAX_STATUS_LIST_VALIDITY_SECONDS}s ceiling any conforming issuer can produce"
    else
      ok status_validity_within_ceiling "nextUpdate - issuedAt is within the ${MAX_STATUS_LIST_VALIDITY_SECONDS}s ceiling"
    fi
    if [ $(( SNUP + STATUS_CLOCK_SKEW_SECONDS )) -lt "$SNOW" ]; then
      stat_bad status_unknown_stale "stale — nextUpdate is $(( SNOW - SNUP ))s in the past, beyond the \
${STATUS_CLOCK_SKEW_SECONDS}s skew allowance. Re-fetch — do not rely on this list."
    else
      ok status_not_stale "not stale (nextUpdate has not passed, allowing for skew)"
    fi
  fi
fi

# --- a list issued at or after the retirement of its own key is not trusted ---
if [ "$STATUS_FAILURES" -eq 0 ] && [ -n "$STATUS_RETIRED_AT" ]; then
  case "$(LC_ALL=C python3 -I -c "$RETIRED_PY" cmp "$SISSUEDAT" "$STATUS_RETIRED_AT" 2>/dev/null)" in
    at_or_after)
      stat_bad status_unknown_retired_key "retired_key — this status list was issued at $(esc "$SISSUEDAT"), at or after the retirement of \
key $(esc "$STATUS_LIST_KID") at $(esc "$STATUS_RETIRED_AT")" ;;
    before)
      ok status_retired_key_list_predates "key $(esc "$STATUS_LIST_KID") is retired (at $(esc "$STATUS_RETIRED_AT")), but this list was issued at $(esc "$SISSUEDAT"), before the retirement" ;;
    *)
      stat_bad status_unknown_date_unparseable "malformed_document — issuedAt '$(esc "$SISSUEDAT")' cannot be compared with the retirement of key \
$(esc "$STATUS_LIST_KID") at $(esc "$STATUS_RETIRED_AT")" ;;
  esac
fi

if [ "$STATUS_FAILURES" -eq 0 ] && [ -n "$MIN_SEQ" ]; then
  SSEQ="$(jq -r '.seq' "$WORKDIR/list.json")"
  if [ "$SSEQ" -lt "$MIN_SEQ" ] 2>/dev/null; then
    stat_bad status_unknown_rolled_back "rolled_back — seq $(esc "${SSEQ}") is lower than the highest previously accepted (${MIN_SEQ})"
  else
    ok status_not_rolled_back "seq $(esc "${SSEQ}") >= previously accepted ${MIN_SEQ} — not a rollback"
  fi
fi

# --- Rule S: a list may not revoke its own signer ---
if [ "$STATUS_FAILURES" -eq 0 ]; then
  if jq -e --arg kid "$LIST_KID" '.keys[]? | select(.kid==$kid)' "$WORKDIR/list.json" >/dev/null 2>&1; then
    stat_bad status_unknown_self_revocation "self_revocation — the list revokes its own signing key ('$(esc "${LIST_KID}")')"
  else
    ok status_not_self_revoking "the list does not name its own signing key among the revoked keys (Rule S)"
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

# The kids Rule K is applied to. With a document: the kid recomputed from the key
# bytes that verified it AND its header kid, ALWAYS, and any --check-kid besides;
# --check-kid never replaces the document's own kid, so a revoked signing key
# cannot be checked under another name. Any one of them listed is REVOKED.
# §6.3's "unknown_kid upgrade": the header kid is used here EVEN IF the posture
# check above already failed on it — safe to do with an unverified field because
# the only reachable effect is a rejection. It can never turn a bad document good.
CHECK_KIDS=()
for k in "${DERIVED_KID:-}" "${KID:-}" "$CHECK_KID"; do
  [ -n "$k" ] || continue
  case " ${CHECK_KIDS[*]-} " in *" $k "*) ;; *) CHECK_KIDS+=("$k") ;; esac
done
EFFECTIVE_KID="${CHECK_KIDS[*]-}"
EFFECTIVE_SLUG="${CHECK_SUBJECT:-${SLUG:-}}"
EFFECTIVE_GENAT="${CHECK_GENERATED_AT:-${GENERATED:-}}"

REVOCATION_STATUS=''
REVOCATION_REASON=''
REVOCATION_VIA=''
REVOCATION_UNKNOWN_BECAUSE=''

if [ "$STATUS_LIST_VALID" -ne 1 ]; then
  REVOCATION_STATUS='unknown'; REVOCATION_UNKNOWN_BECAUSE='list_unverified'
  warn_unknown status_unknown_list_unverified "cannot apply an unverified list — status is UNKNOWN, never 'good'"
elif [ -z "$EFFECTIVE_KID" ] && [ -z "$EFFECTIVE_SLUG" ]; then
  REVOCATION_STATUS='unknown'; REVOCATION_UNKNOWN_BECAUSE='no_subject'
  warn_unknown status_unknown_no_subject "nothing to check (no kid or subject given) — list contents printed above only"
else
  # Rule K — UNCONDITIONAL. revokedAt is deliberately never compared: it is a
  # field the compromised key itself could sign, so a rule over it is decoration.
  for k in "${CHECK_KIDS[@]+"${CHECK_KIDS[@]}"}"; do
    KEY_HIT_REASON="$(jq -r --arg kid "$k" \
      '.keys[]? | select(.kid==$kid) | .reason' "$WORKDIR/list.json" | head -1)"
    if [ -n "$KEY_HIT_REASON" ]; then
      REVOCATION_STATUS='revoked'; REVOCATION_REASON="$KEY_HIT_REASON"; REVOCATION_VIA='key'
      break
    fi
  done

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
        warn_unknown status_unknown_generated_at_missing "subject '$(esc "${EFFECTIVE_SLUG}")' IS listed, but no generatedAt was given \
(--check-generated-at, or --attestation/--claims) to compare against notBefore='$(esc "${SUBJ_NOTBEFORE}")' \
— cannot \
decide, so UNKNOWN, never 'good'"
      else
        SGEN="$(epoch_of "$EFFECTIVE_GENAT")"
        SNB="$(epoch_of "$SUBJ_NOTBEFORE")"
        if [ -z "$SGEN" ] || [ -z "$SNB" ]; then
          REVOCATION_STATUS='unknown'; REVOCATION_UNKNOWN_BECAUSE='list_unverified'
          warn_unknown status_unknown_subject_dates_unparseable "could not parse generatedAt/notBefore as RFC 3339 — UNKNOWN, never 'good'"
        elif [ "$SGEN" -lt "$SNB" ]; then
          REVOCATION_STATUS='revoked'; REVOCATION_REASON="$SUBJ_REASON"; REVOCATION_VIA='subject'
        fi
      fi
    else
      SLIST_TRUNCATED="$(jq -r '.truncated' "$WORKDIR/list.json")"
      if [ "$SLIST_TRUNCATED" = 'true' ]; then
        REVOCATION_STATUS='unknown'; REVOCATION_UNKNOWN_BECAUSE='truncated'
        warn_unknown status_unknown_truncated "subject not found, but truncated=true: entries were dropped for the cap, so \
'not found' does not mean 'not listed' — UNKNOWN on the subject dimension, fail-safe"
      fi
    fi
  fi

  [ -n "$REVOCATION_STATUS" ] || REVOCATION_STATUS='good'
fi

case "$REVOCATION_STATUS" in
  good)
    record good pass 0
    printf '\n%s%sGOOD%s' "$GREEN" "$BOLD" "$RESET"
    if [ "${#CHECK_KIDS[@]}" -gt 1 ]; then
      printf ' — kids %s are not revoked' "$(esc "${EFFECTIVE_KID// /, }")"
    elif [ -n "$EFFECTIVE_KID" ]; then
      printf ' — kid %s is not revoked' "$(esc "$EFFECTIVE_KID")"
    fi
    [ -n "$(esc "$EFFECTIVE_SLUG")" ] && printf ', subject %s carries no earlier withdrawal' "$(esc "$EFFECTIVE_SLUG")"
    printf ' (list seq %s).\n' "$(esc "$(jq -r '.seq' "$WORKDIR/list.json" 2>/dev/null || printf '?')")"
    ;;
  revoked)
    if [ "$REVOCATION_VIA" = key ]; then record revoked_key fail 1; else record revoked_subject fail 1; fi
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
      ATTESTED_OK=1
      printf '\n%sAttested content%s (covered by the signature, and the document verified)\n' "$BOLD" "$RESET"
      # A display failure must never change the verdict.
      python3 -I -c "$DOCX_PY" "$CLAIMS_FILE" summary || printf '        (the summary could not be rendered)\n'
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
  VERDICT=expired
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
    VERDICT=failed
    printf '%s%sVERIFICATION FAILED%s — %d posture check(s) did not hold. Do not rely on this document.\n\n' \
      "$RED" "$BOLD" "$RESET" "$FAILURES" >&2
    exit 1
  fi
  case "$REVOCATION_STATUS" in
    good)
      VERDICT=good
      printf '%s%sGOOD%s — not revoked, per a verified status list.\n\n' "$GREEN" "$BOLD" "$RESET"
      printf '%sThat is all it proves.%s It does not prove the claims inside are true, that the key\n' "$BOLD" "$RESET"
      printf 'belongs to who you think, or that nothing else about the document is wrong. Read\n'
      printf 'docs/security/attest-verification.md §6 and §7 before relying on it.\n\n'
      exit 0
      ;;
    revoked)
      VERDICT=revoked
      printf '%s%sREVOKED%s — reason "%s". Do not rely on this document.\n\n' "$RED" "$BOLD" "$RESET" "$(esc "$REVOCATION_REASON")" >&2
      exit 1
      ;;
    *)
      VERDICT=unknown
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
  record verified pass 0
  VERDICT=verified
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
VERDICT=failed
printf '%s%sVERIFICATION FAILED%s — %d check(s) did not hold. Do not rely on this document.\n\n' \
  "$RED" "$BOLD" "$RESET" "$FAILURES" >&2
exit 1
