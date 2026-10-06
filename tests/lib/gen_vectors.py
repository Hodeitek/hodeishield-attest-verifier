#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
"""Generate the committed test vectors in tests/vectors/v1/.

This is the script that PRODUCED v1, kept so the set can be audited and
extended. It is not how the vectors are consumed: ML-DSA signing is randomised,
so running it again does not reproduce the committed bytes. The vectors ARE the
committed files; tests/vectors.sh checks them against SHA256SUMS and runs them.

It signs with the TEST-ONLY keys in tests/vectors/v1/keys, through
tests/lib/mint.py (the issuer side, written independently of the verifier).

  python3 tests/lib/gen_vectors.py             first generation: refuses to run
                                               if any case file already exists
  python3 tests/lib/gen_vectors.py --extend    keep every existing file and
                                               manifest entry, add only what is
                                               missing (new case ids)
  python3 tests/lib/gen_vectors.py --force     overwrite everything (this
                                               changes the committed bytes; v1
                                               is append-only, see its README)

To add a case, append it below with a NEW id, then run with --extend.
"""
import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
V1 = os.path.join(ROOT, "tests", "vectors", "v1")
sys.path.insert(0, HERE)
import mint  # noqa: E402

ISS = "https://issuer.test"
SLUG = "fixture-org"
GEN = "2026-01-01T00:00:00.000Z"
EXP = "2026-01-01T00:15:00.000Z"
NOW = 1767225900        # GEN + 5 min: inside the validity window
NOW_LATE = 1767312000   # GEN + 1 day: long expired
NOW_EARLY = 1767225000  # GEN - 15 min: beyond the 5 min clock-skew allowance
LIST_AT = "2026-01-01T00:00:00.000Z"
LIST_NEXT = "2026-01-01T02:00:00.000Z"

K_ISSUER = "keys/test-only-issuer.pem"
K_OTHER = "keys/test-only-other.pem"
K_STATUS = "keys/test-only-status.pem"
J_ISSUER = "keys/test-only-issuer-jwks.json"
J_OTHER = "keys/test-only-other-jwks.json"
J_STATUS = "keys/test-only-status-jwks.json"


class Gen:
    def __init__(self, mode):
        self.mode = mode          # "new" | "extend" | "force"
        self.cases = []
        self.known = set()

    def path(self, rel):
        return os.path.join(V1, rel)

    def make(self, rel, fn):
        """Create rel with fn(abs_path), honouring the overwrite policy."""
        p = self.path(rel)
        if os.path.exists(p) and self.mode == "extend":
            return False
        os.makedirs(os.path.dirname(p), exist_ok=True)
        fn(p)
        return True

    def run_mint(self, *args):
        subprocess.run([sys.executable, os.path.join(HERE, "mint.py"), *args],
                       check=True, stdout=subprocess.DEVNULL)

    def attest(self, rel, **kw):
        """mint.py attest with the fixture defaults; kw overrides."""
        o = {"slug": SLUG, "iss": ISS, "generated-at": GEN, "expires-at": EXP}
        o.update({k.replace("_", "-"): v for k, v in kw.items()})
        fw = o.pop("framework", ["iso27001=substantial", "nis2=basic"])
        hdr = o.pop("header", [])

        def f(p):
            a = ["attest", "--key", self.path(K_ISSUER), "--out", p]
            for k, v in o.items():
                a += ["--" + k, v]
            for x in fw:
                a += ["--framework", x]
            for x in hdr:
                a += ["--header", x]
            self.run_mint(*a)
        self.make(rel, f)

    def status(self, rel, key=K_STATUS, **kw):
        def f(p):
            a = ["status", "--key", self.path(key), "--iss", ISS, "--out", p]
            for k, v in kw.items():
                if isinstance(v, list):
                    for x in v:
                        a += ["--" + k.replace("_", "-") + "=" + x]
                else:
                    a += ["--" + k.replace("_", "-"), str(v)]
            self.run_mint(*a)
        self.make(rel, f)

    def edit(self, src, dst, fn):
        """Load JSON src, let fn(d) change it, write indented to dst."""
        def f(p):
            d = json.load(open(self.path(src)))
            fn(d)
            json.dump(d, open(p, "w"), indent=2)
        self.make(dst, f)

    def edit_text(self, src, dst, fn):
        """Rewrite the raw text of src; fn(t) returns the new text."""
        def f(p):
            t = open(self.path(src), newline="").read()
            open(p, "w", newline="").write(fn(t))
        self.make(dst, f)

    def compact(self, src, dst):
        def f(p):
            d = json.load(open(self.path(src)))
            open(p, "w").write(json.dumps(d, separators=(",", ":")))
        self.make(dst, f)

    def case(self, id, description, args, exit, code, match, absent=None,
             canonical_sha256=None, status_canonical_sha256=None):
        if id in self.known:
            raise SystemExit("gen_vectors: case id %r used twice" % id)
        self.known.add(id)
        e = {"exit": exit, "code": code, "match": match}
        if absent:
            e["absent"] = absent
        c = {"id": id, "description": description, "args": args, "expect": e}
        if canonical_sha256:
            c["canonical_sha256"] = canonical_sha256
        if status_canonical_sha256:
            c["status_canonical_sha256"] = status_canonical_sha256
        self.cases.append(c)


def sha_envelope(g, rel):
    claims = json.load(open(g.path(rel)))["attestation"]["claims"]
    return hashlib.sha256(mint.envelope_bytes(claims)).hexdigest()


def sha_status(g, rel):
    lst = json.load(open(g.path(rel)))["statusList"]
    return hashlib.sha256(mint.statuslist_bytes(lst)).hexdigest()


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def build(g):
    # ---- keys: generated once, never overwritten except by --force -----------
    for key, jwks in ((K_ISSUER, J_ISSUER), (K_OTHER, J_OTHER), (K_STATUS, J_STATUS)):
        kp, jp = g.path(key), g.path(jwks)
        if os.path.exists(kp) and g.mode != "force":
            continue
        os.makedirs(os.path.dirname(kp), exist_ok=True)
        g.run_mint("keygen", "--out", kp, "--jwks", jp)
    issuer_kid = json.load(open(g.path(J_ISSUER)))["keys"][0]["kid"]

    A = "attestations/"

    def common(slug=SLUG, now=NOW, jwks=J_ISSUER, iss=ISS):
        return ["--jwks", jwks, "--expect-slug", slug, "--expect-issuer", iss, "--now", str(now)]

    COMMON = common()
    late = common(now=NOW_LATE)

    # ---- base documents ------------------------------------------------------
    g.attest(A + "valid.json")
    sha_valid = sha_envelope(g, A + "valid.json")

    def jws_from(p):
        d = json.load(open(g.path(A + "valid.json")))
        open(p, "w").write(d["attestation"]["signature"] + "\n")
    g.make("jws/valid-detached.jws", jws_from)
    g.make("claims/valid.json", lambda p: json.dump(
        json.load(open(g.path(A + "valid.json")))["attestation"]["claims"], open(p, "w"), indent=2))
    g.make("jws/valid-attached.jws", lambda p: g.run_mint(
        "attach", "--doc", g.path(A + "valid.json"), "--out", p))

    # ---- posture attestation -------------------------------------------------
    g.case("valid-detached", "A genuine detached attestation verifies.",
           ["--attestation", A + "valid.json"] + COMMON, 0, "verified",
           "VERIFIED — this document was signed", canonical_sha256=sha_valid)
    g.case("valid-jws-claims", "The same document given as a detached JWS plus a claims file verifies.",
           ["--jws", "jws/valid-detached.jws", "--claims", "claims/valid.json"] + COMMON, 0, "verified",
           "VERIFIED — this document was signed", canonical_sha256=sha_valid)

    g.edit(A + "valid.json", A + "tampered-field.json",
           lambda d: d["attestation"]["claims"].__setitem__("overallBand", "advanced"))
    g.case("tampered-field", "A signed field (overallBand) changed after signing is rejected.",
           ["--attestation", A + "tampered-field.json"] + COMMON, 1, "signature_invalid",
           "SIGNATURE DOES NOT VERIFY")

    def tamper_sig(d):
        h, p, s = d["attestation"]["signature"].split(".")
        s = ("B" if s[100] == "A" else "A").join([s[:100], s[101:]])
        d["attestation"]["signature"] = ".".join([h, p, s])
    g.edit(A + "valid.json", A + "tampered-signature.json", tamper_sig)
    g.case("tampered-signature", "One character of the signature changed.",
           ["--attestation", A + "tampered-signature.json"] + COMMON, 1, "signature_invalid",
           "SIGNATURE DOES NOT VERIFY")

    def reorder(d):
        h, p, s = d["attestation"]["signature"].split(".")
        hdr = json.loads(b64d(h))
        h2 = b64e(json.dumps(dict(reversed(list(hdr.items()))), separators=(",", ":")).encode())
        d["attestation"]["signature"] = ".".join([h2, p, s])
    g.edit(A + "valid.json", A + "reordered-header.json", reorder)
    g.case("reordered-header", "The protected header re-serialised in another member order is rejected "
           "(the signed bytes are the header as sent).",
           ["--attestation", A + "reordered-header.json"] + COMMON, 1, "signature_invalid",
           "SIGNATURE DOES NOT VERIFY")

    g.attest(A + "other-issuer.json", iss="https://other-issuer.test", framework=["iso27001=basic"])
    g.case("other-issuer", "A genuinely signed document whose iss differs from --expect-issuer.",
           ["--attestation", A + "other-issuer.json"] + COMMON, 1, "issuer_mismatch", "issuer_mismatch")

    g.case("wrong-slug", "A genuine document for another trust-center slug than --expect-slug.",
           ["--attestation", A + "valid.json"] + common(slug="another-org"), 1, "slug_mismatch",
           "not the expected 'another-org'")

    g.case("expired", "A genuine document past expiresAt is EXPIRED, not a forgery.",
           ["--attestation", A + "valid.json"] + late, 1, "expired", "EXPIRED",
           absent=["VERIFICATION FAILED"])
    g.case("expired-says-signature-valid", "The last line of an expired genuine document says the signature is valid.",
           ["--attestation", A + "valid.json"] + late, 1, "expired",
           "EXPIRED — the signature is valid, but this attestation expired on " + EXP + ".",
           absent=["VERIFICATION FAILED"])
    g.case("expired-names-fetch-command", "An expired genuine document names the command to fetch a new one.",
           ["--attestation", A + "valid.json"] + late, 1, "expired",
           "curl -fsS " + ISS + "/api/public/attest/" + SLUG + " -o att.json")
    g.case("expired-tampered", "A tampered document that is also expired is a failed verification, never only expired.",
           ["--attestation", A + "tampered-field.json"] + late, 1, "signature_invalid",
           "VERIFICATION FAILED", absent=["the signature is valid"])
    g.case("expired-wrong-slug", "An expired document for another slug is a failed verification, not just expired.",
           ["--attestation", A + "valid.json"] + common(slug="another-org", now=NOW_LATE), 1, "slug_mismatch",
           "VERIFICATION FAILED", absent=["the signature is valid"])
    g.case("too-old", "A genuine unexpired document older than --max-age-seconds is reported as too old.",
           ["--attestation", A + "valid.json"] + COMMON + ["--max-age-seconds", "60"], 1, "too_old",
           "EXPIRED — the signature is valid, but this attestation was generated on",
           absent=["VERIFICATION FAILED"])

    g.attest(A + "ttl-exceeded.json", expires_at="2026-01-01T02:00:00.000Z")
    g.case("ttl-exceeded", "A validity window of 2 h is above the 1 h issuer ceiling.",
           ["--attestation", A + "ttl-exceeded.json"] + COMMON, 1, "ttl_exceeded", "above the issuer's")

    g.case("not-yet-valid", "A document dated beyond the 5 min clock-skew allowance in the future.",
           ["--attestation", A + "valid.json"] + common(now=NOW_EARLY), 1, "not_yet_valid", "not_yet_valid")

    g.attest(A + "unparseable-date.json", generated_at="the first of january")
    g.case("unparseable-date", "A signed but unparseable generatedAt is rejected, not skipped.",
           ["--attestation", A + "unparseable-date.json"] + COMMON, 1, "date_unparseable",
           "could not parse generatedAt")

    g.attest(A + "extra-header.json", header=["x5u=https://keys.example"])
    g.case("header-extra-member", "A signed protected header member outside {alg, kid, typ}.",
           ["--attestation", A + "extra-header.json"] + COMMON, 1, "header_not_allowed", "header members are")

    g.attest(A + "nonce.json", nonce="challenge-A")
    g.case("nonce-mismatch", "A document answering challenge-A, verified against challenge-B.",
           ["--attestation", A + "nonce.json"] + COMMON + ["--expect-nonce", "challenge-B"], 1,
           "nonce_mismatch", "nonce_mismatch")
    g.case("nonce-match", "A document answering challenge-A, verified against challenge-A.",
           ["--attestation", A + "nonce.json"] + COMMON + ["--expect-nonce", "challenge-A"], 0, "verified",
           "echoes your challenge verbatim", canonical_sha256=sha_envelope(g, A + "nonce.json"))

    g.attest(A + "overclaim.json", overall_band="advanced")
    g.case("overall-band-overclaim", "A signed overallBand stronger than the weakest framework.",
           ["--attestation", A + "overclaim.json"] + COMMON, 1, "overall_band_mismatch", "overall_band_mismatch")

    g.case("unknown-kid", "The key document holds no key with the document's kid: could not check (2), not a forgery.",
           ["--attestation", A + "valid.json"] + common(jwks=J_OTHER), 2, "unknown_kid",
           "no key in this JWKS carries kid")

    def mislabel(d):
        d["keys"][0]["kid"] = issuer_kid
    g.edit(J_OTHER, "jwks/mislabelled.json", mislabel)
    g.case("kid-mismatch", "A key published under a kid its bytes do not derive.",
           ["--attestation", A + "valid.json"] + common(jwks="jwks/mislabelled.json"), 1, "kid_mismatch",
           "kid mismatch — header says")

    def decoy_slug(d):
        c = d["attestation"]["claims"]
        c["posture"] = {"x": {"slug": "another-org"}, **c["posture"]}
    g.edit(A + "valid.json", A + "decoy-slug.json", decoy_slug)
    g.case("decoy-slug-unsigned-member", "An unsigned nested decoy slug does not satisfy --expect-slug.",
           ["--attestation", A + "decoy-slug.json"] + common(slug="another-org"), 1, "unsigned_member",
           "unsigned_member")
    g.case("decoy-slug-reads-signed-slug", "The slug check reads the signed slug, not the decoy.",
           ["--attestation", A + "decoy-slug.json"] + common(slug="another-org"), 1, "slug_mismatch",
           "not the expected 'another-org'")

    def decoy_fresh(d):
        c = d["attestation"]["claims"]
        c["posture"] = {"x": {"generatedAt": "2026-01-02T00:00:00.000Z",
                              "expiresAt": "2026-01-02T00:10:00.000Z"}, **c["posture"]}
    g.edit(A + "valid.json", A + "decoy-fresh.json", decoy_fresh)
    g.case("decoy-timestamps-expired", "Unsigned decoy timestamps do not make an expired document fresh.",
           ["--attestation", A + "decoy-fresh.json"] + late, 1, "unsigned_member", "EXPIRED",
           absent=["the signature is valid"])

    g.edit(A + "valid.json", A + "extra-top.json",
           lambda d: d["attestation"]["claims"].__setitem__("note", "not signed"))
    g.case("unsigned-member-top-level", "An unsigned top-level claims member.",
           ["--attestation", A + "extra-top.json"] + COMMON, 1, "unsigned_member", "claims.note")

    g.edit(A + "valid.json", A + "extra-framework.json",
           lambda d: d["attestation"]["claims"]["posture"]["frameworks"][0].__setitem__("band_note", "x"))
    g.case("unsigned-member-framework", "An unsigned member inside a framework entry.",
           ["--attestation", A + "extra-framework.json"] + COMMON, 1, "unsigned_member",
           "posture.frameworks[0].band_note")

    g.attest(A + "no-expiry.json", expires_at="none")
    g.case("missing-expiry", "A document without expiresAt is rejected, not treated as never expiring.",
           ["--attestation", A + "no-expiry.json"] + COMMON, 1, "missing_expiry", "no expiresAt")

    g.attest(A + "gated-leak.json", visibility="gated", framework=["iso27001=basic"])
    g.case("gated-redaction-leak", "A gated posture that still carries framework coverage.",
           ["--attestation", A + "gated-leak.json"] + COMMON, 1, "redaction_violation", "redaction_violation")

    g.attest(A + "alg-none.json", header=["alg=none"])
    g.case("header-alg-none", "A signed header naming another algorithm (none).",
           ["--attestation", A + "alg-none.json"] + COMMON, 1, "header_alg_invalid", "alg is 'none'")

    g.attest(A + "crit.json", header=["crit=x"])
    g.case("header-crit", "A signed header carrying crit.",
           ["--attestation", A + "crit.json"] + COMMON, 1, "header_not_allowed", "header carries 'crit'")

    def wrapped(d):
        c = d["attestation"]["claims"]
        c["claims"] = {"posture": {**c["posture"], "slug": "another-org"}}
    g.edit(A + "valid.json", A + "wrapped-decoy.json", wrapped)
    g.case("decoy-claims-wrapper", "A nested claims wrapper does not replace the signed posture.",
           ["--attestation", A + "wrapped-decoy.json"] + common(slug="another-org"), 1, "slug_mismatch",
           "not the expected 'another-org'")

    # attached form
    AJ = ["--jws", "jws/valid-attached.jws"]
    g.case("attached-valid", "An attached JWS alone verifies, with its claims decoded from the payload.",
           AJ + COMMON, 0, "verified", "the embedded payload equals the bytes re-derived",
           canonical_sha256=sha_valid)
    g.case("attached-wrong-slug", "An attached JWS alone is held to --expect-slug.",
           AJ + common(slug="another-org"), 1, "slug_mismatch", "not the expected 'another-org'")
    g.case("attached-issuer-mismatch", "An attached JWS alone is held to --expect-issuer.",
           AJ + common(iss="https://other-issuer.test"), 1, "issuer_mismatch", "issuer_mismatch")
    g.case("attached-nonce-mismatch", "An attached JWS alone is held to --expect-nonce.",
           AJ + COMMON + ["--expect-nonce", "challenge-B"], 1, "nonce_mismatch", "nonce_mismatch")
    g.case("attached-expired", "An attached JWS alone is held to its expiry.",
           AJ + late, 1, "expired", "EXPIRED")

    def garbage(p):
        d = json.load(open(g.path(A + "valid.json")))
        h, _, s = d["attestation"]["signature"].split(".")
        open(p, "w").write(".".join([h, "QUFBQQ", s]) + "\n")
    g.make("jws/attached-garbage-payload.jws", garbage)
    g.case("attached-garbage-payload",
           "An attached payload that is not an envelope is a failure (1), not could-not-check (2).",
           ["--jws", "jws/attached-garbage-payload.jws"] + COMMON, 1, "payload_not_envelope",
           "is not a hodei-shield.attest.attestation.v1")

    # duplicate members and strict JSON
    g.compact(A + "valid.json", A + "valid-compact.json")
    g.edit_text(A + "valid-compact.json", A + "dup-posture.json", lambda t: t.replace(
        '"posture":{', '"posture":{"slug":"another-org","expiresAt":"2099-01-01T00:00:00.000Z",', 1))
    g.case("dup-posture-members", "slug/expiresAt duplicated inside posture.",
           ["--attestation", A + "dup-posture.json"] + COMMON, 1, "duplicate_key", "duplicate_key")
    g.edit_text(A + "valid-compact.json", A + "dup-claims.json", lambda t: t.replace(
        '{"attestation":{', '{"attestation":{"claims":{"iss":"x"},', 1))
    g.case("dup-claims-in-attestation", "A second claims member inside attestation.",
           ["--attestation", A + "dup-claims.json"] + COMMON, 1, "duplicate_key", "duplicate_key")
    g.edit_text(A + "valid-compact.json", A + "dup-top-claims.json",
                lambda t: '{"claims":{"iss":"x"},' + t[1:])
    g.case("dup-claims-top-level", "A claims member beside attestation at the top level.",
           ["--attestation", A + "dup-top-claims.json"] + COMMON, 1, "duplicate_key", "duplicate_key")
    g.edit_text(A + "valid-compact.json", A + "dup-attestation.json",
                lambda t: '{"attestation":{"claims":{}},' + t[1:])
    g.case("dup-attestation-member", "A duplicated attestation member.",
           ["--attestation", A + "dup-attestation.json"] + COMMON, 1, "duplicate_key", "duplicate_key")
    g.edit_text(A + "valid-compact.json", A + "dup-band.json",
                lambda t: t.replace('"band":', '"band":"advanced","band":', 1))
    g.case("dup-framework-band", "A duplicated framework band.",
           ["--attestation", A + "dup-band.json"] + COMMON, 1, "duplicate_key", "duplicate_key")
    g.case("compact-valid", "The same document, compact and without duplicates, verifies.",
           ["--attestation", A + "valid-compact.json"] + COMMON, 0, "verified",
           "every member of the claims JSON is covered by the signature", canonical_sha256=sha_valid)

    def claims_compact(p):
        d = json.load(open(g.path("claims/valid.json")))
        open(p, "w").write(json.dumps(d, separators=(",", ":")))
    g.make("claims/valid-compact.json", claims_compact)
    g.edit_text("claims/valid-compact.json", "claims/dup-member.json",
                lambda t: t.replace("{", '{"iss":"https://other-issuer.test",', 1))
    g.case("dup-claims-file", "A duplicated member in a --claims file.",
           ["--jws", "jws/valid-detached.jws", "--claims", "claims/dup-member.json"] + COMMON, 1,
           "duplicate_key", "duplicate_key")

    g.compact(J_ISSUER, "jwks/issuer-compact.json")
    g.edit_text("jwks/issuer-compact.json", "jwks/dup-member.json",
                lambda t: t.replace('"pub":', '"pub":"AAAA","pub":', 1))
    g.case("dup-jwks-member", "A key document with a duplicated member: could not check (2).",
           ["--attestation", A + "valid.json"] + common(jwks="jwks/dup-member.json"), 2, "jwks_duplicate_key",
           "repeats members")

    def dup_deep(t):
        deep = "[" * 990 + "]" * 990
        t = t.replace('"posture":{', '"posture":{"slug":"another-org",', 1)
        return t.rstrip()[:-1] + ',"verification":' + deep + "}"
    g.edit_text(A + "valid-compact.json", A + "dup-deep.json", dup_deep)
    g.case("dup-beside-deep-nesting", "A duplicate beside nesting too deep to walk recursively is still found.",
           ["--attestation", A + "dup-deep.json"] + COMMON, 1, "duplicate_key", "duplicate_key")

    g.edit_text("jwks/issuer-compact.json", "jwks/trailing-text.json", lambda t: t + " trailing")
    g.case("jwks-trailing-text", "A key document with text after the JSON: could not check (2).",
           ["--attestation", A + "valid.json"] + common(jwks="jwks/trailing-text.json"), 2, "not_strict_json",
           "is not strict JSON")

    g.attest(A + "dup-header.json", header=["x=1"])

    def dup_hdr(t):
        d = json.loads(t)
        h, p, s = d["attestation"]["signature"].split(".")
        raw = b64d(h).decode().replace('"x":"1"', '"typ":"application/attest+jws"')
        d["attestation"]["signature"] = ".".join([b64e(raw.encode()), p, s])
        return json.dumps(d)
    g.edit_text(A + "dup-header.json", A + "dup-header.json", dup_hdr)
    g.case("dup-header-member", "A protected header with a duplicated member.",
           ["--attestation", A + "dup-header.json"] + COMMON, 1, "header_not_allowed", "header members are")

    # ---- revocation ----------------------------------------------------------
    S = "status-lists/"
    g.status(S + "empty.json", issued_at=LIST_AT, next_update=LIST_NEXT, seq=7)
    g.status(S + "revokes-key.json", issued_at=LIST_AT, next_update=LIST_NEXT, seq=8,
             revoke_kid=[issuer_kid])
    g.status(S + "revokes-subject-after.json", issued_at=LIST_AT, next_update=LIST_NEXT, seq=8,
             revoke_subject=[SLUG + "@2026-01-01T00:10:00.000Z"])
    g.status(S + "revokes-subject-before.json", issued_at=LIST_AT, next_update=LIST_NEXT, seq=8,
             revoke_subject=[SLUG + "@2025-12-31T23:00:00.000Z"])
    g.status(S + "signed-by-attestation-key.json", key=K_ISSUER, issued_at=LIST_AT, next_update=LIST_NEXT)
    g.status(S + "late-empty.json", issued_at="2026-01-01T23:00:00.000Z",
             next_update="2026-01-02T01:00:00.000Z", seq=9)
    g.status(S + "late-revokes-key.json", issued_at="2026-01-01T23:00:00.000Z",
             next_update="2026-01-02T01:00:00.000Z", seq=9, revoke_kid=[issuer_kid])

    SK = ["--status-list", "--status-keys", J_STATUS]
    SL = SK + ["--attestation", A + "valid.json"] + COMMON
    sha_empty = sha_status(g, S + "empty.json")

    g.case("status-good", "A genuine document on a verified list that revokes nothing is good.",
           SL + ["--status", S + "empty.json"], 0, "good", "GOOD — not revoked, per a verified status list",
           canonical_sha256=sha_valid, status_canonical_sha256=sha_empty)
    g.case("status-revoked-key", "The document's signing key is revoked (Rule K).",
           SL + ["--status", S + "revokes-key.json"], 1, "revoked_key", "REVOKED — via key")
    g.case("status-revoked-subject", "The document was minted before its subject was withdrawn (Rule B).",
           SL + ["--status", S + "revokes-subject-after.json"], 1, "revoked_subject", "REVOKED — via subject")
    g.case("status-good-after-withdrawal", "A document minted after the withdrawal notBefore is good.",
           SL + ["--status", S + "revokes-subject-before.json"], 0, "good",
           "GOOD — not revoked, per a verified status list")

    g.edit(S + "revokes-key.json", S + "stripped-revocation.json",
           lambda d: d["statusList"].__setitem__("keys", []))
    g.case("status-stripped-revocation", "A revocation removed from a list after signing is UNKNOWN, never good.",
           SL + ["--status", S + "stripped-revocation.json"], 3, "status_unknown_bad_signature", "bad_signature")
    g.case("status-wrong-key", "A list signed with the ATTESTATION key is UNKNOWN (key sets are disjoint).",
           SL + ["--status", S + "signed-by-attestation-key.json"], 3, "status_unknown_unknown_kid", "unknown_kid")
    g.case("status-stale", "A list past nextUpdate is UNKNOWN, never good.",
           SK + ["--status", S + "empty.json", "--check-kid", issuer_kid, "--now", str(NOW_LATE)], 3,
           "status_unknown_stale", "stale")
    g.case("status-rolled-back", "A list older than one already accepted (--min-seq) is UNKNOWN.",
           SL + ["--status", S + "empty.json", "--min-seq", "8"], 3, "status_unknown_rolled_back", "rolled_back")
    g.case("status-attached-jws-revoked", "An attached JWS alone does not dodge a subject withdrawal.",
           SK + ["--status", S + "revokes-subject-after.json", "--jws", "jws/valid-attached.jws"] + COMMON,
           1, "revoked_subject", "REVOKED — via subject")

    g.edit(S + "empty.json", S + "truncated-truthy.json",
           lambda d: d["statusList"].__setitem__("truncated", "yes"))
    g.case("status-truncated-not-boolean", "A list whose truncated flag is not a boolean is UNKNOWN.",
           SL + ["--status", S + "truncated-truthy.json"], 3, "status_unknown_truncated_invalid",
           "truncated must be a boolean")

    g.compact(S + "revokes-key.json", S + "revokes-key-compact.json")
    g.edit_text(S + "revokes-key-compact.json", S + "dup-member.json",
                lambda t: t.replace('"keys":', '"keys":[],"keys":', 1))
    g.case("status-dup-member", "A status list with a duplicated member is UNKNOWN.",
           SL + ["--status", S + "dup-member.json"], 3, "status_unknown_duplicate_key", "duplicate_key")

    def bom(p):
        open(p, "wb").write(b"\xef\xbb\xbf" + open(g.path(S + "dup-member.json"), "rb").read())
    g.make(S + "bom-prefixed.json", bom)
    g.case("status-bom", "A status list jq accepts but a strict parser does not is UNKNOWN.",
           SL + ["--status", S + "bom-prefixed.json"], 3, "status_unknown_not_strict_json", "is not strict JSON")

    LATE = SK + ["--attestation", A + "valid.json"] + late
    g.case("status-expired-under-good-list", "A genuine expired document under a good list says it expired.",
           LATE + ["--status", S + "late-empty.json"], 1, "expired",
           "EXPIRED — the signature is valid, but this attestation expired on " + EXP + ".")
    g.case("status-expired-under-revoking-list",
           "A genuine expired document whose key is revoked reports the revocation.",
           LATE + ["--status", S + "late-revokes-key.json"], 1, "revoked_key", "REVOKED — via key",
           absent=["the signature is valid"])

    def decoy_rev(d):
        c = d["attestation"]["claims"]
        c["posture"] = {"x": {"generatedAt": "2026-01-01T00:12:00.000Z"}, **c["posture"]}
    g.edit(A + "valid.json", A + "decoy-generated-at.json", decoy_rev)
    g.case("status-decoy-generated-at", "An unsigned decoy generatedAt does not dodge a subject withdrawal.",
           SK + ["--status", S + "revokes-subject-after.json", "--attestation", A + "decoy-generated-at.json"]
           + COMMON, 1, "unsigned_member", "unsigned_member")


def write_outputs(g):
    mpath = g.path("vectors.json")
    cases = g.cases
    if g.mode == "extend" and os.path.exists(mpath):
        old = json.load(open(mpath))["cases"]
        have = {c["id"] for c in old}
        cases = old + [c for c in g.cases if c["id"] not in have]
    doc = {
        "format": "attest.attestation.v1",
        "statusListFormat": "attest.statuslist.v1",
        "vectorsVersion": "v1",
        "note": "Paths are relative to this directory; run the verifier from here. "
                "expect.exit and expect.code are the contract; expect.match is the "
                "reference script's English.",
        "cases": cases,
    }
    with open(mpath, "w") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    sums = []
    for dp, _, fns in os.walk(V1):
        for fn in fns:
            rel = os.path.relpath(os.path.join(dp, fn), V1)
            if rel != "SHA256SUMS":
                sums.append((rel, hashlib.sha256(open(os.path.join(dp, fn), "rb").read()).hexdigest()))
    with open(g.path("SHA256SUMS"), "w") as fh:
        for rel, h in sorted(sums):
            fh.write("%s  %s\n" % (h, rel))
    return len(cases)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--extend", action="store_true", help="add missing files and cases only")
    ap.add_argument("--force", action="store_true", help="overwrite existing files")
    a = ap.parse_args()
    if a.extend and a.force:
        raise SystemExit("gen_vectors: --extend and --force are exclusive")
    mode = "force" if a.force else "extend" if a.extend else "new"
    if mode == "new":
        existing = []
        for dp, _, fns in os.walk(V1):
            for f in fns:
                rel = os.path.relpath(os.path.join(dp, f), V1)
                if not rel.startswith("keys" + os.sep) and rel != "README.md":
                    existing.append(rel)
        if existing:
            raise SystemExit("gen_vectors: refusing to overwrite %d existing file(s) in tests/vectors/v1 "
                             "(first: %s). Use --extend to add cases, --force to overwrite."
                             % (len(existing), existing[0]))
    g = Gen(mode)
    build(g)
    n = write_outputs(g)
    print("gen_vectors: %d cases, mode %s" % (n, mode))


if __name__ == "__main__":
    main()
