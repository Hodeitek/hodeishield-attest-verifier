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

    def attest(self, rel, key=K_ISSUER, **kw):
        """mint.py attest with the fixture defaults; kw overrides."""
        o = {"slug": SLUG, "iss": ISS, "generated-at": GEN, "expires-at": EXP}
        o.update({k.replace("_", "-"): v for k, v in kw.items()})
        fw = o.pop("framework", ["iso27001=substantial", "nis2=basic"])
        hdr = o.pop("header", [])

        def f(p):
            a = ["attest", "--key", self.path(key), "--out", p]
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
             canonical_sha256=None, status_canonical_sha256=None, signature_only=False):
        if id in self.known:
            raise SystemExit("gen_vectors: case id %r used twice" % id)
        self.known.add(id)
        e = {"exit": exit, "code": code, "match": match}
        if absent:
            e["absent"] = absent
        c = {"id": id, "description": description, "args": args, "expect": e}
        if signature_only:
            c["signature_only"] = True
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

    build_signature_cases(g, A, S, SL, COMMON, issuer_kid)
    build_retired_cases(g, A, S, issuer_kid)


def common_with(common, jwks):
    out = list(common)
    out[out.index("--jwks") + 1] = jwks
    return out


def build_signature_cases(g, A, S, SL, COMMON, issuer_kid):
    """Added 2026-10-06 (follow-up to the first publication): vectors that
    exercise the signature check itself.

    Group A (signature_only: true): every other check passes, so only the
    signature check stands between the document and exit 0 / good. A verifier
    whose signature check always passes accepts every one of these.
    Group B (no flag): structural signature cases rejected by checks that run
    independently of the signature (size, alg, kid derivation, claims.kid)."""
    other_kid = json.load(open(g.path(J_OTHER)))["keys"][0]["kid"]
    status_kid = json.load(open(g.path(J_STATUS)))["keys"][0]["kid"]

    def both_keys(p):
        i = json.load(open(g.path(J_ISSUER)))["keys"]
        o = json.load(open(g.path(J_OTHER)))["keys"]
        json.dump({"keys": i + o}, open(p, "w"), indent=2)
    g.make("jwks/issuer-and-other.json", both_keys)

    def att(rel):
        return ["--attestation", rel] + COMMON

    SIGFAIL = (1, "signature_invalid", "SIGNATURE DOES NOT VERIFY")
    SIGFAIL_S = (3, "status_unknown_bad_signature", "bad_signature")

    def sig_only(id, desc, args):
        g.case(id, desc + " Only the signature check rejects it.", args, *SIGFAIL, signature_only=True)

    def sig_only_s(id, desc, args):
        g.case(id, desc + " Only the signature check rejects it.", args, *SIGFAIL_S, signature_only=True)

    # ---- Group A, payload manipulations (signature untouched) -----------------
    def pst(c):
        return c["posture"]
    manip = [
        ("orgname-char", "One character of the signed orgName changed.",
         lambda c: pst(c).__setitem__("orgName", pst(c)["orgName"][:-1] + "z")),
        ("lastchecked-plus-1s", "lastCheckedAt moved by one second.",
         lambda c: pst(c).__setitem__("lastCheckedAt", "2026-01-01T00:00:01.000Z")),
        ("generatedat-plus-1s", "generatedAt moved by one second (still fresh).",
         lambda c: pst(c).__setitem__("generatedAt", "2026-01-01T00:00:01.000Z")),
        ("expiresat-plus-1s", "expiresAt moved by one second (still within the issuer ceiling).",
         lambda c: pst(c).__setitem__("expiresAt", "2026-01-01T00:15:01.000Z")),
        ("framework-label", "One framework label changed.",
         lambda c: pst(c)["frameworks"][0].__setitem__("label", "ISO27002")),
        ("framework-band-nonweakest", "A non-weakest framework band raised, so overallBand stays consistent.",
         lambda c: pst(c)["frameworks"][0].__setitem__("band", "advanced")),
        ("framework-code", "One framework code renamed.",
         lambda c: pst(c)["frameworks"][1].__setitem__("code", "nis3")),
        ("jti", "The signed jti replaced.",
         lambda c: c.__setitem__("jti", "00000000-0000-4000-8000-000000000000")),
        ("nonce-added", "A nonce added to a document signed without one (no --expect-nonce given).",
         lambda c: c.__setitem__("nonce", "added-after-signing")),
    ]
    for name, desc, fn in manip:
        g.edit(A + "valid.json", A + "sigonly-" + name + ".json",
               lambda d, fn=fn: fn(d["attestation"]["claims"]))
        sig_only("sigonly-att-" + name, desc, att(A + "sigonly-" + name + ".json"))

    def claims_file(p):
        d = json.load(open(g.path("claims/valid.json")))
        d["posture"]["orgName"] = d["posture"]["orgName"][:-1] + "z"
        json.dump(d, open(p, "w"), indent=2)
    g.make("claims/sigonly-orgname-char.json", claims_file)
    sig_only("sigonly-att-claims-file", "A detached JWS with a claims file whose orgName was changed.",
             ["--jws", "jws/valid-detached.jws", "--claims", "claims/sigonly-orgname-char.json"] + COMMON)

    # ---- Group A, signature bytes flipped, length kept at 3309 ----------------
    def flip(pos, status=False):
        def fn(d):
            sig = d["signature"] if status else d["attestation"]["signature"]
            h, p, s = sig.split(".")
            raw = bytearray(b64d(s))
            assert len(raw) == 3309
            raw[pos] ^= 0x01
            new = ".".join([h, p, b64e(bytes(raw))])
            if status:
                d["signature"] = new
            else:
                d["attestation"]["signature"] = new
        return fn
    for name, pos in (("start", 0), ("middle", 1654), ("end", 3308)):
        g.edit(A + "valid.json", A + "sigonly-flip-" + name + ".json", flip(pos))
        sig_only("sigonly-att-sig-flip-" + name,
                 "One bit of signature byte %d of 3309 flipped; the length is unchanged." % pos,
                 att(A + "sigonly-flip-" + name + ".json"))

    # ---- Group A, wrong signer / transplanted signature -----------------------
    g.attest(A + "sigonly-signed-by-other.json", key=K_OTHER, declare_kid=issuer_kid)
    sig_only("sigonly-att-signed-by-other-key",
             "Signed with an unrelated key but presented under the issuer's kid (header kid and claims.kid).",
             att(A + "sigonly-signed-by-other.json"))

    g.attest(A + "donor-advanced.json", framework=["iso27001=advanced", "nis2=advanced"])

    def transplant(d):
        donor = json.load(open(g.path(A + "donor-advanced.json")))
        d["attestation"]["signature"] = donor["attestation"]["signature"]
    g.edit(A + "valid.json", A + "sigonly-transplanted.json", transplant)
    sig_only("sigonly-att-transplanted-signature",
             "A genuine signature from another attestation (other posture, same key and header) put on this "
             "document's claims.", att(A + "sigonly-transplanted.json"))

    g.attest(A + "sigonly-kid-switch.json", key=K_ISSUER, declare_kid=other_kid)
    sig_only("sigonly-att-kid-switch-consistent",
             "Header kid and claims.kid both name the OTHER key, a key set holds both keys, and the signature "
             "is by the issuer key.",
             ["--attestation", A + "sigonly-kid-switch.json"] + common_with(COMMON, "jwks/issuer-and-other.json"))

    # ---- Group A, status lists -----------------------------------------------
    s_manip = [
        ("seq", "The signed seq changed.", lambda L: L.__setitem__("seq", 6)),
        ("nextupdate-plus-1s", "nextUpdate moved by one second.",
         lambda L: L.__setitem__("nextUpdate", "2026-01-01T02:00:01.000Z")),
        ("issuedat-plus-1s", "issuedAt moved by one second.",
         lambda L: L.__setitem__("issuedAt", "2026-01-01T00:00:01.000Z")),
    ]
    for name, desc, fn in s_manip:
        g.edit(S + "empty.json", S + "sigonly-" + name + ".json",
               lambda d, fn=fn: fn(d["statusList"]))
        sig_only_s("sigonly-status-" + name, "A status list: " + desc,
                   SL + ["--status", S + "sigonly-" + name + ".json"])
    for name, pos in (("start", 0), ("middle", 1654), ("end", 3308)):
        g.edit(S + "empty.json", S + "sigonly-flip-" + name + ".json", flip(pos, status=True))
        sig_only_s("sigonly-status-sig-flip-" + name,
                   "A status list with one bit of signature byte %d of 3309 flipped." % pos,
                   SL + ["--status", S + "sigonly-flip-" + name + ".json"])

    def stransplant(d):
        d["signature"] = json.load(open(g.path(S + "revokes-key.json")))["signature"]
    g.edit(S + "empty.json", S + "sigonly-transplanted.json", stransplant)
    sig_only_s("sigonly-status-transplanted-signature",
               "A status list carrying the genuine signature of a different list (same key and header).",
               SL + ["--status", S + "sigonly-transplanted.json"])

    g.status(S + "sigonly-signed-by-other.json", key=K_OTHER, issued_at=LIST_AT, next_update=LIST_NEXT,
             seq=7, declare_kid=status_kid)
    sig_only_s("sigonly-status-signed-by-other-key",
               "A status list signed with an unrelated key under the status kid.",
               SL + ["--status", S + "sigonly-signed-by-other.json"])

    # ---- Group B: structural signature cases ----------------------------------
    def resize(delta, status=False):
        def fn(d):
            sig = d["signature"] if status else d["attestation"]["signature"]
            h, p, s = sig.split(".")
            raw = b64d(s)
            raw = raw[:delta] if delta < 0 else raw + b"\x00" * delta
            new = ".".join([h, p, b64e(raw)])
            if status:
                d["signature"] = new
            else:
                d["attestation"]["signature"] = new
        return fn
    g.edit(A + "valid.json", A + "sig-truncated.json", resize(-1))
    g.case("sig-truncated-3308", "The signature one byte short (3308 bytes).",
           att(A + "sig-truncated.json"), 1, "signature_size_invalid",
           "signature is 3308 bytes, expected 3309")
    g.edit(A + "valid.json", A + "sig-extended.json", resize(1))
    g.case("sig-extended-3310", "The signature one byte long (3310 bytes).",
           att(A + "sig-extended.json"), 1, "signature_size_invalid",
           "signature is 3310 bytes, expected 3309")

    for name, alg in (("ml-dsa-44", "ML-DSA-44"), ("ml-dsa-87", "ML-DSA-87"),
                      ("eddsa", "EdDSA"), ("empty", "")):
        g.attest(A + "alg-" + name + ".json", header=["alg=" + alg])
        g.case("alg-" + name, "A signed protected header whose alg is %r instead of ML-DSA-65." % alg,
               att(A + "alg-" + name + ".json"), 1, "header_alg_invalid",
               "alg is '%s', expected 'ML-DSA-65'" % alg)

    def relabel(d):
        d["keys"][0]["kid"] = "AAAAAAAAAAAAAAAAAAAAAA"
    g.edit(J_ISSUER, "jwks/issuer-relabelled.json", relabel)
    g.attest(A + "header-kid-not-from-key.json", declare_kid="AAAAAAAAAAAAAAAAAAAAAA")
    g.case("header-kid-not-derived-from-key",
           "A validly signed document whose header and claims kid is not the one the key bytes derive, "
           "listed under that kid in the key set.",
           ["--attestation", A + "header-kid-not-from-key.json"]
           + common_with(COMMON, "jwks/issuer-relabelled.json"), 1, "kid_mismatch", "kid mismatch — header says")

    g.attest(A + "claims-kid-differs.json", claims_kid=other_kid)
    g.case("claims-kid-differs-from-header-kid",
           "A validly signed document whose signed claims.kid names another key than the header kid.",
           att(A + "claims-kid-differs.json"), 1, "kid_mismatch", "kid_mismatch — the header says")
    g.attest(A + "claims-kid-differs-other-signer.json", key=K_OTHER, claims_kid=issuer_kid)
    g.case("claims-kid-differs-other-signer",
           "Signed by the other key with its own kid in the header, but claims.kid names the issuer key; "
           "the key set holds both.",
           ["--attestation", A + "claims-kid-differs-other-signer.json"]
           + common_with(COMMON, "jwks/issuer-and-other.json"), 1, "kid_mismatch",
           "kid_mismatch — the header says")

    g.edit(S + "empty.json", S + "sig-truncated.json", resize(-1, status=True))
    g.case("status-sig-truncated-3308", "A status list signature one byte short (3308 bytes).",
           SL + ["--status", S + "sig-truncated.json"], 3, "status_unknown_signature_size",
           "signature is 3308 bytes, expected 3309")
    g.edit(S + "empty.json", S + "sig-extended.json", resize(1, status=True))
    g.case("status-sig-extended-3310", "A status list signature one byte long (3310 bytes).",
           SL + ["--status", S + "sig-extended.json"], 3, "status_unknown_signature_size",
           "signature is 3310 bytes, expected 3309")
    for name, alg in (("ml-dsa-44", "ML-DSA-44"), ("eddsa", "EdDSA")):
        g.status(S + "alg-" + name + ".json", issued_at=LIST_AT, next_update=LIST_NEXT, seq=7,
                 header=["alg=" + alg])
        g.case("status-alg-" + name, "A status list whose signed header alg is %r." % alg,
               SL + ["--status", S + "alg-" + name + ".json"], 3, "status_unknown_unsupported_alg",
               "alg is '%s', expected 'ML-DSA-65'" % alg)


def build_retired_cases(g, A, S, issuer_kid):
    """Retired keys: the hs_retired_at member of a JWK, for both key sets."""
    def common(now, jwks=J_ISSUER):
        return ["--jwks", jwks, "--expect-slug", SLUG, "--expect-issuer", ISS, "--now", str(now)]

    # ---- retired keys (hs_retired_at), added for v1.3.0 ------------------------
    RET = "2026-07-31T18:53:58Z"
    RET_BEFORE = "2026-07-31T18:53:57.999Z"    # one millisecond before RET
    RET_AT = "2026-07-31T18:53:58.000Z"        # exactly RET
    RET_NOW = 1785524038                       # RET as an epoch

    def with_retired(src, dst, value, index=0):
        def fn(d):
            d["keys"][index]["hs_retired_at"] = value
        g.edit(src, dst, fn)

    g.attest(A + "retired-before.json", generated_at=RET_BEFORE, expires_at="2026-07-31T19:08:57.999Z")
    g.attest(A + "retired-at.json", generated_at=RET_AT, expires_at="2026-07-31T19:08:58.000Z")
    sha_rb = sha_envelope(g, A + "retired-before.json")
    with_retired(J_ISSUER, "jwks/retired.json", RET)
    g.case("retired-key-before", "The key is retired at 2026-07-31T18:53:58Z; the document was generated one "
           "millisecond earlier (18:53:57.999Z): it verifies and says the key is retired.",
           ["--attestation", A + "retired-before.json"] + common(RET_NOW, jwks="jwks/retired.json"),
           0, "verified", "but this document was generated at 2026-07-31T18:53:57.999Z, before the retirement",
           canonical_sha256=sha_rb)
    g.case("retired-key-at", "The same retired key; the document was generated exactly at the retirement "
           "(18:53:58.000Z): a failed check, not an expiry.",
           ["--attestation", A + "retired-at.json"] + common(RET_NOW, jwks="jwks/retired.json"),
           1, "retired_key", "retired_key \u2014 this document was generated at 2026-07-31T18:53:58.000Z, "
           "at or after the retirement of key " + issuer_kid + " at 2026-07-31T18:53:58Z",
           absent=["EXPIRED"])
    g.case("retired-key-pinned", "--expect-kid pinned to the retired kid does not rescue a document generated "
           "at the retirement.",
           ["--attestation", A + "retired-at.json", "--expect-kid", issuer_kid]
           + common(RET_NOW, jwks="jwks/retired.json"),
           1, "retired_key", "retired_key \u2014 this document was generated at", absent=["EXPIRED"])
    with_retired(J_ISSUER, "jwks/retired-malformed.json", "2026-07-31T18:53:58.000Z")
    g.case("retired-key-malformed", "hs_retired_at carries a fraction: the key set is invalid, could not check (2).",
           ["--attestation", A + "retired-at.json"] + common(RET_NOW, jwks="jwks/retired-malformed.json"),
           2, "jwks_retired_at_malformed", "hs_retired_at of the key '" + issuer_kid + "' is")

    def other_retired(value):
        def fn(p):
            d = json.load(open(g.path("jwks/issuer-and-other.json")))
            d["keys"][1]["hs_retired_at"] = value
            json.dump(d, open(p, "w"), indent=2)
        return fn
    g.make("jwks/retired-other-key.json", other_retired("2026-01-01T00:00:00Z"))
    g.case("retired-other-key-ignored", "Another key in the set is retired long before the document; the "
           "selected key is not, so nothing changes.",
           ["--attestation", A + "retired-at.json"] + common(RET_NOW, jwks="jwks/retired-other-key.json"),
           0, "verified", "VERIFIED \u2014 this document was signed", absent=["retired"])
    g.make("jwks/retired-other-key-malformed.json", other_retired("not a time"))
    g.case("retired-other-key-malformed-ignored", "Another key in the set carries a malformed hs_retired_at; "
           "only the selected key's member is read.",
           ["--attestation", A + "retired-at.json"] + common(RET_NOW, jwks="jwks/retired-other-key-malformed.json"),
           0, "verified", "VERIFIED \u2014 this document was signed", absent=["retired"])

    SR_COMMON = ["--attestation", A + "retired-before.json"] + common(RET_NOW)
    g.status(S + "retired-before.json", issued_at=RET_BEFORE, next_update="2026-07-31T20:53:57.999Z", seq=10)
    g.status(S + "retired-at.json", issued_at=RET_AT, next_update="2026-07-31T20:53:58.000Z", seq=10)
    with_retired(J_STATUS, "jwks/status-retired.json", RET)
    with_retired(J_STATUS, "jwks/status-retired-malformed.json", "2026-07-31 18:53:58Z")
    SKR = ["--status-list", "--status-keys", "jwks/status-retired.json"] + SR_COMMON
    g.case("status-retired-key-before", "The status key is retired at 2026-07-31T18:53:58Z; the list was issued one "
           "millisecond earlier: it is trusted.",
           SKR + ["--status", S + "retired-before.json"], 0, "good",
           "but this list was issued at 2026-07-31T18:53:57.999Z, before the retirement")
    g.case("status-retired-key-at", "The list was issued exactly at the retirement of its key: not trusted, unknown.",
           SKR + ["--status", S + "retired-at.json"], 3, "status_unknown_retired_key",
           "retired_key \u2014 this status list was issued at 2026-07-31T18:53:58.000Z, at or after the retirement of key")
    g.case("status-retired-key-malformed", "hs_retired_at of the status key is not RFC 3339 UTC: the status key set "
           "is defective, unknown (3), as for any other defect in it.",
           ["--status-list", "--status-keys", "jwks/status-retired-malformed.json"] + SR_COMMON
           + ["--status", S + "retired-before.json"], 3, "status_unknown_retired_at_malformed",
           "malformed_document \u2014 hs_retired_at of the --status-keys entry")

    # Key sets that cannot be read one way: the first entry would win, so a
    # retirement marker could be dodged by ordering.
    def reshape(kind, marker):
        def fn(d):
            k = d["keys"][0]
            if kind == "dup":
                d["keys"] = [dict(k), dict(k, hs_retired_at=marker)]
            elif kind == "object":
                d["keys"] = {"a": dict(k, hs_retired_at=marker)}
            else:
                d["keys"] = ["str", dict(k)]
        return fn
    g.edit(J_ISSUER, "jwks/duplicate-kid.json", reshape("dup", RET))
    g.case("jwks-duplicate-kid", "Two keys carry the same kid, the second marked retired: the key set is invalid, "
           "could not check (2).",
           ["--attestation", A + "retired-before.json"] + common(RET_NOW, jwks="jwks/duplicate-kid.json"),
           2, "jwks_duplicate_kid", "two of its keys carry the same kid")
    g.edit(J_ISSUER, "jwks/keys-not-array.json", reshape("object", RET))
    g.case("jwks-keys-not-array", "`keys` is an object, not an array: the key set is invalid, could not check (2).",
           ["--attestation", A + "retired-before.json"] + common(RET_NOW, jwks="jwks/keys-not-array.json"),
           2, "jwks_keys_not_array", "keys` is not an array of objects")
    g.edit(J_STATUS, "jwks/status-duplicate-kid.json", reshape("dup", RET))
    g.case("status-keys-duplicate-kid", "The status key set has two keys with the same kid: unknown (3).",
           ["--status-list", "--status-keys", "jwks/status-duplicate-kid.json"] + SR_COMMON
           + ["--status", S + "retired-before.json"], 3, "status_unknown_duplicate_kid",
           "duplicate_key \u2014 status-keys.json has two keys with the same kid")
    g.edit(J_STATUS, "jwks/status-keys-object.json", reshape("object", RET))
    g.case("status-keys-not-array", "`keys` of the status key set is an object, whose member carries a retirement "
           "marker: unknown (3), not a list trusted without reading the marker.",
           ["--status-list", "--status-keys", "jwks/status-keys-object.json"] + SR_COMMON
           + ["--status", S + "retired-at.json"], 3, "status_unknown_keys_not_array",
           "malformed_document \u2014 status-keys.json: `keys` is not an array of objects")
    g.edit(J_STATUS, "jwks/status-keys-str-entry.json", reshape("str", RET))
    g.case("status-keys-entry-not-object", "An entry of the status key set's `keys` is a string: unknown (3).",
           ["--status-list", "--status-keys", "jwks/status-keys-str-entry.json"] + SR_COMMON
           + ["--status", S + "retired-before.json"], 3, "status_unknown_keys_not_array",
           "malformed_document \u2014 status-keys.json: `keys` is not an array of objects")


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
