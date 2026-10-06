#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
"""Mint signed ATTEST test documents with a throwaway ML-DSA-65 key.

This is the issuer side the tests need and the verifier must never share code
with: the canonical encoders below are written again from the wire formats in
docs/security/attest-verification.md §4.4 (attestation envelope E1..E7 wrapping
posture F1..F8) and the status-list format (S-rules), NOT imported from
scripts/attest/verify-attestation.sh. If the two ever disagree, the valid case
in tests/run.sh fails, which is the point.

tests/run.sh generates every key at test time into a temporary directory. The
only private keys committed to this repository are the TEST-ONLY keys of the
published vectors (tests/vectors/v1/keys), which sign nothing real, so nothing
here can mint a document that verifies against a key anybody trusts.

Signing uses OpenSSL >= 3.5 (`openssl pkeyutl -sign -rawin`), empty ML-DSA
context string, exactly as RFC 9964 specifies for JOSE.
"""
import argparse
import base64
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import uuid

SPKI_PREFIX = bytes.fromhex("308207b2300b0609608648016503040312038207a100")
KID_DOMAIN = b"hodei-shield.attest.kid.v1"
SUBJECT_DOMAIN = b"hodei-shield.attest.subject.v1"
ATTEST_TYP = "application/attest+jws"
STATUS_TYP = "application/attest-status+jws"


def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


# --- length-prefixed canonical encoding -------------------------------------
def _u64be(n):
    return struct.pack(">Q", n)


def _bytes(b):
    return _u64be(len(b)) + b


def _str(s):
    return _bytes(s.encode("utf-8"))


def _opt(s):
    return b"\x00" if s is None else b"\x01" + _str(s)


def _u64(n):
    return _bytes(_u64be(n))


def posture_bytes(p):
    fw = sorted(p["frameworks"], key=lambda f: f["code"].encode("utf-8"))
    out = [b"hodei-shield.attest.posture.v1", _str(p["version"]), _str(p["slug"]),
           _str(p["orgName"]), _str(p["visibility"]), _str(p["generatedAt"]),
           _opt(p.get("expiresAt")), _opt(p.get("lastCheckedAt")), _u64(len(fw))]
    for f in fw:
        out += [_str(f["code"]), _str(f["label"]), _str(f["band"])]
    return b"".join(out)


def envelope_bytes(c):
    return b"".join([b"hodei-shield.attest.attestation.v1", _str(c["docVersion"]),
                     _str(c["iss"]), _str(c["kid"]), _opt(c.get("jti")),
                     _opt(c.get("nonce")), _opt(c.get("overallBand")),
                     _bytes(posture_bytes(c["posture"]))])


def statuslist_bytes(L):
    ke = sorted(L["keys"], key=lambda e: e["kid"].encode("utf-8"))
    se = sorted(L["subjects"], key=lambda e: e["subjectHash"].encode("utf-8"))
    out = [b"hodei-shield.attest.statuslist.v1", _str(L["docVersion"]), _str(L["iss"]),
           _str(L["kid"]), _u64(L["seq"]), _str(L["issuedAt"]), _str(L["nextUpdate"]),
           _u64(1 if L["truncated"] else 0), _u64(len(ke))]
    for e in ke:
        out += [_str(e["kid"]), _str(e["reason"]), _str(e["revokedAt"])]
    out += [_u64(len(se))]
    for e in se:
        out += [_str(e["subjectHash"]), _str(e["reason"]), _str(e["notBefore"]), _str(e["expiresAt"])]
    return b"".join(out)


# --- keys ---------------------------------------------------------------------
def openssl(*args, data=None):
    return subprocess.run(["openssl", *args], input=data, check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def raw_pub(key_pem):
    der = openssl("pkey", "-in", key_pem, "-pubout", "-outform", "DER")
    if not der.startswith(SPKI_PREFIX) or len(der) != len(SPKI_PREFIX) + 1952:
        raise SystemExit("mint: unexpected ML-DSA-65 SPKI encoding")
    return der[len(SPKI_PREFIX):]


def kid_of(pub):
    return b64url(hashlib.sha256(KID_DOMAIN + pub).digest()[:16])


def sign(key_pem, message):
    with tempfile.NamedTemporaryFile(delete=False) as fh:
        fh.write(message)
        path = fh.name
    try:
        return openssl("pkeyutl", "-sign", "-inkey", key_pem, "-rawin", "-in", path)
    finally:
        os.unlink(path)


def detached_jws(key_pem, kid, typ, payload, extra_header=None):
    hdr = {"alg": "ML-DSA-65", "kid": kid, "typ": typ, **(extra_header or {})}
    header = b64url(json.dumps(hdr, separators=(",", ":")).encode("utf-8"))
    sig = sign(key_pem, (header + "." + b64url(payload)).encode("ascii"))
    return header + ".." + b64url(sig)


def cmd_keygen(a):
    openssl("genpkey", "-algorithm", "ML-DSA-65", "-out", a.out)
    os.chmod(a.out, 0o600)
    pub = raw_pub(a.out)
    jwk = {"kty": "AKP", "alg": "ML-DSA-65", "pub": b64url(pub), "kid": kid_of(pub), "use": "sig"}
    with open(a.jwks, "w") as fh:
        json.dump({"keys": [jwk]}, fh, indent=2)
    print(jwk["kid"])


# --- documents ------------------------------------------------------------------
def cmd_attest(a):
    kid = kid_of(raw_pub(a.key))
    frameworks = [{"code": c, "label": c.upper(), "band": b}
                  for c, b in (x.split("=", 1) for x in a.framework)]
    posture = {
        "version": "attest.posture.v1", "slug": a.slug, "orgName": a.org,
        "visibility": a.visibility, "generatedAt": a.generated_at,
        "expiresAt": None if a.expires_at == "none" else a.expires_at,
        "lastCheckedAt": a.generated_at, "frameworks": frameworks,
    }
    ranks = ["in_progress", "basic", "substantial", "advanced"]
    band = min((f["band"] for f in frameworks), key=ranks.index) if frameworks else None
    if a.overall_band is not None:
        band = a.overall_band
    claims = {"docVersion": "attest.attestation.v1", "iss": a.iss, "kid": kid,
              "jti": str(uuid.uuid4()), "nonce": a.nonce, "overallBand": band,
              "posture": posture}
    payload = envelope_bytes(claims)
    doc = {"attestation": {"claims": claims,
                           "signature": detached_jws(a.key, kid, ATTEST_TYP, payload,
                                                     dict(h.split("=", 1) for h in a.header)),
                           "digest": hashlib.sha256(payload).hexdigest()}}
    with open(a.out, "w") as fh:
        json.dump(doc, fh, indent=2)


def cmd_attach(a):
    """Re-serialise a detached document's signature as an ATTACHED compact JWS.

    Needs no key: the signature is over protected.payload either way, so this is
    something anybody holding a public document can do."""
    att = json.load(open(a.doc))["attestation"]
    h, _, s = att["signature"].split(".")
    with open(a.out, "w") as fh:
        fh.write(h + "." + b64url(envelope_bytes(att["claims"])) + "." + s + "\n")


def subject_hash(slug):
    return b64url(hashlib.sha256(SUBJECT_DOMAIN + slug.encode("utf-8")).digest())


def cmd_status(a):
    kid = kid_of(raw_pub(a.key))
    keys = [{"kid": k, "reason": "key_compromise", "revokedAt": a.issued_at} for k in a.revoke_kid]
    subjects = []
    for spec in a.revoke_subject:
        slug, not_before = spec.split("@", 1)
        subjects.append({"subjectHash": subject_hash(slug), "reason": "subject_withdrawn",
                         "notBefore": not_before, "expiresAt": a.next_update})
    lst = {"docVersion": "attest.statuslist.v1", "iss": a.iss, "kid": kid, "seq": a.seq,
           "issuedAt": a.issued_at, "nextUpdate": a.next_update, "truncated": False,
           "keys": keys, "subjects": subjects}
    doc = {"statusList": lst,
           "signature": detached_jws(a.key, kid, STATUS_TYP, statuslist_bytes(lst))}
    with open(a.out, "w") as fh:
        json.dump(doc, fh, indent=2)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen")
    k.add_argument("--out", required=True)
    k.add_argument("--jwks", required=True)
    k.set_defaults(fn=cmd_keygen)

    t = sub.add_parser("attest")
    t.add_argument("--key", required=True)
    t.add_argument("--out", required=True)
    t.add_argument("--slug", required=True)
    t.add_argument("--org", default="Fixture Org (test only)")
    t.add_argument("--iss", required=True)
    t.add_argument("--generated-at", required=True)
    t.add_argument("--expires-at", required=True, help='RFC 3339, or "none" to omit it')
    t.add_argument("--nonce", default=None)
    t.add_argument("--visibility", default="public")
    t.add_argument("--framework", action="append", default=[], help="code=band")
    t.add_argument("--header", action="append", default=[],
                   help="name=value: an extra protected-header member, signed")
    t.add_argument("--overall-band", default=None,
                   help="sign this overallBand instead of the derived one (an overclaiming issuer)")
    t.set_defaults(fn=cmd_attest)

    x = sub.add_parser("attach")
    x.add_argument("--doc", required=True)
    x.add_argument("--out", required=True)
    x.set_defaults(fn=cmd_attach)

    s = sub.add_parser("status")
    s.add_argument("--key", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--iss", required=True)
    s.add_argument("--seq", type=int, default=1)
    s.add_argument("--issued-at", required=True)
    s.add_argument("--next-update", required=True)
    s.add_argument("--revoke-kid", action="append", default=[])
    s.add_argument("--revoke-subject", action="append", default=[], help="slug@notBefore")
    s.set_defaults(fn=cmd_status)

    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
