// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.
//
// The canonical encodings of section 4.4 of docs/security/attest-verification.md:
// the envelope (what the signature covers), the posture nested in it, and the
// status list. Ported from CANON_PY, DECODE_PY and CANON_STATUS_PY of
// scripts/attest/verify-attestation.sh. Every function throws an Error on a
// document the encoders refuse; the caller turns that into "could not check".
(function (root) {
  "use strict";
  var HV = root.HV || (root.HV = {});
  var B = HV.base, J = HV.json;

  var ENVELOPE_DOMAIN = B.utf8("hodei-shield.attest.attestation.v1");
  var POSTURE_DOMAIN = B.utf8("hodei-shield.attest.posture.v1");
  var STATUS_DOMAIN = B.utf8("hodei-shield.attest.statuslist.v1");
  var MAX_FIELD_BYTES = 4096;
  var MAX_FRAMEWORKS = 64;
  var REASONS = ["key_compromise", "superseded", "issuer_error", "subject_withdrawn", "unspecified"];

  function u64be(n) {
    var o = new Uint8Array(8), v = BigInt(n);
    for (var i = 7; i >= 0; i--) { o[i] = Number(v & 255n); v >>= 8n; }
    return o;
  }
  function bs(b) { return B.concat([u64be(b.length), b]); }
  function strOf(v, label) {
    if (typeof v !== "string") throw new Error("canonical: " + label + " must be a string");
    var b = B.utf8(v); // throws on an unpaired surrogate (R5)
    if (b.length > MAX_FIELD_BYTES) throw new Error("canonical: " + label + " exceeds " + MAX_FIELD_BYTES + " bytes");
    return bs(b);
  }
  // python: p.get(name) is None for an absent member and for a null one
  function member(o, name) {
    var v = o.get(name);
    return v === undefined ? null : v;
  }
  function opt(v, label) { return v === null ? new Uint8Array([0]) : B.concat([new Uint8Array([1]), strOf(v, label)]); }
  function u64(n) { return bs(u64be(n)); }
  function need(o, name) {
    if (!o.has(name)) throw new Error("canonical: missing " + name);
    return o.get(name);
  }

  function postureBytes(p) {
    if (!J.isObj(p)) throw new Error("canonical: posture must be an object");
    if (member(p, "version") !== "attest.posture.v1") throw new Error("canonical: unsupported posture version");
    var vis = member(p, "visibility");
    if (vis !== "public" && vis !== "gated") throw new Error("canonical: bad visibility");
    var list = need(p, "frameworks");
    if (!Array.isArray(list)) throw new Error("canonical: frameworks must be a list");
    var fw = list.map(function (f) {
      if (!J.isObj(f)) throw new Error("canonical: a framework must be an object");
      var code = need(f, "code");
      if (typeof code !== "string") throw new Error("canonical: code must be a string");
      return { f: f, key: B.utf8(code) };
    });
    fw.sort(function (a, b) { return B.bytesCompare(a.key, b.key); }); // R2: UTF-8 byte order
    if (fw.length > MAX_FRAMEWORKS) throw new Error("canonical: too many frameworks");
    for (var i = 1; i < fw.length; i++) {
      if (B.bytesCompare(fw[i - 1].key, fw[i].key) === 0) throw new Error("canonical: duplicate framework code"); // R3
    }
    var out = [POSTURE_DOMAIN, strOf(need(p, "version"), "version"), strOf(need(p, "slug"), "slug"),
      strOf(need(p, "orgName"), "orgName"), strOf(vis, "visibility"),
      strOf(need(p, "generatedAt"), "generatedAt"), opt(member(p, "expiresAt"), "expiresAt"),
      opt(member(p, "lastCheckedAt"), "lastCheckedAt"), u64(fw.length)];
    fw.forEach(function (e) {
      out.push(strOf(need(e.f, "code"), "code"), strOf(need(e.f, "label"), "label"), strOf(need(e.f, "band"), "band"));
    });
    return B.concat(out);
  }

  function envelopeBytes(c) {
    if (!J.isObj(c)) throw new Error("canonical: claims must be an object");
    if (member(c, "docVersion") !== "attest.attestation.v1") throw new Error("canonical: claims.docVersion must be attest.attestation.v1");
    var nested = postureBytes(member(c, "posture")); // E7 first, as the script does
    return B.concat([ENVELOPE_DOMAIN, strOf(c.get("docVersion"), "docVersion"), strOf(need(c, "iss"), "iss"),
      strOf(need(c, "kid"), "kid"), opt(member(c, "jti"), "jti"), opt(member(c, "nonce"), "nonce"),
      opt(member(c, "overallBand"), "overallBand"), bs(nested)]);
  }

  // DECODE_PY: the claims a canonical envelope encodes, strictly (every byte used).
  function decodeEnvelope(b) {
    var pos = 0, cur = b;
    function take(n) {
      if (n < 0 || pos + n > cur.length) throw new Error("decode: truncated payload");
      var o = cur.subarray(pos, pos + n); pos += n; return o;
    }
    function lit(x) { if (!B.bytesEqual(take(x.length), x)) throw new Error("decode: wrong domain separator"); }
    function rawU64() {
      var v = take(8), r = 0n;
      for (var i = 0; i < 8; i++) r = (r << 8n) | BigInt(v[i]);
      return r;
    }
    function raw() {
      var n = rawU64();
      if (n > BigInt(cur.length)) throw new Error("decode: length out of range");
      return take(Number(n));
    }
    function st() { return B.utf8Decode(raw()); }
    function optS() {
      var t = take(1)[0];
      if (t === 0) return null;
      if (t === 1) return st();
      throw new Error("decode: bad option tag");
    }
    function u64d() {
      var v = raw();
      if (v.length !== 8) throw new Error("decode: bad u64");
      var r = 0n;
      for (var i = 0; i < 8; i++) r = (r << 8n) | BigInt(v[i]);
      return r;
    }
    lit(ENVELOPE_DOMAIN);
    var c = new J.JObj();
    c.set("docVersion", st()); c.set("iss", st()); c.set("kid", st());
    c.set("jti", optS()); c.set("nonce", optS()); c.set("overallBand", optS());
    var nested = raw();
    if (pos !== cur.length) throw new Error("decode: trailing bytes after the envelope");
    cur = nested; pos = 0;
    lit(POSTURE_DOMAIN);
    var p = new J.JObj();
    p.set("version", st()); p.set("slug", st()); p.set("orgName", st()); p.set("visibility", st());
    p.set("generatedAt", st()); p.set("expiresAt", optS()); p.set("lastCheckedAt", optS());
    var n = u64d();
    if (n > 64n) throw new Error("decode: too many frameworks");
    var fws = [];
    for (var i = 0; i < Number(n); i++) {
      var f = new J.JObj();
      f.set("code", st()); f.set("label", st()); f.set("band", st());
      fws.push(f);
    }
    p.set("frameworks", fws);
    if (pos !== cur.length) throw new Error("decode: trailing bytes after the posture");
    c.set("posture", p);
    return c;
  }

  // CANON_STATUS_PY. `list` is the statusList object.
  function statusBytes(L) {
    if (!J.isObj(L)) throw new Error("canonical: statusList must be an object");
    // the script re-reads the list after rewriting its numbers (see JNum.pyText)
    if (J.hasHugeIntegerAfterRewrite(L)) throw new Error("canonical: an integer of more than 4300 digits");
    if (member(L, "docVersion") !== "attest.statuslist.v1") throw new Error("canonical: unsupported docVersion");
    var truncated = member(L, "truncated");
    if (typeof truncated !== "boolean") throw new Error("canonical: truncated must be a boolean");
    var seq = member(L, "seq");
    var seqN = J.isNum(seq) ? seq.pyInt() : null;
    if (seqN === null) throw new Error("canonical: seq must be an integer in [0, 2^63)");
    if (seqN < 0n || seqN >= (1n << 63n)) throw new Error("canonical: seq must be an integer in [0, 2^63)");
    function entries(name, idKey) {
      var v = need(L, name);
      if (!Array.isArray(v)) throw new Error("canonical: " + name + " must be a list");
      var e = v.map(function (x) {
        if (!J.isObj(x)) throw new Error("canonical: an entry of " + name + " must be an object");
        var id = need(x, idKey);
        if (typeof id !== "string") throw new Error("canonical: " + idKey + " must be a string");
        return { x: x, key: B.utf8(id), id: id };
      });
      e.sort(function (a, b) { return B.bytesCompare(a.key, b.key); });
      for (var i = 1; i < e.length; i++) if (e[i - 1].id === e[i].id) throw new Error("canonical: duplicate " + idKey);
      return e;
    }
    var ke = entries("keys", "kid"), se = entries("subjects", "subjectHash");
    function rs(s) {
      if (typeof s !== "string" || REASONS.indexOf(s) < 0) throw new Error("canonical: unknown reason");
      return strOf(s, "reason");
    }
    var s = function (v) { return strOf(v, "field"); };
    var out = [STATUS_DOMAIN, s(L.get("docVersion")), s(need(L, "iss")), s(need(L, "kid")), u64(seqN),
      s(need(L, "issuedAt")), s(need(L, "nextUpdate")), u64(truncated ? 1 : 0), u64(ke.length)];
    ke.forEach(function (e) { out.push(s(need(e.x, "kid")), rs(need(e.x, "reason")), s(need(e.x, "revokedAt"))); });
    out.push(u64(se.length));
    se.forEach(function (e) {
      out.push(s(need(e.x, "subjectHash")), rs(need(e.x, "reason")), s(need(e.x, "notBefore")), s(need(e.x, "expiresAt")));
    });
    return B.concat(out);
  }

  HV.canon = { postureBytes: postureBytes, envelopeBytes: envelopeBytes, decodeEnvelope: decodeEnvelope, statusBytes: statusBytes };
})(typeof globalThis !== "undefined" ? globalThis : this);
