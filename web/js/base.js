// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.
//
// Building blocks of the in-browser verifier: bytes, base64url, SHA-256 and
// RFC 3339 instants. No dependency, no network, no storage. Classic script (not
// an ES module) so that the page also works when index.html is opened from disk,
// where browsers refuse to load modules.
//
// Every function mirrors the helper of scripts/attest/verify-attestation.sh that
// carries the same name or job. Where the script has a quirk, the comment says so.
(function (root) {
  "use strict";
  var HV = root.HV || (root.HV = {});

  var enc = new TextEncoder();
  var decStrict = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

  // UTF-8 bytes of a string. Throws on an unpaired surrogate, which TextEncoder
  // would silently turn into U+FFFD (rule R5 of the canonical encoding).
  function utf8(s) {
    for (var i = 0; i < s.length; i++) {
      var c = s.charCodeAt(i);
      if (c >= 0xd800 && c <= 0xdbff) {
        var d = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
        if (d < 0xdc00 || d > 0xdfff) throw new Error("unpaired surrogate");
        i++;
      } else if (c >= 0xdc00 && c <= 0xdfff) {
        throw new Error("unpaired surrogate");
      }
    }
    return enc.encode(s);
  }
  // Strict UTF-8 decode; throws on invalid bytes. A leading BOM is kept (U+FEFF).
  function utf8Decode(bytes) { return decStrict.decode(bytes); }

  function concat(parts) {
    var n = 0, i, o, p;
    for (i = 0; i < parts.length; i++) n += parts[i].length;
    o = new Uint8Array(n); p = 0;
    for (i = 0; i < parts.length; i++) { o.set(parts[i], p); p += parts[i].length; }
    return o;
  }
  function bytesEqual(a, b) {
    if (a.length !== b.length) return false;
    for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
  }
  // memcmp order (rule R2)
  function bytesCompare(a, b) {
    var n = Math.min(a.length, b.length);
    for (var i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
    return a.length === b.length ? 0 : (a.length < b.length ? -1 : 1);
  }
  function hex(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i++) s += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16);
    return s;
  }
  // Latin-1 view of bytes: one character per byte, what a C-locale tool sees.
  function latin1(bytes) {
    var s = "", i;
    for (i = 0; i < bytes.length; i += 8192) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 8192));
    return s;
  }

  // --- base64url ------------------------------------------------------------
  var ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var LOOKUP = (function () {
    var t = new Int16Array(256).fill(-1);
    for (var i = 0; i < 64; i++) t[ALPHA.charCodeAt(i)] = i;
    return t;
  })();

  // b64url_decode of the script. It translates - and _, pads by length, and hands
  // the result to `openssl base64 -d -A`. Two behaviours are copied on purpose,
  // both measured with OpenSSL 3.5:
  //  - a length of 1 modulo 4 is a failure (the script returns 1): returns null;
  //  - anything else OpenSSL cannot decode (a stray character, padding in the
  //    wrong place) is NOT a failure there: it writes nothing and succeeds, so
  //    the result is an EMPTY byte string. Spaces and line breaks are ignored,
  //    bits left over in the last character are ignored.
  // The callers then see an empty header, key or signature and fail on that.
  function b64urlDecode(str) {
    var s = str.replace(/-/g, "+").replace(/_/g, "/");
    var rem = s.length % 4;
    if (rem === 1) return null;
    if (rem === 2) s += "=="; else if (rem === 3) s += "=";
    s = s.replace(/[ \t\n\r]/g, "");
    var empty = new Uint8Array(0);
    if (s.length % 4 !== 0) return empty;
    var pad = 0, end = s.length;
    if (s.charAt(end - 1) === "=") { pad++; end--; }
    if (end > 0 && s.charAt(end - 1) === "=") { pad++; end--; }
    var out = new Uint8Array((s.length / 4) * 3 - pad);
    var o = 0, acc = 0, bits = 0, i, v;
    for (i = 0; i < end; i++) {
      v = LOOKUP[s.charCodeAt(i) & 255];
      if (s.charCodeAt(i) > 255 || v < 0) return empty;
      acc = (acc << 6) | v; bits += 6;
      if (bits >= 8) { bits -= 8; out[o++] = (acc >> bits) & 255; acc &= (1 << bits) - 1; }
    }
    if (o !== out.length) return empty;
    return out;
  }
  function b64urlEncode(bytes) {
    var s = "", i, n = bytes.length, a, b, c;
    for (i = 0; i + 2 < n; i += 3) {
      a = bytes[i]; b = bytes[i + 1]; c = bytes[i + 2];
      s += ALPHA[a >> 2] + ALPHA[((a & 3) << 4) | (b >> 4)] + ALPHA[((b & 15) << 2) | (c >> 6)] + ALPHA[c & 63];
    }
    if (n - i === 1) { a = bytes[i]; s += ALPHA[a >> 2] + ALPHA[(a & 3) << 4]; }
    else if (n - i === 2) { a = bytes[i]; b = bytes[i + 1]; s += ALPHA[a >> 2] + ALPHA[((a & 3) << 4) | (b >> 4)] + ALPHA[(b & 15) << 2]; }
    return s.replace(/\+/g, "-").replace(/\//g, "_");
  }

  // --- SHA-256 (FIPS 180-4), synchronous, so that no secure context is needed ---
  var K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]);
  function sha256(data) {
    var h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
    var n = data.length;
    var total = ((n + 9 + 63) >> 6) << 6;
    var m = new Uint8Array(total);
    m.set(data); m[n] = 0x80;
    var bitsHi = Math.floor(n / 0x20000000), bitsLo = (n << 3) >>> 0;
    m[total - 8] = bitsHi >>> 24; m[total - 7] = bitsHi >>> 16; m[total - 6] = bitsHi >>> 8; m[total - 5] = bitsHi;
    m[total - 4] = bitsLo >>> 24; m[total - 3] = bitsLo >>> 16; m[total - 2] = bitsLo >>> 8; m[total - 1] = bitsLo;
    var w = new Uint32Array(64), i, j, off, a, b, c, d, e, f, g, hh, s0, s1, t1, t2;
    for (off = 0; off < total; off += 64) {
      for (i = 0; i < 16; i++) {
        j = off + i * 4;
        w[i] = ((m[j] << 24) | (m[j + 1] << 16) | (m[j + 2] << 8) | m[j + 3]) >>> 0;
      }
      for (i = 16; i < 64; i++) {
        s0 = (((w[i - 15] >>> 7) | (w[i - 15] << 25)) ^ ((w[i - 15] >>> 18) | (w[i - 15] << 14)) ^ (w[i - 15] >>> 3)) >>> 0;
        s1 = (((w[i - 2] >>> 17) | (w[i - 2] << 15)) ^ ((w[i - 2] >>> 19) | (w[i - 2] << 13)) ^ (w[i - 2] >>> 10)) >>> 0;
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4]; f = h[5]; g = h[6]; hh = h[7];
      for (i = 0; i < 64; i++) {
        s1 = (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) >>> 0;
        t1 = (hh + s1 + (((e & f) ^ (~e & g)) >>> 0) + K[i] + w[i]) >>> 0;
        s0 = (((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) >>> 0;
        t2 = (s0 + (((a & b) ^ (a & c) ^ (b & c)) >>> 0)) >>> 0;
        hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    var out = new Uint8Array(32);
    for (i = 0; i < 8; i++) { out[i * 4] = h[i] >>> 24; out[i * 4 + 1] = h[i] >>> 16; out[i * 4 + 2] = h[i] >>> 8; out[i * 4 + 3] = h[i]; }
    return out;
  }

  // --- RFC 3339 instants, exact (RETIRED_PY "cmp" of the script) --------------
  // An instant is a rational number of seconds: { n: BigInt, d: BigInt } with d a
  // power of ten. The grammar is the script's INSTANT regex: a real calendar date
  // and time, Z or a numeric offset, any number of fraction digits, no leap second.
  var INSTANT = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?(?:Z|([+-])([0-9]{2}):([0-9]{2}))$/;
  var RETIRED = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;
  function isLeap(y) { return (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0; }
  function daysInMonth(y, m) { return [31, isLeap(y) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m - 1]; }
  // days since 1970-01-01 of a proleptic Gregorian date
  function daysFromCivil(y, m, d) {
    y -= m <= 2 ? 1 : 0;
    var era = Math.floor(y / 400), yoe = y - era * 400;
    var doy = Math.floor((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1;
    var doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
    return era * 146097 + doe - 719468;
  }
  function instant(v) {
    if (typeof v !== "string") return null;
    var m = INSTANT.exec(v);
    if (!m) return null;
    var y = +m[1], mo = +m[2], d = +m[3], h = +m[4], mi = +m[5], s = +m[6];
    if (y < 1 || mo < 1 || mo > 12 || d < 1 || d > daysInMonth(y, mo) || h > 23 || mi > 59 || s > 59) return null;
    var off = 0;
    if (m[8]) {
      var oh = +m[9], om = +m[10];
      if (oh > 23 || om > 59) return null;
      off = (oh * 3600 + om * 60) * (m[8] === "+" ? 1 : -1);
    }
    var sec = daysFromCivil(y, mo, d) * 86400 + h * 3600 + mi * 60 + s - off;
    var den = 1n, num = BigInt(sec);
    if (m[7]) {
      var digits = m[7].slice(1);
      den = 10n ** BigInt(digits.length);
      num = num * den + BigInt(digits);
    }
    return { n: num, d: den };
  }
  function strictInstant(v) { return typeof v === "string" && RETIRED.test(v) && instant(v) !== null; }
  // A compared with B plus extra seconds: "before", "equal", "after" or "unparseable".
  function cmpInstants(a, b, extra) {
    var x = instant(a), y = instant(b);
    if (x === null || y === null) return "unparseable";
    var l = x.n * y.d, r = (y.n + BigInt(extra || 0) * y.d) * x.d;
    return l > r ? "after" : (l === r ? "equal" : "before");
  }
  // whole seconds, rounded down (the script's epoch_of)
  function epochFloor(v) {
    var x = instant(v);
    if (x === null) return null;
    var q = x.n / x.d;
    if (x.n % x.d !== 0n && x.n < 0n) q -= 1n;
    return Number(q);
  }
  // "now" as an RFC 3339 UTC time with whole seconds (rfc3339_of)
  function rfc3339Of(epoch) {
    var dt = new Date(epoch * 1000);
    if (isNaN(dt.getTime())) return "";
    var p = function (n, w) { var t = String(n); while (t.length < w) t = "0" + t; return t; };
    return p(dt.getUTCFullYear(), 4) + "-" + p(dt.getUTCMonth() + 1, 2) + "-" + p(dt.getUTCDate(), 2) + "T" +
      p(dt.getUTCHours(), 2) + ":" + p(dt.getUTCMinutes(), 2) + ":" + p(dt.getUTCSeconds(), 2) + "Z";
  }

  HV.base = {
    utf8: utf8, utf8Decode: utf8Decode, concat: concat, bytesEqual: bytesEqual, bytesCompare: bytesCompare,
    hex: hex, latin1: latin1, b64urlDecode: b64urlDecode, b64urlEncode: b64urlEncode, sha256: sha256,
    instant: instant, strictInstant: strictInstant, cmpInstants: cmpInstants, epochFloor: epochFloor, rfc3339Of: rfc3339Of
  };
})(typeof globalThis !== "undefined" ? globalThis : this);
