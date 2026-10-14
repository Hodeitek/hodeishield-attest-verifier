// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.
//
// A strict JSON reader that keeps what JSON.parse throws away: the order of the
// members and the members that appear twice. The script reads every document
// strictly (DUPKEY_PY: UTF-8, no byte order mark, one value, nothing after it)
// and refuses a repeated member, because which value counts would depend on the
// reader. JSON.parse keeps the last of a repeated member and cannot tell you.
//
// Differences from the Python reader, all in the direction of refusing more:
// NaN, Infinity and -Infinity are not accepted, and nesting is limited to 1000
// levels. A lone surrogate escape (\ud800) is accepted, as Python does; the
// canonical encoder refuses it later. An integer of more than 4,300 digits is
// refused, as Python 3.11 and later refuses it (its limit on converting a digit
// string to an int); the script's readers then say the document is not strict
// JSON, and so does the page.
(function (root) {
  "use strict";
  var HV = root.HV || (root.HV = {});
  var MAX_DEPTH = 1000;
  var MAX_INT_DIGITS = 4300;

  // A JSON object: entries in document order, repeated members included.
  function JObj() { this.entries = []; this.map = new Map(); this.dups = []; }
  JObj.prototype.set = function (k, v) {
    this.entries.push([k, v]);
    if (this.map.has(k)) this.dups.push(k);
    this.map.set(k, v); // the last value wins, at the position of the first
  };
  JObj.prototype.get = function (k) { return this.map.has(k) ? this.map.get(k) : undefined; };
  JObj.prototype.has = function (k) { return this.map.has(k); };
  JObj.prototype.keys = function () { return Array.from(this.map.keys()); };
  // A number is kept as written: callers only need to know it is not a string, and
  // whether it is an integer.
  function JNum(raw) { this.raw = raw; }
  JNum.prototype.isInt = function () { return /^-?(0|[1-9][0-9]*)$/.test(this.raw); };

  // The text of a number after the script's reader of the status list (jsonq) has
  // rewritten it with Python's Decimal and str() (JSONQ_PY, num()): leading zeros
  // gone, an exponent of 0 gone ("7e0" is "7", "0.7e1" is "7"), a fraction kept
  // ("70e-1" is "7.0"), a positive exponent in scientific form ("1e2" is "1E+2").
  // Python's json then reads that text back: plain digits are an int, anything else
  // a float. The context of jsonq has a huge precision and an exponent range of
  // +-999999999: beyond it a number becomes the largest double or a zero.
  JNum.prototype.pyText = function () {
    var m = /^(-?)([0-9]*)(?:\.([0-9]*))?(?:[eE]([+-]?[0-9]+))?$/.exec(this.raw);
    if (!m) return this.raw;
    var sign = m[1], frac = m[3] || "", exp = (m[4] ? parseInt(m[4], 10) : 0) - frac.length;
    var coef = (m[2] + frac).replace(/^0+/, "") || "0";
    var adjusted = exp + coef.length - 1;
    if (coef !== "0" && adjusted > 999999999) return sign + "1.7976931348623157e+308";
    if (exp < -1147483646) return sign + "0E-1147483646";
    var out;
    if (exp <= 0 && adjusted >= -6) {
      if (exp === 0) out = coef;
      else if (coef.length > -exp) out = coef.slice(0, coef.length + exp) + "." + coef.slice(coef.length + exp);
      else out = "0." + "0".repeat(-exp - coef.length) + coef;
    } else {
      out = coef.charAt(0) + (coef.length > 1 ? "." + coef.slice(1) : "") + "E" + (adjusted >= 0 ? "+" : "-") + Math.abs(adjusted);
    }
    return sign + out;
  };
  // the integer value after that round trip, or null when Python's json would read a float
  JNum.prototype.pyInt = function () {
    var t = this.pyText();
    return /^-?[0-9]+$/.test(t) ? BigInt(t) : null;
  };

  var NUM = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;

  function parseText(t) {
    var i = 0, n = t.length;
    function fail(why) { throw new Error("json: " + why + " at " + i); }
    function ws() {
      while (i < n) {
        var c = t.charCodeAt(i);
        if (c === 32 || c === 9 || c === 10 || c === 13) i++; else break;
      }
    }
    var ESC = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
    function str() {
      // t[i] is the opening quote
      var out = "", start = ++i, c;
      for (;;) {
        if (i >= n) fail("unterminated string");
        c = t.charCodeAt(i);
        if (c === 34) { out += t.slice(start, i); i++; return out; }
        if (c < 32) fail("control character in string");
        if (c === 92) {
          out += t.slice(start, i);
          i++;
          if (i >= n) fail("bad escape");
          var e = t.charAt(i);
          if (e === "u") {
            var h = t.slice(i + 1, i + 5);
            if (!/^[0-9a-fA-F]{4}$/.test(h)) fail("bad \\u escape");
            out += String.fromCharCode(parseInt(h, 16));
            i += 5;
          } else {
            if (!Object.prototype.hasOwnProperty.call(ESC, e)) fail("bad escape");
            out += ESC[e]; i++;
          }
          start = i;
        } else { i++; }
      }
    }
    function lit(word, val) {
      if (t.substr(i, word.length) !== word) fail("unexpected token");
      i += word.length;
      return val;
    }
    function value(depth) {
      if (depth > MAX_DEPTH) fail("too deep");
      if (i >= n) fail("unexpected end");
      var ch = t.charAt(i), r;
      if (ch === "{") {
        r = new JObj(); i++; ws();
        if (t.charAt(i) === "}") { i++; return r; }
        for (;;) {
          if (t.charAt(i) !== '"') fail("expected a key");
          var k = str(); ws();
          if (t.charAt(i) !== ":") fail("expected :");
          i++; ws();
          r.set(k, value(depth + 1)); ws();
          var c = t.charAt(i);
          if (c === ",") { i++; ws(); continue; }
          if (c === "}") { i++; return r; }
          fail("expected , or }");
        }
      }
      if (ch === "[") {
        r = []; i++; ws();
        if (t.charAt(i) === "]") { i++; return r; }
        for (;;) {
          r.push(value(depth + 1)); ws();
          var d = t.charAt(i);
          if (d === ",") { i++; ws(); continue; }
          if (d === "]") { i++; return r; }
          fail("expected , or ]");
        }
      }
      if (ch === '"') return str();
      if (ch === "t") return lit("true", true);
      if (ch === "f") return lit("false", false);
      if (ch === "n") return lit("null", null);
      if (ch === "-" || (ch >= "0" && ch <= "9")) {
        NUM.lastIndex = i;
        var m = NUM.exec(t);
        if (!m) fail("bad number");
        if (/^-?[0-9]+$/.test(m[0]) && m[0].replace("-", "").length > MAX_INT_DIGITS) fail("integer of more than " + MAX_INT_DIGITS + " digits");
        i += m[0].length;
        return new JNum(m[0]);
      }
      return fail("unexpected character");
    }
    ws();
    var v = value(0);
    ws();
    if (i !== n) fail("data after the value");
    return v;
  }

  // bytes -> value. Throws on anything the script's strict reader refuses.
  function parse(bytes) {
    var text = typeof bytes === "string" ? bytes : HV.base.utf8Decode(bytes);
    return parseText(text);
  }

  function isObj(v) { return v instanceof JObj; }
  function isNum(v) { return v instanceof JNum; }

  function vis(t) {
    var s = "", i, c;
    for (i = 0; i < t.length; i++) {
      c = t.charCodeAt(i);
      s += (c >= 32 && c < 127) ? t.charAt(i) : (c < 256 ? "\\x" : "\\u") + (c < 16 ? "0" : "") + c.toString(16).padStart(c < 256 ? 2 : 4, "0");
    }
    return s;
  }
  // DUPKEY_PY: the members that appear twice anywhere, as paths, sorted and unique.
  function duplicates(doc) {
    var out = [], stack = [[doc, ""]], cur, v, path, i, k, here;
    while (stack.length) {
      cur = stack.pop(); v = cur[0]; path = cur[1];
      if (isObj(v)) {
        var seen = new Set();
        for (i = 0; i < v.entries.length; i++) {
          k = v.entries[i][0];
          here = path ? path + "." + k : k;
          if (seen.has(k)) out.push(here);
          seen.add(k);
          stack.push([v.entries[i][1], here]);
        }
      } else if (Array.isArray(v)) {
        for (i = 0; i < v.length; i++) stack.push([v[i], path + "[" + i + "]"]);
      }
    }
    if (isObj(doc) && doc.has("attestation")) {
      ["claims", "signature"].forEach(function (m) { if (doc.has(m)) out.push(m + " (beside and inside attestation)"); });
    }
    return Array.from(new Set(out.map(vis))).sort();
  }

  // Whether any object, at any depth, has a member name twice (the script reads the
  // protected header's members with a hook that sees every nested object).
  function hasDuplicateMember(doc) {
    var stack = [doc], v, i;
    while (stack.length) {
      v = stack.pop();
      if (isObj(v)) {
        if (v.dups.length) return true;
        for (i = 0; i < v.entries.length; i++) stack.push(v.entries[i][1]);
      } else if (Array.isArray(v)) {
        for (i = 0; i < v.length; i++) stack.push(v[i]);
      }
    }
    return false;
  }

  function loneHighSurrogate(s) {
    for (var i = 0; i < s.length; i++) {
      var c = s.charCodeAt(i);
      if (c >= 0xd800 && c <= 0xdbff) {
        var d = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
        if (d < 0xdc00 || d > 0xdfff) return true;
        i++;
      }
    }
    return false;
  }
  // The two refusals of jsonq, the script's reader of the status list (JSONQ_PY in
  // scripts/attest/verify-attestation.sh), that the strict reader does not make:
  //  - a string, or a member name, with an unpaired high surrogate (a lone low one
  //    is replaced, not refused);
  //  - nesting that weighs more than 256, where an array or an object costs 1 and
  //    one that is the value of an object member costs 2, summed along the open
  //    containers.
  // The script then cannot read the document: the status list is UNKNOWN.
  function jsonqRefuses(root) {
    var stack = [[root, 0, false]], it, v, w, inObj, i, nw;
    while (stack.length) {
      it = stack.pop(); v = it[0]; w = it[1]; inObj = it[2];
      if (typeof v === "string") { if (loneHighSurrogate(v)) return true; continue; }
      if (Array.isArray(v) || isObj(v)) {
        nw = w + (inObj ? 2 : 1);
        if (nw > 256) return true;
        if (Array.isArray(v)) {
          for (i = 0; i < v.length; i++) stack.push([v[i], nw, false]);
        } else {
          for (i = 0; i < v.entries.length; i++) {
            if (loneHighSurrogate(v.entries[i][0])) return true;
            stack.push([v.entries[i][1], nw, true]);
          }
        }
      }
    }
    return false;
  }

  // Python 3.11 and later refuses to read back an integer of more than 4,300 digits:
  // after the rewrite above, an exponent that makes a number a plain integer can
  // make it too long ("1...1e0", 4,301 ones). True when any number of the value does.
  function hasHugeIntegerAfterRewrite(root) {
    var stack = [root], v, i, t;
    while (stack.length) {
      v = stack.pop();
      if (isNum(v)) {
        t = v.pyText();
        if (/^-?[0-9]+$/.test(t) && t.replace("-", "").length > MAX_INT_DIGITS) return true;
      } else if (Array.isArray(v)) {
        for (i = 0; i < v.length; i++) stack.push(v[i]);
      } else if (isObj(v)) {
        for (i = 0; i < v.entries.length; i++) stack.push(v.entries[i][1]);
      }
    }
    return false;
  }

  HV.json = { hasHugeIntegerAfterRewrite: hasHugeIntegerAfterRewrite, hasDuplicateMember: hasDuplicateMember, jsonqRefuses: jsonqRefuses, parse: parse, parseText: parseText, JObj: JObj, JNum: JNum, isObj: isObj, isNum: isNum, duplicates: duplicates, vis: vis };
})(typeof globalThis !== "undefined" ? globalThis : this);
