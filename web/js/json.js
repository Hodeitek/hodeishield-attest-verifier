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
// canonical encoder refuses it later.
(function (root) {
  "use strict";
  var HV = root.HV || (root.HV = {});
  var MAX_DEPTH = 1000;

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

  HV.json = { parse: parse, parseText: parseText, JObj: JObj, JNum: JNum, isObj: isObj, isNum: isNum, duplicates: duplicates, vis: vis };
})(typeof globalThis !== "undefined" ? globalThis : this);
