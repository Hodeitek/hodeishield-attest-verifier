// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.
//
// The verifier. A port of scripts/attest/verify-attestation.sh to plain
// JavaScript: same checks, same order, same exit codes (0/1/2, and 0/1/2/3 in
// status-list mode), same reason codes (docs/security/reason-codes.md). Where
// this file and the specification differ, the script is the reference and this
// file follows the script.
//
// The signature itself is checked by the WebAssembly module (engine.js), never
// by native WebCrypto. Everything else, including SHA-256, is in this page.
//
// Not in this page, on purpose: the key statement (--anchor-file), which needs
// Sigstore (cosign) and the network; the deprecated --posture; --json, --raw and
// --help, which are about a terminal. Fetching a status list or a key set from
// a URL is not done either: the page never opens a network connection. The
// reader supplies those documents as files.
(function (root) {
  "use strict";
  var HV = root.HV || (root.HV = {});
  var B = HV.base, J = HV.json, C = HV.canon;

  var VERSION = "1.6.0";
  var NOW_MAX = 253402300799;
  var MAX_TTL_SECONDS = 3600;
  var POSTURE_CLOCK_SKEW_SECONDS = 300;
  var MAX_STATUS_LIST_VALIDITY_SECONDS = 86400;
  var STATUS_CLOCK_SKEW_SECONDS = 300;
  var STATUS_DOC_MAX_BYTES = 2000000;
  var STATUS_KEYS_MAX_BYTES = 1000000;
  var HEADER_MAX_BYTES = 4096;
  var KID_SHAPE = /^[A-Za-z0-9_-]{21}[AQgw]$/;
  var STRENGTH = ["in_progress", "basic", "substantial", "advanced"];

  function Stop(rc) { this.rc = rc; }

  // ---- small helpers shared by the sections ---------------------------------
  function lenient(bytes) { return new TextDecoder("utf-8", { fatal: false, ignoreBOM: true }).decode(bytes); }
  // The value of a protected-header member, as HEADER_PY of the script reads it: the
  // JSON string, with its escapes decoded. A value that is not a string, a member
  // that is missing, and a string with an unpaired surrogate all read as empty; a
  // NUL character is shown as \x00, as the script's shell cannot hold one.
  function headerString(hdr, name) {
    var v = J.isObj(hdr) ? hdr.get(name) : undefined;
    if (typeof v !== "string") return "";
    for (var i = 0; i < v.length; i++) {
      var c = v.charCodeAt(i);
      if (c >= 0xd800 && c <= 0xdbff) {
        var d = i + 1 < v.length ? v.charCodeAt(i + 1) : 0;
        if (d < 0xdc00 || d > 0xdfff) return "";
        i++;
      } else if (c >= 0xdc00 && c <= 0xdfff) return "";
    }
    return v.replace(/\u0000/g, "\\x00");
  }
  // The protected header is read with no more than 64 nested containers, as the script
  // does (HEADER_PY): a header holds three strings, and the check is made before the reader
  // runs. Throws, as a header that is not JSON does.
  function parseHeader(bytes) {
    var s = B.latin1(bytes), depth = 0, quoted = false, escaped = false, i, c;
    for (i = 0; i < s.length; i++) {
      c = s.charAt(i);
      if (quoted) {
        if (escaped) escaped = false;
        else if (c === "\\") escaped = true;
        else if (c === '"') quoted = false;
      } else if (c === '"') quoted = true;
      else if (c === "[" || c === "{") { if (++depth > 64) throw new Error("header nested too deep"); }
      else if (c === "]" || c === "}") depth--;
    }
    return J.parse(bytes);
  }
  function stripSpace(s) { return s.replace(/[ \t\n\v\f\r]/g, ""); }
  function stripTrailingNewlines(s) { return s.replace(/\n+$/, ""); }
  function isDigits(max, s) { return typeof s === "string" && new RegExp("^[0-9]{1," + max + "}$").test(s); }
  function memberOf(v, k) { // jsonq member(): None passes through, a non-object is an error
    if (J.isObj(v)) { var x = v.get(k); return x === undefined ? null : x; }
    if (v === null) return null;
    throw new Error("cannot index");
  }
  // jq-like text of a value, for the places the script prints or compares one
  function dumpValue(v) {
    if (v === null || v === undefined) return "null";
    if (v === true) return "true";
    if (v === false) return "false";
    if (J.isNum(v)) return v.pyText();
    if (typeof v === "string") return JSON.stringify(v);
    if (Array.isArray(v)) return "[" + v.map(dumpValue).join(",") + "]";
    return "{" + v.keys().map(function (k) { return JSON.stringify(k) + ":" + dumpValue(v.get(k)); }).join(",") + "}";
  }
  function plain(v) { return typeof v === "string" ? v : dumpValue(v); }
  function listItems(v) {
    if (J.isObj(v)) return v.keys().map(function (k) { return v.get(k); });
    return Array.isArray(v) ? v : [];
  }
  function kidOf(pub) {
    return B.b64urlEncode(B.sha256(B.concat([B.utf8("hodei-shield.attest.kid.v1"), pub])).subarray(0, 16));
  }

  // RETIRED_PY "key": the entry of `keys` whose kid is `kid`, and its retirement marker
  function selectKey(doc, kid) {
    var r = { status: "none", val: "", pub: "" };
    var keys = J.isObj(doc) ? doc.get("keys") : undefined;
    if (!Array.isArray(keys) || !keys.every(J.isObj)) { r.status = "invalid"; return r; }
    var seen = new Set(), dup = false;
    keys.forEach(function (k) {
      var x = k.get("kid");
      if (typeof x === "string") { if (seen.has(x)) dup = true; seen.add(x); }
    });
    if (dup) { r.status = "duplicate"; return r; }
    for (var i = 0; i < keys.length; i++) {
      var k = keys[i];
      if (k.get("kid") === kid && typeof k.get("pub") === "string") {
        r.pub = k.get("pub");
        r.status = "absent";
        if (k.has("hs_retired_at")) {
          var v = k.get("hs_retired_at");
          r.status = B.strictInstant(v) ? "ok" : "malformed";
          r.val = typeof v === "string" ? v : dumpValue(v);
        }
        break;
      }
    }
    return r;
  }

  // ---- the verification -----------------------------------------------------
  function verify(inp, engine) {
    var checks = [];
    var facts = {};
    var state = { verdict: "", dieMsg: "", usage: false, usageCode: "usage", usageMsg: "", attested: null, anchorTag: null };
    var FAILURES = 0, STALE_FAILURES = 0, STALE_EXPIRED = false, SIGNATURE_VERIFIED = false, STATUS_FAILURES = 0;
    var canonicalSha = null, statusCanonicalSha = null;

    function record(code, result, cls) {
      var last = checks[checks.length - 1];
      if (last && last.code === code && last.result === result && last.exit_class === cls) return;
      checks.push({ code: code, result: result, exit_class: cls });
    }
    function ok(code) { record(code, "pass", 0); }
    function warn(code) { record(code, "warn", 0); }
    function warnUnknown(code) { record(code, "warn", 3); }
    function bad(code) { record(code, "fail", 1); FAILURES++; }
    function stale(code) { bad(code); STALE_FAILURES++; }
    function statBad(code) { record(code, "fail", 3); STATUS_FAILURES++; }
    function die(code, msg) {
      record(code, "fail", 2);
      state.verdict = "could_not_check"; state.dieMsg = msg || code;
      throw new Stop(2);
    }
    function argDie(msg, code) {
      state.usage = true; state.usageMsg = msg; state.usageCode = code || "usage";
      throw new Stop(2);
    }

    var statusMode = !!inp.statusList;
    var nowOverride = null;
    var rc = 0;
    var ctx = {};
    try {
      rc = body();
    } catch (e) {
      if (e instanceof Stop) rc = e.rc;
      else { // anything unexpected is "could not check", never a pass
        record("internal_error", "fail", 2);
        state.verdict = "could_not_check"; state.dieMsg = "internal error: " + (e && e.message ? e.message : String(e));
        rc = 2;
      }
    }
    return finish(rc);

    // ---------------------------------------------------------------------
    function body() {
      // --- arguments (the browser has no command line, but the same rules) ---
      var o = inp;
      if (o.maxAgeSeconds !== undefined && o.maxAgeSeconds !== null && o.maxAgeSeconds !== "") {
        if (!isDigits(9, String(o.maxAgeSeconds))) argDie("max age must be a whole number of seconds (digits only, at most 9)");
      }
      var maxAge = (o.maxAgeSeconds === undefined || o.maxAgeSeconds === null || o.maxAgeSeconds === "") ? 3600 : parseInt(String(o.maxAgeSeconds), 10);
      if (o.now !== undefined && o.now !== null && o.now !== "") {
        if (!isDigits(12, String(o.now))) argDie("now must be a Unix time in seconds (digits only, at most 12)");
        nowOverride = parseInt(String(o.now), 10);
        if (nowOverride > NOW_MAX) argDie("now is out of range: at most " + NOW_MAX);
      }
      var expectKids = o.expectKids || [];
      expectKids.forEach(function (k) { if (!KID_SHAPE.test(k)) argDie("expect-kid is not a kid (22 base64url characters)"); });
      if (o.checkKid) { if (!KID_SHAPE.test(o.checkKid)) argDie("check-kid is not a kid (22 base64url characters)"); }
      var minSeq = null;
      if (o.minSeq !== undefined && o.minSeq !== null && o.minSeq !== "") {
        if (!isDigits(18, String(o.minSeq))) argDie("min-seq must be a non-negative integer");
        minSeq = BigInt(String(o.minSeq));
      }
      var statusOpt = o.status || o.statusKeys || o.checkKid || o.checkSubject || o.checkGeneratedAt || minSeq !== null;
      if (statusOpt && !statusMode) argDie("a status-list option needs the status-list mode");
      var expectSlug = o.expectSlug || "", expectIssuer = o.expectIssuer || "", expectNonceSet = o.expectNonce !== undefined && o.expectNonce !== null;
      var expectNonce = expectNonceSet ? String(o.expectNonce) : "";

      var jwsBytes = o.jws || null, attBytes = o.attestation || null, claimsBytes = o.claims || null;
      var jwksBytes = o.jwks || null, pubB64 = o.pubB64url || "";
      var haveAtt = !!(jwsBytes || attBytes);

      if (statusMode) {
        if (!o.status) die("status_source_missing", "the status list is required");
        if (!o.statusKeys) die("status_keys_source_missing", "the status key set is required");
        if (!haveAtt && !o.checkKid && !o.checkSubject) die("status_list_nothing_to_check", "nothing to check against the list");
      }
      if (expectKids.length && !haveAtt) die("expect_kid_needs_attestation", "a pinned key id needs a document");
      if (haveAtt || !statusMode) {
        if (!haveAtt) die("attestation_missing", "no document");
        if (!jwksBytes && !pubB64) die("key_source_missing", "no key set");
      }
      if (jwksBytes && pubB64) die("pub_b64url_with_jwks", "two sources for the signing key");

      // --- environment: the module that checks ML-DSA-65 ---
      if (!engine || typeof engine.verify !== "function" || engine.ready === false) die("engine_unavailable", "the signature engine is not available");
      ok("wasm_mldsa65_available");

      // --- the anchor: needs Sigstore, which this page does not have ---
      if (o.anchor) {
        die("anchor_unverified", "this page cannot check a signed key statement; use the script for --anchor-file");
      }

      // --- document resolution ---
      var claimsObj = null, claimsDup = false, attDoc = null, jwsText = null;
      var attachedUndecodable = "";
      if (attBytes) {
        try { attDoc = J.parse(attBytes); } catch (e1) { die("attestation_unparseable", "cannot read the document as an attestation"); }
        var d = attDoc;
        if (!J.isObj(d)) die("attestation_unparseable", "expected a JSON object");
        if (d.has("attestation") && J.isObj(d.get("attestation"))) d = d.get("attestation");
        var c = d.has("claims") ? d.get("claims") : d;
        var sig = d.get("signature");
        if (!J.isObj(c)) die("attestation_unparseable", "no claims object found");
        if (!claimsBytes) claimsObj = c;
        if (!jwsBytes) {
          if (typeof sig !== "string" || sig === "") die("attestation_signature_missing", "the document carries no signature");
          jwsText = sig;
        }
      }
      if (claimsBytes) {
        try { claimsObj = J.parse(claimsBytes); } catch (e2) { claimsObj = undefined; }
      }
      if (jwsBytes) jwsText = lenient(jwsBytes);

      // attached JWS without claims: decode the payload into the claims it encodes
      if (jwsText !== null && !claimsObj && claimsObj !== undefined) {
        var parts = stripSpace(jwsText).split(".");
        var attPayload = parts.length >= 2 ? parts[1] : "";
        if (attPayload) {
          try {
            var pb = B.b64urlDecode(attPayload);
            if (pb === null) throw new Error("payload segment is not valid base64url");
            claimsObj = C.decodeEnvelope(pb);
          } catch (e3) { attachedUndecodable = e3.message || "payload cannot be decoded"; claimsObj = null; }
        }
      }

      // duplicate members in the document as handed over
      var dupKeys = [];
      if (attDoc) dupKeys = dupKeys.concat(J.duplicates(attDoc));
      if (claimsBytes) {
        if (claimsObj === undefined) dupKeys.push("(the file could not be parsed strictly)");
        else dupKeys = dupKeys.concat(J.duplicates(claimsObj));
      }

      var postureObj = null;
      if (claimsObj !== null && claimsObj !== undefined) {
        postureObj = J.isObj(claimsObj) ? claimsObj.get("posture") : undefined;
        if (!J.isObj(postureObj)) die("claims_posture_missing", "the claims have no usable posture object");
      } else if (claimsObj === undefined) {
        die("claims_posture_missing", "the claims cannot be read");
      }
      var haveClaims = claimsObj !== null && claimsObj !== undefined;

      var KID = "", DERIVED_KID = "", RETIRED_AT = "", CLAIMS_KID = "";
      var SLUG = "", GENERATED = "", EXPIRES = "", POSTURE_READ = false;
      var CLAIMS_ISS = "", CLAIMS_NONCE = "", CLAIMS_NONCE_PRESENT = false;

      function claimsField(obj, name) {
        var v = obj.get(name), s;
        if (typeof v === "string") {
          s = v;
          if (s.indexOf("\u0000") >= 0) { s = s.replace(/\u0000/g, "\\x00"); bad("nul_byte"); }
          return s;
        }
        if (v === null || v === undefined) return "";
        return dumpValue(v);
      }

      if (jwsText !== null) {
        // --- 1. Structure ---
        var JWS = stripSpace(jwsText);
        var dots = JWS.split(".").length - 1;
        if (dots < 2) die("jws_not_compact", "not a compact JWS");
        var first = JWS.indexOf("."), second = JWS.indexOf(".", first + 1);
        var H = JWS.slice(0, first), P = JWS.slice(first + 1, second), S = JWS.slice(second + 1);
        if (S.indexOf(".") >= 0) die("jws_too_many_dots", "too many dots");
        var FORM;
        if (P === "") {
          FORM = "detached"; ok("jws_detached");
          if (!haveClaims) die("jws_detached_needs_claims", "a detached JWS needs the claims");
        } else { FORM = "attached"; ok("jws_attached"); }

        var headerBytes = B.b64urlDecode(H);
        if (headerBytes === null) die("header_not_base64url", "the header is not valid base64url");
        var headerFull = headerBytes;
        if (headerBytes.length > HEADER_MAX_BYTES) {
          bad("header_too_large");
          headerBytes = headerBytes.subarray(0, HEADER_MAX_BYTES);
        }
        var sigBytes = B.b64urlDecode(S);
        if (sigBytes === null) die("signature_not_base64url", "the signature is not valid base64url");
        if (sigBytes.length === 3309) ok("signature_size_valid"); else bad("signature_size_invalid");

        // --- 2. Header ---
        var members = "(not JSON)", ALG = "", TYP = "", hdr = null;
        try {
          hdr = parseHeader(headerBytes);
          if (J.isObj(hdr)) {
            if (J.hasDuplicateMember(hdr)) members = "duplicated";
            else members = hdr.keys().sort().join(",");
          } else members = "(not a JSON object)";
        } catch (e4) { members = "(not JSON)"; hdr = null; }
        // alg, typ and kid come from the same parse; only for a header over the cap
        // (which already failed) they are read from the whole of it, as the script does
        var vals = hdr;
        if (headerFull !== headerBytes) { try { vals = parseHeader(headerFull); } catch (e4b) { vals = null; } }
        ALG = headerString(vals, "alg"); TYP = headerString(vals, "typ"); KID = headerString(vals, "kid");
        if (ALG === "ML-DSA-65") ok("header_alg_valid"); else bad("header_alg_invalid");
        if (TYP === "application/attest+jws") ok("header_typ_valid"); else bad("header_typ_invalid");
        if (B.latin1(headerBytes).indexOf('"crit"') >= 0) bad("header_not_allowed"); else ok("header_crit_absent");
        if (members === "alg,kid,typ") ok("header_members_valid"); else bad("header_not_allowed");

        // --- 3. Public key ---
        if (!pubB64) {
          var keyDoc;
          try {
            keyDoc = J.parse(jwksBytes);
          } catch (e5) { die("not_strict_json", "the key document is not strict JSON (UTF-8, no BOM, one value)"); }
          if (J.duplicates(keyDoc).length) die("jwks_duplicate_key", "the key document repeats members");
          var sel = selectKey(keyDoc, KID);
          if (sel.status === "invalid") die("jwks_keys_not_array", "keys is not an array of objects");
          if (sel.status === "duplicate") die("jwks_duplicate_kid", "two keys carry the same kid");
          pubB64 = stripTrailingNewlines(sel.pub);
          if (pubB64 === "") die("unknown_kid", "no key in this key set carries the kid of the document");
          ok("jwks_key_selected");
          if (sel.status === "ok") RETIRED_AT = sel.val;
          else if (sel.status !== "absent") die("jwks_retired_at_malformed", "hs_retired_at is not an RFC 3339 UTC time with seconds");
        }
        var pubBytes = B.b64urlDecode(pubB64);
        if (pubBytes === null) die("public_key_not_base64url", "the public key is not valid base64url");
        if (pubBytes.length === 1952) ok("public_key_size_valid"); else die("public_key_size_invalid", "the public key is " + pubBytes.length + " bytes, expected 1952");
        DERIVED_KID = kidOf(pubBytes);
        if (DERIVED_KID === KID) ok("kid_derivable"); else bad("kid_mismatch");
        if (expectKids.length) {
          if (expectKids.indexOf(DERIVED_KID) >= 0) ok("kid_pinned"); else bad("unexpected_kid");
        }
        ok("public_key_loaded");

        // --- 4. Payload: the signing envelope ---
        var PAYLOAD_B64, canonBytes = null;
        if (haveClaims) {
          try { canonBytes = C.envelopeBytes(claimsObj); } catch (e6) { die("canonicalise_failed", "could not canonicalise the claims: " + e6.message); }
          ok("canonical_rederived");
          canonicalSha = B.hex(B.sha256(canonBytes));
          PAYLOAD_B64 = B.b64urlEncode(canonBytes);
          if (FORM === "attached") {
            if (PAYLOAD_B64 === P) ok("payload_matches_claims"); else bad("payload_claims_mismatch");
          }
          CLAIMS_KID = claimsField(claimsObj, "kid");
          if (CLAIMS_KID === KID) ok("claims_kid_matches"); else bad("kid_mismatch");
        } else if (attachedUndecodable) {
          bad("payload_not_envelope");
          PAYLOAD_B64 = P;
        } else {
          ok("payload_embedded");
          var pl = B.b64urlDecode(P);
          if (pl === null) die("payload_not_base64url", "the payload is not valid base64url");
          PAYLOAD_B64 = P;
          warn("opaque_bytes");
        }

        // --- 5. Signature ---
        var signingInput = B.utf8(H + "." + PAYLOAD_B64);
        var good = false;
        try { good = !!engine.verify(pubBytes, signingInput, sigBytes); } catch (e7) { die("engine_unavailable", "the signature engine failed: " + e7.message); }
        if (good) { ok("signature_valid"); SIGNATURE_VERIFIED = true; } else bad("signature_invalid");

        // --- 6. Freshness ---
        var NOW = nowOverride !== null ? nowOverride : Math.floor(Date.now() / 1000);
        ctx.NOW = NOW;
        facts.now = NOW;
        if (postureObj) {
          GENERATED = claimsField(postureObj, "generatedAt");
          EXPIRES = claimsField(postureObj, "expiresAt");
          SLUG = claimsField(postureObj, "slug");
          POSTURE_READ = true;
          var G = null;
          if (GENERATED !== "") {
            G = B.epochFloor(GENERATED);
            if (G !== null) {
              var age = NOW - G;
              facts.ageSeconds = age; facts.maxAgeSeconds = maxAge;
              var NOW_RFC = B.rfc3339Of(NOW);
              var cm = B.cmpInstants(GENERATED, NOW_RFC, POSTURE_CLOCK_SKEW_SECONDS);
              if (cm === "after") bad("not_yet_valid");
              else if (cm === "before" || cm === "equal") {
                if (age > maxAge) stale("too_old"); else ok("fresh");
              } else bad("date_unparseable");
            } else bad("date_unparseable");
          } else bad("generated_at_missing");

          if (RETIRED_AT !== "" && GENERATED !== "") {
            var rcmp = B.cmpInstants(GENERATED, RETIRED_AT, 0);
            if (rcmp === "equal" || rcmp === "after") bad("retired_key");
            else if (rcmp === "before") ok("retired_key_document_predates");
            else bad("date_unparseable");
            facts.retiredAt = RETIRED_AT;
          }

          if (EXPIRES !== "") {
            var E = B.epochFloor(EXPIRES);
            if (E === null) bad("date_unparseable");
            else {
              if (NOW > E) { stale("expired"); STALE_EXPIRED = true; } else ok("not_expired");
            }
            if (E !== null && G !== null) {
              var tcmp = B.cmpInstants(EXPIRES, GENERATED, MAX_TTL_SECONDS);
              if (tcmp === "after") bad("ttl_exceeded");
              else if (tcmp === "before" || tcmp === "equal") ok("ttl_within_ceiling");
              else bad("date_unparseable");
            }
          } else bad("missing_expiry");

          if (expectSlug !== "") {
            if (SLUG === expectSlug) ok("slug_match"); else bad("slug_mismatch");
          }
        } else {
          warn("freshness_unchecked");
          if (RETIRED_AT !== "") bad("retired_key");
        }

        // --- 7. Claims ---
        if (haveClaims) {
          var DOCV = claimsField(claimsObj, "docVersion");
          CLAIMS_ISS = claimsField(claimsObj, "iss");
          claimsField(claimsObj, "jti");
          CLAIMS_NONCE = claimsField(claimsObj, "nonce");
          var nv = claimsObj.get("nonce");
          CLAIMS_NONCE_PRESENT = !(nv === null || nv === undefined);
          var CLAIMS_BAND = claimsField(claimsObj, "overallBand");
          var bv = claimsObj.get("overallBand");
          var BAND_PRESENT = !(bv === null || bv === undefined);

          if (DOCV === "attest.attestation.v1") ok("doc_version_valid"); else bad("unsupported_version");
          if (dupKeys.length) bad("duplicate_key");
          var unsigned = unsignedMembers(claimsObj);
          if (!unsigned.length && !dupKeys.length) ok("members_signed");
          else if (unsigned.length) bad("unsigned_member");
          facts.unsignedMembers = unsigned;
          facts.duplicateKeys = dupKeys;

          if (CLAIMS_ISS === "") bad("iss_empty");
          if (POSTURE_READ && SLUG === "") bad("slug_empty");
          if (expectIssuer !== "") {
            if (CLAIMS_ISS === expectIssuer) ok("issuer_match"); else bad("issuer_mismatch");
          } else warn("issuer_unpinned");

          if (expectNonceSet) {
            if (expectNonce === "") {
              if (!CLAIMS_NONCE_PRESENT) ok("nonce_match"); else bad("nonce_mismatch");
            } else if (CLAIMS_NONCE_PRESENT && CLAIMS_NONCE === expectNonce) ok("nonce_match");
            else bad("nonce_mismatch");
          } else if (CLAIMS_NONCE_PRESENT) warn("nonce_unchecked");

          var ranks = [];
          listItems(postureObj.get("frameworks")).forEach(function (f) {
            var b = f.get("band");
            var ix = typeof b === "string" ? STRENGTH.indexOf(b) : -1;
            if (ix >= 0) ranks.push(ix);
          });
          var DERIVED_BAND = ranks.length ? STRENGTH[Math.min.apply(null, ranks)] : "";
          if (CLAIMS_BAND === DERIVED_BAND) ok("overall_band_valid"); else bad("overall_band_mismatch");

          var VISIBILITY = claimsField(postureObj, "visibility");
          if (VISIBILITY === "gated") {
            var fwCount = listItems(postureObj.get("frameworks")).length;
            var chk = postureObj.get("lastCheckedAt");
            var checkedPresent = !(chk === null || chk === undefined);
            if (fwCount === 0 && !checkedPresent && !BAND_PRESENT) ok("redaction_valid"); else bad("redaction_violation");
          }
          facts.docVersion = DOCV;
        }
        facts.kid = KID; facts.derivedKid = DERIVED_KID; facts.iss = CLAIMS_ISS; facts.slug = SLUG;
        facts.generatedAt = GENERATED; facts.expiresAt = EXPIRES;
        facts.signatureVerified = SIGNATURE_VERIFIED;
      }

      // --- 8. Status list ---
      var STATUS = { valid: false };
      if (statusMode) STATUS = statusSection({
        o: o, minSeq: minSeq, expectIssuer: expectIssuer, now: (ctx.NOW !== undefined ? ctx.NOW : (nowOverride !== null ? nowOverride : Math.floor(Date.now() / 1000)))
      });

      // --- 9. Revocation check ---
      var REV = { status: "", reason: "", via: "", because: "" };
      if (statusMode) REV = revocationSection({
        o: o, STATUS: STATUS, DERIVED_KID: DERIVED_KID, KID: KID, POSTURE_READ: POSTURE_READ, SLUG: SLUG, GENERATED: GENERATED
      });
      facts.revocation = statusMode ? { status: REV.status, via: REV.via, reason: REV.reason, because: REV.because, seq: STATUS.seq || null } : null;

      // --- attested content ---
      if (jwsText !== null) {
        if (FAILURES === 0 && (!statusMode || REV.status === "good")) {
          if (haveClaims) state.attested = attestedOf(claimsObj);
        }
      }

      // --- verdict ---
      var haveJws = jwsText !== null;
      var staleOnly = SIGNATURE_VERIFIED && FAILURES > 0 && FAILURES === STALE_FAILURES;
      function staleVerdict() { state.verdict = "expired"; facts.expiredBecause = STALE_EXPIRED ? "expired" : "too_old"; return 1; }
      if (statusMode) {
        if (haveJws && staleOnly && REV.status !== "revoked") return staleVerdict();
        if (haveJws && FAILURES !== 0 && !staleOnly) { state.verdict = "failed"; return 1; }
        if (REV.status === "good") { record("good", "pass", 0); state.verdict = "good"; return 0; }
        if (REV.status === "revoked") { record(REV.via === "key" ? "revoked_key" : "revoked_subject", "fail", 1); state.verdict = "revoked"; return 1; }
        state.verdict = "unknown"; return 3;
      }
      if (FAILURES === 0) { record("verified", "pass", 0); state.verdict = "verified"; return 0; }
      if (staleOnly) return staleVerdict();
      state.verdict = "failed";
      return 1;
    }

    function unsignedMembers(doc) {
      var SC = ["docVersion", "iss", "kid", "jti", "nonce", "overallBand", "posture"];
      var SP = ["version", "slug", "orgName", "visibility", "generatedAt", "expiresAt", "lastCheckedAt", "frameworks"];
      var SF = ["code", "label", "band"];
      var extra = [];
      doc.keys().forEach(function (k) { if (SC.indexOf(k) < 0) extra.push("claims." + k); });
      var p = doc.get("posture");
      if (J.isObj(p)) {
        p.keys().forEach(function (k) { if (SP.indexOf(k) < 0) extra.push("posture." + k); });
        var fw = p.get("frameworks");
        if (Array.isArray(fw)) fw.forEach(function (f, i) {
          if (J.isObj(f)) f.keys().forEach(function (k) { if (SF.indexOf(k) < 0) extra.push("posture.frameworks[" + i + "]." + k); });
        });
      }
      return extra.map(J.vis);
    }

    function attestedOf(doc) {
      var p = doc.get("posture");
      var fws = listItems(p.get("frameworks")).filter(J.isObj).map(function (f) {
        return { label: f.get("label"), code: f.get("code"), band: f.get("band") };
      });
      function sv(o, k) { var v = o.get(k); return v === undefined ? null : v; }
      return {
        overallBand: sv(doc, "overallBand"), orgName: sv(p, "orgName"), slug: sv(p, "slug"), visibility: sv(p, "visibility"),
        generatedAt: sv(p, "generatedAt"), expiresAt: sv(p, "expiresAt"), lastCheckedAt: sv(p, "lastCheckedAt"),
        iss: sv(doc, "iss"), kid: sv(doc, "kid"), jti: sv(doc, "jti"), nonce: sv(doc, "nonce"), frameworks: fws
      };
    }

    // ---------------------------------------------------------------------
    // Section 8: the signed status list and its own key set
    // ---------------------------------------------------------------------
    function statusSection(a) {
      var o = a.o, R = { valid: false, seq: null };
      var statusBytes = o.status, keysBytes = o.statusKeys;
      var STATUS_DOC_OVER = false, STATUS_KEYS_OVER = false;
      if (statusBytes.length > STATUS_DOC_MAX_BYTES) { STATUS_DOC_OVER = true; statBad("status_unknown_document_too_large"); }
      if (keysBytes.length > STATUS_KEYS_MAX_BYTES) { STATUS_KEYS_OVER = true; statBad("status_unknown_keys_too_large"); }

      var statusDoc = null, keysDoc = null;
      [["status", statusBytes, STATUS_DOC_OVER], ["keys", keysBytes, STATUS_KEYS_OVER]].forEach(function (x) {
        if (x[2]) return;
        var doc;
        try { doc = J.parse(x[1]); } catch (e) { statBad("status_unknown_not_strict_json"); return; }
        if (x[0] === "status") statusDoc = doc; else keysDoc = doc;
        if (J.duplicates(doc).length) statBad("status_unknown_duplicate_key");
      });

      var listObj, STATUS_JWS = "";
      // jsonq, the script's reader of the status list, refuses an unpaired high
      // surrogate and nesting that weighs more than 256 (see J.jsonqRefuses).
      var shapeOk = STATUS_FAILURES === 0 && J.isObj(statusDoc) && statusDoc.has("statusList") && statusDoc.has("signature") && !J.jsonqRefuses(statusDoc);
      if (shapeOk) {
        listObj = statusDoc.get("statusList");
        STATUS_JWS = stripTrailingNewlines(plain(statusDoc.get("signature")));
        ok("status_shape_valid");
      } else statBad("status_unknown_malformed_document");

      // list_field: a jq-like read of a member, with the script's failure modes
      function listField(obj, name, stringOnly) {
        var v;
        try { v = memberOf(obj, name); } catch (e) { statBad("status_unknown_malformed_document"); return ""; }
        if (stringOnly && typeof v !== "string") return "";
        var text = plain(v);
        if (typeof v === "string" && v.indexOf("\u0000") >= 0) { text = text.replace(/\u0000/g, "\\x00"); statBad("status_unknown_nul_byte"); }
        return text;
      }

      var STATUS_DOC_VERSION = "";
      if (STATUS_FAILURES === 0) {
        var dv;
        try { dv = memberOf(listObj, "docVersion"); } catch (e) { statBad("status_unknown_malformed_document"); dv = undefined; }
        if (dv === undefined) STATUS_DOC_VERSION = "";
        else if (dv === null || dv === false) STATUS_DOC_VERSION = "";
        else {
          STATUS_DOC_VERSION = plain(dv);
          if (typeof dv === "string" && dv.indexOf("\u0000") >= 0) { STATUS_DOC_VERSION = STATUS_DOC_VERSION.replace(/\u0000/g, "\\x00"); statBad("status_unknown_nul_byte"); }
        }
        if (STATUS_DOC_VERSION === "attest.statuslist.v1") ok("status_doc_version_valid");
        else statBad("status_unknown_unsupported_version");
      }

      var SH = "", SP = "", SS = "";
      if (STATUS_FAILURES === 0) {
        if (STATUS_JWS.split(".").length - 1 >= 2) {
          var f1 = STATUS_JWS.indexOf("."), f2 = STATUS_JWS.indexOf(".", f1 + 1);
          SH = STATUS_JWS.slice(0, f1); SP = STATUS_JWS.slice(f1 + 1, f2); SS = STATUS_JWS.slice(f2 + 1);
        } else statBad("status_unknown_not_compact_jws");
      }
      if (STATUS_FAILURES === 0 && SS.indexOf(".") >= 0) statBad("status_unknown_too_many_dots");
      if (STATUS_FAILURES === 0) {
        if (SP !== "") statBad("status_unknown_signature_not_detached"); else ok("status_jws_detached");
      }
      var hdrBytes = null, sigBytes = null;
      if (STATUS_FAILURES === 0) {
        hdrBytes = B.b64urlDecode(SH);
        if (hdrBytes === null) statBad("status_unknown_header_not_base64url");
      }
      if (STATUS_FAILURES === 0 && hdrBytes.length > HEADER_MAX_BYTES) statBad("status_unknown_header_too_large");
      if (STATUS_FAILURES === 0) {
        sigBytes = B.b64urlDecode(SS);
        if (sigBytes === null) statBad("status_unknown_signature_not_base64url");
      }
      if (STATUS_FAILURES === 0) {
        if (sigBytes.length === 3309) ok("status_signature_size_valid"); else statBad("status_unknown_signature_size");
      }
      var hdr = null, hdrOk = false;
      if (STATUS_FAILURES === 0) {
        try { hdr = J.parse(hdrBytes); hdrOk = true; } catch (e) { hdrOk = false; }
        if (hdrOk && (!J.isObj(hdr) || J.jsonqRefuses(hdr))) statBad("status_unknown_header_not_object");
        else if (!hdrOk) {
          var t0 = B.latin1(hdrBytes).replace(/^(\xef\xbb\xbf)?[ \t\r\n]*/, "");
          if (t0.charAt(0) === "{") statBad("status_unknown_header_not_strict_json"); else statBad("status_unknown_header_not_object");
        } else if (hdr.dups.length || J.duplicates(hdr).length) statBad("status_unknown_header_duplicate_key");
      }
      if (STATUS_FAILURES === 0) {
        if (hdr.has("crit")) statBad("status_unknown_unsupported_crit"); else ok("status_header_crit_absent");
      }
      if (STATUS_FAILURES === 0) {
        if (hdr.keys().sort().join(",") === "alg,kid,typ") ok("status_header_members_valid");
        else statBad("status_unknown_header_not_allowed");
      }
      var SALG = "", STYP = "", LKID = "";
      if (STATUS_FAILURES === 0) {
        SALG = listField(hdr, "alg", true); STYP = listField(hdr, "typ", true); LKID = listField(hdr, "kid", true);
        if (SALG === "ML-DSA-65") ok("status_header_alg_valid"); else statBad("status_unknown_unsupported_alg");
        if (STYP === "application/attest-status+jws") ok("status_header_typ_valid"); else statBad("status_unknown_unexpected_typ");
      }
      var pubB64 = "", RETIRED = "";
      if (STATUS_FAILURES === 0) {
        var sel = selectKey(keysDoc, LKID);
        if (sel.status === "invalid") statBad("status_unknown_keys_not_array");
        else if (sel.status === "duplicate") statBad("status_unknown_duplicate_kid");
        pubB64 = stripTrailingNewlines(sel.pub);
        if (STATUS_FAILURES !== 0) { /* already unknown */ }
        else if (pubB64 !== "") {
          ok("status_key_selected");
          if (sel.status === "ok") RETIRED = sel.val;
          else if (sel.status !== "absent") statBad("status_unknown_retired_at_malformed");
        } else statBad("status_unknown_unknown_kid");
      }
      var pubBytes = null, derived = "";
      if (STATUS_FAILURES === 0) {
        pubBytes = B.b64urlDecode(pubB64);
        if (pubBytes === null) statBad("status_unknown_public_key_not_base64url");
      }
      if (STATUS_FAILURES === 0) {
        if (pubBytes.length === 1952) ok("status_public_key_size_valid"); else statBad("status_unknown_public_key_size");
      }
      if (STATUS_FAILURES === 0) {
        derived = kidOf(pubBytes);
        if (derived === LKID) ok("status_kid_derivable"); else statBad("status_unknown_kid_mismatch");
      }
      if (STATUS_FAILURES === 0) ok("status_public_key_loaded");

      var canon = null;
      if (STATUS_FAILURES === 0) {
        try { canon = C.statusBytes(listObj); ok("status_canonical_rederived"); }
        catch (e) {
          statBad(/truncated must be a boolean/.test(e.message) ? "status_unknown_truncated_invalid" : "status_unknown_encoding_failed");
        }
      }
      if (STATUS_FAILURES === 0) {
        statusCanonicalSha = B.hex(B.sha256(canon));
        var input = B.utf8(SH + "." + B.b64urlEncode(canon));
        var good = false;
        try { good = !!engine.verify(pubBytes, input, sigBytes); } catch (e) { die("engine_unavailable", "the signature engine failed: " + e.message); }
        if (good) ok("status_signature_valid"); else statBad("status_unknown_bad_signature");
      }
      if (STATUS_FAILURES === 0) {
        var lk = listField(listObj, "kid");
        if (lk === LKID) ok("status_kid_matches"); else statBad("status_unknown_kid_mismatch");
      }
      if (STATUS_FAILURES === 0 && a.expectIssuer !== "") {
        var li = listField(listObj, "iss");
        if (li === a.expectIssuer) ok("status_issuer_match"); else statBad("status_unknown_issuer_mismatch");
      }
      var issuedAt = "", nextUpdate = "";
      if (STATUS_FAILURES === 0) {
        var SNOW = a.now;
        issuedAt = listField(listObj, "issuedAt"); nextUpdate = listField(listObj, "nextUpdate");
        var SIAT = B.epochFloor(issuedAt), SNUP = B.epochFloor(nextUpdate);
        if (SIAT === null || SNUP === null) statBad("status_unknown_date_unparseable");
        else {
          var c1 = B.cmpInstants(issuedAt, B.rfc3339Of(SNOW), STATUS_CLOCK_SKEW_SECONDS);
          if (c1 === "after") statBad("status_unknown_not_yet_valid");
          else if (c1 === "before" || c1 === "equal") ok("status_not_future");
          else statBad("status_unknown_date_unparseable");
          var c2 = B.cmpInstants(nextUpdate, issuedAt, MAX_STATUS_LIST_VALIDITY_SECONDS);
          if (c2 === "after") statBad("status_unknown_validity_exceeded");
          else if (c2 === "before" || c2 === "equal") ok("status_validity_within_ceiling");
          else statBad("status_unknown_date_unparseable");
          if (SNUP + STATUS_CLOCK_SKEW_SECONDS < SNOW) statBad("status_unknown_stale"); else ok("status_not_stale");
        }
      }
      if (STATUS_FAILURES === 0 && RETIRED !== "") {
        var c3 = B.cmpInstants(issuedAt, RETIRED, 0);
        if (c3 === "equal" || c3 === "after") statBad("status_unknown_retired_key");
        else if (c3 === "before") ok("status_retired_key_list_predates");
        else statBad("status_unknown_date_unparseable");
      }
      var seqText = "";
      if (STATUS_FAILURES === 0 && a.minSeq !== null) {
        seqText = listField(listObj, "seq");
        var lower = /^-?[0-9]+$/.test(seqText) && BigInt(seqText) < a.minSeq;
        if (lower) statBad("status_unknown_rolled_back"); else ok("status_not_rolled_back");
      }
      if (STATUS_FAILURES === 0) {
        var selfrev = false;
        try {
          var lkid = memberOf(listObj, "kid");
          listItems(memberOf(listObj, "keys")).forEach(function (e) { if (typeof lkid === "string" && memberOf(e, "kid") === lkid) selfrev = true; });
        } catch (e) { selfrev = false; }
        if (selfrev) statBad("status_unknown_self_revocation"); else ok("status_not_self_revoking");
      }
      if (STATUS_FAILURES === 0) {
        R.valid = true; R.listObj = listObj;
        try { R.seq = plain(memberOf(listObj, "seq")); } catch (e) { R.seq = null; }
        facts.statusList = { seq: R.seq, issuedAt: issuedAt, nextUpdate: nextUpdate };
      }
      return R;
    }

    // ---------------------------------------------------------------------
    // Section 9: apply a verified list to a kid and a subject
    // ---------------------------------------------------------------------
    function revocationSection(a) {
      var o = a.o, STATUS = a.STATUS, R = { status: "", reason: "", via: "", because: "" };
      var checkKids = [];
      [a.DERIVED_KID, a.KID, o.checkKid || ""].forEach(function (k) {
        if (k && checkKids.indexOf(k) < 0) checkKids.push(k);
      });
      var subjSlugs = [], subjGen = [], subjNames = [];
      function addSubject(slug, gen, isDoc) {
        if (slug === "" && !isDoc) return;
        for (var i = 0; i < subjSlugs.length; i++) if (subjSlugs[i] === slug && subjGen[i] === gen) return;
        subjSlugs.push(slug); subjGen.push(gen);
        if (subjNames.indexOf(slug) < 0) subjNames.push(slug);
      }
      if (a.POSTURE_READ) addSubject(a.SLUG, a.GENERATED, true);
      if (o.checkSubject) addSubject(o.checkSubject, o.checkGeneratedAt || a.GENERATED, false);
      else if (o.checkGeneratedAt && a.POSTURE_READ) addSubject(a.SLUG, o.checkGeneratedAt, true);

      if (!STATUS.valid) {
        R.status = "unknown"; R.because = "list_unverified"; warnUnknown("status_unknown_list_unverified");
        return R;
      }
      if (checkKids.length === 0 && subjSlugs.length === 0) {
        R.status = "unknown"; R.because = "no_subject"; warnUnknown("status_unknown_no_subject");
        return R;
      }
      var L = STATUS.listObj;
      function lookup(kind, want) { // -> { rc, entry }
        try {
          var items = listItems(memberOf(L, kind === "k" ? "keys" : "subjects"));
          var mem = kind === "k" ? "kid" : "subjectHash", first = null;
          for (var i = 0; i < items.length; i++) {
            if (memberOf(items[i], mem) === want && first === null) first = items[i];
          }
          return { rc: 0, entry: first };
        } catch (e) { return { rc: 2, entry: null }; }
      }
      function reasonOf(entry) { return plain(memberOf(entry, "reason")).split("\n")[0].replace(/\u0000/g, ""); }

      var hashes = subjSlugs.map(function (s) {
        return B.b64urlEncode(B.sha256(B.concat([B.utf8("hodei-shield.attest.subject.v1"), B.utf8(s)])));
      });
      facts.subjectHashes = hashes;
      // Rule K: unconditional, revokedAt is never compared
      for (var j = 0; j < checkKids.length; j++) {
        var lk = lookup("k", checkKids[j]);
        if (lk.rc !== 0) { R.status = "unknown"; R.because = "list_unverified"; warnUnknown("status_unknown_list_unverified"); continue; }
        var hit = lk.entry === null ? "" : reasonOf(lk.entry);
        if (hit !== "") { R.status = "revoked"; R.reason = hit; R.via = "key"; break; }
      }
      // Rule B: reads the timestamp
      if (R.status !== "revoked") {
        var firstUnknown = "";
        for (var i = 0; i < subjSlugs.length; i++) {
          var out = subjectRule(L, lookup, reasonOf, subjSlugs[i], subjGen[i], hashes[i]);
          if (out.outcome === "revoked") { R.status = "revoked"; R.reason = out.reason; R.via = "subject"; break; }
          if (out.outcome === "unknown" && !firstUnknown) firstUnknown = out.because;
        }
        if (R.status !== "revoked" && firstUnknown) { R.status = "unknown"; R.because = firstUnknown; }
      }
      if (R.status === "") R.status = "good";
      return R;
    }

    function subjectRule(L, lookup, reasonOf, slug, genat, hash) {
      var r = { outcome: "good", reason: "", because: "" };
      var lk = lookup("s", hash);
      if (lk.rc !== 0) { r.outcome = "unknown"; r.because = "list_unverified"; warnUnknown("status_unknown_list_unverified"); return r; }
      var entry = lk.entry;
      if (entry !== null) {
        var nb;
        try { nb = plain(memberOf(entry, "notBefore")); } catch (e) { nb = ""; }
        if (genat === "") { r.outcome = "unknown"; r.because = "list_unverified"; warnUnknown("status_unknown_generated_at_missing"); return r; }
        var c = B.cmpInstants(genat, nb, 0);
        if (c === "before") {
          try { r.reason = plain(memberOf(entry, "reason")).replace(/\n+$/, ""); r.outcome = "revoked"; }
          catch (e) { r.outcome = "unknown"; r.because = "list_unverified"; warnUnknown("status_unknown_list_unverified"); }
        } else if (c === "equal" || c === "after") { /* not withdrawn at that time */ }
        else { r.outcome = "unknown"; r.because = "list_unverified"; warnUnknown("status_unknown_subject_dates_unparseable"); }
      } else {
        var tr;
        try { tr = plain(memberOf(L, "truncated")); } catch (e) { tr = null; }
        if (tr === null) { r.outcome = "unknown"; r.because = "list_unverified"; warnUnknown("status_unknown_list_unverified"); }
        else if (tr === "true") { r.outcome = "unknown"; r.because = "truncated"; warnUnknown("status_unknown_truncated"); }
      }
      return r;
    }

    // ---------------------------------------------------------------------
    function reasonOf(rc) {
      if (state.usage) return state.usageCode;
      if (rc === 0) return state.verdict;
      var wanted = { revoked: ["revoked_key", "revoked_subject"], expired: ["expired"] }[state.verdict] || [];
      var i, c;
      for (i = checks.length - 1; i >= 0; i--) {
        c = checks[i];
        if (wanted.indexOf(c.code) >= 0 && c.result === "fail") return c.code;
      }
      var skip = state.verdict === "failed" ? ["too_old", "expired"] : [];
      var pass = ["fail", null];
      for (var w = 0; w < pass.length; w++) {
        for (i = 0; i < checks.length; i++) {
          c = checks[i];
          if (c.exit_class === rc && skip.indexOf(c.code) < 0 && (pass[w] === null || c.result === pass[w])) return c.code;
        }
      }
      return null;
    }

    function finish(rc) {
      var verdict = state.verdict;
      if (!verdict) verdict = rc === 0 ? (statusMode ? "good" : "verified") : (rc === 1 ? "failed" : (rc === 3 ? "unknown" : "could_not_check"));
      var res = {
        schema: "hodeishield.verifier.result.v1",
        verifier: { version: VERSION, runtime: "browser" },
        mode: statusMode ? "status-list" : "attestation",
        exit_code: rc,
        verdict: verdict,
        reason: (function () { state.verdict = verdict; return reasonOf(rc); })(),
        checks: checks,
        attested: rc === 0 ? state.attested : null,
        facts: facts,
        canonical_sha256: canonicalSha,
        status_canonical_sha256: statusCanonicalSha
      };
      if (state.usage) res.message = state.usageMsg; else if (state.dieMsg) res.message = state.dieMsg;
      return res;
    }
  }

  HV.verify = verify;
  HV.VERSION = VERSION;
})(typeof globalThis !== "undefined" ? globalThis : this);
