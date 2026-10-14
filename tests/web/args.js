// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.
//
// Test support: turns the command-line arguments of a case in
// tests/vectors/v1/vectors.json into the input of HV.verify, and checks a result
// against the case's expectation. Used by the browser runner and by the Node
// check. It knows nothing about the page's text or layout.
(function (root) {
  "use strict";
  var T = root.HVT || (root.HVT = {});
  var FILE_OPTS = { "--attestation": "attestation", "--jws": "jws", "--claims": "claims", "--jwks": "jwks",
    "--status": "status", "--status-keys": "statusKeys", "--anchor-file": "anchorFile", "--anchor-bundle": "anchorBundle" };

  // the paths a case reads
  T.filesOf = function (args) {
    var out = [];
    for (var i = 0; i < args.length; i++) if (FILE_OPTS[args[i]] && i + 1 < args.length) out.push(args[i + 1]);
    return out;
  };

  // files: { path: Uint8Array }
  T.buildInput = function (args, files) {
    var inp = { expectKids: [] }, i = 0;
    while (i < args.length) {
      var a = args[i], v = args[i + 1];
      if (FILE_OPTS[a]) { inp[FILE_OPTS[a]] = files[v]; i += 2; continue; }
      switch (a) {
        case "--status-list": inp.statusList = true; i += 1; break;
        case "--expect-slug": inp.expectSlug = v; i += 2; break;
        case "--expect-issuer": inp.expectIssuer = v; i += 2; break;
        case "--expect-nonce": inp.expectNonce = v; i += 2; break;
        case "--expect-kid": inp.expectKids.push(v); i += 2; break;
        case "--max-age-seconds": inp.maxAgeSeconds = v; i += 2; break;
        case "--now": inp.now = v; i += 2; break;
        case "--check-kid": inp.checkKid = v; i += 2; break;
        case "--check-subject": inp.checkSubject = v; i += 2; break;
        case "--check-generated-at": inp.checkGeneratedAt = v; i += 2; break;
        case "--min-seq": inp.minSeq = v; i += 2; break;
        default: throw new Error("test: unknown argument " + a);
      }
    }
    // the page cannot check a signed key statement (it needs Sigstore): it only
    // has to know that one was asked for
    if (inp.anchorFile) inp.anchor = true;
    delete inp.anchorFile; delete inp.anchorBundle;
    return inp;
  };

  // The relaxed reason rule of tests/vectors.sh --json: the reason is the case's
  // code, or the case's code is among several failed checks of the exit class.
  T.reasonOk = function (res, want, exit) {
    if (res.reason === want) return true;
    var fails = res.checks.filter(function (c) { return c.result === "fail" && c.exit_class === exit; });
    return fails.length > 1 && fails.some(function (c) { return c.code === want; });
  };

  // Differences from the script that are known and explained in
  // docs/security/browser-verifier.md. The exit code and the verdict still have to
  // agree; only the reason code may differ, and it must be exactly this one.
  T.KNOWN_REASON_DIFFERENCES = {
    // The script reads the release tag out of a certificate it has verified with
    // cosign. The page cannot verify a Sigstore bundle, so it says the statement
    // could not be verified (the code of the other two anchor cases).
    "anchor-statement-older-than-verifier": "anchor_unverified"
  };

  // returns "" when the result is what the case expects, else why not
  T.judge = function (c, res) {
    var e = c.expect;
    var verdictOfExit = { 0: ["verified", "good"], 1: ["failed", "expired", "revoked"], 2: ["could_not_check"], 3: ["unknown"] }[e.exit];
    if (res.exit_code !== e.exit) return "exit " + res.exit_code + ", expected " + e.exit;
    if (verdictOfExit.indexOf(res.verdict) < 0) return "verdict " + res.verdict + " does not belong to exit " + e.exit;
    var known = T.KNOWN_REASON_DIFFERENCES[c.id];
    if (known) {
      if (res.reason !== known) return "reason " + res.reason + ", expected the documented " + known;
    } else if (!T.reasonOk(res, e.code, e.exit)) return "reason " + res.reason + ", expected " + e.code;
    if (e.exit !== 0 && res.attested !== null) return "attested content shown on exit " + e.exit;
    if (c.canonical_sha256 && res.canonical_sha256 !== c.canonical_sha256) return "canonical sha-256 " + res.canonical_sha256;
    if (c.status_canonical_sha256 && res.status_canonical_sha256 !== c.status_canonical_sha256) return "status canonical sha-256 " + res.status_canonical_sha256;
    return "";
  };
})(typeof globalThis !== "undefined" ? globalThis : this);
