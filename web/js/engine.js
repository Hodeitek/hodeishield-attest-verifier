// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.
//
// The signature engine: the ML-DSA-65 verify primitive of aws-lc-rs, compiled to
// WebAssembly by tools/mldsa-wasm/build.sh (a pinned, reproducible build). This
// file only loads that module and passes bytes in and out of it. It never uses
// the browser's own WebCrypto for ML-DSA.
//
// The module's bytes come from mldsa/mldsa_wasm.b64.js (the same bytes as
// mldsa/mldsa_wasm.wasm, as base64) so that the page needs no network request and
// also works when it is opened from disk, where browsers refuse to fetch a file.
(function (root) {
  "use strict";
  var HV = root.HV || (root.HV = {});
  var B = HV.base;

  var module_ = null;
  var engine = { ready: false, wasmSha256: null, error: null };

  function base64ToBytes(b64) {
    var bin = atob(b64), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // factory: the Emscripten loader (global `Module` once mldsa_wasm.js is loaded);
  // wasmBytes: the module. Resolves to the engine; never rejects (see engine.error).
  engine.init = function (factory, wasmBytes) {
    engine.ready = false; engine.error = null;
    return Promise.resolve().then(function () {
      if (typeof factory !== "function") throw new Error("the loader is missing");
      if (!wasmBytes || !wasmBytes.length) throw new Error("the module is missing");
      engine.wasmSha256 = B.hex(B.sha256(wasmBytes));
      // The loader is told to take the module from these bytes (instantiateWasm)
      // instead of fetching mldsa_wasm.wasm, which a page opened from disk cannot do.
      var started = factory({
        instantiateWasm: function (imports, done) {
          WebAssembly.instantiate(wasmBytes, imports).then(function (r) { done(r.instance, r.module); }, function (e) {
            engine.error = e && e.message ? e.message : String(e);
          });
          return {};
        }
      });
      // a module that cannot be instantiated must not leave the page waiting for ever
      var limit = new Promise(function (_, reject) {
        setTimeout(function () { reject(new Error(engine.error || "the signature module did not start in time")); }, 30000);
      });
      return Promise.race([started, limit]);
    }).then(function (m) {
      module_ = m;
      if (typeof m._mldsa_verify !== "function" || typeof m._malloc !== "function" || typeof m._free !== "function") {
        throw new Error("the module does not export what is needed");
      }
      engine.ready = true;
      return engine;
    }).catch(function (e) {
      engine.error = e && e.message ? e.message : String(e);
      engine.ready = false;
      return engine;
    });
  };

  // Browser start-up: the loader and the bytes are already on the page.
  engine.initFromPage = function () {
    var b64 = root.HV_MLDSA_WASM_B64;
    var factory = root.Module;
    if (typeof b64 !== "string" || typeof factory !== "function") {
      engine.error = "the signature module is not on the page";
      return Promise.resolve(engine);
    }
    return engine.init(factory, base64ToBytes(b64));
  };

  // 1 valid, 0 anything else: wrong sizes, bad signature, bad key.
  engine.verify = function (pub, msg, sig) {
    if (!engine.ready) throw new Error("the signature engine is not ready");
    var m = module_, ptrs = [], r;
    function put(bytes) {
      var p = m._malloc(bytes.length || 1);
      if (!p) throw new Error("out of memory");
      ptrs.push(p);
      return p;
    }
    var pp = put(pub), mp = put(msg), sp = put(sig);
    try {
      var heap = m.HEAPU8; // read after every allocation: the memory may have grown
      heap.set(pub, pp); heap.set(msg, mp); heap.set(sig, sp);
      r = m._mldsa_verify(pp, pub.length, mp, msg.length, sp, sig.length);
    } finally {
      ptrs.forEach(function (p) { m._free(p); });
    }
    return r === 1;
  };

  HV.engine = engine;
})(typeof globalThis !== "undefined" ? globalThis : this);
