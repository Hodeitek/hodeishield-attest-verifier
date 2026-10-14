// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.
//
// Runs in a real browser (started by tests/web/run.mjs). It frames the page as it
// ships, then:
//   1. runs every case of tests/vectors/v1 through the page's own HV.verify and
//      its real WebAssembly module, and compares verdict, exit code and reason
//      code with the case;
//   2. drives the page like a reader (file inputs, paste, drop, the language
//      switcher, the check button) and reads data-verdict, data-exit and
//      data-reason, never the text;
//   3. checks that the page made no request but for its own files and kept
//      nothing in cookies or storage.
// The outcome goes back to run.mjs as one POST.
(function () {
  "use strict";
  var q = new URLSearchParams(location.search);
  var mode = q.get("mode");
  var server = mode === "http" ? "" : q.get("server");
  var result = { cases: [], ui: [], reasonDifferences: [], userAgent: navigator.userAgent };

  function send(path, obj) {
    return fetch(server + path, { method: "POST", mode: mode === "http" ? "same-origin" : "no-cors", headers: { "content-type": "text/plain" }, body: JSON.stringify(obj) });
  }
  function log(m) { try { send("/log", String(m)); } catch (e) { /* the log is a convenience */ } }
  function finish(extra) {
    if (extra) result.error = extra;
    send("/result", result).catch(function () {});
  }
  window.addEventListener("error", function (e) { log("error: " + e.message); });

  function loadScript(src) {
    return new Promise(function (res, rej) {
      var s = document.createElement("script");
      s.src = src; s.onload = res; s.onerror = function () { rej(new Error("cannot load " + src)); };
      document.head.appendChild(s);
    });
  }
  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }
  function waitFor(cond, ms, what) {
    var t0 = Date.now();
    return new Promise(function (res, rej) {
      (function tick() {
        var v; try { v = cond(); } catch (e) { v = false; }
        if (v) return res(v);
        if (Date.now() - t0 > ms) return rej(new Error("timeout waiting for " + what));
        setTimeout(tick, 25);
      })();
    });
  }
  function b64bytes(b64, win) {
    var bin = atob(b64), out = new (win ? win.Uint8Array : Uint8Array)(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  var frame, win, doc;
  function ui(name, fn) {
    return Promise.resolve().then(fn).then(function (why) {
      result.ui.push({ name: name, ok: !why, why: why || "" });
    }, function (e) {
      result.ui.push({ name: name, ok: false, why: String(e && e.message || e) });
    });
  }

  // The cases of tests/web/differential/cases.json through the page's logic, in this
  // browser. The expected result of each is what the real script gives (the
  // differential test run by tests/web-differential.sh checks that it still does).
  function differentialWhy(w) {
    var spec = HVT_DIFF, bad = [];
    if (!spec.cases || spec.cases.length < spec.minimum) return "fewer cases than the minimum";
    var enc = new TextEncoder(), dec = new TextDecoder();
    spec.cases.forEach(function (c) {
      try {
        var gen = "gen/" + c.id + ".json", files = {};
        var args = HVD.args(c, spec, { v1: "v1", fx: "fx", gen: gen });
        HVT.filesOf(args).forEach(function (p) {
          if (p.indexOf("v1/") === 0) files[p] = b64bytes(HVT_FILES[p.slice(3)], w);
          else if (p === gen) files[p] = new w.Uint8Array(enc.encode(HVD.generate(dec.decode(b64bytes(HVT_FILES["status-lists/empty.json"])), c.generated)));
          else files[p] = b64bytes(HVT_FILES[p], w);
        });
        var res = w.HV.verify(HVT.buildInput(args, files), w.HV.engine);
        if (res.exit_code !== c.expect.exit || res.reason !== c.expect.reason) {
          bad.push(c.id + ": exit " + res.exit_code + " " + res.reason + ", the script gives " + c.expect.exit + " " + c.expect.reason);
        }
      } catch (e) { bad.push(c.id + ": " + (e && e.message || e)); }
    });
    return bad.join("; ");
  }

  function runVectors() {
    HVT_CASES.forEach(function (c) {
      var why;
      try {
        var files = {};
        HVT.filesOf(c.args).forEach(function (p) { files[p] = b64bytes(HVT_FILES[p], win); });
        var res = win.HV.verify(HVT.buildInput(c.args, files), win.HV.engine);
        why = HVT.judge(c, res);
        if (!why && HVT.KNOWN_REASON_DIFFERENCES[c.id]) result.reasonDifferences.push(c.id);
      } catch (e) { why = "exception: " + (e && e.message || e); }
      result.cases.push({ id: c.id, ok: !why, why: why || "" });
    });
  }

  // ---- driving the page as a reader -------------------------------------------
  function $(sel) { return doc.querySelector(sel); }
  function slot(name) { return doc.querySelector('[data-slot="' + name + '"]'); }
  function setFile(name, bytes, fname) {
    var input = slot(name).querySelector("[data-file]");
    var dt = new win.DataTransfer();
    dt.items.add(new win.File([bytes], fname || "x.json", { type: "application/json" }));
    input.files = dt.files;
    input.dispatchEvent(new win.Event("change", { bubbles: true }));
  }
  function slotHasFile(name) { return slot(name).querySelector("[data-drop]").classList.contains("has-file"); }
  function resetPage() {
    if (!$("#again").hidden) $("#again").click();
    ["doc", "keys", "status", "statusKeys"].forEach(function (n) { var rm = slot(n).querySelector("[data-remove]"); if (!rm.hidden) rm.click(); });
    ["#o-slug", "#o-issuer", "#o-nonce", "#o-age", "#o-kid"].forEach(function (s) { $(s).value = ""; });
  }
  function fileBytes(p) { return b64bytes(HVT_FILES[p], win); }
  function runCheckAndRead() {
    var r = $("#result");
    r.setAttribute("data-verdict", ""); r.setAttribute("data-exit", "");
    var b = $("#check");
    return waitFor(function () { return !b.disabled; }, 5000, "the check button").then(function () {
      b.click();
      return waitFor(function () { return r.getAttribute("data-verdict"); }, 5000, "a verdict");
    }).then(function () {
      return { verdict: r.getAttribute("data-verdict"), exit: r.getAttribute("data-exit"), reason: r.getAttribute("data-reason"), hidden: r.hidden };
    });
  }
  function fakeNow(epoch) {
    var real = win.Date.now;
    win.Date.now = function () { return epoch * 1000; };
    return function () { win.Date.now = real; };
  }
  var FIXED = 1767225900;
  var VALID = { doc: "attestations/valid.json", keys: "keys/test-only-issuer-jwks.json" };
  function fillValid() {
    setFile("doc", fileBytes(VALID.doc), "att.json");
    setFile("keys", fileBytes(VALID.keys), "keys.json");
    $("#o-slug").value = "fixture-org"; $("#o-issuer").value = "https://issuer.test";
    return waitFor(function () { return slotHasFile("doc") && slotHasFile("keys"); }, 3000, "files to be read");
  }

  function uiChecks() {
    var seq = Promise.resolve();
    function add(name, fn) { seq = seq.then(function () { return ui(name, fn); }); }
    var langs = ["es", "en", "de", "fr", "it", "eu"];

    add("the page is ready, the signature engine passed its self-check", function () {
      return waitFor(function () { return doc.documentElement.getAttribute("data-engine"); }, 30000, "the engine").then(function (s) {
        if (s !== "ready") return "engine state " + s;
        if (!doc.documentElement.getAttribute("data-ready")) return "not ready";
        return "";
      });
    });
    add("the crafted differential inputs give what the script gives", function () { return differentialWhy(win); });
    add("the engine self-check refuses a wrong engine", function () {
      if (win.HV.selfCheck({ verify: function () { return true; } })) return "accepted an engine that says yes to everything";
      if (win.HV.selfCheck({ verify: function () { return false; } })) return "accepted an engine that says no to everything";
      if (!win.HV.selfCheck(win.HV.engine)) return "refused the real engine";
      return "";
    });
    add("every language fills every marked element", function () {
      var texts = {}, bad = "";
      return langs.reduce(function (p, l) {
        return p.then(function () {
          var sel = $("#lang");
          sel.value = l; sel.dispatchEvent(new win.Event("change", { bubbles: true }));
          return waitFor(function () { return doc.documentElement.lang === l && $("#lang").value === l; }, 3000, "language " + l).then(function () {
            return sleep(30);
          }).then(function () {
            var empty = Array.prototype.filter.call(doc.querySelectorAll("[data-i18n]"), function (e) { return e.textContent.trim() === "" || e.textContent === e.getAttribute("data-i18n"); });
            if (empty.length) bad += l + " has " + empty.length + " empty elements; ";
            texts[l] = $("h1").textContent;
          });
        });
      }, Promise.resolve()).then(function () {
        var distinct = {}; langs.forEach(function (l) { distinct[texts[l]] = 1; });
        if (Object.keys(distinct).length !== langs.length) bad += "two languages share the same heading; ";
        var sel = $("#lang"); sel.value = "en"; sel.dispatchEvent(new win.Event("change", { bubbles: true }));
        return waitFor(function () { return doc.documentElement.lang === "en"; }, 3000, "english").then(function () { return bad; });
      });
    });
    add("a file chosen for each slot gives verified (exit 0)", function () {
      resetPage(); var restore = fakeNow(FIXED);
      return fillValid().then(runCheckAndRead).then(function (r) {
        restore();
        if (r.verdict !== "verified" || r.exit !== "0" || r.reason !== "verified") return JSON.stringify(r);
        if ($("#content").hidden) return "the signed content is not shown for a verified document";
        if (doc.activeElement !== $("#result-title")) return "focus did not move to the result";
        return "";
      });
    });
    add("a tampered document gives failed (exit 1) and shows none of its content", function () {
      resetPage(); var restore = fakeNow(FIXED);
      setFile("doc", fileBytes("attestations/tampered-field.json"), "att.json");
      setFile("keys", fileBytes(VALID.keys), "keys.json");
      return waitFor(function () { return slotHasFile("doc") && slotHasFile("keys"); }, 3000, "files").then(runCheckAndRead).then(function (r) {
        restore();
        if (r.verdict !== "failed" || r.exit !== "1") return JSON.stringify(r);
        if (!$("#content").hidden) return "content shown for a document that did not verify";
        return "";
      });
    });
    add("the wrong key file gives could not check (exit 2), not failed", function () {
      resetPage(); var restore = fakeNow(FIXED);
      setFile("doc", fileBytes(VALID.doc), "att.json");
      setFile("keys", fileBytes("keys/test-only-other-jwks.json"), "keys.json");
      return waitFor(function () { return slotHasFile("doc") && slotHasFile("keys"); }, 3000, "files").then(runCheckAndRead).then(function (r) {
        restore();
        return r.verdict === "could_not_check" && r.exit === "2" && r.reason === "unknown_kid" ? "" : JSON.stringify(r);
      });
    });
    add("with no file added the answer is could not check, never verified", function () {
      resetPage();
      return runCheckAndRead().then(function (r) { return r.verdict === "could_not_check" && r.exit === "2" ? "" : JSON.stringify(r); });
    });
    add("pasted text works like a file", function () {
      resetPage(); var restore = fakeNow(FIXED);
      var td = new TextDecoder();
      [["doc", VALID.doc], ["keys", VALID.keys]].forEach(function (p) {
        slot(p[0]).querySelector("details.paste").open = true;
        var ta = slot(p[0]).querySelector("[data-paste]");
        ta.value = td.decode(fileBytes(p[1]));
        ta.dispatchEvent(new win.Event("input", { bubbles: true }));
      });
      $("#o-slug").value = "fixture-org"; $("#o-issuer").value = "https://issuer.test";
      return runCheckAndRead().then(function (r) { restore(); return r.verdict === "verified" && r.exit === "0" ? "" : JSON.stringify(r); });
    });
    add("dropping a file on a slot adds it", function () {
      resetPage();
      var dt = new win.DataTransfer();
      dt.items.add(new win.File([fileBytes(VALID.doc)], "att.json", { type: "application/json" }));
      var zone = slot("doc").querySelector("[data-drop]");
      zone.dispatchEvent(new win.DragEvent("dragenter", { bubbles: true, cancelable: true, dataTransfer: dt }));
      var over = zone.classList.contains("is-over");
      zone.dispatchEvent(new win.DragEvent("drop", { bubbles: true, cancelable: true, dataTransfer: dt }));
      return waitFor(function () { return slotHasFile("doc"); }, 3000, "the drop").then(function () { return over ? "" : "no drop highlight"; });
    });
    add("dropping two files at once puts each where it belongs", function () {
      resetPage();
      var dt = new win.DataTransfer();
      dt.items.add(new win.File([fileBytes(VALID.keys)], "keys.json", { type: "application/json" }));
      dt.items.add(new win.File([fileBytes(VALID.doc)], "att.json", { type: "application/json" }));
      slot("doc").querySelector("[data-drop]").dispatchEvent(new win.DragEvent("drop", { bubbles: true, cancelable: true, dataTransfer: dt }));
      return waitFor(function () { return slotHasFile("doc") && slotHasFile("keys"); }, 3000, "both files").then(function () { return ""; });
    });
    function typeIn(sel, value) { var i = $(sel); i.value = value; i.dispatchEvent(new win.Event("input", { bubbles: true })); }
    function switchLanguage(l) {
      var sel = $("#lang"); sel.value = l; sel.dispatchEvent(new win.Event("change", { bubbles: true }));
      return waitFor(function () { return doc.documentElement.lang === l; }, 3000, "language " + l).then(function () { return sleep(40); });
    }
    function shown() { return !$("#result").hidden && $("#result").getAttribute("data-verdict") !== ""; }
    add("changing any file or option takes a shown result off the page, and a language change does not bring it back", function () {
      var restore = fakeNow(FIXED);
      var changes = [
        ["the attestation file", function () { setFile("doc", fileBytes("attestations/tampered-field.json"), "other.json"); }],
        ["the key file", function () { setFile("keys", fileBytes("keys/test-only-other-jwks.json"), "other.json"); }],
        ["removing the attestation", function () { slot("doc").querySelector("[data-remove]").click(); }],
        ["removing the keys", function () { slot("keys").querySelector("[data-remove]").click(); }],
        ["pasting into the attestation", function () { slot("doc").querySelector("details.paste").open = true; typeIn('[data-slot="doc"] [data-paste]', "{}"); }],
        ["the withdrawal list", function () { setFile("status", fileBytes("status-lists/revokes-key.json"), "other.json"); }],
        ["the withdrawal list keys", function () { setFile("statusKeys", fileBytes("keys/test-only-other-jwks.json"), "other.json"); }],
        ["removing the withdrawal list", function () { slot("status").querySelector("[data-remove]").click(); }],
        ["the organisation", function () { typeIn("#o-slug", "other-org"); }],
        ["the issuer", function () { typeIn("#o-issuer", "https://other.test"); }],
        ["the challenge", function () { typeIn("#o-nonce", "abc"); }],
        ["the oldest age", function () { typeIn("#o-age", "5"); }],
        ["the key identifier", function () { typeIn("#o-kid", "U4ak4BB34tmbAwevvbToHw"); }]
      ];
      var bad = [];
      return changes.reduce(function (p, c) {
        return p.then(function () {
          resetPage();
          setFile("status", fileBytes("status-lists/empty.json"), "list.json");
          setFile("statusKeys", fileBytes("keys/test-only-status-jwks.json"), "keys.json");
          return fillValid().then(function () { return waitFor(function () { return slotHasFile("status") && slotHasFile("statusKeys"); }, 3000, "files"); })
            .then(runCheckAndRead).then(function (r) {
              if (!shown() || r.exit !== "0") { bad.push(c[0] + ": no result to start from (" + JSON.stringify(r) + ")"); return; }
              c[1]();
              return sleep(60).then(function () {
                if (shown() || !$("#result").hidden || $("#result").getAttribute("data-verdict") !== "") bad.push(c[0] + ": the old result is still shown");
                return switchLanguage("de").then(function () {
                  if (!$("#result").hidden) bad.push(c[0] + ": a language change brought the old result back");
                  return switchLanguage("en");
                });
              });
            });
        });
      }, Promise.resolve()).then(function () { restore(); return bad.join("; "); });
    });
    add("a language change keeps a result whose inputs have not changed", function () {
      resetPage(); var restore = fakeNow(FIXED);
      return fillValid().then(runCheckAndRead).then(function () {
        return switchLanguage("fr").then(function () {
          var kept = shown(), t1 = $("#result-title").textContent;
          return switchLanguage("en").then(function () { restore(); return kept && t1 && $("#result-title").textContent !== t1 ? "" : "the result was lost or not translated"; });
        });
      });
    });
    function printable(s) { return !/[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}]/u.test(s); }
    add("a control or direction character in the signed text or the file name is not shown raw", function () {
      resetPage(); var restore = fakeNow(1791937200);
      setFile("doc", fileBytes("fx/bidi.json"), "att\u202egnp.json");
      setFile("keys", fileBytes(VALID.keys), "keys.json");
      $("#o-slug").value = "fixture-org"; $("#o-issuer").value = "https://issuer.test";
      return waitFor(function () { return slotHasFile("doc") && slotHasFile("keys"); }, 3000, "files").then(runCheckAndRead).then(function (r) {
        restore();
        if (r.verdict !== "verified") return "the fixture did not verify: " + JSON.stringify(r);
        var shownText = $("#content-list").textContent + "|" + $("#stamp").textContent + "|" + slot("doc").querySelector("[data-status]").textContent;
        if (!printable(shownText)) return "a control or format character is shown: " + JSON.stringify(shownText);
        if (shownText.indexOf("?") < 0) return "the character was removed without a mark";
        return "";
      });
    });
    add("a genuine but old document gives expired (exit 1), with the real clock", function () {
      resetPage();
      return fillValid().then(runCheckAndRead).then(function (r) {
        return r.verdict === "expired" && r.exit === "1" ? "" : JSON.stringify(r);
      });
    });
    add("the revocation check gives good (exit 0) for a clean list", function () {
      resetPage(); var restore = fakeNow(FIXED);
      var c = HVT_CASES.filter(function (x) { return x.expect.code === "good" && x.args.indexOf("--attestation") >= 0; })[0];
      var m = { "--attestation": "doc", "--jwks": "keys", "--status": "status", "--status-keys": "statusKeys" };
      for (var i = 0; i < c.args.length; i++) if (m[c.args[i]]) setFile(m[c.args[i]], fileBytes(c.args[i + 1]), "f.json");
      var slugI = c.args.indexOf("--expect-slug"), issI = c.args.indexOf("--expect-issuer");
      if (slugI >= 0) $("#o-slug").value = c.args[slugI + 1];
      if (issI >= 0) $("#o-issuer").value = c.args[issI + 1];
      return waitFor(function () { return slotHasFile("status") && slotHasFile("statusKeys"); }, 3000, "files").then(runCheckAndRead).then(function (r) {
        restore();
        return r.verdict === "good" && r.exit === "0" ? "" : JSON.stringify(r) + " for " + c.id;
      });
    });
    add("start again clears the result and the files", function () {
      $("#again").click();
      if (!$("#result").hidden) return "the result is still shown";
      if (slotHasFile("doc")) return "a file is still held";
      return "";
    });
    add("the page asked for nothing but its own files, and kept nothing", function () {
      var bad = [];
      win.performance.getEntriesByType("resource").forEach(function (e) {
        if (e.initiatorType === "fetch" || e.initiatorType === "xmlhttprequest" || e.initiatorType === "beacon") bad.push(e.initiatorType + " " + e.name);
        var base = mode === "http" ? location.origin + "/app/" : q.get("page").replace(/index\.html$/, "");
        if (e.name.indexOf(base) !== 0) bad.push("outside the page: " + e.name);
      });
      if (win.document.cookie !== "") bad.push("a cookie was set");
      try { if (win.localStorage.length || win.sessionStorage.length) bad.push("storage was written"); } catch (e) { /* not available from disk: nothing kept */ }
      return bad.join("; ");
    });
    add("the Content-Security-Policy is the strict one", function () {
      var m = doc.querySelector('meta[http-equiv="Content-Security-Policy"]');
      if (!m) return "no policy";
      var p = m.getAttribute("content");
      if (/unsafe-inline|unsafe-eval|https?:|\*/.test(p.replace(/wasm-unsafe-eval/g, ""))) return "loose policy: " + p;
      if (!/default-src 'none'/.test(p) || !/script-src 'self' 'wasm-unsafe-eval'/.test(p)) return "unexpected policy: " + p;
      return "";
    });
    return seq;
  }

  // Direct mode (Firefox from disk): the browser gives every file its own origin, so
  // a frame cannot be looked into. The page's scripts are loaded here, in the
  // order of index.html, and the vectors run on the real module. The page's own
  // look and CSP from disk are checked by run.mjs with a screenshot.
  var PAGE_SCRIPTS = ["locales/en.js", "js/base.js", "js/json.js", "js/canon.js", "js/verify.js", "js/i18n.js", "js/engine.js",
    "js/selftest.js", "mldsa/mldsa_wasm.b64.js", "mldsa/mldsa_wasm.js"];
  function startDirect() {
    var base = q.get("page").replace(/index\.html$/, "");
    return loadScript(server + "/data.js").then(function () {
      return PAGE_SCRIPTS.reduce(function (p, f) { return p.then(function () { return loadScript(base + f); }); }, Promise.resolve());
    }).then(function () { return HV.engine.initFromPage(); }).then(function (eng) {
      if (!eng.ready) throw new Error("the signature engine did not start: " + eng.error);
      if (!HV.selfCheck(eng)) throw new Error("the signature engine failed its self-check");
      win = window;
      HVT_CASES.forEach(function (c) {
        var why;
        try {
          var files = {};
          HVT.filesOf(c.args).forEach(function (p) { files[p] = b64bytes(HVT_FILES[p]); });
          var res = HV.verify(HVT.buildInput(c.args, files), HV.engine);
          why = HVT.judge(c, res);
          if (!why && HVT.KNOWN_REASON_DIFFERENCES[c.id]) result.reasonDifferences.push(c.id);
        } catch (e) { why = "exception: " + (e && e.message || e); }
        result.cases.push({ id: c.id, ok: !why, why: why || "" });
      });
      var dw = differentialWhy(window);
      result.ui.push({ name: "the crafted differential inputs give what the script gives", ok: !dw, why: dw });
      result.direct = true;
    }).then(function () { finish(); }, function (e) { finish(String(e && e.message || e)); });
  }

  function start() {
    loadScript(server + "/data.js").then(function () {
      frame = document.createElement("iframe");
      frame.width = 1100; frame.height = 900;
      frame.src = mode === "http" ? "/app/index.html?lang=en" : q.get("page") + "?lang=en";
      document.body.appendChild(frame);
      return new Promise(function (res) { frame.onload = res; });
    }).then(function () {
      win = frame.contentWindow; doc = frame.contentDocument;
      return waitFor(function () { return doc.documentElement.getAttribute("data-engine"); }, 30000, "the signature engine");
    }).then(function () {
      if (doc.documentElement.getAttribute("data-engine") !== "ready") throw new Error("the signature engine did not start in the framed page: " + (win.HV && win.HV.engine && win.HV.engine.error) + " selfcheck=" + (win.HV && win.HV.engine && win.HV.selfCheck && win.HV.selfCheck(win.HV.engine)));
      runVectors();
      return uiChecks();
    }).then(function () { finish(); }, function (e) {
      var info = "";
      try { info = " [HV=" + typeof win.HV + ", engine.error=" + (win.HV && win.HV.engine && win.HV.engine.error) + ", i18n=" + (win.HV && win.HV.i18n && win.HV.i18n.current) + ", state=" + doc.documentElement.getAttribute("data-engine") + ", ready=" + doc.documentElement.getAttribute("data-ready") + "]"; } catch (x) { info = " [no access to the frame: " + x.message + "]"; }
      finish(String(e && e.message || e) + info);
    });
  }
  if (q.get("direct")) startDirect(); else start();
})();
