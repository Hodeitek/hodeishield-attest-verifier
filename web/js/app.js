// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.
//
// The page. It reads the files the reader gives it, hands them to HV.verify (the
// port of the reference script) and shows the answer. Nothing here sends a file
// anywhere: the page has no network permission (see the Content-Security-Policy
// in index.html) and keeps nothing in cookies or storage.
//
// Every string comes from HV.i18n.t. The result element carries data-verdict,
// data-exit and data-reason, which tests read instead of the text.
(function (root) {
  "use strict";
  var HV = root.HV, t = function (k, p) { return HV.i18n.t(k, p); };
  var doc = root.document;
  var MAX_BYTES = 5000000;

  var slots = {};      // name -> { el, bytes, name, source }
  var last = null;     // { res, input } of the last check, to re-render on a language change
  var engineOk = false;

  function $(sel, scope) { return (scope || doc).querySelector(sel); }
  function $all(sel, scope) { return Array.prototype.slice.call((scope || doc).querySelectorAll(sel)); }
  function el(tag, cls, text) {
    var e = doc.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }
  function svgIcon(id, cls) {
    var ns = "http://www.w3.org/2000/svg";
    var s = doc.createElementNS(ns, "svg");
    s.setAttribute("class", cls);
    s.setAttribute("aria-hidden", "true");
    var u = doc.createElementNS(ns, "use");
    u.setAttribute("href", "#" + id);
    s.appendChild(u);
    return s;
  }
  // What the reader sees of a text that the document or the file system supplied:
  // a control, format (direction override, zero-width), separator, private-use,
  // unassigned or lone-surrogate character becomes "?", as the script's summary does
  // (it keeps only what Python's isprintable calls printable). A signed organisation
  // name cannot then reorder or hide what is shown beside it.
  var UNPRINTABLE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}\p{Zs}]/gu;
  function clean(v) { return String(v).replace(UNPRINTABLE, function (c) { return c === " " ? c : "?"; }); }
  function fmtSize(n) {
    if (n < 1000) return n + " B";
    if (n < 1000000) return (n / 1000).toFixed(1) + " kB";
    return (n / 1000000).toFixed(1) + " MB";
  }
  function fmtDate(iso) {
    if (!iso) return "";
    var d = new Date(iso);
    if (isNaN(d.getTime())) return clean(iso);
    try {
      return new Intl.DateTimeFormat(HV.i18n.current, { dateStyle: "long", timeStyle: "short", timeZone: "UTC" }).format(d) + " UTC";
    } catch (e) { return clean(iso); }
  }

  // ---- input slots -----------------------------------------------------------
  function setStatus(slot, msg, isError) {
    var s = $("[data-status]", slot.el);
    s.textContent = msg || "";
    s.classList.toggle("is-error", !!isError);
  }
  function refreshSlot(slot) {
    var has = !!slot.bytes;
    $("[data-remove]", slot.el).hidden = !has;
    $("[data-drop]", slot.el).classList.toggle("has-file", has);
    if (has) {
      setStatus(slot, slot.source === "paste" ? t("drop.addedPaste", { size: fmtSize(slot.bytes.length) }) : t("drop.added", { name: clean(slot.name), size: fmtSize(slot.bytes.length) }));
    } else if (!slot.error) setStatus(slot, "");
    updateButton();
  }
  function clearSlot(slot) {
    invalidate();
    slot.bytes = null; slot.name = ""; slot.source = ""; slot.error = null;
    $("[data-paste]", slot.el).value = "";
    $("[data-file]", slot.el).value = "";
    refreshSlot(slot);
  }
  // A result belongs to the files and options it was made from. Changing any of
  // them takes it off the page, so that a verdict is never shown beside inputs it
  // was not made from (the language switch re-renders a result only while it holds).
  function invalidate() {
    last = null;
    var box = $("#result");
    box.hidden = true;
    ["data-verdict", "data-exit", "data-reason"].forEach(function (a) { box.setAttribute(a, ""); });
    ["#checklist", "#notes", "#content-list", "#tech-facts", "#tech-checks", "#stamp"].forEach(function (s) { $(s).textContent = ""; });
    $("#content").hidden = true;
    $("#again").hidden = true;
  }
  function putBytes(slot, bytes, name, source) {
    invalidate();
    slot.bytes = bytes; slot.name = name; slot.source = source; slot.error = null;
    if (source !== "paste") $("[data-paste]", slot.el).value = "";
    refreshSlot(slot);
  }
  function readFile(file) {
    return new Promise(function (resolve, reject) {
      if (file.size > MAX_BYTES) return reject({ code: "big", size: file.size });
      var done = function (buf) { resolve(new Uint8Array(buf)); };
      if (file.arrayBuffer) file.arrayBuffer().then(done, function () { reject({ code: "read" }); });
      else {
        var r = new FileReader();
        r.onload = function () { done(r.result); };
        r.onerror = function () { reject({ code: "read" }); };
        r.readAsArrayBuffer(file);
      }
    });
  }
  function addFile(slot, file) {
    return readFile(file).then(function (bytes) {
      putBytes(slot, bytes, file.name, "file");
    }, function (e) {
      invalidate();
      slot.bytes = null; slot.error = true;
      refreshSlot(slot);
      setStatus(slot, e && e.code === "big" ? t("drop.tooBig", { size: fmtSize(e.size), max: fmtSize(MAX_BYTES) }) : t("drop.unreadable"), true);
    });
  }
  // A guess at which slot a dropped file belongs to, from its first bytes. Only
  // used when several files are dropped at once; one file goes where it was dropped.
  function classify(bytes) {
    try {
      var o = HV.json.parse(bytes);
      if (HV.json.isObj(o)) {
        if (o.has("statusList")) return "status";
        if (Array.isArray(o.get("keys"))) return "keys";
      }
    } catch (e) { /* not JSON: leave it as a document */ }
    return "doc";
  }
  function routeMany(files) {
    var order = ["doc", "keys", "status"];
    var jobs = Array.prototype.map.call(files, function (f) {
      return readFile(f).then(function (b) { return { f: f, b: b, to: classify(b) }; }, function () { return null; });
    });
    return Promise.all(jobs).then(function (items) {
      var taken = {};
      items.forEach(function (it) {
        if (!it) return;
        var to = it.to;
        if (taken[to]) return;
        taken[to] = true;
        if (order.indexOf(to) >= 0) putBytes(slots[to], it.b, it.f.name, "file");
      });
      if (taken.status || taken.keys) {
        if (taken.status) $("#rev").open = true;
      }
      $("#form").dispatchEvent(new CustomEvent("routed"));
    });
  }

  function wireSlot(slotEl) {
    var name = slotEl.getAttribute("data-slot");
    var slot = slots[name] = { el: slotEl, bytes: null, name: "", source: "", error: null };
    var drop = $("[data-drop]", slotEl), input = $("[data-file]", slotEl);
    $("[data-choose]", slotEl).addEventListener("click", function () { input.click(); });
    input.addEventListener("change", function () { if (input.files && input.files[0]) addFile(slot, input.files[0]); });
    ["dragenter", "dragover"].forEach(function (ev) {
      drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.add("is-over"); });
    });
    ["dragleave", "dragend"].forEach(function (ev) {
      drop.addEventListener(ev, function () { drop.classList.remove("is-over"); });
    });
    drop.addEventListener("drop", function (e) {
      e.preventDefault(); drop.classList.remove("is-over");
      var files = e.dataTransfer && e.dataTransfer.files;
      if (!files || !files.length) return;
      if (files.length > 1) routeMany(files).then(function () { announceRouted(); });
      else addFile(slot, files[0]);
    });
    $("[data-remove]", slotEl).addEventListener("click", function () { clearSlot(slot); $("[data-choose]", slotEl).focus(); });
    $("[data-paste]", slotEl).addEventListener("input", function (e) {
      var v = e.target.value;
      if (v === "") { if (slot.source === "paste") clearSlot(slot); return; }
      var bytes = new TextEncoder().encode(v);
      if (bytes.length > MAX_BYTES) { invalidate(); slot.bytes = null; refreshSlot(slot); setStatus(slot, t("drop.tooBig", { size: fmtSize(bytes.length), max: fmtSize(MAX_BYTES) }), true); return; }
      putBytes(slot, bytes, "", "paste");
    });
  }
  function announceRouted() { setStatus(slots.doc, slots.doc.bytes ? t("drop.routed") : ""); }

  function updateButton() {
    var b = $("#check");
    b.disabled = !engineOk;
  }

  // ---- reading the options ---------------------------------------------------
  function readOptions() {
    var o = {};
    var v = function (id) { return $(id).value.trim(); };
    if (v("#o-slug")) o.expectSlug = v("#o-slug");
    if (v("#o-issuer")) o.expectIssuer = v("#o-issuer");
    if (v("#o-nonce")) o.expectNonce = $("#o-nonce").value;
    if (v("#o-kid")) o.expectKids = [v("#o-kid")];
    var age = v("#o-age");
    if (age !== "") o.maxAgeSeconds = String(Math.round(Number(age) * 60));
    return o;
  }

  // ---- the check -------------------------------------------------------------
  function buildInput() {
    var inp = readOptions();
    inp.attestation = slots.doc.bytes || undefined;
    inp.jwks = slots.keys.bytes || undefined;
    if (slots.status.bytes || slots.statusKeys.bytes) {
      inp.statusList = true;
      inp.status = slots.status.bytes || undefined;
      inp.statusKeys = slots.statusKeys.bytes || undefined;
    }
    if (inp.maxAgeSeconds !== undefined && !/^[0-9]{1,9}$/.test(inp.maxAgeSeconds)) inp.maxAgeSeconds = "x";
    return inp;
  }
  function runCheck() {
    var btn = $("#check");
    btn.textContent = t("action.checking");
    btn.disabled = true;
    // let the browser paint "Checking…" before the (short) synchronous work
    setTimeout(function () {
      var inp = buildInput(), res;
      try { res = HV.verify(inp, HV.engine); }
      catch (e) { res = { exit_code: 2, verdict: "could_not_check", reason: "internal_error", checks: [], attested: null, facts: {}, mode: "attestation" }; }
      last = { res: res, input: inp, time: new Date(Date.now()).toISOString(), doc: slots.doc.source === "paste" ? "" : slots.doc.name,
        fp: slots.doc.bytes ? HV.base.hex(HV.base.sha256(slots.doc.bytes)).slice(0, 16) : "" };
      btn.textContent = t("action.check");
      updateButton();
      renderResult(true);
    }, 30);
  }

  // ---- reason texts ------------------------------------------------------------
  var STRUCTURE = ["header_alg_invalid", "header_typ_invalid", "header_not_allowed", "header_too_large", "signature_size_invalid", "public_key_size_invalid",
    "kid_mismatch", "payload_claims_mismatch", "payload_not_envelope", "date_unparseable", "generated_at_missing", "missing_expiry", "ttl_exceeded",
    "unsupported_version", "duplicate_key", "unsigned_member", "iss_empty", "slug_empty", "overall_band_mismatch", "redaction_violation", "nul_byte"];
  var UNREADABLE = ["attestation_unparseable", "attestation_signature_missing", "claims_posture_missing", "jws_not_compact", "jws_too_many_dots",
    "jws_detached_needs_claims", "header_not_base64url", "signature_not_base64url", "payload_not_base64url", "public_key_not_base64url",
    "canonicalise_failed", "canonicalise_posture_failed", "claims_unreadable", "attestation_unreadable", "jws_unreadable"];
  var KEYS_UNUSABLE = ["not_strict_json", "jwks_duplicate_key", "jwks_keys_not_array", "jwks_duplicate_kid", "jwks_retired_at_malformed", "public_key_rejected", "jwks_unreadable"];
  var MISSING = ["attestation_missing", "key_source_missing", "status_source_missing", "status_keys_source_missing", "status_list_nothing_to_check", "expect_kid_needs_attestation"];
  var DIRECT = ["signature_invalid", "not_yet_valid", "unexpected_kid", "slug_mismatch", "issuer_mismatch", "nonce_mismatch", "retired_key", "revoked_key", "revoked_subject", "unknown_kid", "engine_unavailable"];

  function reasonKey(code) {
    if (!code) return null;
    if (DIRECT.indexOf(code) >= 0) return "reason." + code;
    if (STRUCTURE.indexOf(code) >= 0) return "reason.structure";
    if (UNREADABLE.indexOf(code) >= 0) return "reason.unreadable";
    if (KEYS_UNUSABLE.indexOf(code) >= 0) return "reason.keys_unusable";
    if (MISSING.indexOf(code) >= 0) return "reason.missing_input";
    if (code === "anchor_unverified") return "reason.anchor";
    if (code === "usage" || code === "pub_b64url_with_jwks" || code === "posture_with_claims" || code === "anchor_bundle_without_file") return "reason.usage";
    if (code === "internal_error") return "reason.internal";
    if (code === "status_unknown_stale") return "reason.status_stale";
    if (code === "status_unknown_rolled_back") return "reason.status_rollback";
    if (code === "status_unknown_list_unverified" || code === "status_unknown_generated_at_missing" || code === "status_unknown_subject_dates_unparseable") return "reason.status_unverified";
    if (code === "status_unknown_truncated") return "reason.status_truncated";
    if (code === "status_unknown_no_subject") return "reason.status_no_subject";
    if (code.indexOf("status_unknown_") === 0) return "reason.status_unknown";
    return null;
  }

  // ---- the checklist -----------------------------------------------------------
  function buildChecklist(res, inp) {
    var by = {};
    res.checks.forEach(function (c) { by[c.code] = by[c.code] === "fail" ? "fail" : c.result; });
    var any = function (codes, result) { return codes.some(function (c) { return by[c] === result; }); };
    var all = function (codes) { return codes.every(function (c) { return by[c] === "pass"; }); };
    var ran = by.jws_attached || by.jws_detached;
    var items = [];

    var sig = by.signature_valid === "pass" ? "pass" : (any(["signature_invalid", "signature_size_invalid"], "fail") ? "fail" : "notreached");
    items.push({ k: "list.sig", s: sig });

    var key = any(["kid_mismatch", "unexpected_kid", "retired_key", "public_key_size_invalid", "public_key_rejected"], "fail") ? "fail"
      : (all(["kid_derivable", "claims_kid_matches"]) ? "pass" : "notreached");
    items.push({ k: "list.key", s: key });

    var structFail = any(STRUCTURE.filter(function (c) { return ["kid_mismatch", "date_unparseable", "generated_at_missing", "missing_expiry", "ttl_exceeded", "public_key_size_invalid", "signature_size_invalid"].indexOf(c) < 0; }), "fail");
    var struct = structFail ? "fail" : (all(["members_signed", "header_members_valid", "header_alg_valid", "header_typ_valid", "doc_version_valid"]) ? "pass" : "notreached");
    items.push({ k: "list.structure", s: struct });

    var ageFail = any(["too_old", "expired", "not_yet_valid", "ttl_exceeded", "date_unparseable", "generated_at_missing", "missing_expiry"], "fail");
    var age = ageFail ? "fail" : (all(["fresh", "not_expired", "ttl_within_ceiling"]) ? "pass" : "notreached");
    items.push({ k: "list.age", s: age });

    var slugS = by.slug_mismatch === "fail" ? "fail" : (by.slug_match === "pass" ? "pass" : "skip");
    items.push({ k: "list.slug", s: slugS, hint: slugS === "skip" ? "list.slugHint" : null });
    var issS = by.issuer_mismatch === "fail" ? "fail" : (by.issuer_match === "pass" ? "pass" : "skip");
    items.push({ k: "list.issuer", s: issS, hint: issS === "skip" ? "list.issuerHint" : null });

    var rev;
    if (!inp.statusList) rev = "skip";
    else if (res.verdict === "good") rev = "pass";
    else if (res.verdict === "revoked") rev = "fail";
    else rev = "notreached";
    items.push({ k: "list.revoked", s: rev, hint: rev === "skip" ? "list.revokedHint" : null });
    if (!ran) items.forEach(function (i) { if (i.s !== "skip") i.s = "notreached"; });
    return items;
  }

  // ---- rendering ---------------------------------------------------------------
  var GLYPH = { verified: "i-check", good: "i-check", failed: "i-cross", expired: "i-clock", could_not_check: "i-pause", revoked: "i-ban", unknown: "i-question" };

  function renderResult(focus) {
    if (!last) return;
    var res = last.res, inp = last.input, facts = res.facts || {};
    var box = $("#result");
    var verdict = GLYPH[res.verdict] ? res.verdict : "could_not_check";
    box.hidden = false;
    box.setAttribute("data-verdict", res.verdict);
    box.setAttribute("data-exit", String(res.exit_code));
    box.setAttribute("data-reason", res.reason || "");
    $("#glyph-use").setAttribute("href", "#" + GLYPH[verdict]);
    $("#result-title").textContent = t("result." + verdict + ".title");
    $("#result-meaning").textContent = t("result." + verdict + ".meaning");
    $("#result-next").textContent = t("result." + verdict + ".next");

    // the reason, for everything that is not a clean pass
    var why = $("#result-why");
    var text = "";
    if (res.exit_code !== 0) {
      if (verdict === "expired") {
        text = facts.expiredBecause === "expired" ? t("reason.expired", { date: fmtDate(facts.expiresAt) })
          : t("reason.too_old", { date: fmtDate(facts.generatedAt), minutes: Math.round((facts.maxAgeSeconds || 3600) / 60) });
      } else {
        var k = reasonKey(res.reason);
        text = k ? t(k) : "";
      }
    }
    why.hidden = !text;
    $("#why-label").textContent = t("result.reasonLabel");
    $("#why-text").textContent = text;

    var notes = $("#notes");
    notes.textContent = "";
    if (res.exit_code === 0 || verdict === "expired") {
      var codes = res.checks.map(function (c) { return c.code; });
      if (codes.indexOf("issuer_unpinned") >= 0) notes.appendChild(el("li", "", t("note.issuer_unpinned")));
      if (codes.indexOf("nonce_unchecked") >= 0) notes.appendChild(el("li", "", t("note.nonce_unchecked")));
    }
    if (verdict === "verified") notes.appendChild(el("li", "", t("note.withdrawal_unchecked")));
    var stamp = $("#stamp");
    stamp.hidden = !last.fp;
    stamp.textContent = last.fp ? t("result.stamp", { date: fmtDate(last.time), doc: last.doc ? clean(last.doc) : t("result.pastedDoc"), hash: last.fp }) : "";
    var lim = $("#limits");
    lim.hidden = !(verdict === "verified" || verdict === "good");
    lim.textContent = lim.hidden ? "" : t("result.limits");

    // checklist
    var ol = $("#checklist");
    ol.textContent = "";
    buildChecklist(res, inp).forEach(function (it, i) {
      var li = el("li", "st-" + it.s);
      li.style.setProperty("--i", String(i));
      li.appendChild(svgIcon(it.s === "pass" ? "i-check" : (it.s === "fail" ? "i-cross" : "i-dash"), "icon mark"));
      var label = el("span", "label", t(it.k));
      if (it.hint) { var h = el("span", "hint", t(it.hint)); label.appendChild(h); }
      li.appendChild(label);
      li.appendChild(el("span", "state", t("state." + it.s)));
      ol.appendChild(li);
    });

    renderContent(res);
    renderTech(res);
    $("#again").hidden = false;
    if (focus) {
      box.scrollIntoView({ behavior: "auto", block: "start" });
      $("#result-title").focus({ preventScroll: true });
    }
  }

  function renderContent(res) {
    var sec = $("#content"), dl = $("#content-list");
    dl.textContent = "";
    var a = res.attested;
    sec.hidden = !a;
    if (!a) return;
    function row(label, valueNode) {
      dl.appendChild(el("dt", "", t(label)));
      var dd = el("dd");
      if (typeof valueNode === "string") dd.textContent = valueNode; else dd.appendChild(valueNode);
      dl.appendChild(dd);
    }
    if (a.orgName) row("content.org", clean(a.orgName));
    if (a.slug) row("content.slug", clean(a.slug));
    row("content.level", a.overallBand ? t("band." + a.overallBand) : t("band.none"));
    if (a.generatedAt) row("content.issuedAt", fmtDate(a.generatedAt));
    if (a.expiresAt) row("content.expiresAt", fmtDate(a.expiresAt));
    if (a.iss) row("content.issuer", clean(a.iss));
    var ul = el("ul", "fw");
    if (!a.frameworks.length) ul.appendChild(el("li", "", t("content.none")));
    a.frameworks.forEach(function (f) {
      var b = String(f.band);
      var bandText = ["in_progress", "basic", "substantial", "advanced"].indexOf(b) >= 0 ? t("band." + b) : clean(b);
      ul.appendChild(el("li", "", clean(f.label) + " (" + clean(f.code) + "): " + bandText));
    });
    row("content.frameworks", ul);
  }

  function renderTech(res) {
    var f = $("#tech-facts");
    f.textContent = "";
    function fact(label, value, mono) {
      f.appendChild(el("dt", "", t(label)));
      f.appendChild(el("dd", mono ? "mono" : "", value));
    }
    fact("details.verdict", res.verdict, true);
    fact("details.reason", res.reason || "-", true);
    fact("details.exit", String(res.exit_code), true);
    fact("details.mode", res.mode, true);
    if (res.canonical_sha256) fact("details.canon", res.canonical_sha256, true);
    if (res.status_canonical_sha256) fact("details.canon", res.status_canonical_sha256, true);
    if (HV.engine.wasmSha256) fact("details.engine", HV.engine.wasmSha256, true);
    var ol = $("#tech-checks");
    ol.textContent = "";
    res.checks.forEach(function (c) {
      var li = el("li");
      li.appendChild(el("span", "r-" + (c.result === "pass" ? "pass" : (c.result === "warn" ? "warn" : "fail")), t("details." + c.result)));
      li.appendChild(el("span", "", c.code));
      li.appendChild(el("span", "", String(c.exit_class)));
      ol.appendChild(li);
    });
  }

  function resetAll() {
    last = null;
    $("#result").hidden = true;
    $("#again").hidden = true;
    Object.keys(slots).forEach(function (k) { clearSlot(slots[k]); });
    $all("#form input[type=text], #form input[type=url], #form input[type=number]").forEach(function (i) { i.value = ""; });
    $("#form").scrollIntoView({ block: "start" });
    $("[data-choose]", slots.doc.el).focus();
  }

  function copyReport() {
    if (!last) return;
    var res = last.res;
    var report = {
      schema: res.schema, verifier: res.verifier, mode: res.mode, exit_code: res.exit_code, verdict: res.verdict, reason: res.reason,
      checks: res.checks, canonical_sha256: res.canonical_sha256, status_canonical_sha256: res.status_canonical_sha256,
      signature_module_sha256: HV.engine.wasmSha256
    };
    var text = JSON.stringify(report, null, 2);
    var ok = function () { $("#copied").textContent = t("details.copied"); setTimeout(function () { $("#copied").textContent = ""; }, 2500); };
    if (root.navigator && root.navigator.clipboard && root.navigator.clipboard.writeText) root.navigator.clipboard.writeText(text).then(ok, function () {});
  }

  // ---- language ----------------------------------------------------------------
  function fillLanguages() {
    var sel = $("#lang");
    sel.textContent = "";
    HV.i18n.languages.forEach(function (l) {
      var o = el("option", "", l.name);
      o.value = l.code; o.setAttribute("lang", l.code);
      sel.appendChild(o);
    });
    sel.value = HV.i18n.current;
  }
  function applyLanguage() {
    HV.i18n.apply(doc);
    $("#lang").value = HV.i18n.current;
    $("#version").textContent = t("foot.version", { version: HV.VERSION });
    $("#check").textContent = t("action.check");
    Object.keys(slots).forEach(function (k) { refreshSlot(slots[k]); });
    setEngineMessage();
    if (last) renderResult(false);
  }
  function setLanguage(code, pushUrl) {
    return HV.i18n.set(code).then(function () {
      applyLanguage();
      if (pushUrl) {
        try { root.history.replaceState(null, "", "?lang=" + HV.i18n.current); } catch (e) { /* file: pages cannot change their address */ }
      }
    });
  }

  function setEngineMessage() {
    var p = $("#engine");
    if (engineState === "ready") { p.textContent = ""; p.classList.remove("is-error"); }
    else if (engineState === "failed") { p.textContent = t("engine.failed"); p.classList.add("is-error"); }
    else { p.textContent = t("engine.loading"); p.classList.remove("is-error"); }
  }
  var engineState = "loading";

  // ---- start ---------------------------------------------------------------------
  function start() {
    $all("[data-slot]").forEach(wireSlot);
    $("#form").addEventListener("submit", function (e) { e.preventDefault(); if (engineOk) runCheck(); });
    $("#again").addEventListener("click", resetAll);
    $("#copy").addEventListener("click", copyReport);
    $("#lang").addEventListener("change", function (e) { setLanguage(e.target.value, true); });
    $all("#opts input").forEach(function (i) { i.addEventListener("input", invalidate); i.addEventListener("change", invalidate); });
    // A file dropped beside a drop zone must not make the browser open it and leave the page.
    ["dragover", "drop"].forEach(function (ev) { root.addEventListener(ev, function (e) { e.preventDefault(); }); });

    var lang = HV.i18n.detect(root.location.search, root.navigator.languages || [root.navigator.language]);
    setLanguage(lang, false).then(function () {
      fillLanguages();
      applyLanguage();
      doc.documentElement.setAttribute("data-ready", "1");
    });

    HV.engine.initFromPage().then(function (eng) {
      engineOk = !!eng.ready && HV.selfCheck(eng);
      engineState = engineOk ? "ready" : "failed";
      if (!engineOk) HV.engine.ready = false;
      setEngineMessage();
      updateButton();
      doc.documentElement.setAttribute("data-engine", engineOk ? "ready" : "failed");
    });
  }

  if (doc.readyState === "loading") doc.addEventListener("DOMContentLoaded", start); else start();
})(typeof globalThis !== "undefined" ? globalThis : this);
