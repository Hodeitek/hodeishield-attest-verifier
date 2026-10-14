// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.
//
// Interface text. Every string the page shows lives in web/locales/<code>.js;
// nothing is written in the markup or in the code except the <noscript> note.
// The language follows the browser (navigator.languages, primary subtag), can be
// forced with ?lang=xx, and falls back to English for a language that is not
// shipped and for a key that a file lacks. The choice is kept in memory and in
// the address only: no cookie, no storage.
(function (root) {
  "use strict";
  var HV = root.HV || (root.HV = {});
  var LANGS = [
    { code: "es", name: "Español" },
    { code: "en", name: "English" },
    { code: "de", name: "Deutsch" },
    { code: "fr", name: "Français" },
    { code: "it", name: "Italiano" },
    { code: "eu", name: "Euskara" }
  ];
  var FALLBACK = "en";
  var i18n = { languages: LANGS, fallback: FALLBACK, current: FALLBACK };

  function supported(code) {
    for (var i = 0; i < LANGS.length; i++) if (LANGS[i].code === code) return true;
    return false;
  }
  function primary(tag) { return String(tag || "").toLowerCase().split(/[-_]/)[0]; }

  // The language to start in: ?lang=, then the browser's list, then English.
  i18n.detect = function (search, languages) {
    var m = /(?:^|[?&])lang=([A-Za-z-]+)/.exec(search || "");
    if (m && supported(primary(m[1]))) return primary(m[1]);
    var list = languages || [];
    for (var i = 0; i < list.length; i++) if (supported(primary(list[i]))) return primary(list[i]);
    return FALLBACK;
  };

  function lookup(key) {
    var L = HV.locales || {};
    var cur = L[i18n.current], fb = L[FALLBACK];
    if (cur && Object.prototype.hasOwnProperty.call(cur, key) && cur[key] !== "") return cur[key];
    if (fb && Object.prototype.hasOwnProperty.call(fb, key)) return fb[key];
    return key;
  }
  // t("key", { name: value }): {name} is replaced by the value, as text.
  i18n.t = function (key, params) {
    return String(lookup(key)).replace(/\{([A-Za-z0-9_]+)\}/g, function (m, k) {
      return params && Object.prototype.hasOwnProperty.call(params, k) ? String(params[k]) : m;
    });
  };

  // Load a locale file from the page's own files (a script, allowed by 'self').
  i18n.load = function (code) {
    return new Promise(function (resolve) {
      if (!supported(code) || (HV.locales && HV.locales[code])) return resolve(true);
      var s = document.createElement("script");
      s.src = "locales/" + code + ".js";
      s.onload = function () { resolve(!!(HV.locales && HV.locales[code])); };
      s.onerror = function () { resolve(false); };
      document.head.appendChild(s);
    });
  };

  // Put the text of the current language into every marked element.
  i18n.apply = function (rootEl) {
    var scope = rootEl || document;
    var attrs = { "data-i18n-aria-label": "aria-label", "data-i18n-placeholder": "placeholder", "data-i18n-title": "title" };
    Array.prototype.forEach.call(scope.querySelectorAll("[data-i18n]"), function (el) {
      el.textContent = i18n.t(el.getAttribute("data-i18n"));
    });
    Object.keys(attrs).forEach(function (a) {
      Array.prototype.forEach.call(scope.querySelectorAll("[" + a + "]"), function (el) {
        el.setAttribute(attrs[a], i18n.t(el.getAttribute(a)));
      });
    });
    document.documentElement.setAttribute("lang", i18n.current);
    document.title = i18n.t("app.title") + " · " + i18n.t("app.name");
  };

  // Switch language: load the file, fall back to English if it cannot be loaded.
  i18n.set = function (code) {
    var want = supported(code) ? code : FALLBACK;
    return i18n.load(FALLBACK).then(function () { return i18n.load(want); }).then(function (okLoaded) {
      i18n.current = okLoaded ? want : FALLBACK;
      return i18n.current;
    });
  };

  HV.i18n = i18n;
})(typeof globalThis !== "undefined" ? globalThis : this);
