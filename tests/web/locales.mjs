// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.
//
// The six interface languages (web/locales/{es,en,de,fr,it,eu}.js) keep the same
// keys and say something of their own:
//   - no file lacks a key that English has, none has an extra key, none has an
//     empty value;
//   - no value is identical to the English one, except the few listed in
//     tests/web/locales-allow.json (proper nouns and the like), so a file that
//     is English copied into another language fails;
//   - the {placeholders} of a value are the same in every language;
//   - every key the page uses exists (static keys read from index.html and
//     app.js, and the families built at run time);
//   - the key "_review" (a file marked for native review) is ignored, and listed.
// Reads files only. Needs Node; no dependency.
//   node tests/web/locales.mjs
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const web = path.join(root, "web");
const LANGS = ["es", "en", "de", "fr", "it", "eu"];
const allow = JSON.parse(fs.readFileSync(path.join(root, "tests/web/locales-allow.json"), "utf8"));
let failed = 0;
function check(name, ok, why) {
  if (ok) console.log("ok - " + name);
  else { console.log("not ok - " + name + (why ? " (" + why + ")" : "")); failed++; }
}

const L = {};
for (const l of LANGS) {
  const sandbox = { HV: {} };
  sandbox.globalThis = sandbox;
  vm.runInNewContext(fs.readFileSync(path.join(web, "locales", l + ".js"), "utf8"), sandbox, { filename: l + ".js" });
  L[l] = sandbox.HV.locales && sandbox.HV.locales[l];
  check(l + ".js defines HV.locales." + l, !!L[l]);
}
const keysOf = (o) => Object.keys(o).filter((k) => k !== "_review");
const en = L.en;
const enKeys = keysOf(en);
const ph = (s) => (String(s).match(/\{[A-Za-z0-9_]+\}/g) || []).sort().join(",");
const reviewed = [];

for (const l of LANGS) {
  if (l === "en") continue;
  const o = L[l], ks = keysOf(o);
  if (typeof o._review === "string") reviewed.push(l);
  const missing = enKeys.filter((k) => !(k in o)), extra = ks.filter((k) => !(k in en));
  const empty = ks.filter((k) => typeof o[k] !== "string" || o[k].trim() === "");
  check(l + ": no missing key", missing.length === 0, missing.join(", "));
  check(l + ": no extra key", extra.length === 0, extra.join(", "));
  check(l + ": no empty value", empty.length === 0, empty.join(", "));
  const okList = new Set([...(allow.all || []), ...((allow.perLocale && allow.perLocale[l]) || [])]);
  const same = ks.filter((k) => k in en && o[k] === en[k] && !okList.has(k));
  check(l + ": no value identical to English (outside the allow-list)", same.length === 0, same.join(", "));
  const badPh = ks.filter((k) => k in en && ph(o[k]) !== ph(en[k]));
  check(l + ": the {placeholders} are those of English", badPh.length === 0, badPh.join(", "));
  const stale = [...okList].filter((k) => k in en && o[k] !== en[k] && (allow.perLocale || {})[l] && allow.perLocale[l].includes(k));
  check(l + ": every allow-list entry is still needed", stale.length === 0, stale.join(", "));
}
check("en: no empty value", enKeys.every((k) => typeof en[k] === "string" && en[k].trim() !== ""));
check("en: _review is not set (English is the reference of the fallback)", !("_review" in en));
check("es: _review is not set (Spanish is the reference text)", !("_review" in L.es));

// the keys the page asks for
const html = fs.readFileSync(path.join(web, "index.html"), "utf8");
const app = fs.readFileSync(path.join(web, "js/app.js"), "utf8");
const i18njs = fs.readFileSync(path.join(web, "js/i18n.js"), "utf8");
const used = new Set();
const code = (src) => src.replace(/\/\/[^\n]*/g, "");
for (const m of html.matchAll(/data-i18n(?:-[a-z-]+)?="([^"]+)"/g)) used.add(m[1]);
for (const m of (code(app) + code(i18njs)).matchAll(/\bt\(\s*"([^"]+)"/g)) used.add(m[1]);
for (const m of code(app).matchAll(/"((?:reason|list|state|band|details|content|result|note|foot|opts|rev|drop|slot|engine|action)\.[A-Za-z_.]*[A-Za-z_])"/g)) used.add(m[1]);
// reason texts are chosen by code: "reason." + a code of the DIRECT list of app.js
const direct = /var DIRECT = \[([^\]]*)\]/.exec(app);
for (const c of JSON.parse("[" + direct[1] + "]")) used.add("reason." + c);
used.add("reason.expired"); used.add("reason.too_old");
for (const k of [...used]) if (k.endsWith(".")) used.delete(k); // prefixes of keys built at run time, listed below
const verdicts = ["verified", "good", "failed", "expired", "could_not_check", "revoked", "unknown"];
for (const v of verdicts) for (const p of ["title", "meaning", "next"]) used.add("result." + v + "." + p);
for (const b of ["in_progress", "basic", "substantial", "advanced"]) used.add("band." + b);
for (const s of ["pass", "fail", "skip", "notreached"]) used.add("state." + s);
for (const r of ["pass", "warn", "fail"]) used.add("details." + r);
const unknownKeys = [...used].filter((k) => !(k in en));
check("every key the page uses exists in English", unknownKeys.length === 0, unknownKeys.join(", "));
const unused = enKeys.filter((k) => !used.has(k) && k !== "app.name");
check("every English key is used by the page", unused.length === 0, unused.join(", "));

check("the language list of the page is exactly " + LANGS.join(", "), JSON.stringify([...i18njs.matchAll(/code: "([a-z]{2})"/g)].map((m) => m[1])) === JSON.stringify(LANGS));
if (reviewed.length) console.log("# marked for native review: " + reviewed.join(", "));
process.exit(failed ? 1 : 0);
