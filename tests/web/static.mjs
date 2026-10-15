// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.
//
// Static checks of the page's source (web/): the Content-Security-Policy is the
// strict one and nothing in the markup or the code goes round it. Reads files,
// runs nothing else. Needs Node; no dependency.
//   node tests/web/static.mjs
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const web = path.join(root, "web");
let failed = 0;
function check(name, ok, why) {
  if (ok) console.log("ok - " + name);
  else { console.log("not ok - " + name + (why ? " (" + why + ")" : "")); failed++; }
}
const read = (p) => fs.readFileSync(path.join(web, p), "utf8");
const html = read("index.html");

// ---- the policy --------------------------------------------------------------
const EXPECTED_CSP = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'none'; base-uri 'none'; form-action 'none'";
const m = /<meta http-equiv="Content-Security-Policy" content="([^"]*)">/.exec(html);
check("index.html carries the Content-Security-Policy meta tag", !!m);
check("the policy is exactly the strict one", m && m[1] === EXPECTED_CSP, m && m[1]);
check("the policy has no 'unsafe-inline', no 'unsafe-eval' (only 'wasm-unsafe-eval'), no origin, no wildcard",
  m && !/unsafe-inline|https?:|\*/.test(m[1]) && !/unsafe-eval/.test(m[1].replace(/'wasm-unsafe-eval'/g, "")));
check("the referrer policy is no-referrer", /<meta name="referrer" content="no-referrer">/.test(html));

// ---- the markup ---------------------------------------------------------------
const tags = [...html.matchAll(/<([a-zA-Z][a-zA-Z0-9]*)\b([^>]*)>/g)];
check("no inline script", ![...html.matchAll(/<script\b([^>]*)>/g)].some((s) => !/\bsrc="/.test(s[1])));
check("no <style> element and no style attribute", !/<style\b/i.test(html) && !tags.some((t) => /\sstyle\s*=/.test(t[2])));
check("no inline event handler", !tags.some((t) => /\son[a-z]+\s*=/i.test(t[2])));
check("no javascript: or data: URL", !/(?:href|src|action)\s*=\s*"(?:javascript|data):/i.test(html));
const external = [];
for (const t of tags) {
  const attrs = t[2];
  for (const a of attrs.matchAll(/\s(src|href|action|poster|data)\s*=\s*"([^"]*)"/g)) {
    const isLink = t[1].toLowerCase() === "a";
    if (/^(https?:)?\/\//i.test(a[2]) && !isLink) external.push(t[1] + " " + a[1] + "=" + a[2]);
  }
}
check("nothing is loaded from another origin (only <a> links leave the page)", external.length === 0, external.join("; "));
const outLinks = [...html.matchAll(/<a\b[^>]*\shref="(https?:[^"]*)"[^>]*>/g)];
check("every outside link opens with rel=noopener noreferrer", outLinks.every((l) => /rel="noopener noreferrer"/.test(l[0])));
const noscriptRemoved = html.replace(/<noscript>[\s\S]*?<\/noscript>/g, "").replace(/<script[\s\S]*?<\/script>/g, "").replace(/<svg[\s\S]*?<\/svg>/g, "").replace(/<!--[\s\S]*?-->/g, "").replace(/<title>[\s\S]*?<\/title>/g, "");
const strings = [...noscriptRemoved.matchAll(/>([^<>]*[A-Za-z][^<>]*)</g)].map((x) => x[1].trim()).filter(Boolean);
check("no visible string in the markup (all text is in locales/*.js; the <noscript> note and the product name in the title excepted)", strings.length === 0, strings.join(" | "));

// ---- the code -----------------------------------------------------------------
const banned = [
  [/\beval\s*\(/, "eval"], [/\bnew\s+Function\b/, "new Function"], [/\bfetch\s*\(/, "fetch"], [/XMLHttpRequest/, "XMLHttpRequest"],
  [/\bWebSocket\b/, "WebSocket"], [/sendBeacon/, "sendBeacon"], [/\blocalStorage\b/, "localStorage"], [/\bsessionStorage\b/, "sessionStorage"],
  [/\bindexedDB\b/, "indexedDB"], [/document\.cookie/, "document.cookie"], [/\binnerHTML\b/, "innerHTML"], [/\bouterHTML\b/, "outerHTML"],
  [/insertAdjacentHTML/, "insertAdjacentHTML"], [/document\.write/, "document.write"], [/\bimport\s*\(/, "dynamic import"],
  [/\bsetTimeout\s*\(\s*["'`]/, "setTimeout with a string"], [/crypto\.subtle/, "native WebCrypto (the signature is checked by the WebAssembly module only)"],
  [/setAttribute\(\s*["']style["']/, "style attribute"], [/\.style\.cssText/, "cssText"],
];
const sources = ["js", "locales"].flatMap((d) => fs.readdirSync(path.join(web, d)).filter((f) => f.endsWith(".js")).map((f) => d + "/" + f));
for (const f of sources) {
  const text = read(f).replace(/\/\/[^\n]*/g, "");
  const hits = banned.filter(([re]) => re.test(text)).map(([, n]) => n);
  check(f + " uses none of the banned APIs", hits.length === 0, hits.join(", "));
}
const css = read("css/app.css");
const cssUrls = [...css.matchAll(/url\(([^)]*)\)/g)].map((u) => u[1].trim().replace(/^["']|["']$/g, ""));
check("the CSS imports nothing and loads no URL but the bundled fonts (fonts/*.woff2, present in web/)",
  !/@import/.test(css) && cssUrls.length > 0 && cssUrls.every((u) => /^\.\.\/fonts\/[a-z0-9-]+\.woff2$/.test(u) && fs.existsSync(path.join(web, "css", u))),
  cssUrls.join(", "));

// ---- the files ------------------------------------------------------------------
const all = [];
(function walk(d) { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) walk(p); else all.push(path.relative(web, p)); } })(web);
check("web/ holds no built file (the module and its loader come from tools/mldsa-wasm/build.sh)", !all.some((f) => /\.wasm$|^mldsa\//.test(f)), all.filter((f) => /\.wasm$|^mldsa\//.test(f)).join(", "));
// brand/ holds the HodeiShield logo, a trademark outside the Apache-2.0 licence (see
// NOTICE); fonts/ holds third-party fonts with their SIL Open Font License texts.
// Neither gets an Apache-2.0 header.
const noHeader = all.filter((f) => /\.(js|css|html|svg)$/.test(f) && !/^brand\//.test(f) && !/SPDX-License-Identifier: Apache-2\.0/.test(read(f).slice(0, 400)));
check("every source file carries the SPDX header (the logo in brand/ excepted)", noHeader.length === 0, noHeader.join(", "));
const brand = all.filter((f) => /^brand\//.test(f));
check("brand/ holds only the logo SVG files", brand.length > 0 && brand.every((f) => /^brand\/hodeishield-[a-z0-9-]+\.svg$/.test(f)), brand.join(", "));
const fonts = all.filter((f) => /^fonts\//.test(f));
const woff = fonts.filter((f) => /\.woff2$/.test(f));
check("fonts/ holds only .woff2 files and their OFL licence texts, one licence per font",
  woff.length > 0 && fonts.every((f) => /^fonts\/([a-z0-9-]+\.woff2|OFL-[A-Za-z]+\.txt)$/.test(f)) && fonts.length === 2 * woff.length
    && fonts.filter((f) => /\.txt$/.test(f)).every((f) => /SIL Open Font License, Version 1\.1/.test(read(f))),
  fonts.join(", "));
const runner = fs.readFileSync(path.join(root, "tests/web/runner.js"), "utf8");
const listed = JSON.parse("[" + /var PAGE_SCRIPTS = \[([\s\S]*?)\];/.exec(runner)[1] + "]");
const inPage = [...html.matchAll(/<script src="([^"]+)"><\/script>/g)].map((x) => x[1]).filter((s) => s !== "js/app.js");
check("the scripts the from-disk runner loads are those of index.html, in order", JSON.stringify(listed) === JSON.stringify(inPage), JSON.stringify(inPage));
const ver = /var VERSION = "([^"]+)"/.exec(read("js/verify.js"))[1];
const script = fs.readFileSync(path.join(root, "scripts/attest/verify-attestation.sh"), "utf8");
check("the page's version is the script's version (VERIFIER_VERSION)", new RegExp('^VERIFIER_VERSION="' + ver.replace(/\./g, "\\.") + '"', "m").test(script), ver);

process.exit(failed ? 1 : 0);
