// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.
//
// Runs tests/web/runner.html in one real browser, headless, against the page as
// it would be shipped, and prints what the runner found. No dependency: Node's
// own http server, the browser's own command line, and a POST from the runner
// back to this process (Firefox cannot print the DOM, Chrome could).
//
//   node tests/web/run.mjs --browser chrome|firefox --mode http|file --page DIR
//
// http: the page is served from 127.0.0.1 and framed by the runner.
// file: the page is opened from disk (file://), as a downloaded copy is. The
//       browser is started with its same-directory file access relaxed, only so
//       that the runner can look inside the frame; the page itself is unchanged.
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import zlib from "node:zlib";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "../..");
const vdir = path.join(root, "tests/vectors/v1");

function arg(name, def) {
  const i = process.argv.indexOf("--" + name);
  return i > 0 ? process.argv[i + 1] : def;
}
const browser = arg("browser", "chrome");
const mode = arg("mode", "http");
const pageDir = path.resolve(arg("page", ""));
const timeoutMs = Number(arg("timeout", "180")) * 1000;
if (!["chrome", "firefox"].includes(browser) || !["http", "file"].includes(mode) || !fs.existsSync(path.join(pageDir, "index.html"))) {
  console.error("usage: run.mjs --browser chrome|firefox --mode http|file --page DIR");
  process.exit(2);
}

// the vectors, as a script the runner loads (so it needs no fetch, which a page
// opened from disk may not do)
function dataScript() {
  const manifest = JSON.parse(fs.readFileSync(path.join(vdir, "vectors.json"), "utf8"));
  const files = {};
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else files[path.relative(vdir, p).split(path.sep).join("/")] = fs.readFileSync(p).toString("base64");
    }
  };
  walk(vdir);
  return "globalThis.HVT_CASES=" + JSON.stringify(manifest.cases) + ";globalThis.HVT_FILES=" + JSON.stringify(files) + ";";
}

const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml", ".wasm": "application/wasm", ".json": "application/json" };
function serveFile(res, base, rel) {
  const p = path.resolve(base, "." + path.posix.normalize("/" + rel));
  if (!p.startsWith(base + path.sep) || !fs.existsSync(p) || !fs.statSync(p).isFile()) { res.writeHead(404); res.end("not found"); return; }
  res.writeHead(200, { "content-type": TYPES[path.extname(p)] || "application/octet-stream", "cache-control": "no-store" });
  fs.createReadStream(p).pipe(res);
}

let resolveResult;
const gotResult = new Promise((r) => { resolveResult = r; });
const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  if (req.method === "POST" && url.pathname === "/result") {
    let body = "";
    req.on("data", (c) => { body += c; });
    req.on("end", () => { res.writeHead(204, { "access-control-allow-origin": "*" }); res.end(); try { resolveResult(JSON.parse(body)); } catch (e) { resolveResult({ error: "bad result: " + e.message }); } });
    return;
  }
  if (req.method === "POST" && url.pathname === "/log") {
    let body = "";
    req.on("data", (c) => { body += c; });
    req.on("end", () => { res.writeHead(204, { "access-control-allow-origin": "*" }); res.end(); console.log("  [browser]", body.slice(0, 300)); });
    return;
  }
  if (url.pathname === "/data.js") { res.writeHead(200, { "content-type": TYPES[".js"], "cache-control": "no-store" }); res.end(dataScript()); return; }
  if (url.pathname.startsWith("/app/")) return serveFile(res, pageDir, url.pathname.slice(5));
  if (url.pathname.startsWith("/test/")) return serveFile(res, here, url.pathname.slice(6));
  res.writeHead(404); res.end("not found");
});

await new Promise((r) => server.listen(0, "127.0.0.1", r));
const port = server.address().port;
const origin = "http://127.0.0.1:" + port;

const profile = fs.mkdtempSync(path.join(os.tmpdir(), "hv-" + browser + "-"));
let runnerUrl, args, cmd;
if (mode === "http") runnerUrl = origin + "/test/runner.html?mode=http";
else runnerUrl = pathToFileURL(path.join(here, "runner.html")).href + "?mode=file&server=" + encodeURIComponent(origin) + "&page=" + encodeURIComponent(pathToFileURL(path.join(pageDir, "index.html")).href) + (browser === "firefox" ? "&direct=1" : "");

if (browser === "chrome") {
  cmd = process.env.CHROME || "google-chrome";
  args = ["--headless=new", "--no-sandbox", "--disable-gpu", "--no-first-run", "--disable-extensions", "--disable-background-networking",
    "--user-data-dir=" + profile, "--window-size=1200,1000"];
  if (mode === "file") args.push("--allow-file-access-from-files");
  args.push(runnerUrl);
} else {
  cmd = process.env.FIREFOX || "firefox";
  fs.writeFileSync(path.join(profile, "user.js"), [
    'user_pref("browser.shell.checkDefaultBrowser", false);',
    'user_pref("datareporting.policy.dataSubmissionEnabled", false);',
    'user_pref("app.update.enabled", false);',
    'user_pref("browser.startup.homepage_override.mstone", "ignore");',
    'user_pref("network.captive-portal-service.enabled", false);',
  ].join("\n"));
  args = ["--headless", "--no-remote", "--profile", profile, "--width=1200", "--height=1000", runnerUrl];
}

// Minimal PNG reader (8-bit, not interlaced): the share of pixels of one colour.
function pngColourShare(file, rgb, tol) {
  const b = fs.readFileSync(file);
  let p = 8, w = 0, h = 0, depth = 0, ctype = 0, idat = [];
  while (p < b.length) {
    const len = b.readUInt32BE(p), type = b.toString("latin1", p + 4, p + 8), data = b.subarray(p + 8, p + 8 + len);
    if (type === "IHDR") { w = data.readUInt32BE(0); h = data.readUInt32BE(4); depth = data[8]; ctype = data[9]; if (data[12] !== 0) throw new Error("interlaced"); }
    if (type === "IDAT") idat.push(data);
    p += 12 + len;
  }
  if (depth !== 8 || (ctype !== 2 && ctype !== 6)) throw new Error("unsupported png");
  const bpp = ctype === 6 ? 4 : 3, stride = w * bpp, raw = zlib.inflateSync(Buffer.concat(idat));
  const px = Buffer.alloc(h * stride);
  for (let y = 0; y < h; y++) {
    const f = raw[y * (stride + 1)], src = raw.subarray(y * (stride + 1) + 1, (y + 1) * (stride + 1));
    for (let x = 0; x < stride; x++) {
      const a = x >= bpp ? px[y * stride + x - bpp] : 0, up = y ? px[(y - 1) * stride + x] : 0, c = x >= bpp && y ? px[(y - 1) * stride + x - bpp] : 0;
      let v = src[x];
      if (f === 1) v += a; else if (f === 2) v += up; else if (f === 3) v += (a + up) >> 1;
      else if (f === 4) { const pp = a + up - c, pa = Math.abs(pp - a), pb = Math.abs(pp - up), pc = Math.abs(pp - c); v += pa <= pb && pa <= pc ? a : (pb <= pc ? up : c); }
      px[y * stride + x] = v & 255;
    }
  }
  let n = 0;
  for (let i = 0; i < px.length; i += bpp) if (Math.abs(px[i] - rgb[0]) <= tol && Math.abs(px[i + 1] - rgb[1]) <= tol && Math.abs(px[i + 2] - rgb[2]) <= tol) n++;
  return n / (w * h);
}
// Firefox cannot be looked into from disk: open the real index.html once and
// look at the picture. The primary button is filled with the accent colour only
// when the page has started (its scripts ran under its policy and the signature
// engine passed its self-check); until then it is an empty outline.
async function firefoxDiskSmoke() {
  const prof = fs.mkdtempSync(path.join(os.tmpdir(), "hv-ffshot-"));
  const url = pathToFileURL(path.join(pageDir, "index.html")).href + "?lang=en";
  let share = -1;
  // The picture is taken when the page has loaded, which can be just before the
  // module has started; a page that never starts never passes, so look again.
  for (let attempt = 0; attempt < 5 && !(share > 0.004); attempt++) {
    const shot = path.join(prof, "shot" + attempt + ".png");
    await new Promise((resolve) => {
      const c = spawn(process.env.FIREFOX || "firefox", ["--headless", "--no-remote", "--profile", prof, "--screenshot", shot, "--window-size=1000,1100", url], { stdio: "ignore", detached: true });
      const t = setTimeout(() => { try { process.kill(-c.pid, "SIGKILL"); } catch (e) { /* gone */ } resolve(); }, 90000);
      c.on("exit", () => { clearTimeout(t); resolve(); });
    });
    try { share = pngColourShare(shot, [10, 92, 99], 6); } catch (e) { share = -1; }
  }
  try { fs.rmSync(prof, { recursive: true, force: true }); } catch (e) { /* ignore */ }
  return { name: "firefox from disk: the real index.html starts under its policy (primary button filled: " + (share * 100).toFixed(2) + "% accent pixels)", ok: share > 0.004, why: share < 0 ? "no readable screenshot" : "the button is not filled: the page did not start" };
}

const child = spawn(cmd, args, { stdio: ["ignore", "ignore", "pipe"], detached: true });
let stderr = "";
child.stderr.on("data", (d) => { stderr += d; if (stderr.length > 20000) stderr = stderr.slice(-20000); });
child.on("error", (e) => resolveResult({ error: "could not start " + cmd + ": " + e.message }));

const timer = setTimeout(() => resolveResult({ error: "timeout after " + timeoutMs / 1000 + " s" }), timeoutMs);
const result = await gotResult;
clearTimeout(timer);
try { process.kill(-child.pid, "SIGKILL"); } catch (e) { /* already gone */ }
server.close();
try { fs.rmSync(profile, { recursive: true, force: true }); } catch (e) { /* the browser may still hold it */ }

if (browser === "firefox" && mode === "file" && !result.error) result.ui.push(await firefoxDiskSmoke());
console.log("# web " + browser + " " + mode + ": " + (result.userAgent || "?"));
if (result.error) {
  console.log("not ok - " + result.error);
  if (stderr) console.log(stderr.split("\n").slice(-8).map((l) => "    # " + l).join("\n"));
  process.exit(1);
}
for (const c of result.cases) console.log((c.ok ? "ok - " : "not ok - ") + c.id + (c.ok ? "" : " (" + c.why + ")"));
for (const u of result.ui) console.log((u.ok ? "ok - ui: " : "not ok - ui: ") + u.name + (u.ok ? "" : " (" + u.why + ")"));
const passed = result.cases.filter((c) => c.ok).length, uiPassed = result.ui.filter((u) => u.ok).length;
console.log("# web " + browser + " " + mode + ": " + passed + "/" + result.cases.length + " vectors, " + uiPassed + "/" + result.ui.length + " page checks" +
  (result.reasonDifferences.length ? "; documented reason differences: " + result.reasonDifferences.join(", ") : ""));
process.exit(passed === result.cases.length && result.cases.length > 0 && uiPassed === result.ui.length ? 0 : 1);
