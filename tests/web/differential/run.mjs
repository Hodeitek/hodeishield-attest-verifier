// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.
//
// Differential test: the page's verifier logic and the real script, on the same
// arguments, must agree on the exit code, the verdict and the reason code. The
// cases (cases.json) are inputs on which the page once gave a weaker verdict than
// the script, or that probe a rule the 136 vectors do not cover.
//
//   node tests/web/differential/run.mjs PAGE_DIR
//
// PAGE_DIR is the assembled page (tools/verify-page/build.sh) or any folder with
// js/ and mldsa/ in it. Needs what the script needs: bash, OpenSSL >= 3.5 and
// python3. The script is run with --json and without colour; nothing is changed.
//
// Beyond "page equals script" each case carries the result the script is known to
// give ("expect"), which the script must still give: that is what the browser runner
// (tests/web/runner.js) compares the page with, since a browser cannot run the
// script. The test fails if the case list is shorter than "minimum", so that
// deleting cases cannot make it pass.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import vm from "node:vm";
import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "../../..");
const page = path.resolve(process.argv[2] || "");
const script = path.join(root, "scripts/attest/verify-attestation.sh");
const v1 = path.join(root, "tests/vectors/v1");
const require = createRequire(import.meta.url);

for (const f of ["base", "json", "canon", "verify", "engine"]) {
  vm.runInThisContext(fs.readFileSync(path.join(page, "js", f + ".js"), "utf8"), { filename: f + ".js" });
}
vm.runInThisContext(fs.readFileSync(path.join(root, "tests/web/args.js"), "utf8"));
vm.runInThisContext(fs.readFileSync(path.join(here, "gen.js"), "utf8"));
await HV.engine.init(require(path.join(page, "mldsa/mldsa_wasm.js")), new Uint8Array(fs.readFileSync(path.join(page, "mldsa/mldsa_wasm.wasm"))));
if (!HV.engine.ready) { console.error("not ok - the signature engine did not start: " + HV.engine.error); process.exit(1); }

const spec = JSON.parse(fs.readFileSync(path.join(here, "cases.json"), "utf8"));
let failed = 0;
function bad(msg) { console.log("not ok - " + msg); failed++; }

if (!Number.isInteger(spec.minimum) || spec.minimum < 1) { bad("cases.json has no positive \"minimum\""); }
if (spec.cases.length < (spec.minimum || 1)) bad("only " + spec.cases.length + " cases; cases.json says there must be at least " + spec.minimum);
const ids = spec.cases.map((c) => c.id);
if (new Set(ids).size !== ids.length) bad("two cases share an id");

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "hv-diff-"));
process.on("exit", () => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (e) { /* ignore */ } });
const baseText = fs.readFileSync(path.join(v1, "status-lists/empty.json"), "utf8");

for (const c of spec.cases) {
  let gen = "";
  if (c.generated) { gen = path.join(tmp, c.id + ".json"); fs.writeFileSync(gen, HVD.generate(baseText, c.generated)); }
  const args = HVD.args(c, spec, { v1, fx: path.join(here, "fixtures"), gen });
  // page
  const files = {};
  for (const p of HVT.filesOf(args)) files[p] = new Uint8Array(fs.readFileSync(p));
  const res = HV.verify(HVT.buildInput(args, files), HV.engine);
  // script: its real exit status as well as the one it reports
  const r = spawnSync("bash", [script, "--json", ...args], { env: { ...process.env, NO_COLOR: "1" }, encoding: "utf8", timeout: 180000 });
  let s;
  try { s = JSON.parse(r.stdout); } catch (e) { s = null; }
  if (!s) { bad(c.id + " (the script gave no JSON: exit " + r.status + ")"); continue; }
  if (/^openssl_|^python3_/.test(String(s.reason))) { bad(c.id + " (the script cannot run here: " + s.reason + ")"); continue; }
  const why = [];
  if (r.status !== s.exit_code) why.push("the script's process exit status is " + r.status + " but its JSON says " + s.exit_code);
  if (res.exit_code !== s.exit_code || res.verdict !== s.verdict || res.reason !== s.reason) {
    why.push("page: exit " + res.exit_code + " " + res.verdict + " " + res.reason + "; script: exit " + s.exit_code + " " + s.verdict + " " + s.reason);
  }
  if (!c.expect) why.push("no \"expect\" in cases.json; the script gives exit " + s.exit_code + " " + s.verdict + " " + s.reason);
  else if (c.expect.exit !== s.exit_code || c.expect.reason !== s.reason) why.push("the script no longer gives the expected exit " + c.expect.exit + " " + c.expect.reason);
  if (why.length) bad(c.id + " (" + why.join("; ") + ")");
  else console.log("ok - " + c.id + " (exit " + s.exit_code + ", " + s.verdict + ", " + s.reason + ")");
}
console.log("# differential: " + (spec.cases.length - failed) + " of " + spec.cases.length + " agree (at least " + spec.minimum + " required)");
process.exit(failed ? 1 : 0);
