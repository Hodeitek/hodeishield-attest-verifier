// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.
//
// Differential test: the page's verifier logic and the real script, on the same
// arguments, must agree on the exit code, the verdict and the reason code. The
// cases (cases.json) are inputs on which the page once gave a weaker verdict than
// the script, or that probe a rule the 118 vectors do not cover.
//
//   node tests/web/differential/run.mjs PAGE_DIR
//
// PAGE_DIR is the assembled page (tools/verify-page/build.sh) or any folder with
// js/ and mldsa/ in it. Needs what the script needs: bash, OpenSSL >= 3.5 and
// python3. The script is run with --json and without colour; nothing is changed.
import fs from "node:fs";
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
await HV.engine.init(require(path.join(page, "mldsa/mldsa_wasm.js")), new Uint8Array(fs.readFileSync(path.join(page, "mldsa/mldsa_wasm.wasm"))));
if (!HV.engine.ready) { console.error("not ok - the signature engine did not start: " + HV.engine.error); process.exit(1); }

const spec = JSON.parse(fs.readFileSync(path.join(here, "cases.json"), "utf8"));
const sub = (a) => a.map((x) => x.replace("{v1}", v1).replace("{fx}", path.join(here, "fixtures")));
let failed = 0;
for (const c of spec.cases) {
  const args = [...sub(c.args), ...sub(c.defaults || spec.defaults)];
  // page
  const files = {};
  for (const p of HVT.filesOf(args)) files[p] = new Uint8Array(fs.readFileSync(p));
  const res = HV.verify(HVT.buildInput(args, files), HV.engine);
  // script
  const r = spawnSync("bash", [script, "--json", ...args], { env: { ...process.env, NO_COLOR: "1" }, encoding: "utf8", timeout: 180000 });
  let s;
  try { s = JSON.parse(r.stdout); } catch (e) { s = null; }
  if (!s) { console.log("not ok - " + c.id + " (the script gave no JSON: exit " + r.status + ")"); failed++; continue; }
  if (/^openssl_|^python3_/.test(String(s.reason))) { console.log("not ok - " + c.id + " (the script cannot run here: " + s.reason + ")"); failed++; continue; }
  const same = res.exit_code === s.exit_code && res.verdict === s.verdict && res.reason === s.reason;
  if (same) console.log("ok - " + c.id + " (exit " + s.exit_code + ", " + s.verdict + ", " + s.reason + ")");
  else { console.log("not ok - " + c.id + " (page: exit " + res.exit_code + " " + res.verdict + " " + res.reason + "; script: exit " + s.exit_code + " " + s.verdict + " " + s.reason + ")"); failed++; }
}
console.log("# differential: " + (spec.cases.length - failed) + " of " + spec.cases.length + " agree");
process.exit(failed ? 1 : 0);
