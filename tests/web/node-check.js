// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.
//
// Quick check for development: the page's verifier logic and the real WebAssembly
// module, in Node, over tests/vectors/v1. The test that counts runs in real
// browsers (tests/web-vectors.sh); this one only shortens the loop.
//   node tests/web/node-check.js PAGE_DIR
"use strict";
const fs = require("fs"), path = require("path"), vm = require("vm");
const page = path.resolve(process.argv[2] || "");
const root = path.resolve(__dirname, "../..");
const vdir = path.join(root, "tests/vectors/v1");
for (const f of ["base", "json", "canon", "verify", "engine"]) {
  vm.runInThisContext(fs.readFileSync(path.join(page, "js", f + ".js"), "utf8"), { filename: f + ".js" });
}
vm.runInThisContext(fs.readFileSync(path.join(__dirname, "args.js"), "utf8"));
const factory = require(path.join(page, "mldsa/mldsa_wasm.js"));
(async () => {
  const wasm = fs.readFileSync(path.join(page, "mldsa/mldsa_wasm.wasm"));
  await HV.engine.init(factory, new Uint8Array(wasm));
  if (!HV.engine.ready) { console.error("engine:", HV.engine.error); process.exit(1); }
  const cases = JSON.parse(fs.readFileSync(path.join(vdir, "vectors.json"), "utf8")).cases;
  let pass = 0, fail = 0;
  for (const c of cases) {
    const files = {};
    for (const p of HVT.filesOf(c.args)) files[p] = new Uint8Array(fs.readFileSync(path.join(vdir, p)));
    const res = HV.verify(HVT.buildInput(c.args, files), HV.engine);
    const why = HVT.judge(c, res);
    if (why) { fail++; console.log("not ok -", c.id, "[" + c.expect.code + "]", why); } else pass++;
  }
  console.log(`# node: ${pass} passed, ${fail} failed of ${cases.length}`);
  process.exit(fail ? 1 : 0);
})();
