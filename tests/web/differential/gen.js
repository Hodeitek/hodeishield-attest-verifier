// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.
//
// Test support for the differential cases (cases.json): the generated fixtures and
// the arguments of a case. A generated fixture is tests/vectors/v1/status-lists/
// empty.json with one number written another way:
//   where "x":   an extra member "x" in the status list, which the canonical bytes
//                ignore, so the signature stays valid and only the way the reader
//                treats the number can change the verdict;
//   where "seq": the signed sequence number 7 written as the token, which is the
//                same number (7e0, 0.7e1) or not (7.0, 70e-1).
// "{1xN}" in a token is the digit 1, N times. Classic script: Node and the browser
// runner both load it.
(function (root) {
  "use strict";
  var D = root.HVD || (root.HVD = {});
  var SEQ_LINE = '"seq": 7,';

  function expand(token) { return token.replace(/\{1x([0-9]+)\}/g, function (m, n) { return "1".repeat(Number(n)); }); }

  // the text of a generated fixture, from the text of the base status list
  D.generate = function (baseText, g) {
    var token = expand(g.token);
    if (baseText.indexOf(SEQ_LINE) < 0) throw new Error("the base status list has no " + SEQ_LINE);
    if (g.where === "seq") return baseText.replace(SEQ_LINE, '"seq": ' + token + ",");
    if (g.where === "x") return baseText.replace(SEQ_LINE, '"x": ' + token + ",\n    " + SEQ_LINE);
    throw new Error("unknown place " + g.where);
  };

  // the arguments of a case, with {v1}, {fx} and {gen} replaced by the given strings
  D.args = function (c, spec, places) {
    var base = c.template ? spec.templates[c.template] : c.args;
    var tail = c.defaults || spec.defaults;
    return base.concat(tail).map(function (a) {
      return a.replace("{v1}", places.v1).replace("{fx}", places.fx).replace("{gen}", places.gen);
    });
  };
})(typeof globalThis !== "undefined" ? globalThis : this);
