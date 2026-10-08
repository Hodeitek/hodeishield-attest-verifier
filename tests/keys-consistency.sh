#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
# =============================================================================
# tests/keys-consistency.sh - docs/security/keys.json must say what
# docs/security/keys.md says.
#
# Static: reads only those two files, runs no document and no network. Fails
# if the kids, roles, status, endpoints, active-since dates or retirement times
# differ, or if keys.json is not exactly the shape hodeishield.keys.statement.v1
# allows. Needs bash and python3 (standard library only).
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 -I - "$ROOT/docs/security/keys.md" "$ROOT/docs/security/keys.json" <<'PY'
import json, re, sys

md_path, json_path = sys.argv[1], sys.argv[2]
errors = []

def err(msg):
    errors.append(msg)

# ---- keys.md: the table rows whose first cell is a backticked kid ----------
md_keys = []
for line in open(md_path, encoding="utf-8"):
    if not line.startswith("|"):
        continue
    cells = [c.strip() for c in line.strip().strip("|").split("|")]
    m = re.fullmatch(r"`([A-Za-z0-9_-]{22})`", cells[0]) if cells else None
    if not m:
        continue
    if len(cells) != 7:
        err("keys.md: row for %s has %d cells, expected 7" % (m.group(1), len(cells)))
        continue
    role = cells[1]
    if role == "status list":
        role = "status-list"
    since = re.match(r"\d{4}-\d{2}-\d{2}", cells[4])
    retired = cells[5].strip("`")
    md_keys.append({
        "kid": m.group(1),
        "role": role,
        "status": cells[2],
        "published_at": cells[3].strip("`"),
        "active_since": since.group(0) if since else None,
        "retired_at": None if retired == "-" else retired,
    })
if not md_keys:
    err("keys.md: no key rows found")

# ---- keys.json: strict shape -----------------------------------------------
try:
    doc = json.load(open(json_path, encoding="utf-8"))
except ValueError as e:
    print("FAIL  keys.json does not parse: %s" % e)
    sys.exit(1)

RFC3339 = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
if not isinstance(doc, dict) or set(doc) != {"schema", "issuer", "keys"}:
    err("keys.json: top level must be exactly schema, issuer, keys")
    doc = {"keys": []}
if doc.get("schema") != "hodeishield.keys.statement.v1":
    err("keys.json: schema is not hodeishield.keys.statement.v1")
if doc.get("issuer") != "https://app.hodeishield.com":
    err("keys.json: issuer is not https://app.hodeishield.com")
js_keys = doc.get("keys")
if not isinstance(js_keys, list):
    err("keys.json: keys is not an array")
    js_keys = []
allowed = {"kid", "role", "status", "published_at", "active_since", "retired_at"}
required = {"kid", "role", "status", "published_at"}
good = []
for k in js_keys:
    if not isinstance(k, dict) or not required <= set(k) <= allowed:
        err("keys.json: unexpected members in %r" % (k,))
        continue
    if not all(isinstance(v, str) for v in k.values()):
        err("keys.json: %r has a non-string member" % (k,))
        continue
    good.append(k)
    if k["role"] not in ("attestation", "status-list"):
        err("keys.json: %s has role %r" % (k["kid"], k["role"]))
    if k["status"] not in ("active", "retired"):
        err("keys.json: %s has status %r" % (k["kid"], k["status"]))
    if "retired_at" in k and not RFC3339.fullmatch(k["retired_at"]):
        err("keys.json: %s retired_at is not YYYY-MM-DDTHH:MM:SSZ" % k["kid"])
    if "active_since" in k and not DATE.fullmatch(k["active_since"]):
        err("keys.json: %s active_since is not YYYY-MM-DD" % k["kid"])
    if (k["status"] == "retired") != ("retired_at" in k):
        err("keys.json: %s retired_at must be present exactly for retired keys" % k["kid"])
kids = [k["kid"] for k in good]
if len(set(kids)) != len(kids):
    err("keys.json: a kid is listed twice")

# ---- the two must agree ----------------------------------------------------
md = {k["kid"]: k for k in md_keys}
js = {k["kid"]: k for k in good}
for kid in sorted(set(md) | set(js)):
    if kid not in js:
        err("%s is in keys.md but not in keys.json" % kid)
    elif kid not in md:
        err("%s is in keys.json but not in keys.md" % kid)
    else:
        a, b = md[kid], js[kid]
        for f in ("role", "status", "published_at", "active_since", "retired_at"):
            if a[f] != b.get(f):
                err("%s: %s differs (keys.md %r, keys.json %r)" % (kid, f, a[f], b.get(f)))

if errors:
    for e in errors:
        print("FAIL  " + e)
    sys.exit(1)
print("ok    keys.json matches keys.md (%d keys)" % len(md))
PY
