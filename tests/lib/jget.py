# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
"""Read a JSON file for tests/run.sh, in place of `jq`, which the suite no longer needs.

  jget.py [-r | -c] FILE [KEY ...]

Prints the document, or the member reached by following KEY ... (an object
member, or an array index when KEY is a number), as JSON indented by two spaces;
-c prints it compact, -r prints a string as it is. Non-ASCII text is written as
UTF-8, not escaped, as `jq` wrote it. Only the standard library; exit 1 on a
file or a path that is not there.
"""
import json
import sys


def main(argv):
    mode, args = "", argv[1:]
    if args and args[0] in ("-r", "-c"):
        mode, args = args[0], args[1:]
    if not args:
        sys.stderr.write("usage: jget.py [-r | -c] FILE [KEY ...]\n")
        return 2
    with open(args[0], "rb") as fh:
        value = json.loads(fh.read().decode("utf-8"))
    for key in args[1:]:
        value = value[int(key)] if isinstance(value, list) else value[key]
    if mode == "-r" and isinstance(value, str):
        text = value
    elif mode == "-c":
        text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    else:
        text = json.dumps(value, ensure_ascii=False, indent=2)
    sys.stdout.buffer.write((text + "\n").encode("utf-8"))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except (OSError, ValueError, KeyError, IndexError):
        sys.exit(1)
