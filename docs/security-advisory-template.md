# Security advisory template

Every security advisory for the verifier is written from this template, as
described in [SECURITY.md](../SECURITY.md#how-advisories-are-published), so that
every advisory has the same fields in the same order. Copy everything below the
line into a new GitHub security advisory for this repository, fill in each
field, and delete the parts in *italics*. Keep a heading and write "None"
rather than removing it, so readers and scripts find the same sections every
time.

The first table maps to the fields of GitHub's advisory form; the rest is the
advisory's description.

---

| Advisory form field | Value |
|---|---|
| Title | *One line: the component, the flaw and its effect, e.g. "A status key set fetched over cleartext HTTP was accepted".* |
| Affected versions | *A range, e.g. `>= 1.2.0, < 1.4.1`.* |
| Patched versions | *e.g. `1.4.1`.* |
| Severity | *Critical, High, Medium or Low, from the CVSS v3.1 base score.* |
| CVSS v3.1 vector | *e.g. `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:N`.* |
| Weakness | *CWE identifier, if one fits.* |
| Credits | *Reporter, as they asked to be credited, or "None" if they prefer not to be.* |

## Summary

*Two or three sentences: what is wrong, what an attacker can do, and what to do
about it.*

## Affected versions

*Every release in the range, and every way of running the verifier that shipped
them (the script from a release, the signed container image, a checkout of the
repository). Say if one was not affected.*

## Fixed versions

*The first release with the fix, with a link to its release page.*

## Severity

*The rating and the CVSS v3.1 vector, with one sentence on why each metric that
is not obvious was chosen.*

## Impact

*What an attacker gains (for example a wrong verdict, a document that verifies
when it should not, or hidden terminal output) and what they need first
(network position, a crafted document or URL, local access, the user running a
particular option).*

## Who is affected

*The options, environment variables and platforms involved, e.g. "anyone who
runs `--status-list` with a cleartext `--status-keys` URL", "anyone who runs the
verifier on LibreSSL". Say who is not affected, and whether the verdict of a
run that used `--anchor-file` was affected.*

## Workarounds

*What to do until you can update, or "None: update". If earlier verdicts may
have been wrong, say which ones to run again.*

## How to check whether you are affected

```sh
./verify-attestation.sh --version
```

*Compare the version with the affected range above. For the container image,
the image tag is the version; check the tag or digest your pipeline pins. Add
any other check: an option, a file, a line of the output.*

## How to update

Verify every download as described in
[Verifying a release](https://github.com/Hodeitek/hodeishield-attest-verifier/blob/main/README.md#verifying-a-release).
*Delete the ways of running the verifier that did not ship an affected
version.*

- **Script from a release:** download the files that section lists from the
  release page of `<fixed version>`, with their `.sigstore.json` bundles, run
  `sha256sum -c SHA256SUMS` and the `cosign verify-blob` commands of that
  section with `<TAG>` set to `v<fixed version>`, and replace the copy you run.
- **Container image:** pull the `<fixed version>` image by digest, check it with
  `cosign verify` as the README describes under "A signed image", and pin the
  new digest in your pipeline. Releases up to v1.4.0 have no image.
- **Repository checkout:** check out the tag `v<fixed version>` and verify it
  as the README describes: the tag is signed.

## Timeline

| Date (UTC) | Event |
|---|---|
| *YYYY-MM-DD* | Reported |
| *YYYY-MM-DD* | Fixed in `<fixed version>` |
| *YYYY-MM-DD* | Advisory published |

*Add other dates that matter, such as when exploitation was first seen.*

## Credit

*Who reported it and how they asked to be named, or "Reported privately; the
reporter asked not to be named".*

## References

- *The release notes of `<fixed version>`.*
- *The pull request or commit with the fix, once public.*
- *The CVE identifier, if one was assigned.*
- *Anything else a reader needs: related advisories, upstream issues.*
