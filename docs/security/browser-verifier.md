# Decision record: hosting the in-browser verifier

- Status: Accepted. Built; **not deployed yet** (see [Status](#status)).
- Date: 2026-10-14
- Scope: where an in-browser version of the verifier is published, who can
  publish it, and how a reader checks that the bytes they are served are the
  bytes we released.

## Context

The verifier is a script you run yourself. An in-browser page would let a reader
check an attestation without installing anything. That is only worth having if
the page is as checkable as the script: a verifier page that you cannot check
is a page you have to trust, which is the thing this repository exists to avoid.

## Decision

- **Where.** The page is published with GitHub Pages from this public
  repository, at `https://verify.hodeishield.com`, with HTTPS enforced. It is
  not published from the HodeiShield signing service or from the application
  at `app.hodeishield.com`. The page and the service that issues attestations
  do not share a host, a deployment or a credential.
- **When.** Deployments happen only from signed, published release tags (`v*`).
  Never from a push to a branch. The workflow is
  [`.github/workflows/pages.yml`](../../.github/workflows/pages.yml).
- **What.** The bytes served are the files inside one release asset,
  `verify-page-<tag>.tar.gz`. Nothing is built at deploy time.
- **How it is gated.** The `github-pages` environment accepts deployments only
  from tags `v*`. The workflow deploys only if the repository variable
  `PAGES_ENABLED` is `true`; until then it does nothing.

## How a deployment is made

1. A maintainer pushes a signed, annotated `v*` tag. `release.yml` tests, builds
   and signs the assets and creates a **draft** release.
2. A maintainer reviews and publishes the draft by hand.
3. Publishing triggers `pages.yml`. It checks that the tag is annotated and that
   GitHub reports its signature as verified, that the run is on that tag, and
   that the release is public.
4. It downloads `SHA256SUMS`, checks its Sigstore signature, then downloads
   every file listed there and checks each SHA-256 and each Sigstore signature.
   The signature identity is pinned to `release.yml` at that tag, with GitHub
   Actions as the issuer. This is the same check as
   [Verifying a release](../../README.md#verifying-a-release).
5. It unpacks `verify-page-<tag>.tar.gz`, refusing absolute paths, `..` in a
   path, and anything that is not a plain file or directory.
6. It uploads the unpacked files as the Pages artifact and deploys them. The
   bundle's SHA-256 is written to the job summary.

Only the deploy job has `pages: write` and `id-token: write`; the rest of the
workflow has `contents: read`. Every action is pinned by its full commit SHA.

## How to check what you are served

The release asset is the reference. To check that what `verify.hodeishield.com`
serves is what we released:

1. Download `verify-page-<tag>.tar.gz`, `SHA256SUMS` and
   `verify-page-<tag>.tar.gz.sigstore.json` from the
   [release](https://github.com/Hodeitek/hodeishield-attest-verifier/releases).
2. Compare the hash. It must match the line in `SHA256SUMS` and the hash in the
   release notes:

   ```bash
   sha256sum -c SHA256SUMS --ignore-missing
   ```

3. Verify the signature:

   ```bash
   cosign verify-blob --bundle verify-page-<tag>.tar.gz.sigstore.json \
     --certificate-identity "https://github.com/Hodeitek/hodeishield-attest-verifier/.github/workflows/release.yml@refs/tags/<tag>" \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     verify-page-<tag>.tar.gz
   ```

   Also verify `SHA256SUMS` with its own bundle, as in the README, so the hash
   you compared is itself signed.
4. Unpack the archive and compare each file with what the site serves, for
   example `curl -s https://verify.hodeishield.com/index.html | sha256sum`
   against `sha256sum index.html`. The two must be equal. GitHub Pages serves
   the files; it does not serve the archive, so the comparison is file by file.
   The archive carries `MANIFEST.sha256`, the SHA-256 of every other file it
   holds in `sha256sum` format, so this check can cover every served file:
   run `sha256sum -c MANIFEST.sha256` in the unpacked folder, and compare each
   served file with its line. The manifest is inside the signed archive, so
   steps 2 and 3 also cover it. It lists `mldsa/mldsa_wasm.wasm` too: that file
   is the ML-DSA-65 module, and its SHA-256 is the one pinned in
   [`tools/mldsa-wasm/expected.sha256`](../../tools/mldsa-wasm/expected.sha256),
   so you can also rebuild it yourself
   ([`tools/mldsa-wasm`](../../tools/mldsa-wasm/README.md)) and compare. The
   page shows the SHA-256 of the module it is running under "Technical details".

If anything differs, do not use the page, and report it as described in
[SECURITY.md](../../SECURITY.md).

## The offline copy

The same archive is a download on the release. Unpack it and open `index.html`
from your own disk: the page does not need the network to verify an
attestation, so you do not have to trust the web host at all. After step 2 and
3 above, the offline copy is exactly what was deployed. Prefer it when the
result matters. It works from disk in Chrome and Firefox (the page is made of
classic scripts, which browsers load from `file://`; module scripts and `fetch`
they do not, which is why the module also ships as a script,
`mldsa/mldsa_wasm.b64.js`).

## The domain

`verify.hodeishield.com` is on a domain that the GitHub organisation has
verified. A verified domain stops anyone else from claiming that name for their
own Pages site if the DNS record is ever left dangling (a subdomain takeover).
The custom domain is set in the repository's Pages settings. The file
[`web/CNAME`](../../web/CNAME) records the same name for readers of the
repository; with a deployment made by an Actions workflow it is informational,
and the setting is what counts.

## What this does and does not give you

- The page is published from this repository by a workflow whose every input is
  public: a signed tag, a signed release asset, a public workflow file.
- A reader can prove that the files served are the files in the release, and
  that the release was built by this repository's release workflow at that tag.
- It does **not** prove the page is correct. As with the script, read it. The
  page must pass all 118 cases of `tests/vectors/v1` in headless Chrome and
  Firefox before a release containing it is drafted (see [Tests](#tests)).
- It does not protect a reader whose browser or network is already hostile:
  a page you load over the web can be replaced on the way. That is why the
  offline copy exists, and why the script remains the reference verifier.

## The page

`web/index.html`, `web/css/app.css` and `web/js/*.js`, plain HTML, CSS and
JavaScript. No framework, no runtime npm dependency, no CDN, no web font, no
analytics. The scripts are classic scripts, not ES modules, so that the page also
works when opened from disk. Every string the reader sees is in
`web/locales/*.js`; the only text in the markup is a `<noscript>` note.

What a reader does: adds the attestation and the issuer's key file (drag and drop,
the file picker, or pasted text), optionally fills in what they were told to
expect (organisation, issuer, challenge, oldest age accepted, key identifier) and
adds the withdrawal list and its key set, and presses one button. The page shows
one of seven results, each with what it means and what to do next, a plain list of
what was looked at, and, behind a disclosure, the technical details: the reason
code, the exit code the script would give, every check in order, the SHA-256 of the
signed bytes and of the signature module.

| Result | Exit code of the script | Meaning |
|---|---|---|
| verified | 0 | genuine, unaltered, current |
| good | 0 (`--status-list`) | the same, and the signed withdrawal list does not include it |
| failed | 1 | a check did not hold |
| expired | 1 | genuine, but older than allowed or past `expiresAt` |
| revoked | 1 (`--status-list`) | withdrawn by the issuer |
| could not check | 2 | something stopped the check; not evidence against the document |
| unknown | 3 (`--status-list`) | the list could not be verified or does not settle the case |

Nothing the page is given is sent anywhere: it makes no network request at all (the
policy below forbids one), and it stores nothing in cookies or storage. The page
says that it is not a replacement for the script: the bash script remains the
reference verifier.

### What the page checks

The same as `scripts/attest/verify-attestation.sh`, in the same order and with the
same reason codes ([reason-codes.md](reason-codes.md)): the input and the closed
header set, `alg` and `typ`, the `kid` recomputed from the key bytes and bound to
the key set and to the signed body, key selection and `hs_retired_at`, the
canonical envelope of [section 4.4](attest-verification.md#44-the-canonical-encoding--what-the-signature-actually-covers),
the freshness window, the status list and its own key set, and the revocation rules
for the key and the subject. Only the ML-DSA-65 check itself is done by the
WebAssembly module built by `tools/mldsa-wasm/build.sh` (`aws-lc-rs`, a different
implementation from the issuer's); SHA-256 is in the page; the browser's own
WebCrypto is not used. At start-up the page asks the module three questions with
known answers (a genuine signature, the same with one bit flipped, the same on
another message) and gives no verdict if it answers any of them wrongly.

### What it does not do, and where it differs from the script

- **The key statement (`--anchor-file`) is not checked.** It needs Sigstore: the
  certificate chain, the transparency log and the TUF trust root, with cosign and
  the network. A page that never connects cannot do it. There is no input for it;
  the library answers "could not check" (exit 2, `anchor_unverified`) if one is
  asked for. The case `anchor-statement-older-than-verifier` of the vectors expects
  `anchor_statement_older`, the reason the script finds by reading the tag out of a
  verified certificate; the page gives `anchor_unverified` for it. Exit code and
  verdict agree. This is the one reason-code difference of the 118 cases, and
  `tests/web/args.js` names it.
- `--posture` (deprecated), `--json`, `--raw` and `--help` are about a terminal and
  are not offered. `--now` is not offered in the page (the library takes it, and
  the tests use it).
- The page never fetches a status list or a key set from a URL. The reader gives
  files. The link "Where to get the keys" is an ordinary link to the issuer's
  published key set.
- The checks found only in the page have codes of their own, not in
  `reason-codes.md`: `wasm_mldsa65_available` (pass), `engine_unavailable` (the
  module did not start, exit 2) and `internal_error` (anything unexpected, exit 2:
  the page never turns an exception into a pass).
- Strict JSON is a little stricter than Python's reader: `NaN` and `Infinity` are
  refused, and nesting deeper than 1,000 levels is refused. Both end in "could not
  check" or a refused document, never a pass.

### Differences between the script and its documentation

Found while porting it. Where they differ, the script is the reference and the page
follows the script.

1. [reason-codes.md](reason-codes.md) describes `header_not_base64url`,
   `signature_not_base64url` and `public_key_not_base64url` as "not base64url".
   In the script, `b64url_decode` fails only when the length is 1 modulo 4. Any
   other invalid input is decoded by `openssl base64 -d -A` as an empty string,
   with success (measured with OpenSSL 3.5; spaces and line breaks are ignored,
   leftover bits are ignored), and the run then fails later for another reason:
   `signature_size_invalid` (exit 1), `header_alg_invalid`, or the key size.
2. `public_key_size_invalid` is documented as exit 1. The script records it, then
   builds the key for OpenSSL, which refuses a key of the wrong size, and the run
   ends with `public_key_rejected` (exit 2).
3. The attestation's `alg`, `typ` and `kid` are read from the decoded header with
   `sed`, as text, and not parsed as JSON: the last occurrence of the member on the
   first line that has one is the one used. The closed-set check parses the header
   as JSON, so the two readings can differ for a header that repeats a member (the
   set check then fails it).

## Browsers

Tested, in headless mode, in CI and by the release workflow: Google Chrome and
Firefox, from `http://127.0.0.1` and from disk (`file://`). Versions used for the
results in this document: Chrome 155 and Firefox 153 ESR, on Linux.

**Safari: not tested.** WebKit is not Safari, and no real Safari was available, so
the page says "Safari: not tested" and so does this document.

## Content-Security-Policy

`web/index.html` carries the policy as a `<meta>` tag:

```
default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self'; connect-src 'none'; base-uri 'none'; form-action 'none'
```

with `<meta name="referrer" content="no-referrer">`. No `'unsafe-inline'`, no
`'unsafe-eval'`, no origin. `'wasm-unsafe-eval'` is what lets the browser compile
the WebAssembly module and nothing else; there is no `eval`. There are no inline
scripts or styles and no inline event handlers (`tests/web/static.mjs` checks the
markup and the code, including that nothing calls `fetch`, `eval`, `localStorage`
or `crypto.subtle`). `connect-src 'none'` means the page cannot open a connection;
it does not need one, because the page does not fetch the issuer's key set or a
status list: the reader supplies them as files.

A `<meta>` policy cannot set `frame-ancestors` (browsers ignore it there), and
GitHub Pages does not let a site set response headers. So the page cannot forbid
being framed by another site. Framing does not give the other site access to the
files a reader adds (the page is on its own origin), but it could show the page
inside a misleading frame. The offline copy has no such issue.

## Languages

Spanish (the reference text), English (the fallback), German, French, Italian and
Basque, in plain language and with the vocabulary of the project's public site
(attestation, verification, evidence, supplier). The language follows the
browser's list (`navigator.languages`, primary subtag), can be forced with
`?lang=xx`, and can be changed with the selector, which shows each language in its
own name. The choice is kept in memory and in the address; there is no cookie. A
missing key is shown in English. `tests/web/locales.mjs` fails if a file has a
missing, extra or empty key, a value identical to English (outside the short list
in `tests/web/locales-allow.json`), or different `{placeholders}`. The Basque file is
marked `"_review": "pending native review"`: it has not been reviewed by a native
speaker.

## The bundle

`verify-page-<tag>.tar.gz` is made by `tools/verify-page/build.sh` from `web/` and
the files built by `tools/mldsa-wasm/build.sh` (nothing built is committed):

- `index.html` at the root, then `css/`, `js/`, `locales/`, `icon.svg`, `CNAME`;
- `mldsa/mldsa_wasm.wasm` and `mldsa/mldsa_wasm.js`, as built, and
  `mldsa/mldsa_wasm.b64.js`, the same module bytes as base64 in a script;
- `MANIFEST.sha256`, the SHA-256 of every other file.

Sorted names, owner 0:0, modes 0644 and 0755, mtime from `SOURCE_DATE_EPOCH` (the
tagged commit's time), `gzip -n`; regular files and folders only.
`tests/web-bundle.sh` builds it twice, in other directories, with another umask,
and compares. `release.yml` builds it twice and refuses a release if the two
differ, lists it in `SHA256SUMS`, signs it with Sigstore like the other assets,
checks it as a reader would (names, the manifest, the module's hash), prints its
SHA-256 in the release notes, and drafts the release only after the web tests
passed.

The same inputs give the same bytes on the same toolchain; a different `gzip` or
`tar` build could in principle give other compressed bytes for the same tree. The
manifest inside the archive is independent of that.

## Tests

- `bash tests/web-vectors.sh [--wasm DIR]`: all 118 cases of `tests/vectors/v1`, with
  the fixed time of each case (`--now`), in headless Chrome and Firefox, from
  `http://127.0.0.1` and from disk, on the page as the bundle ships it. Each case
  must give the verdict, exit code and reason code of the case (with the one
  documented exception above) and the canonical SHA-256 the case records. The
  runner also drives the page like a reader (file picker, paste, drop, the
  language selector, the check button) and reads `data-verdict`, `data-exit` and
  `data-reason` from the page, never its text. In Firefox from disk the browser
  gives every file its own origin, so the frame cannot be inspected: the vectors
  run on the page's scripts and module loaded from disk, and a screenshot of the
  real `index.html` confirms that it starts under its policy.
- `bash tests/web-static.sh`: the policy and the code, and the six languages.
- `bash tests/web-bundle.sh`: the bundle.
- CI runs them on every pull request (`wasm-build`, `web-static`, `web-vectors`).

Result, 2026-10-14, Chrome 155.0.8059.39 and Firefox 153.4.0esr on Linux, with the
module of `tools/mldsa-wasm` (`mldsa_wasm.wasm` SHA-256 `4a3c6a43...87da`): 118 of
118 cases, from http and from disk, in both browsers.

## Enabling the deployment (one time)

A repository administrator does this once, and only after the page passes all
118 vectors and the release workflow builds the archive. The order matters.

1. Verify `hodeishield.com` for the GitHub organisation (organisation settings,
   Pages, Verified domains; a DNS TXT record). This step has no API.
2. Enable Pages with GitHub Actions as the source:

   ```bash
   gh api -X POST repos/Hodeitek/hodeishield-attest-verifier/pages -f build_type=workflow
   ```

3. Allow deployments to the `github-pages` environment from `v*` tags only, then
   delete any branch policy that Pages created by default:

   ```bash
   gh api -X PUT repos/Hodeitek/hodeishield-attest-verifier/environments/github-pages \
     --input - <<< '{"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}'
   gh api -X POST repos/Hodeitek/hodeishield-attest-verifier/environments/github-pages/deployment-branch-policies \
     -f name='v*' -f type=tag
   ```

4. Point `verify.hodeishield.com` at GitHub Pages (a DNS CNAME to
   `hodeitek.github.io`, not proxied), then set the custom domain:

   ```bash
   gh api -X PUT repos/Hodeitek/hodeishield-attest-verifier/pages -f cname=verify.hodeishield.com
   ```

5. Once GitHub has issued the certificate, enforce HTTPS:

   ```bash
   gh api -X PUT repos/Hodeitek/hodeishield-attest-verifier/pages -F https_enforced=true
   ```

6. Last, open the gate:

   ```bash
   gh variable set PAGES_ENABLED --body true --repo Hodeitek/hodeishield-attest-verifier
   ```

A manual re-deployment (`workflow_dispatch`) must run on the tag it deploys, so
it works only for tags that already contain `.github/workflows/pages.yml`.

## Status

Built, not deployed. The page, the bundle step of `release.yml` and the web tests
exist, and the page passes all 118 vectors in Chrome and Firefox. The deployment
workflow is committed but inert (`PAGES_ENABLED` is not set), and the first release
that carries `verify-page-<tag>.tar.gz` is the next one after this change. Nothing
is served at `verify.hodeishield.com` until a repository administrator has done
the steps above and a release with the bundle is published
([#25](https://github.com/Hodeitek/hodeishield-attest-verifier/issues/25)).
The page's version is the script's `VERIFIER_VERSION`; `tests/web/static.mjs` fails
if the two differ.
