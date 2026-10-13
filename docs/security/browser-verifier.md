# Decision record: hosting the in-browser verifier

- Status: Accepted. **Not deployed yet.**
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
   The archive will carry a manifest with the SHA-256 of every file it holds,
   so this check can cover every served file. The manifest is inside the signed
   archive, so steps 2 and 3 also cover it.

If anything differs, do not use the page, and report it as described in
[SECURITY.md](../../SECURITY.md).

## The offline copy

The same archive is a download on the release. Unpack it and open `index.html`
from your own disk: the page does not need the network to verify an
attestation, so you do not have to trust the web host at all. After step 2 and
3 above, the offline copy is exactly what was deployed. Prefer it when the
result matters.

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
  page must pass all 118 cases of `tests/vectors/v1` in a headless browser
  before a release containing it is drafted.
- It does not protect a reader whose browser or network is already hostile:
  a page you load over the web can be replaced on the way. That is why the
  offline copy exists, and why the script remains the reference verifier.

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

Not deployed. The workflow is committed but inert (`PAGES_ENABLED` is not set),
the release workflow does not yet build `verify-page-<tag>.tar.gz`, and the
page itself does not exist. It will be enabled when the page passes all 118
vectors ([#25](https://github.com/Hodeitek/hodeishield-attest-verifier/issues/25)).
