# Contributing

## Language

Issues, milestones, labels, pull request titles and bodies, and commit
messages are written in English. A commit subject is lowercase, uses a
conventional type (`fix:`, `feat:`, `docs:`…) and names the defect or gap
it addresses rather than the change.

## Commits

- Commits must be signed.
- A commit that fixes an issue says `Closes #N` in the commit message itself,
  not only in the pull request body. GitHub closes the issue when the commit
  reaches `main`; a merge into `dev` closes nothing. Use `Refs #N` for a commit
  that only contributes to an issue.
- Commit messages must not mention Claude or carry any AI-assistant
  attribution: no `Claude-Session:` or `Co-Authored-By: Claude` trailers, no
  claude.ai links. The same goes for pull request titles and bodies.
- To have git check this locally, enable the hook once per clone:

  ```bash
  git config core.hooksPath .githooks
  ```

## Developer Certificate of Origin

Every commit must carry a `Signed-off-by: Name <email>` trailer whose email
matches the commit author. It certifies the
[Developer Certificate of Origin 1.1](https://developercertificate.org/) and is
added with `git commit -s`. This is separate from commit signing above.

The `DCO` workflow checks this on commits of pull requests opened from forks.

## Pull requests

- Work lands on `dev`, which is promoted to `main` through a pull request
  merged with a merge commit.
- The `Attribution` workflow checks the pull request's new commits, title and
  body for the rule above and fails the check if any of them mentions Claude.
  Commits published before the rule was adopted (up to the `CUTOFF` commit
  recorded in the workflow) are not checked.
- The `DCO` workflow checks that the new commits of a pull request opened from
  a fork each carry a `Signed-off-by` trailer matching their author. Commits
  published before the workflow was adopted (up to its `CUTOFF` commit) are not
  checked.

## Issues

No issue stays open once the code that fixes it is on `main`.

- **After every promotion to `main`** (and every release), every open issue is
  reviewed against what is now on `main`:
  - **Fixed:** closed, with a comment citing the commit or pull request and the
    file, line or test that shows it.
  - **Partly fixed:** a comment says what is done and what remains, and it
    stays open.
  - **Still valid:** left as it is.
  - **Obsolete** (superseded, duplicate, out of scope): closed with the reason
    and a link.
- **After a merge into `dev`:** the issues the pull request mentions (`Refs #N`,
  its body, its branch name) are checked. They are closed only if the fix is
  complete; otherwise a comment records the status.
- A security issue is closed only with evidence that it is fixed or not
  exploitable.
- Closing comments are in English and, like everything in this public
  repository, cite only public material.

## Dependencies

No third-party bot with write access runs on this repository.

- **GitHub Actions** are pinned by commit SHA, with the version in a trailing
  comment. Dependabot (`.github/dependabot.yml`) opens one grouped pull request
  against `dev` each week to move them.
- **The `debian:trixie-slim` digest and the cosign version** (`cosign-release`
  in `release.yml`) are bumped by hand, in the periodic dependency reviews:
  - Take a new digest or release only once it is at least 7 days old.
  - The digest is pinned in the workflows (`ci.yml`, `live.yml`,
    `release.yml`, and a comment in `container.yml`) and in the two container
    commands in `README.md`. Change all of them in the same commit;
    `tests/container.sh` fails if they differ.
  - `bash tests/container.sh` must pass before the pull request is opened.
  - To read the current multi-architecture digest of the tag:
    `docker buildx imagetools inspect debian:trixie-slim` (the `Digest:` line).
- **The `alpine:3.22` digest** in `ci.yml` (the LibreSSL job) follows the same
  rules: bumped by hand, at least 7 days old.
