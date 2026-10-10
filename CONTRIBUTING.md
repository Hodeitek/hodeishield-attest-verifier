# Contributing

## Language

Issues, milestones, labels, pull request titles and bodies, and commit
messages are written in English. A commit subject is lowercase, uses a
conventional type (`fix:`, `feat:`, `docs:`…) and names the defect or gap
it addresses rather than the change.

## Design

A reference for designing or refactoring part of the verifier. Words used
the same way throughout:

- **Module**: anything with an interface and an implementation, at any scale
  (a shell function, the script, a test helper).
- **Interface**: everything a caller must know to use it: arguments,
  invariants, exit codes and errors, ordering.
- **Depth**: behaviour per unit of interface. Deep is much behaviour behind a
  small interface; shallow is an interface nearly as complex as the code.
- **Seam**: a place where behaviour can change without editing that place.
- **Adapter**: a concrete implementation plugged into a seam.
- **Locality**: what changes together lives together. A change should touch
  one module, not five.

Principles:

- Depth lives in the interface. Judge a module by how little a caller must learn.
- Deletion test: imagine inlining the module into its callers. If the
  complexity vanishes it was a pass-through; if it spreads to every caller it
  earns its place.
- The interface is the test surface. Test through it; a test that reaches past
  it pins the implementation.
- One adapter is a hypothetical seam, two make it real. No abstraction for a
  single implementation "for later", unless a test double or a second real
  backend exists today.

For this repository the public interface is the command line: arguments,
stdout and stderr messages, and exit codes (0 verified, 1 check failed,
2 could not check, 3 unknown in `--status-list` mode). Tests and the published
vectors in `tests/vectors/v1/` exercise that, not internal functions. A
refactor that keeps the interface must keep every vector passing unchanged.

Locality: a verification rule (the check, its message and its exit code) lives
in one place in the script, and its test case sits beside the others for that
rule. A new rule should not need edits scattered across the script.

Adapted from [aihero.dev /codebase-design](https://www.aihero.dev/skills-codebase-design).

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

## Releasing

The release commit does two things, and `tests/version-consistency.sh` checks
both:

- It sets `VERIFIER_VERSION` in `scripts/attest/verify-attestation.sh` to the
  version being released. `--anchor-file` compares the release tag of a key
  statement with it, so a statement from an older release is refused.
- It dates the changelog heading: `## Unreleased` becomes
  `## vX.Y.Z - YYYY-MM-DD`.

Between releases, with `## Unreleased` on top, `VERIFIER_VERSION` is the next
version and must be greater than the newest dated heading. On a tag push,
`release.yml` fails before signing anything unless `VERIFIER_VERSION` equals the
tag without its `v` and the changelog has the dated heading.

## Dependencies

No third-party bot with write access runs on this repository.

- **GitHub Actions** are pinned by commit SHA, with the version in a trailing
  comment. Dependabot (`.github/dependabot.yml`) opens one grouped pull request
  against `dev` each week to move them.
- **The `debian:trixie-slim` digest and the cosign version** (`cosign-release`
  in `release.yml`) are bumped by hand, in the periodic dependency reviews:
  - Take a new digest or release only once it is at least 7 days old.
  - The digest is pinned in the workflows (`ci.yml`, `live.yml`,
    `release.yml`, `image.yml`, and a comment in `container.yml`), in
    `container/Dockerfile`, and in the two container commands in `README.md`.
    Change all of them in the same commit;
    `tests/container.sh` fails if they differ.
  - `bash tests/container.sh` must pass before the pull request is opened.
  - To read the current multi-architecture digest of the tag:
    `docker buildx imagetools inspect debian:trixie-slim` (the `Digest:` line).
- **The cosign version** is also used by `image.yml`, which signs the container
  image: bump it there in the same commit as in `release.yml`. `image.yml` also
  pins `anchore/sbom-action` and `actions/attest` by commit SHA; Dependabot
  moves both with the other actions. The SBOM tool (Syft) is the version the
  pinned `anchore/sbom-action` runs.
- **The Semgrep version** in the `semgrep-parse` job of `ci.yml` (pip, in a
  venv, `semgrep==1.163.0`) is bumped by hand, at least 7 days old. The job only
  checks that Semgrep's bash parser reads `verify-attestation.sh` completely.
- **The `alpine:3.22` digest** in `ci.yml` (the LibreSSL job) follows the same
  rules: bumped by hand, at least 7 days old.
