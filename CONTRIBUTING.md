# Contributing

## Commits

- Commits must be signed.
- Commit messages must not mention Claude or carry any AI-assistant
  attribution: no `Claude-Session:` or `Co-Authored-By: Claude` trailers, no
  claude.ai links. The same goes for pull request titles and bodies.
- To have git check this locally, enable the hook once per clone:

  ```bash
  git config core.hooksPath .githooks
  ```

## Pull requests

- Work lands on `dev`, which is promoted to `main` through a pull request
  merged with a merge commit.
- The `Attribution` workflow checks the pull request's new commits, title and
  body for the rule above and fails the check if any of them mentions Claude.
  Commits published before the rule was adopted (up to the `CUTOFF` commit
  recorded in the workflow) are not checked.
