# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately, either through GitHub's private
vulnerability reporting (**Security** tab, **Report a vulnerability**) or by
email to **security@hodeitek.com**. Include the artefact, the exact command
and the full output, so the problem can be reproduced.

Do not open a public issue for a vulnerability.

We will acknowledge your report, keep you informed while we investigate, and
credit you in the advisory if you want to be credited.

- Encrypted email: not offered at the moment.
- Bug bounty: there is no bounty programme; we credit reporters publicly in the
  advisory.

## What happens after you report

A report made through GitHub opens a draft security advisory that only you and
the maintainers can see; we talk to you there. A report made by email is
answered by email.

| Step | What you get | When |
|---|---|---|
| Acknowledgement | Confirmation that we received the report | Within 3 business days |
| First assessment | Whether it is a vulnerability, its severity, and whether we know of it being exploited | Within 10 business days |
| Status updates | Progress on the fix and the expected release, until the advisory is published | At least every 14 days |
| Fix | A release that fixes it, and the published advisory | See the targets below |

### Severity and fix targets

We rate severity with
[CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document) and use its
qualitative ratings. You can comment on the rating in the advisory or by email.
The targets below are for shipping a fixed release. For Critical and High they
count from the first assessment. For Medium they count from your report, so a
fix never lands after the disclosure period ends.

| Severity | CVSS v3.1 base score | Target to ship a fix |
|---|---|---|
| Critical | 9.0 - 10.0 | 7 days |
| High | 7.0 - 8.9 | 30 days |
| Medium | 4.0 - 6.9 | 90 days from your report |
| Low | 0.1 - 3.9 | The next release |

A fix is a new release of a supported major version, as described under
[Supported versions](#supported-versions).

### Coordinated disclosure

We ask you to keep the vulnerability confidential until the advisory is
published, and we agree the publication date with you. The coordinated
disclosure period is 90 days from your report. It ends earlier if a fix is
released or if the vulnerability is being actively exploited. We can extend it
by mutual agreement. If no fix is released by the end of the period, we publish
the advisory with the workarounds we know of.

If the vulnerability is being actively exploited, we publish earlier, with the
workarounds we know of, and we expedite the fix.

### Safe harbour

We welcome good-faith security research and will not take legal action against
you, or ask anyone else to, for research that follows this policy: you report to
us privately and give us reasonable time to fix the issue before you disclose
it; you access only the data you need to show the vulnerability, and do not
keep, change or share anyone else's data; you do not harm other people's
systems or data; and you test only against systems and data you own or are
allowed to use. If in doubt, ask us first.

## Supported versions

Each major version of the verifier is supported for five years, counted from the
release of its first version (v1.0.0 for version 1). A supported major version
receives security fixes. They ship in a new release of that major version: to
get them, update to the latest release of your major version.

The verifier is free to use. Every release is a public download, and using or
updating it needs no account or subscription, so security fixes stay available
to you for as long as your major version is supported.

| Version | Released | Security fixes until |
|---|---|---|
| 1.x | 2026-09-29 (v1.0.0) | 2031-09-29 |

The end-of-support date of each major version is published in this table and in
the release notes. Twelve months before a major version's support ends, an
end-of-support notice is published here and in the release notes. A release that
ends support for an older major version says so in its release notes, with the
date, and this table is updated in the same release.

## Where fixes and advisories are announced

A fixed release is published on the repository's
[Releases page](https://github.com/Hodeitek/hodeishield-attest-verifier/releases),
and a security fix is listed under `### Security` in that release's section of
[CHANGELOG.md](CHANGELOG.md). The advisory is published under
[Security → Advisories](https://github.com/Hodeitek/hodeishield-attest-verifier/security/advisories)
with the fixed release, or earlier if the vulnerability is being actively
exploited (see [Coordinated disclosure](#coordinated-disclosure)). It says which
versions are affected, what to do in the meantime, and whether a fix is in
progress. To be told, watch this repository's releases on GitHub (*Watch →
Custom → Releases*) or follow
[its releases feed](https://github.com/Hodeitek/hodeishield-attest-verifier/releases.atom),
and check the advisories page.

## How advisories are published

Every fixed vulnerability gets a GitHub security advisory in this repository,
written from
[docs/security-advisory-template.md](docs/security-advisory-template.md) so that
every advisory has the same fields:

- a description of the vulnerability and its impact;
- who is affected: which options, configurations and ways of running the
  verifier;
- the affected versions and the fixed versions;
- the severity, with its CVSS v3.1 vector;
- workarounds, how to check whether you are affected, and how to update;
- the timeline (reported, fixed, published), the credit, and references.

Each advisory has a GHSA identifier. When a vulnerability needs a CVE
identifier, we request it through the advisory, with GitHub as the CVE
Numbering Authority. The reporter is credited in the advisory unless they
decline.
