# Security Policy

eyebrow is a supply-chain integrity tool, so the integrity of eyebrow itself
matters. If you find a vulnerability, please report it privately.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting:
**[Report a vulnerability](https://github.com/alexverify/eyebrow/security/advisories/new)**
(the "Report a vulnerability" button under the repository's Security tab).

Please do **not** open a public issue for a security problem before a fix is
released.

Include, as far as you can:

- the eyebrow version (`eyebrow version`) and OS,
- a description of the issue and its impact,
- steps to reproduce, and
- any suggested remediation.

## What to expect

- We aim to acknowledge a report within **3 business days**.
- We will work with you on a fix and a coordinated disclosure date, and credit
  you in the advisory unless you prefer otherwise.

## Supported versions

eyebrow is pre-1.0; security fixes land on the latest released minor.

| Version | Supported |
| ------- | --------- |
| 0.2.x   | ✅        |
| < 0.2   | ❌        |

## Scope

In scope: the `eyebrow` binary and its packaged distributions (npm, Homebrew,
`install.sh`), the MCP shim/proxy/sandbox, and the control-plane server. The
local dashboard is loopback-only and unauthenticated by design — report issues
that let a *remote* page reach or drive it (e.g. a bypass of the loopback-Host
or write-token guards), not the absence of auth on the loopback surface itself.
