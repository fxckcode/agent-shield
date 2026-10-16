# Security Policy

## Reporting a vulnerability

Do not open a public issue. Use the repository's
[private vulnerability report](https://github.com/fxckcode/agent-shield/security/advisories/new).

Include what you need to make the report actionable:

- the affected version or commit,
- a reproduction — the exact command, URL, or proxy request,
- the observed behaviour and the behaviour you expected,
- the impact you believe it has,
- a suggested fix if you have one.

Never include live credentials, tokens, or personal data in a report. If a proof of concept needs a
credential, describe the shape of it instead.

You will get an acknowledgement, an assessment of whether it is in scope, and a note when a fix lands.
This is a small project maintained alongside other work, so expect days rather than hours.

## What counts as a vulnerability here

In scope, and treated as security issues rather than documentation preferences:

- a destination that reaches the network despite the address policy — an SSRF bypass,
- a DNS-rebinding window between validation and connection,
- a redirect chain that escapes the policy,
- content that is delivered without its untrusted classification,
- a block that leaks the blocked destination, a credential, or the hostile payload,
- guidance in this repository that would lead someone to an insecure configuration.

## Out of scope

- **The absence of content inspection on the `serve` proxy path.** A CONNECT tunnel carries TLS the
  proxy cannot see into. The README states this explicitly; it is a design boundary, not a defect.
- **Prompt-injection detection missing an injection.** The classifier is regular-expression based and
  the README says so. A new pattern is a feature request, not a vulnerability.
- **`AGP_ALLOW_PRIVATE=1` disabling the private-IP block.** That is what the escape is for; it prints a
  warning and the README says it is testing-only.
- Problems in a server, client, or SDK you are proxying. Report those upstream.
- Running `serve` for untrusted local users. It is a localhost, unauthenticated proxy for a single
  trusted user; the README documents that boundary.

## Supported versions

The `main` branch is the supported line. There are no tagged releases yet.
