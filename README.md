# agent-guard-proxy

Secure fetch gateway for agent CLIs. Blocks phishing/SSRF targets, revalidates
redirects, filters dangerous content, and wraps external content in an explicit
untrusted-data envelope so fetched text can never be treated as trusted
instructions.

## Purpose

An agent CLI must never let fetched content become authority over the machine.
`agent-guard-proxy` sits between the agent and the network:

- **SSRF protection** — private, loopback, link-local, metadata, and
  disallowed-resolved IP destinations are blocked before the connection.
- **Redirect safety** — every redirect hop is revalidated against the policy;
  a chain cannot escape to a blocked destination.
- **Content filtering** — unsupported or dangerous content types, oversized
  bodies, and excessive redirects are rejected.
- **Untrusted-data envelope** — external content is returned tagged as
  untrusted and cannot alter gateway policy or tool permissions.
- **Prompt-injection quarantine** — injected instructions are detected or
  quarantined by a versioned policy; uncertain classifications fail closed.
- **Safe block reporting** — every block includes a reason code and a
  correlation id, without echoing secrets or full hostile payloads.

## Build

```bash
cargo build --release        # optimized: LTO + strip + opt-level=3
```

## Test

```bash
cargo fmt --check            # format gate
cargo clippy -- -D warnings  # lint gate (no warnings allowed)
cargo test                   # unit + integration + probe tests
```

The repository CI (`.github/workflows/ci.yml`) enforces all three gates on
every push to `main` and on every pull request.

## Usage

```bash
# Fetch a URL through the security policy
agent-guard-proxy fetch <url>

# Show help
agent-guard-proxy --help
```

The `fetch` command applies SSRF protection, redirect validation, content
filtering, and prompt-injection detection before returning content wrapped in
an untrusted-data envelope.

## Security policy

- Blocks: private/loopback/link-local/metadata IPs, dangerous content types,
  oversized bodies, excessive redirects, detected prompt injection.
- Fails closed: any uncertain classification is treated as hostile.
- Blocks are reported with a safe reason code and correlation id; secrets and
  hostile payloads are never echoed.

## Non-goals

- Perfect semantic detection of all prompt injection.
- Replacing sandboxing or human review.

## License

Private. All rights reserved.