# agent-shield

**Secure fetch gateway + forward proxy for agent CLIs.**

agent-shield sits between your agent CLI and the network. It blocks phishing/SSRF
targets, revalidates redirects, filters dangerous content, detects
prompt-injection, and wraps external content in an explicit **untrusted-data
envelope** so fetched text can never become authority over the machine.

It also runs as an **HTTP forward proxy** that validates every destination
(SSRF) *before* opening a tunnel — the headroom-style integration layer for
agent CLIs.

## Why

An agent CLI must never let fetched content become trusted instructions.
OpenCode, Claude Code, Cursor, command-code, kiro and other CLIs fetch web
content; a hostile page could try to exfiltrate context or alter tool
permissions. agent-shield gives you a single, policy-enforced choke point.

## Features

- **SSRF protection** — private, loopback, link-local, metadata, and
  disallowed-resolved IP destinations are blocked before the connection.
- **Redirect safety** — every redirect hop is revalidated; a chain cannot
  escape to a blocked destination.
- **Content filtering** — unsupported or dangerous content types, oversized
  bodies, and excessive redirects are rejected.
- **Untrusted-data envelope** — content is returned tagged as untrusted and
  cannot alter gateway policy or tool permissions.
- **Prompt-injection quarantine** — injected instructions are detected or
  quarantined by a versioned policy; uncertain classifications **fail closed**.
- **Safe block reporting** — every block includes a reason code and a
  correlation id, without echoing secrets or hostile payloads.
- **Forward proxy server** — `serve` validates every CONNECT/absolute request
  destination before opening the tunnel (`HTTP(S)_PROXY` compatible).

## Build

```bash
cargo build --release        # optimized: LTO + strip + opt-level=3
```

## Test

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test                   # 75 unit + integration + probe tests
python3 probes/e2e_full.py            # fetch E2E vs local fixtures (9/9)
python3 probes/e2e_proxy_server.py    # forward-proxy E2E vs real network (7/7)
```

CI (`.github/workflows/ci.yml`) enforces fmt/clippy/test on every push and PR.

## CLI usage

```bash
agent-shield fetch <url>          # fetch through the security policy (envelope)
agent-shield serve [--port N]     # forward proxy (default port 8087)
agent-shield --help
```

Example:

```bash
$ agent-shield fetch http://example.com/
{"status":"allowed","correlation_id":"...","classification":"ExternalUntrusted","body":"..."}

$ agent-shield fetch http://169.254.169.254/
{"status":"blocked","reason_code":"SSRF_PRIVATE_IP","correlation_id":"..."}
```

## Integration with agent CLIs (headroom-style)

Start the proxy, then point your agent CLI at it. The proxy validates every
destination before the tunnel — an agent told to fetch `http://169.254.169.254/`
or any internal/metadata address gets a clean `403 SSRF_PRIVATE_IP` instead of
reaching internal infrastructure.

```bash
agent-shield serve --port 8087
```

### Environment-variable proxies (most CLIs)

Most Node/Bun/Rust CLIs honor standard proxy env vars:

| CLI | Config |
|---|---|
| **opencode** | `HTTPS_PROXY=http://127.0.0.1:8087` `HTTP_PROXY=http://127.0.0.1:8087` |
| **command-code / cmd** | same env vars, or `proxy` in `~/.commandcode/config.json` |
| **kiro cli** | same env vars; or `HTTP_PROXY` in `.kiro/settings/` |
| **cursor** | `HTTPS_PROXY` / `HTTP_PROXY` env vars |
| **any fetch-based tool** | same env vars (curl, python, etc.) |

```bash
HTTPS_PROXY=http://127.0.0.1:8087 HTTP_PROXY=http://127.0.0.1:8087 opencode
```

### Per-CLI config

- **opencode**: run with the env vars above, or set them in your shell profile.
- **cmd (command-code)**: `~/.commandcode/config.json` accepts a `proxy` field.
- **kiro**: export the env vars; kiro honors standard proxy variables.
- **cursor**: export the env vars before launching.

The proxy responds to `CONNECT` and absolute-form requests, so plain
`HTTP(S)_PROXY` routing works without per-tool plugins.

### Testing the setup

```bash
# 1. start the proxy
agent-shield serve --port 8087

# 2. confirm SSRF blocking is active
curl -s -x http://127.0.0.1:8087 http://169.254.169.254/ -o /dev/null -w "%{http_code}\n"
# → 403

# 3. confirm real traffic works
curl -s -x http://127.0.0.1:8087 http://example.com/ -o /dev/null -w "%{http_code}\n"
# → 200

# 4. run an agent through it
HTTPS_PROXY=http://127.0.0.1:8087 HTTP_PROXY=http://127.0.0.1:8087 opencode
```

> **Testing escape**: `AGP_ALLOW_PRIVATE=1` disables the private-IP block for
> local fixture testing (prints an explicit warning). Never use in production.

## Security policy

- Blocks: private/loopback/link-local/metadata IPs, dangerous content types,
  oversized bodies, excessive redirects, detected prompt-injection.
- **Fails closed**: any uncertain classification is treated as hostile.
- Blocks are reported with a safe reason code and correlation id; secrets and
  hostile payloads are never echoed.

## Non-goals

- Perfect semantic detection of all prompt injection.
- Replacing sandboxing or human review.

## Similar projects

- **headroom** (headroomlabs-ai/headroom) — token-compression proxy for agent
  CLIs; the integration pattern (env-var proxy / wrap) this project follows.
  agent-shield focuses on *security policy* (SSRF, injection, untrusted data)
  rather than compression.

## License

Apache-2.0.