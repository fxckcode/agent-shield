# agent-shield

**Destination-validating forward proxy and secure fetch gateway for agent CLIs.**

agent-shield has two modes with **different guarantees**, and the difference matters:

| Mode | What it does | What it does not do |
| --- | --- | --- |
| `serve` — forward proxy | Validates every destination before connecting, for CONNECT tunnels and absolute-form HTTP. This is the path real agent traffic uses, because HTTPS goes through CONNECT. | Does **not** inspect content. A CONNECT tunnel carries TLS the proxy cannot see into, so there is no content filtering, no prompt-injection detection and no envelope here. |
| `fetch` — one-shot gateway | The full content pipeline: destination validation, redirect revalidation, content-type and size filtering, prompt-injection detection, untrusted-data envelope. | **Plaintext HTTP only.** Every scheme except `http` is rejected, so it cannot fetch the HTTPS URLs an agent normally encounters. |

In short: `serve` decides *where* a connection may go and cannot see what travels over it; `fetch`
can inspect content but only over plaintext HTTP. Neither mode alone gives you both, and the feature
list below describes the two paths separately on purpose.

## Why

An agent CLI must never let fetched content become trusted instructions.
OpenCode, Claude Code, Cursor, command-code, kiro and other CLIs fetch web
content; a hostile page could try to exfiltrate context or alter tool
permissions. `fetch` gives you a policy-enforced choke point for content you pull
in yourself; `serve` gives you a choke point for the destinations a CLI reaches.

## Features

### `serve` — destination validation

- **SSRF protection** — loopback, private, link-local, metadata, CGNAT, reserved, and
  unspecified destinations (`0.0.0.0`, `::`) are blocked before the connection, for IPv4
  and IPv6 alike, including 6to4 (`2002::/16`) and Teredo (`2001::/32`).
- **Validated address, pinned connection** — the proxy resolves once, validates, and connects to the
  exact `SocketAddr` it checked, so an answer that changes between the check and the connect cannot
  escape the policy.
- **Absolute-form GET and HEAD** — proxied with the destination validated first. POST is refused: it
  needs real HTTP body framing, and agent CLIs use CONNECT instead.
- **Bounded** — connect, read and write timeouts on every socket.
- **Safe block reporting** — every block includes a reason code and a correlation id, without echoing
  secrets or hostile payloads.

### `fetch` — content pipeline (plaintext HTTP)

- **Redirect safety** — every redirect hop is revalidated; a chain cannot
  escape to a blocked destination.
- **Content filtering** — unsupported or dangerous content types, oversized
  bodies, and excessive redirects are rejected.
- **Untrusted-data envelope** — content is returned tagged as untrusted.
- **Prompt-injection detection** — content matching the pattern set is blocked. This is a
  regular-expression classifier, not a semantic one: content that matches nothing is delivered as
  untrusted, not verified safe. See "Security policy" for the precise claim.
- **Fails closed on destinations** — an unresolvable name or an empty resolution is denied rather
  than treated as safe.

## Build

```bash
cargo build --release        # optimized: LTO + strip + opt-level=3
```

## Test

```bash
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked            # 94 tests (unit + integration)
python3 probes/checklist.py    # the six acceptance properties, in order
python3 probes/e2e_full.py            # fetch E2E vs local fixtures (needs a built release binary)
python3 probes/e2e_proxy_server.py    # forward-proxy E2E vs real network (needs a built release binary)
```

CI (`.github/workflows/ci.yml`) runs fmt/clippy/test on every push and PR, fails the build if the
forward proxy reintroduces an unchecked `TcpStream::connect` on a host string, and runs the four
probes above against the release binary so the proxy's byte-stream behaviour has an automated witness.

### Running the gates without installing Rust on the host

The toolchain can stay in a container. Redirect `CARGO_TARGET_DIR` and `CARGO_HOME` outside the
working tree so the container leaves no root-owned files in the repository:

```bash
docker run --rm -e CARGO_HOME=/cargo-home -e CARGO_TARGET_DIR=/target -e HOME=/tmp \
  -v "$PWD":/w -v "$PWD/../.cargo-home":/cargo-home -v "$PWD/../.target":/target -w /w rust:1 \
  bash -c 'rustup component add rustfmt clippy && cargo fmt --check && \
           cargo clippy --all-targets --locked -- -D warnings && cargo test --locked'
```

## CLI usage

```bash
agent-shield fetch <url>                       # content pipeline (plaintext HTTP, envelope)
agent-shield serve [--port N]                  # forward proxy (default port 8087)
agent-shield wrap --list                       # supported agent CLIs and detection
agent-shield wrap <cli> [--port N] [--dry-run]  # point a CLI at the proxy (prints the exports)
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

The proxy responds to `CONNECT` plus absolute-form `GET`/`HEAD`, so plain `HTTP(S)_PROXY` routing
works without per-tool plugins. Absolute-form `POST` is refused rather than mis-framed; use the
`CONNECT` path (i.e. `https://`) for anything with a request body.

### Reaching internal hosts

The private-IP block is deliberate, so internal destinations are refused by default. The sanctioned
bypass is `NO_PROXY`, which is standard, per-client, and says exactly what it means — internal traffic
does not go through the proxy:

```bash
export HTTPS_PROXY=http://127.0.0.1:8087 HTTP_PROXY=http://127.0.0.1:8087
export NO_PROXY=localhost,127.0.0.1,.internal.example.com,192.168.0.0/16
```

`agent-shield wrap <cli>` prints a starting value; extend it with the hosts you actually need.
Support for CIDR entries in `NO_PROXY` varies by client, so verify with the tool you use.

> **Testing escape**: `AGP_ALLOW_PRIVATE=1` disables the private-IP block for every destination,
> including cloud metadata, and prints an explicit warning. It exists for local fixture testing.
> Never use it in production — `NO_PROXY` is the narrow tool for internal hosts.

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

## Security policy

Applies to both modes unless a bullet says otherwise.

- **Blocked destinations**: loopback, RFC 1918 private, link-local and cloud metadata,
  RFC 6598 CGNAT (`100.64.0.0/10`), `0.0.0.0/8`, `192.0.0.0/24`, `192.88.99.0/24`,
  `198.18.0.0/15`, `240.0.0.0/4`, plus IPv6 loopback, the unspecified address `::`, multicast,
  IPv4-mapped, link-local and unique-local space, and 6to4/Teredo. TEST-NET ranges stay reachable:
  they are unroutable documentation space.
- **Deny-list, not allow-list.** An address is refused only if it matches an entry in the table, so a
  special-purpose range that is not listed passes. The table is curated; every entry has a test.
- **One predicate, every caller**: `is_blocked_ip` serves the fetch path, the redirect
  revalidation, and the forward proxy, so a range cannot be missing from only one of them.
- **Validated address, pinned connection**: the proxy resolves once, validates, and connects to
  the exact `SocketAddr` it checked — it never re-resolves the host name after validation, which
  closes the DNS-rebinding window.
- **Fails closed on destinations**: an unresolvable name or an empty resolution is denied, never
  treated as safe.
- **Bounded**: connect, read, and write timeouts on both the fetch and proxy paths.
- Blocks are reported with a safe reason code and correlation id; secrets and hostile payloads are
  never echoed.

### What the `fetch` content pipeline does not claim

- **Prompt-injection detection is a regular-expression classifier** (`injection_policy_version: "v1"`).
  Content matching a pattern is blocked. Content matching nothing is delivered inside the untrusted
  envelope, which is a *label*, not a verdict — it is not evidence that the content is safe. A
  downstream agent decides what that label means; this tool cannot enforce how it interprets content.
- **The envelope does not make content inert.** It marks content as untrusted. Whether that changes
  the consuming agent's behaviour is the agent's business, not something a fetch gateway can guarantee.

Every claim above is backed by a test in the repository; `cargo test` and `probes/checklist.py`
are the evidence.

## Non-goals

- Perfect semantic detection of all prompt injection.
- Replacing sandboxing or human review.
- Acting as a general-purpose proxy: `serve` binds `127.0.0.1` only and is meant for local agent
  CLIs, not for exposing a network.

## Similar projects

- **headroom** (headroomlabs-ai/headroom) — token-compression proxy for agent
  CLIs; the integration pattern (env-var proxy / wrap) this project follows.
  agent-shield focuses on *security policy* (SSRF, injection, untrusted data)
  rather than compression.

## License

Apache-2.0.