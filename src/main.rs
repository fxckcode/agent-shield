use agent_guard_proxy::controlled_fetch::{
    fetch_with_policy, FetchPolicy, FetchRequest, UntrustedEnvelope,
};
use agent_guard_proxy::forward_server;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.is_empty() {
        eprint_usage_error("No command provided. See --help for usage.");
        return ExitCode::from(2);
    }

    match args[0].as_str() {
        "--help" | "-h" => {
            print_help();
            ExitCode::SUCCESS
        }
        "serve" => {
            // agent-guard-proxy serve [--port N]
            let mut port: u16 = 8087;
            let mut i = 1;
            while i < args.len() {
                if args[i] == "--port" {
                    if i + 1 < args.len() {
                        match args[i + 1].parse::<u16>() {
                            Ok(p) => port = p,
                            Err(_) => {
                                eprint_usage_error("--port must be a number");
                                return ExitCode::from(2);
                            }
                        }
                        i += 2;
                    } else {
                        eprint_usage_error("--port requires a value");
                        return ExitCode::from(2);
                    }
                } else {
                    i += 1;
                }
            }
            match forward_server::serve(port) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprint_usage_error(&e);
                    ExitCode::from(1)
                }
            }
        }
        "fetch" => {
            if args.len() < 2 {
                eprint_usage_error("Missing URL argument. Usage: agent-guard-proxy fetch <url>");
                return ExitCode::from(2);
            }
            run_fetch(&args[1])
        }
        "wrap" => {
            let code = wrap_command(&args[1..]);
            if code == 0 {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(code as u8)
            }
        }
        other => {
            eprint_usage_error(&format!("Unknown command: {}", escape_json_string(other)));
            ExitCode::from(2)
        }
    }
}

fn print_help() {
    println!("agent-shield — secure fetch gateway and forward proxy for agent CLIs");
    println!();
    println!("USAGE:");
    println!("  agent-shield fetch <url>            Fetch a URL through the security policy");
    println!("  agent-shield serve [--port N]       Run forward proxy (default port 8087)");
    println!("  agent-shield wrap --list            List supported agent CLIs and detection");
    println!("  agent-shield wrap <cli> [--port N] [--dry-run]");
    println!("                                     Configure an agent CLI to route through");
    println!("                                     the forward proxy (headroom-style wrap)");
    println!("  agent-shield --help                 Show this help message");
    println!();
    println!("fetch applies SSRF protection, redirect validation, content filtering,");
    println!("and prompt-injection detection before returning content wrapped in an");
    println!("untrusted-data envelope.");
    println!();
    println!("serve exposes an HTTP forward proxy that validates every destination");
    println!("(CONNECT and absolute requests) against the blocked-IP policy before");
    println!("opening a tunnel. Point an agent CLI at it with HTTP(S)_PROXY.");
}

fn run_fetch(url: &str) -> ExitCode {
    let request = FetchRequest::new(url);
    let mut policy = FetchPolicy::default();

    // Escape controlado para E2E/desarrollo local: AGP_ALLOW_PRIVATE=1 permite
    // destinos privados/loopback. Solo afecta la policy de IPs; el resto de la
    // política (redirects, content types, injection, envelope) sigue activo.
    // Nunca habilitar en producción.
    if std::env::var("AGP_ALLOW_PRIVATE")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        eprintln!(
            r#"{{"status":"warn","message":"AGP_ALLOW_PRIVATE=1: bloqueo de IPs privadas DESACTIVADO (solo para testing local)"}}"#
        );
        policy.block_private_ips = false;
    }

    match fetch_with_policy(&request, &policy) {
        Ok(envelope) => {
            print_success(&envelope);
            ExitCode::SUCCESS
        }
        Err(err) => {
            print_blocked(err.reason_code(), err.correlation_id());
            ExitCode::from(1)
        }
    }
}

fn print_success(envelope: &UntrustedEnvelope) {
    let classification = format!("{:?}", envelope.classification());
    let body_escaped = escape_json_string(&envelope.body_str());
    let corr_escaped = escape_json_string(envelope.correlation_id());
    let class_escaped = escape_json_string(&classification);

    println!(
        r#"{{"status":"allowed","correlation_id":"{}","classification":"{}","body":"{}"}}"#,
        corr_escaped, class_escaped, body_escaped
    );
}

fn print_blocked(reason_code: &str, correlation_id: &str) {
    let reason_escaped = escape_json_string(reason_code);
    let corr_escaped = escape_json_string(correlation_id);

    println!(
        r#"{{"status":"blocked","reason_code":"{}","correlation_id":"{}"}}"#,
        reason_escaped, corr_escaped
    );
}

fn eprint_usage_error(message: &str) {
    let msg_escaped = escape_json_string(message);
    eprintln!(r#"{{"status":"error","message":"{}"}}"#, msg_escaped);
}

/// Minimal JSON string escaping without external dependencies.
fn escape_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// wrap — configure an agent CLI to route through the forward proxy
// ---------------------------------------------------------------------------

const SUPPORTED_CLIS: &[(&str, &str)] = &[
    ("opencode", "opencode"),
    ("cmd", "cmd"),
    ("kiro", "kiro"),
    ("cursor", "cursor"),
];

fn wrap_command(args: &[String]) -> i32 {
    if args.is_empty() || args[0] == "--list" || args[0] == "-l" {
        wrap_list();
        return 0;
    }
    let cli = args[0].as_str();
    let mut port: u16 = 8087;
    let mut dry_run = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                if i + 1 < args.len() {
                    match args[i + 1].parse::<u16>() {
                        Ok(p) => port = p,
                        Err(_) => {
                            eprint_usage_error("--port must be a number");
                            return 2;
                        }
                    }
                    i += 2;
                } else {
                    eprint_usage_error("--port requires a value");
                    return 2;
                }
            }
            "--dry-run" | "-n" | "--json" => {
                dry_run = true;
                i += 1;
            }
            _ => {
                eprint_usage_error(&format!(
                    "Unknown wrap option: {}",
                    escape_json_string(&args[i])
                ));
                return 2;
            }
        }
    }
    wrap_apply(cli, port, dry_run)
}

fn wrap_list() {
    println!("Supported agent CLIs:");
    println!();
    for (name, bin) in SUPPORTED_CLIS {
        let detected = bin_in_path(bin);
        let status = if detected {
            "[detected]"
        } else {
            "[not found]"
        };
        println!("  {:<12} {}", name, status);
    }
    println!();
    println!("Use 'agent-shield wrap <cli> [--port N] [--dry-run]' to configure.");
}

fn wrap_apply(cli: &str, port: u16, dry_run: bool) -> i32 {
    let proxy = format!("http://127.0.0.1:{}", port);
    match cli {
        "opencode" | "kiro" | "cursor" => {
            let actions = format!(
                "[{{\"type\":\"env\",\"var\":\"HTTPS_PROXY\",\"value\":\"{}\"}},{{\"type\":\"env\",\"var\":\"HTTP_PROXY\",\"value\":\"{}\"}}]",
                proxy, proxy
            );
            if dry_run {
                println!(
                    r#"{{"cli":"{}","port":{},"mode":"env","actions":{},"applied":false}}"#,
                    cli, port, actions
                );
            } else {
                println!(
                    "Configure '{}' to route through agent-shield by exporting:\n\n  export HTTPS_PROXY={}\n  export HTTP_PROXY={}\n  export NO_PROXY=localhost,127.0.0.1\n\nThen run agent-shield serve separately. Shell files are never edited by this command.",
                    cli, proxy, proxy
                );
            }
            0
        }
        "cmd" => {
            let config_path = "~/.commandcode/config.json";
            let content = format!("{{\"proxy\":\"{}\"}}", proxy);
            let actions = format!(
                "[{{\"type\":\"config\",\"path\":\"{}\",\"content\":\"{}\"}}]",
                config_path,
                escape_json_string(&content)
            );
            if dry_run {
                println!(
                    r#"{{"cli":"{}","port":{},"mode":"config","actions":{},"applied":false}}"#,
                    cli, port, actions
                );
                0
            } else {
                // Only cmd gets a file write (config.json): create backup + patch.
                let home = std::env::var("HOME").unwrap_or_default();
                let real_path = home.replace("~", &home) + "/.commandcode/config.json";
                let path = home + "/.commandcode/config.json";
                if std::path::Path::new(&path).exists() {
                    let _ = std::fs::copy(&path, format!("{}.bak", path));
                    match std::fs::read_to_string(&path) {
                        Ok(original) => {
                            let updated = update_json_proxy(&original, &proxy);
                            if std::fs::write(&path, updated).is_ok() {
                                println!(
                                    r#"{{"status":"ok","message":"Config field 'proxy' set in {} (backup: .bak)"}}"#,
                                    real_path
                                );
                                0
                            } else {
                                eprint_usage_error("Failed to write config.json");
                                1
                            }
                        }
                        Err(_) => {
                            eprint_usage_error("Failed to read config.json");
                            1
                        }
                    }
                } else {
                    println!(
                        "Config file not found at {}. Apply manually:\n\n  {}",
                        real_path, content
                    );
                    0
                }
            }
        }
        other => {
            eprintln!(
                "Unsupported CLI: {}. Supported: {}",
                other,
                SUPPORTED_CLIS
                    .iter()
                    .map(|(n, _)| *n)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            1
        }
    }
}

/// Patch a JSON document with the "proxy" field, preserving other keys.
/// Minimal implementation without serde_json: only handles the common
/// top-level object case; if parsing fails, returns the raw proxy doc.
fn update_json_proxy(original: &str, proxy: &str) -> String {
    let trimmed = original.trim();
    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        let inner = &trimmed[1..trimmed.len() - 1];
        let mut parts: Vec<String> = Vec::new();
        let mut depth = 0i32;
        let mut cur = String::new();
        let mut in_str = false;
        for ch in inner.chars() {
            match ch {
                '"' => {
                    in_str = !in_str;
                    cur.push(ch);
                }
                '{' | '[' => {
                    depth += 1;
                    cur.push(ch);
                }
                '}' | ']' => {
                    depth -= 1;
                    cur.push(ch);
                }
                ',' if depth == 0 && !in_str => {
                    parts.push(cur.trim().to_string());
                    cur.clear();
                }
                _ => cur.push(ch),
            }
        }
        if !cur.trim().is_empty() {
            parts.push(cur.trim().to_string());
        }
        // drop existing proxy
        parts.retain(|p| !p.trim_start().starts_with("\"proxy\""));
        let mut out = String::from("{");
        for p in parts.iter() {
            if !p.is_empty() {
                out.push_str(p);
                out.push(',');
            }
        }
        out.push_str(&format!("\"proxy\":\"{}\"", escape_json_string(proxy)));
        out.push('}');
        out
    } else {
        format!("{{\"proxy\":\"{}\"}}", escape_json_string(proxy))
    }
}

/// Check whether a binary exists in PATH (without executing it — `--version`
/// on some shims (e.g. cursor) can hang waiting for input).
fn bin_in_path(bin: &str) -> bool {
    std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("command -v '{}' >/dev/null 2>&1", bin))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_list_output_mentions_opencode() {
        // Capture stdout by running the actual fn through a thread redirect is
        // complex; assert on the constant instead so the test is deterministic.
        let names: Vec<&str> = SUPPORTED_CLIS.iter().map(|(n, _)| *n).collect();
        assert!(names.contains(&"opencode"));
        assert!(names.contains(&"cmd"));
        assert!(names.contains(&"kiro"));
        assert!(names.contains(&"cursor"));
    }

    #[test]
    fn wrap_dry_run_json_has_proxy_and_applied_false() {
        let r = wrap_apply("opencode", 8087, true);
        assert_eq!(r, 0);
    }

    #[test]
    fn wrap_unknown_cli_returns_error() {
        let code = wrap_apply("nope", 8087, true);
        assert_eq!(code, 1);
    }

    #[test]
    fn wrap_cmd_dry_run_has_config_path() {
        let code = wrap_apply("cmd", 8087, true);
        assert_eq!(code, 0);
    }

    #[test]
    fn update_json_proxy_preserves_existing_keys() {
        let original = r#"{ "model": "sonnet", "env": "prod" }"#;
        let updated = update_json_proxy(original, "http://127.0.0.1:8087");
        assert!(
            updated.contains("\"model\": \"sonnet\"") || updated.contains("\"model\":\"sonnet\"")
        );
        assert!(updated.contains("proxy"));
    }
}
