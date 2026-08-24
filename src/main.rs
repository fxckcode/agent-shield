use agent_guard_proxy::controlled_fetch::{
    fetch_with_policy, FetchPolicy, FetchRequest, UntrustedEnvelope,
};
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
        "fetch" => {
            if args.len() < 2 {
                eprint_usage_error("Missing URL argument. Usage: agent-guard-proxy fetch <url>");
                return ExitCode::from(2);
            }
            run_fetch(&args[1])
        }
        other => {
            eprint_usage_error(&format!("Unknown command: {}", escape_json_string(other)));
            ExitCode::from(2)
        }
    }
}

fn print_help() {
    println!("agent-guard-proxy — controlled fetch CLI adapter");
    println!();
    println!("USAGE:");
    println!("  agent-guard-proxy fetch <url>   Fetch a URL through the security policy");
    println!("  agent-guard-proxy --help        Show this help message");
    println!();
    println!("The fetch command applies SSRF protection, redirect validation,");
    println!("content filtering, and prompt-injection detection before returning");
    println!("content wrapped in an untrusted-data envelope.");
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
