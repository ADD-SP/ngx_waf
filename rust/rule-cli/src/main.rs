//! The command line tool that checks and tests the rules of `ngx-waf-rule`.

use std::ffi::OsStr;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use ngx_waf_rule::{compile, Header, Request, TracedEvaluation, UserVariables, Verdict};

#[derive(Parser)]
#[command(
    name = "ngx-waf-rule",
    version,
    about = "Check and test the rules of the next generation ngx_waf rule engine"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Parse and compile a rule file.
    Check {
        /// The rule file, or `-` to read the standard input.
        file: PathBuf,
    },
    /// Evaluate a rule file against a synthetic request.
    Test {
        /// The rule file, or `-` to read the standard input.
        file: PathBuf,
        /// The path and query string of the request.
        #[arg(long, default_value = "/")]
        url: String,
        /// The request method.
        #[arg(long, default_value = "GET")]
        method: String,
        /// The server port.
        #[arg(long, default_value_t = 80)]
        port: u16,
        /// The client address.
        #[arg(long = "client-ip", default_value = "127.0.0.1")]
        client_ip: IpAddr,
        /// A request header, as `Name: Value`; repeat for several headers.
        #[arg(long = "header", value_name = "NAME: VALUE")]
        headers: Vec<String>,
        /// A user variable, as `name=value`; repeat for several variables.
        #[arg(long = "var", value_name = "NAME=VALUE")]
        variables: Vec<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Commands::Check { file } => check(&file),
        Commands::Test {
            file,
            url,
            method,
            port,
            client_ip,
            headers,
            variables,
        } => test(&file, &url, &method, port, client_ip, &headers, &variables),
    }
}

fn check(file: &Path) -> ExitCode {
    let source = match read_source(file) {
        Ok(source) => source,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(1);
        }
    };

    match compile(&source) {
        Ok(rules) => {
            println!("ok: {} rules", rules.len());
            ExitCode::SUCCESS
        }
        Err(errors) => {
            for error in errors.as_slice() {
                eprintln!("{error}");
            }
            ExitCode::from(1)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn test(
    file: &Path,
    url: &str,
    method: &str,
    port: u16,
    client_ip: IpAddr,
    headers: &[String],
    variables: &[String],
) -> ExitCode {
    let source = match read_source(file) {
        Ok(source) => source,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(1);
        }
    };
    let rules = match compile(&source) {
        Ok(rules) => rules,
        Err(errors) => {
            for error in errors.as_slice() {
                eprintln!("{error}");
            }
            return ExitCode::from(1);
        }
    };

    let headers = match parse_headers(headers) {
        Ok(headers) => headers,
        Err(message) => {
            eprintln!("ngx-waf-rule: {message}");
            return ExitCode::from(2);
        }
    };
    let variables = match parse_variables(variables) {
        Ok(variables) => variables,
        Err(message) => {
            eprintln!("ngx-waf-rule: {message}");
            return ExitCode::from(2);
        }
    };

    let (path, query) = match url.split_once('?') {
        Some((path, query)) => (path, query),
        None => (url, ""),
    };
    let header_views: Vec<Header<'_>> = headers
        .iter()
        .map(|(name, value)| Header {
            name: name.as_bytes(),
            value: value.as_bytes(),
        })
        .collect();
    let request = Request::new(
        path.as_bytes(),
        query.as_bytes(),
        method.as_bytes(),
        port,
        client_ip,
        &header_views,
    );
    let traced = rules.evaluate_traced_with(&request, &variables);

    print_evaluation(&traced, &request);
    ExitCode::SUCCESS
}

fn read_source(path: &Path) -> Result<String, String> {
    if path.as_os_str() == OsStr::new("-") {
        let mut source = String::new();
        std::io::stdin()
            .read_to_string(&mut source)
            .map_err(|error| format!("cannot read the standard input: {error}"))?;
        Ok(source)
    } else {
        std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))
    }
}

fn parse_headers(raw: &[String]) -> Result<Vec<(String, String)>, String> {
    raw.iter()
        .map(|header| {
            let (name, value) = header
                .split_once(':')
                .ok_or_else(|| format!("invalid --header '{header}': expected 'Name: Value'"))?;
            let name = name.trim_end();
            if name.is_empty() {
                return Err(format!("invalid --header '{header}': the name is empty"));
            }
            let value = value.strip_prefix(' ').unwrap_or(value);
            Ok((name.to_string(), value.to_string()))
        })
        .collect()
}

fn parse_variables(raw: &[String]) -> Result<UserVariables, String> {
    let mut variables = UserVariables::new();
    for entry in raw {
        let (name, value) = entry
            .split_once('=')
            .ok_or_else(|| format!("invalid --var '{entry}': expected 'name=value'"))?;
        if !is_user_variable(name) {
            return Err(format!(
                "invalid --var '{entry}': '{name}' is not a user variable name"
            ));
        }
        let value = value
            .parse::<i64>()
            .map_err(|_| format!("invalid --var '{entry}': the value is not an integer"))?;
        variables.insert(name.to_string(), value);
    }
    Ok(variables)
}

fn is_user_variable(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(character) if character.is_ascii_alphabetic() || character == '_' => {}
        _ => return false,
    }
    if !chars.all(|character| character.is_ascii_alphanumeric() || character == '_') {
        return false;
    }
    !is_builtin(name)
}

fn is_builtin(name: &str) -> bool {
    matches!(
        name.to_ascii_uppercase().as_str(),
        "URL" | "QUERY_STRING" | "METHOD" | "PORT" | "CLIENT_IP" | "HEADER" | "HEADERS"
    )
}

fn print_evaluation(traced: &TracedEvaluation, request: &Request<'_>) {
    let mut target = display(request.url);
    if !request.query_string.is_empty() {
        target.push('?');
        target.push_str(&display(request.query_string));
    }
    println!(
        "request: {} {} (port {}) from {}",
        display(request.method),
        target,
        request.port,
        request.client_ip
    );

    for rule in &traced.rules {
        let mark = if rule.matched { "[x]" } else { "[ ]" };
        println!("  {mark} line {}: {}", rule.line, rule.condition);
        for action in &rule.actions {
            println!("      -> {action}");
        }
    }

    match traced.evaluation.verdict {
        Verdict::Continue => println!("verdict: continue"),
        Verdict::Allow { line } => println!("verdict: allow (line {line})"),
        Verdict::Deny { line } => println!("verdict: deny (line {line})"),
    }

    if traced.evaluation.variables.is_empty() {
        println!("variables: (none)");
    } else {
        let variables: Vec<String> = traced
            .evaluation
            .variables
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect();
        println!("variables: {}", variables.join(", "));
    }

    if traced.evaluation.logged.is_empty() {
        println!("logged: (none)");
    } else {
        let logged: Vec<String> = traced
            .evaluation
            .logged
            .iter()
            .map(|entry| match &entry.message {
                Some(message) => format!("line {} (msg: {message})", entry.line),
                None => format!("line {}", entry.line),
            })
            .collect();
        println!("logged: {}", logged.join(", "));
    }
}

fn display(value: &[u8]) -> String {
    String::from_utf8_lossy(value).into_owned()
}
