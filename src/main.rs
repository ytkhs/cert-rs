use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use cert_rs::cert::{CertInfo, cert_info_from_der, error_info};
use cert_rs::fetch::{Options, client_config, fetch_with_config};
use cert_rs::output::{Format, render};
use cert_rs::target::{Resolve, parse_resolve, split_host_port};
use clap::{ArgAction, Parser};
use rustls::ClientConfig;

#[derive(Parser)]
#[command(name = "cert", version, disable_version_flag = true)]
struct Cli {
    #[arg(short = 'f', long, value_enum, default_value = "table")]
    format: Format,
    #[arg(short = 'k', long)]
    skip_verify: bool,
    #[arg(short = 'u', long)]
    utc: bool,
    #[arg(short = 's', long, default_value_t = 3)]
    timeout: u64,
    #[arg(short = 'r', long, value_parser = parse_resolve)]
    resolve: Vec<Resolve>,
    #[arg(short = 'v', long, action = ArgAction::Version)]
    version: Option<bool>,
    #[arg(value_name = "HOST")]
    hosts: Vec<String>,
}

fn inspect(
    input: &str,
    opts: &Options,
    config: &Result<Arc<ClientConfig>, String>,
    utc: bool,
) -> CertInfo {
    let (host, port) = match split_host_port(input) {
        Ok(hp) => hp,
        Err(e) => return error_info(input, e),
    };
    let config = match config {
        Ok(c) => c.clone(),
        Err(e) => return error_info(&host, e),
    };
    let fetched = match fetch_with_config(&host, &port, opts, config) {
        Ok(f) => f,
        Err(e) => return error_info(&host, e),
    };
    let Some(leaf) = fetched.chain.first() else {
        return error_info(&host, "no certificate presented");
    };
    cert_info_from_der(leaf, &host, &fetched.ip, &port, utc)
        .unwrap_or_else(|e| error_info(&host, e))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if cli.hosts.is_empty() {
        eprintln!("Input at least one domain name.");
        return ExitCode::from(1);
    }

    let opts = Options {
        skip_verify: cli.skip_verify,
        timeout: Duration::from_secs(cli.timeout),
        resolve: cli.resolve,
    };
    let config = client_config(cli.skip_verify);

    let results: Vec<CertInfo> = std::thread::scope(|s| {
        let handles: Vec<_> = cli
            .hosts
            .iter()
            .map(|h| {
                let (opts, config) = (&opts, &config);
                s.spawn(move || inspect(h, opts, config, cli.utc))
            })
            .collect();
        handles
            .into_iter()
            .zip(&cli.hosts)
            .map(|(h, input)| {
                h.join()
                    .unwrap_or_else(|_| error_info(input, "internal error"))
            })
            .collect()
    });

    print!("{}", render(&results, cli.format));
    ExitCode::SUCCESS
}
