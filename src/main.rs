use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use cert_rs::cert::{CertInfo, cert_info_from_der, error_info};
use cert_rs::chain::{ChainEntry, chain_check_label, chain_entries, check_chain};
use cert_rs::fetch::{Options, client_config, fetch_with_config};
use cert_rs::output::{Format, render};
use cert_rs::target::{Resolve, parse_resolve, split_host_port, unmatched_resolves};
use clap::{ArgAction, Parser};
use rustls::ClientConfig;

/// Show TLS certificate details for one or more hosts.
#[derive(Parser)]
#[command(name = "cert", version, disable_version_flag = true)]
struct Cli {
    /// Output format
    #[arg(short = 'f', long, value_enum, default_value = "table")]
    format: Format,
    /// Skip certificate chain and hostname verification (handshake signatures are still checked)
    #[arg(short = 'k', long)]
    skip_verify: bool,
    /// Show times in UTC instead of local time
    #[arg(short = 'u', long)]
    utc: bool,
    /// Seconds allowed for connect and handshake combined, excluding DNS lookup; 0 means no limit
    #[arg(short = 's', long, value_name = "SECONDS", default_value_t = 3)]
    timeout: u64,
    /// Connect to ADDR instead of resolving HOST for that HOST:PORT; repeatable, IPv6 ADDR in brackets
    #[arg(short = 'r', long, value_name = "HOST:PORT:ADDR", value_parser = parse_resolve)]
    resolve: Vec<Resolve>,
    /// Show the certificates exactly as the server sent them and check their links and validity
    #[arg(long)]
    chain: bool,
    /// Print version
    #[arg(short = 'v', long, action = ArgAction::Version)]
    version: Option<bool>,
    /// Hosts to inspect: host, host:port, [IPv6]:port or https:// URL
    #[arg(value_name = "HOST")]
    hosts: Vec<String>,
}

fn inspect(
    input: &str,
    opts: &Options,
    config: &Result<Arc<ClientConfig>, String>,
    utc: bool,
    chain: bool,
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
    let info = match cert_info_from_der(leaf, &host, &fetched.ip, &port, utc) {
        Ok(info) => info,
        Err(e) => return error_info(&host, e),
    };
    if !chain {
        return info;
    }
    let ders: Vec<&[u8]> = fetched.chain.iter().map(|c| c.as_ref()).collect();
    match entries_and_problems(&ders, utc) {
        Ok((entries, problems)) => CertInfo {
            chain: Some(entries),
            chain_check: Some(chain_check_label(&problems)),
            ..info
        },
        // A broken chain is a finding about the server, not a failure of the row.
        Err(e) => CertInfo {
            chain: Some(Vec::new()),
            chain_check: Some(format!("NG: {e}")),
            ..info
        },
    }
}

fn entries_and_problems(
    ders: &[&[u8]],
    utc: bool,
) -> Result<(Vec<ChainEntry>, Vec<String>), String> {
    let entries = chain_entries(ders, utc)?;
    let problems = check_chain(ders, jiff::Timestamp::now())?;
    Ok((entries, problems))
}

/// Keeps file descriptors under a typical ulimit.
const MAX_PARALLEL: usize = 128;

fn map_bounded<T: Sync, R: Send>(
    items: &[T],
    workers: usize,
    f: impl Fn(&T) -> R + Sync,
    on_panic: impl Fn(&T) -> R + Sync,
) -> Vec<R> {
    let next = AtomicUsize::new(0);
    let mut indexed: Vec<(usize, R)> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..workers.min(items.len()))
            .map(|_| {
                s.spawn(|| {
                    let mut done = Vec::new();
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        let Some(item) = items.get(i) else { break };
                        let r = catch_unwind(AssertUnwindSafe(|| f(item)))
                            .unwrap_or_else(|_| on_panic(item));
                        done.push((i, r));
                    }
                    done
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("worker panics are caught per item"))
            .collect()
    });
    indexed.sort_unstable_by_key(|(i, _)| *i);
    indexed.into_iter().map(|(_, r)| r).collect()
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if cli.hosts.is_empty() {
        eprintln!("Input at least one domain name.");
        return ExitCode::from(1);
    }

    let targets: Vec<(String, String)> = cli
        .hosts
        .iter()
        .filter_map(|h| split_host_port(h).ok())
        .collect();
    for r in unmatched_resolves(&cli.resolve, &targets) {
        eprintln!("warning: --resolve {r} matched no host");
    }

    let opts = Options {
        skip_verify: cli.skip_verify,
        timeout: Duration::from_secs(cli.timeout),
        resolve: cli.resolve,
    };
    let config = client_config(cli.skip_verify);

    let results: Vec<CertInfo> = map_bounded(
        &cli.hosts,
        MAX_PARALLEL,
        |h| inspect(h, &opts, &config, cli.utc, cli.chain),
        |h| error_info(h, "internal error"),
    );

    print!("{}", render(&results, cli.format));
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn keeps_input_order() {
        let items: Vec<usize> = (0..50).collect();
        let out = map_bounded(&items, 4, |&i| i * 2, |_| usize::MAX);
        assert_eq!(out, items.iter().map(|i| i * 2).collect::<Vec<_>>());
    }

    #[test]
    fn never_exceeds_worker_limit() {
        let running = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let items: Vec<usize> = (0..40).collect();
        map_bounded(
            &items,
            3,
            |_| {
                let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(5));
                running.fetch_sub(1, Ordering::SeqCst);
            },
            |_| (),
        );
        assert_eq!(peak.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn panic_becomes_fallback_and_others_continue() {
        let items = vec![1, 2, 3];
        let out = map_bounded(
            &items,
            2,
            |&i| {
                if i == 2 {
                    panic!("boom");
                }
                i
            },
            |&i| i * 100,
        );
        assert_eq!(out, vec![1, 200, 3]);
    }
}
