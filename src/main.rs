use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use cert_rs::cert::{CertInfo, cert_info, error_info};
use cert_rs::chain::{TrustAnchors, inspect_chain, parse_chain};
use cert_rs::fetch::{
    Options, client_config, config_with_verifier, fetch_keeping_rejected, fetch_with_config,
    native_roots, server_verifier,
};
use cert_rs::output::{Format, render};
use cert_rs::target::{Resolve, parse_resolve, split_host_port, unmatched_resolves};
use clap::{ArgAction, Parser};
use jiff::Timestamp;
use rustls::ClientConfig;
use rustls::client::danger::ServerCertVerifier;

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

struct Run {
    opts: Options,
    config: Result<Arc<ClientConfig>, String>,
    /// Set only with --chain and without -k: a rejected chain is exactly what
    /// --chain exists to explain, so it is kept instead of failing the row.
    keep_rejected: Option<Result<Arc<dyn ServerCertVerifier>, String>>,
    /// Empty without --chain, where it is not consulted.
    anchors: TrustAnchors,
    utc: bool,
    chain: bool,
    /// One reference time for every row, so a shared intermediate gets the same verdict.
    now: Timestamp,
}

fn inspect(input: &str, run: &Run) -> CertInfo {
    let (host, port) = match split_host_port(input) {
        Ok(hp) => hp,
        Err(e) => return error_info(input, e),
    };
    let fetched = match &run.keep_rejected {
        Some(verifier) => verifier
            .clone()
            .and_then(|v| fetch_keeping_rejected(&host, &port, &run.opts, v)),
        None => run
            .config
            .clone()
            .and_then(|c| fetch_with_config(&host, &port, &run.opts, c)),
    };
    let fetched = match fetched {
        Ok(f) => f,
        Err(e) => return error_info(&host, e),
    };
    let ders: Vec<&[u8]> = fetched.chain.iter().map(|c| c.as_ref()).collect();
    build_row(&host, &port, &fetched.ip, &ders, fetched.rejection, run)
}

fn build_row(
    host: &str,
    port: &str,
    ip: &str,
    ders: &[&[u8]],
    rejection: Option<String>,
    run: &Run,
) -> CertInfo {
    if ders.is_empty() {
        return error_info(host, "no certificate presented");
    }
    let certs = if run.chain {
        parse_chain(ders)
    } else {
        parse_chain(&ders[..1])
    };
    let leaf = certs[0]
        .as_ref()
        .map_err(String::clone)
        .and_then(|leaf| cert_info(leaf, host, ip, port, run.utc));
    let error = [rejection, leaf.as_ref().err().cloned()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("; ");
    let info = match leaf {
        Ok(info) => info,
        // The rest of the chain is still worth showing when only the leaf is unreadable.
        Err(_) if run.chain => CertInfo {
            ip: ip.to_string(),
            port: port.to_string(),
            ..error_info(host, "")
        },
        Err(e) => return error_info(host, e),
    };
    let info = CertInfo { error, ..info };
    if !run.chain {
        return info;
    }
    let report = inspect_chain(ders, &certs, &run.anchors, run.utc, run.now);
    CertInfo {
        chain_check: Some(report.label()),
        chain: Some(report.entries),
        ..info
    }
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

    // Read once and shared: loading the OS store takes a noticeable moment.
    let roots = if cli.skip_verify && !cli.chain {
        Vec::new()
    } else {
        native_roots()
    };
    let verifier = (!cli.skip_verify).then(|| server_verifier(&roots));
    let run = Run {
        opts: Options {
            skip_verify: cli.skip_verify,
            timeout: Duration::from_secs(cli.timeout),
            resolve: cli.resolve,
        },
        config: match &verifier {
            None => client_config(true),
            Some(v) => v.clone().and_then(config_with_verifier),
        },
        keep_rejected: if cli.chain { verifier } else { None },
        anchors: if cli.chain {
            TrustAnchors::from_ders(roots.iter().map(|r| r.as_ref()))
        } else {
            TrustAnchors::default()
        },
        utc: cli.utc,
        chain: cli.chain,
        now: Timestamp::now(),
    };

    let results: Vec<CertInfo> = map_bounded(
        &cli.hosts,
        MAX_PARALLEL,
        |h| inspect(h, &run),
        |h| error_info(h, "internal error"),
    );

    print!("{}", render(&results, cli.format));
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn chain_run() -> Run {
        Run {
            opts: Options {
                skip_verify: false,
                timeout: Duration::from_secs(1),
                resolve: Vec::new(),
            },
            config: Err("unused".into()),
            keep_rejected: None,
            anchors: TrustAnchors::default(),
            utc: true,
            chain: true,
            now: "2026-06-01T00:00:00Z".parse().unwrap(),
        }
    }

    fn self_signed(cn: &str) -> Vec<u8> {
        let mut params = rcgen::CertificateParams::new(vec![cn.to_string()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2026, 1, 1);
        params.not_after = rcgen::date_time_ymd(2027, 1, 1);
        let key = rcgen::KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().der().to_vec()
    }

    #[test]
    fn unreadable_leaf_keeps_the_rest_of_the_chain() {
        let good = self_signed("Example CA");
        let ders: [&[u8]; 2] = [&[0, 1, 2, 3], &good];
        let row = build_row(
            "a.example.com",
            "443",
            "192.0.2.1",
            &ders,
            Some("rejected".into()),
            &chain_run(),
        );
        assert!(row.error.starts_with("rejected; "), "{}", row.error);
        assert_eq!(row.ip, "192.0.2.1");
        assert_eq!(row.common_name, "");
        let chain = row.chain.unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[1].subject, "CN=rcgen self signed cert");
        let check = row.chain_check.unwrap();
        assert!(
            check.starts_with("NG: [0] failed to parse certificate: "),
            "{check}"
        );
    }

    #[test]
    fn unreadable_leaf_is_a_plain_error_without_chain_flag() {
        let run = Run {
            chain: false,
            ..chain_run()
        };
        let ders: [&[u8]; 1] = [&[0, 1, 2, 3]];
        let row = build_row("a.example.com", "443", "192.0.2.1", &ders, None, &run);
        assert_eq!(row.ip, "");
        assert!(row.chain.is_none());
        assert!(!row.error.is_empty());
    }

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
