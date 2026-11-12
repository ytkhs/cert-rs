mod common;

use assert_cmd::Command;
use common::{closed_port, make_cert, spawn_tls_server};

fn cert() -> Command {
    Command::cargo_bin("cert").unwrap()
}

#[test]
fn no_hosts() {
    cert()
        .assert()
        .code(1)
        .stderr("Input at least one domain name.\n");
}

#[test]
fn single_dash_long_option_is_rejected() {
    cert()
        .args(["-format", "json", "example.com"])
        .assert()
        .failure();
}

#[test]
fn bad_format_value() {
    cert().args(["-f", "yaml", "x"]).assert().failure();
}

#[test]
fn mixed_results_keep_order_and_exit_0() {
    let (der, key) = make_cert(None, &[], false, &["localhost"]);
    let port = spawn_tls_server(der, key);
    let out = cert()
        .args([
            "-k",
            "-f",
            "json",
            "-s",
            "1",
            &format!("127.0.0.1:{}", closed_port()),
            &format!("localhost:{port}"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let rows: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows[0]["error"].as_str().is_some_and(|e| !e.is_empty()));
    assert!(
        rows[0]["domainName"]
            .as_str()
            .is_some_and(|d| d == "127.0.0.1")
    );
    assert!(rows[1].get("error").is_none_or(|e| e.as_str() == Some("")));
}

fn json_rows(args: &[&str]) -> Vec<serde_json::Value> {
    let out = cert()
        .args(args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let rows: serde_json::Value = serde_json::from_slice(&out).unwrap();
    rows.as_array().unwrap().clone()
}

#[test]
fn timeout_zero_and_huge_succeed() {
    let (der, key) = make_cert(None, &[], false, &["localhost"]);
    let port = spawn_tls_server(der, key);
    for timeout in ["0", "18446744073709551615"] {
        let rows = json_rows(&[
            "-k",
            "-f",
            "json",
            "-s",
            timeout,
            &format!("localhost:{port}"),
        ]);
        assert_eq!(rows[0]["commonName"], "localhost", "-s {timeout}");
    }
}

#[test]
fn untrusted_without_k_shows_error_and_exits_0() {
    let (der, key) = make_cert(None, &[], false, &["localhost"]);
    let port = spawn_tls_server(der, key);
    let rows = json_rows(&["-f", "json", &format!("localhost:{port}")]);
    assert_eq!(rows.len(), 1);
    let err = rows[0]["error"].as_str().unwrap();
    assert!(err.contains("certificate"), "{err}");
}

#[test]
fn unmatched_resolve_warns_once_on_stderr() {
    let (der, key) = make_cert(None, &[], false, &["localhost"]);
    let port = spawn_tls_server(der, key);
    let target = format!("localhost:{port}");
    let used = format!("localhost:{port}:127.0.0.1");
    let base = cert()
        .args(["-k", "-f", "json", "-r", &used, &target])
        .assert()
        .success()
        .stderr("")
        .get_output()
        .stdout
        .clone();
    let out = cert()
        .args([
            "-k",
            "-f",
            "json",
            "-r",
            &used,
            "-r",
            "example.com:443:192.0.2.10",
            &target,
        ])
        .assert()
        .success()
        .stderr("warning: --resolve example.com:443:192.0.2.10 matched no host\n")
        .get_output()
        .stdout
        .clone();
    assert_eq!(base, out);
}

#[test]
fn resolve_with_bad_port_is_rejected() {
    cert()
        .args(["-r", "example.com:0:192.0.2.10", "example.com"])
        .assert()
        .failure();
}

#[test]
fn help_describes_options() {
    let out = cert()
        .arg("--help")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let help = String::from_utf8(out).unwrap();
    for phrase in [
        "Output format",
        "Skip certificate chain and hostname verification",
        "Show times in UTC",
        "0 means no limit",
        "Connect to ADDR instead of resolving HOST",
        "Show the certificates exactly as the server sent them",
        "Print version",
        "Hosts to inspect",
    ] {
        assert!(help.contains(phrase), "missing {phrase:?} in:\n{help}");
    }
}

#[test]
fn version() {
    let out = cert()
        .arg("-v")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert!(String::from_utf8(out).unwrap().starts_with("cert "));
}

#[test]
#[ignore]
fn live_sites() {
    let out = cert()
        .args([
            "-f",
            "json",
            "www.google.com",
            "www.microsoft.com",
            "www.mufg.jp",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let rows: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let types: Vec<&str> = rows
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["validationType"].as_str().unwrap())
        .collect();
    assert_eq!(types, ["DV", "OV", "EV"]);
}

#[test]
fn chain_flag_adds_chain_to_json() {
    let (der, key) = make_cert(None, &[], false, &["localhost"]);
    let port = spawn_tls_server(der, key);
    let rows = json_rows(&["--chain", "-k", "-f", "json", &format!("localhost:{port}")]);
    assert_eq!(rows[0]["chainCheck"], "OK");
    assert_eq!(rows[0]["chain"].as_array().unwrap().len(), 1);
}

#[test]
fn chain_is_shown_for_rejected_certificates_without_k() {
    let (der, key) = make_cert(None, &[], false, &["localhost"]);
    let port = spawn_tls_server(der, key);
    let rows = json_rows(&["--chain", "-f", "json", &format!("localhost:{port}")]);
    let error = rows[0]["error"].as_str().unwrap();
    assert!(error.contains("certificate"), "{error}");
    assert_eq!(rows[0]["commonName"], "localhost");
    assert_eq!(rows[0]["chainCheck"], "OK");
    assert_eq!(rows[0]["chain"].as_array().unwrap().len(), 1);
}

#[test]
fn rejected_certificates_stay_plain_errors_without_chain_flag() {
    let (der, key) = make_cert(None, &[], false, &["localhost"]);
    let port = spawn_tls_server(der, key);
    let rows = json_rows(&["-f", "json", &format!("localhost:{port}")]);
    assert_eq!(rows[0]["commonName"], "");
    assert!(rows[0].get("chain").is_none());
}

#[test]
fn chain_is_absent_without_flag() {
    let (der, key) = make_cert(None, &[], false, &["localhost"]);
    let port = spawn_tls_server(der, key);
    let rows = json_rows(&["-k", "-f", "json", &format!("localhost:{port}")]);
    assert!(rows[0].get("chain").is_none());
    assert!(rows[0].get("chainCheck").is_none());
}

#[test]
fn chain_is_not_added_to_error_rows() {
    let rows = json_rows(&[
        "--chain",
        "-f",
        "json",
        "-s",
        "1",
        &format!("127.0.0.1:{}", closed_port()),
    ]);
    assert!(rows[0].get("chain").is_none());
    assert!(rows[0].get("chainCheck").is_none());
}

#[test]
fn json_rows_carry_error_kind_and_days_left() {
    let (der, key) = make_cert(None, &[], false, &["localhost"]);
    let port = spawn_tls_server(der, key);
    let closed = format!("127.0.0.1:{}", closed_port());
    let rows = json_rows(&["-k", "-f", "json", &format!("localhost:{port}"), &closed]);
    assert_eq!(rows[0]["errorKind"], serde_json::Value::Null);
    assert!(rows[0]["daysLeft"].is_i64(), "{}", rows[0]);
    assert!(rows[0]["notAfterUtc"].as_str().unwrap().ends_with('Z'));
    assert_eq!(rows[1]["errorKind"], "connect");
    assert_eq!(rows[1]["daysLeft"], serde_json::Value::Null);
}

#[test]
fn chain_problems_are_listed_in_json() {
    let (der, key) = make_cert(None, &[], false, &["localhost"]);
    let port = spawn_tls_server(der, key);
    let rows = json_rows(&["--chain", "-k", "-f", "json", &format!("localhost:{port}")]);
    assert_eq!(rows[0]["chainProblems"], serde_json::json!([]));
}

#[test]
fn fail_exits_1_when_a_host_fails_and_keeps_the_output() {
    let closed = format!("127.0.0.1:{}", closed_port());
    let out = cert()
        .args(["--fail", "-f", "json", &closed])
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let rows: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(rows[0]["errorKind"], "connect");
}

#[test]
fn fail_exits_0_when_every_host_is_fine() {
    let (der, key) = make_cert(None, &[], false, &["localhost"]);
    let port = spawn_tls_server(der, key);
    cert()
        .args(["--fail", "-k", &format!("localhost:{port}")])
        .assert()
        .success();
}

#[test]
fn failures_still_exit_0_without_fail() {
    let closed = format!("127.0.0.1:{}", closed_port());
    cert().args([closed.as_str()]).assert().success();
}

#[test]
fn error_rows_keep_the_port_that_was_tried() {
    let port = closed_port().to_string();
    let rows = json_rows(&["-f", "json", &format!("127.0.0.1:{port}")]);
    assert_eq!(rows[0]["port"], port.as_str());
}

#[test]
fn handshake_failures_keep_the_address_that_was_reached() {
    let (der, key) = make_cert(None, &[], false, &["localhost"]);
    let port = spawn_tls_server(der, key);
    let rows = json_rows(&["-f", "json", &format!("127.0.0.1:{port}")]);
    assert!(rows[0]["errorKind"].is_string(), "{}", rows[0]);
    assert_eq!(rows[0]["ip"], "127.0.0.1");
}

#[test]
fn timeouts_point_to_the_limit_option() {
    let port = common::spawn_silent_listener();
    let rows = json_rows(&["-f", "json", "-s", "1", &format!("127.0.0.1:{port}")]);
    assert_eq!(rows[0]["errorKind"], "timeout");
    let error = rows[0]["error"].as_str().unwrap();
    assert!(
        error.contains("the limit is 1s, raise it with -s"),
        "{error}"
    );
}

#[test]
fn json_reports_the_negotiated_tls_and_the_key() {
    let (der, key) = make_cert(None, &[], false, &["localhost"]);
    let port = spawn_tls_server(der, key);
    let rows = json_rows(&["-k", "-f", "json", &format!("localhost:{port}")]);
    assert_eq!(rows[0]["tlsVersion"], "TLSv1.3");
    assert!(
        rows[0]["cipherSuite"]
            .as_str()
            .unwrap()
            .starts_with("TLS13_")
    );
    assert_eq!(rows[0]["keyType"], "EC");
    assert_eq!(rows[0]["curve"], "P-256");
    assert_eq!(rows[0]["signatureAlgorithm"], "ecdsa-with-SHA256");
}

#[test]
fn table_shows_days_left() {
    let (der, key) = make_cert(None, &[], false, &["localhost"]);
    let port = spawn_tls_server(der, key);
    let out = cert()
        .args(["-k", &format!("localhost:{port}")])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let out = String::from_utf8(out).unwrap();
    let days = out
        .lines()
        .find_map(|l| l.strip_prefix("DaysLeft:     "))
        .unwrap_or_else(|| panic!("{out}"));
    assert!(days.parse::<i64>().is_ok(), "{out}");
}
