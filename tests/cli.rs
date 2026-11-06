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
