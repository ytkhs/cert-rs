use clap::ValueEnum;

use crate::cert::CertInfo;

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Format {
    Table,
    Md,
    Json,
}

pub fn render(certs: &[CertInfo], format: Format) -> String {
    match format {
        Format::Table => render_table(certs),
        Format::Md => render_md(certs),
        Format::Json => render_json(certs),
    }
}

// Escape HTML-sensitive characters and line separators; they can only appear inside string literals.
fn render_json(certs: &[CertInfo]) -> String {
    serde_json::to_string(certs)
        .expect("CertInfo is always serializable")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

/// Empty for rows without a certificate, like the other fields of an error row.
fn days_left(c: &CertInfo) -> String {
    c.days_left.map(|d| d.to_string()).unwrap_or_default()
}

/// `EC P-256`, `RSA 2048`, `Ed25519`: a named curve already says the size.
fn key_summary(c: &CertInfo) -> String {
    let Some(kind) = c.key_type.as_deref() else {
        return String::new();
    };
    match (c.curve.as_deref(), c.key_bits) {
        (Some(curve), _) => format!("{kind} {curve}"),
        (None, Some(bits)) if !kind.starts_with("Ed") => format!("{kind} {bits}"),
        _ => kind.to_string(),
    }
}

fn sans_list(c: &CertInfo) -> String {
    format!("[{}]", c.sans.as_deref().unwrap_or_default().join(" "))
}

fn render_table(certs: &[CertInfo]) -> String {
    let mut out = String::new();
    for c in certs {
        out.push_str(&format!("DomainName:   {}\n", c.domain_name));
        out.push_str(&format!("IP:           {}\n", c.ip));
        out.push_str(&format!("Port:         {}\n", c.port));
        out.push_str(&format!("Issuer:       {}\n", c.issuer));
        out.push_str(&format!("Validation:   {}\n", c.validation_type));
        if !c.organization.is_empty() {
            out.push_str(&format!("Organization: {}\n", c.organization));
        }
        out.push_str(&format!("NotBefore:    {}\n", c.not_before));
        out.push_str(&format!("NotAfter:     {}\n", c.not_after));
        out.push_str(&format!("DaysLeft:     {}\n", days_left(c)));
        out.push_str(&format!("CommonName:   {}\n", c.common_name));
        out.push_str(&format!("SANs:         {}\n", sans_list(c)));
        out.push_str(&format!(
            "TLS:          {}\n",
            c.tls_version.as_deref().unwrap_or_default()
        ));
        out.push_str(&format!("Key:          {}\n", key_summary(c)));
        out.push_str(&format!("Error:        {}\n", c.error));
        if let Some(chain) = &c.chain {
            out.push_str("Chain:\n");
            for (i, e) in chain.iter().enumerate() {
                out.push_str(&format!("  [{i}] {}\n", e.subject));
                out.push_str(&format!("      Issuer:    {}\n", e.issuer));
                out.push_str(&format!("      NotBefore: {}\n", e.not_before));
                out.push_str(&format!("      NotAfter:  {}\n", e.not_after));
                out.push_str(&format!("      Serial:    {}\n", e.serial));
                out.push_str(&format!("      SHA256:    {}\n", e.sha256));
            }
        }
        if let Some(check) = &c.chain_check {
            out.push_str(&format!("ChainCheck:   {check}\n"));
        }
        out.push('\n');
    }
    out.push('\n');
    out
}

/// Names and error text come from the server and may hold any text, so every
/// character with meaning in a markdown table cell or in HTML is neutralized.
fn escape_md_cell(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' | '|' | '*' | '_' | '`' | '[' | ']' | '~' => {
                out.push('\\');
                out.push(ch);
            }
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '\n' | '\r' => out.push(' '),
            _ => out.push(ch),
        }
    }
    out
}

fn render_md(certs: &[CertInfo]) -> String {
    let with_chain = certs
        .iter()
        .any(|c| c.chain.is_some() || c.chain_check.is_some());
    let mut header = vec![
        "DomainName",
        "IP",
        "Port",
        "Issuer",
        "Validation",
        "Organization",
        "NotBefore",
        "NotAfter",
        "DaysLeft",
        "CN",
        "SANs",
        "Error",
    ];
    if with_chain {
        header.extend(["Chain", "ChainCheck"]);
    }
    let mut out = header.join(" | ");
    out.push('\n');
    out.push_str(&vec!["---"; header.len()].join(" | "));
    out.push('\n');
    for c in certs {
        let sans: String = c
            .sans
            .iter()
            .flatten()
            .map(|s| format!("{}<br/>", escape_md_cell(s)))
            .collect();
        let mut cells: Vec<String> = [
            &c.domain_name,
            &c.ip,
            &c.port,
            &c.issuer,
            &c.validation_type,
            &c.organization,
            &c.not_before,
            &c.not_after,
            &days_left(c),
            &c.common_name,
        ]
        .into_iter()
        .map(|s| escape_md_cell(s))
        .collect();
        cells.push(sans);
        cells.push(escape_md_cell(&c.error));
        if with_chain {
            let chain: String = c
                .chain
                .iter()
                .flatten()
                .enumerate()
                .map(|(i, e)| {
                    format!(
                        "[{i}] {} (NotAfter: {})<br/>",
                        escape_md_cell(&e.subject),
                        e.not_after
                    )
                })
                .collect();
            cells.push(chain);
            // Fixed wording and parser errors only; nothing the server chose.
            cells.push(c.chain_check.clone().unwrap_or_default());
        }
        out.push_str(&cells.join(" | "));
        out.push('\n');
    }
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::error_info;
    use crate::chain::{ChainEntry, ChainProblem, ChainProblemKind};
    use crate::error::ErrorKind;

    fn ok() -> CertInfo {
        CertInfo {
            domain_name: "a.example.com".into(),
            ip: "192.0.2.1".into(),
            port: "443".into(),
            issuer: "Test CA".into(),
            validation_type: "OV".into(),
            organization: "Acme".into(),
            common_name: "a.example.com".into(),
            sans: Some(vec!["a.example.com".into(), "*.example.com".into()]),
            not_before: "NB".into(),
            not_after: "NA".into(),
            not_before_utc: Some("2026-01-01T00:00:00Z".into()),
            not_after_utc: Some("2027-01-01T00:00:00Z".into()),
            days_left: Some(42),
            error: "".into(),
            error_kind: None,
            tls_version: None,
            cipher_suite: None,
            key_type: None,
            key_bits: None,
            curve: None,
            signature_algorithm: None,
            chain: None,
            chain_check: None,
            chain_problems: None,
        }
    }
    fn dv() -> CertInfo {
        CertInfo {
            validation_type: "DV".into(),
            organization: "".into(),
            ..ok()
        }
    }
    fn err() -> CertInfo {
        error_info("bad.example", ErrorKind::Dns, "boom")
    }
    fn entry(subject: &str, issuer: &str, serial: &str) -> ChainEntry {
        ChainEntry {
            subject: subject.into(),
            issuer: issuer.into(),
            not_before: "NB".into(),
            not_after: "NA".into(),
            not_before_utc: Some("2026-01-01T00:00:00Z".into()),
            not_after_utc: Some("2027-01-01T00:00:00Z".into()),
            serial: serial.into(),
            sha256: "AA:BB".into(),
        }
    }
    fn chained() -> CertInfo {
        CertInfo {
            chain: Some(vec![
                entry("CN=a.example.com", "CN=Test CA", "0A1B"),
                entry("CN=Test CA", "CN=Test Root", "01"),
            ]),
            chain_check: Some("NG: [1] expired".into()),
            chain_problems: Some(vec![ChainProblem {
                index: 1,
                kind: ChainProblemKind::Expired,
                message: "[1] expired".into(),
            }]),
            ..dv()
        }
    }

    #[test]
    fn table() {
        assert_eq!(
            render(&[ok(), dv(), err()], Format::Table),
            "DomainName:   a.example.com\nIP:           192.0.2.1\nPort:         443\nIssuer:       Test CA\nValidation:   OV\nOrganization: Acme\nNotBefore:    NB\nNotAfter:     NA\nDaysLeft:     42\nCommonName:   a.example.com\nSANs:         [a.example.com *.example.com]\nTLS:          \nKey:          \nError:        \n\n\
DomainName:   a.example.com\nIP:           192.0.2.1\nPort:         443\nIssuer:       Test CA\nValidation:   DV\nNotBefore:    NB\nNotAfter:     NA\nDaysLeft:     42\nCommonName:   a.example.com\nSANs:         [a.example.com *.example.com]\nTLS:          \nKey:          \nError:        \n\n\
DomainName:   bad.example\nIP:           \nPort:         \nIssuer:       \nValidation:   \nNotBefore:    \nNotAfter:     \nDaysLeft:     \nCommonName:   \nSANs:         []\nTLS:          \nKey:          \nError:        boom\n\n\n"
        );
    }

    fn with_key(key_type: &str, key_bits: Option<usize>, curve: Option<&str>) -> CertInfo {
        CertInfo {
            tls_version: Some("TLSv1.3".into()),
            key_type: Some(key_type.into()),
            key_bits,
            curve: curve.map(Into::into),
            ..ok()
        }
    }

    fn tls_and_key_lines(c: CertInfo) -> (String, String) {
        let out = render(&[c], Format::Table);
        let line = |prefix: &str| {
            out.lines()
                .find_map(|l| l.strip_prefix(prefix))
                .unwrap()
                .to_string()
        };
        (line("TLS:          "), line("Key:          "))
    }

    #[test]
    fn table_shows_tls_version_and_key() {
        assert_eq!(
            tls_and_key_lines(with_key("EC", Some(256), Some("P-256"))),
            ("TLSv1.3".to_string(), "EC P-256".to_string())
        );
        assert_eq!(
            tls_and_key_lines(with_key("RSA", Some(2048), None)).1,
            "RSA 2048"
        );
        assert_eq!(
            tls_and_key_lines(with_key("Ed25519", Some(256), None)).1,
            "Ed25519"
        );
        assert_eq!(tls_and_key_lines(with_key("DSA", None, None)).1, "DSA");
    }

    #[test]
    fn table_with_chain() {
        assert_eq!(
            render(&[chained(), err()], Format::Table),
            "DomainName:   a.example.com\nIP:           192.0.2.1\nPort:         443\nIssuer:       Test CA\nValidation:   DV\nNotBefore:    NB\nNotAfter:     NA\nDaysLeft:     42\nCommonName:   a.example.com\nSANs:         [a.example.com *.example.com]\nTLS:          \nKey:          \nError:        \n\
Chain:\n\
\x20 [0] CN=a.example.com\n\
\x20     Issuer:    CN=Test CA\n\
\x20     NotBefore: NB\n\
\x20     NotAfter:  NA\n\
\x20     Serial:    0A1B\n\
\x20     SHA256:    AA:BB\n\
\x20 [1] CN=Test CA\n\
\x20     Issuer:    CN=Test Root\n\
\x20     NotBefore: NB\n\
\x20     NotAfter:  NA\n\
\x20     Serial:    01\n\
\x20     SHA256:    AA:BB\n\
ChainCheck:   NG: [1] expired\n\n\
DomainName:   bad.example\nIP:           \nPort:         \nIssuer:       \nValidation:   \nNotBefore:    \nNotAfter:     \nDaysLeft:     \nCommonName:   \nSANs:         []\nTLS:          \nKey:          \nError:        boom\n\n\n"
        );
    }

    #[test]
    fn markdown_with_chain() {
        assert_eq!(
            render(&[chained(), err()], Format::Md),
            "DomainName | IP | Port | Issuer | Validation | Organization | NotBefore | NotAfter | DaysLeft | CN | SANs | Error | Chain | ChainCheck\n--- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---\n\
a.example.com | 192.0.2.1 | 443 | Test CA | DV |  | NB | NA | 42 | a.example.com | a.example.com<br/>\\*.example.com<br/> |  | [0] CN=a.example.com (NotAfter: NA)<br/>[1] CN=Test CA (NotAfter: NA)<br/> | NG: [1] expired\n\
bad.example |  |  |  |  |  |  |  |  |  |  | boom |  | \n\n"
        );
    }

    #[test]
    fn json_with_chain() {
        assert_eq!(
            render(&[chained()], Format::Json),
            r#"[{"domainName":"a.example.com","ip":"192.0.2.1","port":"443","issuer":"Test CA","validationType":"DV","commonName":"a.example.com","sans":["a.example.com","*.example.com"],"notBefore":"NB","notAfter":"NA","notBeforeUtc":"2026-01-01T00:00:00Z","notAfterUtc":"2027-01-01T00:00:00Z","daysLeft":42,"error":"","errorKind":null,"tlsVersion":null,"cipherSuite":null,"keyType":null,"keyBits":null,"curve":null,"signatureAlgorithm":null,"chain":[{"subject":"CN=a.example.com","issuer":"CN=Test CA","notBefore":"NB","notAfter":"NA","notBeforeUtc":"2026-01-01T00:00:00Z","notAfterUtc":"2027-01-01T00:00:00Z","serial":"0A1B","sha256":"AA:BB"},{"subject":"CN=Test CA","issuer":"CN=Test Root","notBefore":"NB","notAfter":"NA","notBeforeUtc":"2026-01-01T00:00:00Z","notAfterUtc":"2027-01-01T00:00:00Z","serial":"01","sha256":"AA:BB"}],"chainCheck":"NG: [1] expired","chainProblems":[{"index":1,"kind":"expired","message":"[1] expired"}]}]"#
        );
    }

    fn chain_parse_failed() -> CertInfo {
        CertInfo {
            chain: Some(vec![]),
            chain_check: Some("NG: bad der".into()),
            chain_problems: Some(vec![ChainProblem {
                index: 0,
                kind: ChainProblemKind::ParseError,
                message: "bad der".into(),
            }]),
            ..dv()
        }
    }

    #[test]
    fn table_chain_parse_failure() {
        assert_eq!(
            render(&[chain_parse_failed()], Format::Table),
            "DomainName:   a.example.com\nIP:           192.0.2.1\nPort:         443\nIssuer:       Test CA\nValidation:   DV\nNotBefore:    NB\nNotAfter:     NA\nDaysLeft:     42\nCommonName:   a.example.com\nSANs:         [a.example.com *.example.com]\nTLS:          \nKey:          \nError:        \nChain:\nChainCheck:   NG: bad der\n\n\n"
        );
    }

    #[test]
    fn markdown_chain_parse_failure() {
        assert_eq!(
            render(&[chain_parse_failed()], Format::Md),
            "DomainName | IP | Port | Issuer | Validation | Organization | NotBefore | NotAfter | DaysLeft | CN | SANs | Error | Chain | ChainCheck\n--- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---\n\
a.example.com | 192.0.2.1 | 443 | Test CA | DV |  | NB | NA | 42 | a.example.com | a.example.com<br/>\\*.example.com<br/> |  |  | NG: bad der\n\n"
        );
    }

    #[test]
    fn json_chain_parse_failure() {
        assert_eq!(
            render(&[chain_parse_failed()], Format::Json),
            r#"[{"domainName":"a.example.com","ip":"192.0.2.1","port":"443","issuer":"Test CA","validationType":"DV","commonName":"a.example.com","sans":["a.example.com","*.example.com"],"notBefore":"NB","notAfter":"NA","notBeforeUtc":"2026-01-01T00:00:00Z","notAfterUtc":"2027-01-01T00:00:00Z","daysLeft":42,"error":"","errorKind":null,"tlsVersion":null,"cipherSuite":null,"keyType":null,"keyBits":null,"curve":null,"signatureAlgorithm":null,"chain":[],"chainCheck":"NG: bad der","chainProblems":[{"index":0,"kind":"parse_error","message":"bad der"}]}]"#
        );
    }

    #[test]
    fn markdown_escapes_star_in_chain_subject() {
        let c = CertInfo {
            chain: Some(vec![entry("CN=*.example.com", "CN=Test CA", "01")]),
            chain_check: Some("OK".into()),
            ..dv()
        };
        assert_eq!(
            render(&[c], Format::Md),
            "DomainName | IP | Port | Issuer | Validation | Organization | NotBefore | NotAfter | DaysLeft | CN | SANs | Error | Chain | ChainCheck\n--- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---\n\
a.example.com | 192.0.2.1 | 443 | Test CA | DV |  | NB | NA | 42 | a.example.com | a.example.com<br/>\\*.example.com<br/> |  | [0] CN=\\*.example.com (NotAfter: NA)<br/> | OK\n\n"
        );
    }

    #[test]
    fn markdown_neutralizes_table_and_html_syntax_in_chain_subject() {
        let c = CertInfo {
            chain: Some(vec![entry(
                "O=Foo|Bar, OU=<img src=x onerror=alert(1)>, CN=a_b [x](y) `c` \\ ~d & e\nf",
                "CN=Test CA",
                "01",
            )]),
            chain_check: Some("OK".into()),
            ..dv()
        };
        let md = render(&[c], Format::Md);
        let row = md.lines().nth(2).unwrap();
        assert_eq!(row.matches(" | ").count(), 13, "{row}");
        assert!(
            row.contains(
                "[0] O=Foo\\|Bar, OU=&lt;img src=x onerror=alert(1)&gt;, CN=a\\_b \\[x\\](y) \\`c\\` \\\\ \\~d &amp; e f (NotAfter: NA)<br/>"
            ),
            "{row}"
        );
    }

    #[test]
    fn markdown_neutralizes_table_and_html_syntax_in_every_column() {
        let c = CertInfo {
            issuer: "A|B".into(),
            organization: "<b>Acme</b>".into(),
            common_name: "x_y".into(),
            sans: Some(vec!["a|b.example".into()]),
            error: "boom | <script>".into(),
            ..ok()
        };
        let md = render(&[c], Format::Md);
        let row = md.lines().nth(2).unwrap();
        assert_eq!(
            row,
            "a.example.com | 192.0.2.1 | 443 | A\\|B | OV | &lt;b&gt;Acme&lt;/b&gt; | NB | NA | 42 | x\\_y | a\\|b.example<br/> | boom \\| &lt;script&gt;"
        );
    }

    #[test]
    fn markdown_escapes_star_in_sans() {
        assert_eq!(
            render(&[ok(), err()], Format::Md),
            "DomainName | IP | Port | Issuer | Validation | Organization | NotBefore | NotAfter | DaysLeft | CN | SANs | Error\n--- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---\n\
a.example.com | 192.0.2.1 | 443 | Test CA | OV | Acme | NB | NA | 42 | a.example.com | a.example.com<br/>\\*.example.com<br/> | \n\
bad.example |  |  |  |  |  |  |  |  |  |  | boom\n\n"
        );
    }

    #[test]
    fn json() {
        assert_eq!(
            render(&[dv(), err()], Format::Json),
            r#"[{"domainName":"a.example.com","ip":"192.0.2.1","port":"443","issuer":"Test CA","validationType":"DV","commonName":"a.example.com","sans":["a.example.com","*.example.com"],"notBefore":"NB","notAfter":"NA","notBeforeUtc":"2026-01-01T00:00:00Z","notAfterUtc":"2027-01-01T00:00:00Z","daysLeft":42,"error":"","errorKind":null,"tlsVersion":null,"cipherSuite":null,"keyType":null,"keyBits":null,"curve":null,"signatureAlgorithm":null},{"domainName":"bad.example","ip":"","port":"","issuer":"","validationType":"","commonName":"","sans":null,"notBefore":"","notAfter":"","notBeforeUtc":null,"notAfterUtc":null,"daysLeft":null,"error":"boom","errorKind":"dns","tlsVersion":null,"cipherSuite":null,"keyType":null,"keyBits":null,"curve":null,"signatureAlgorithm":null}]"#
        );
    }

    #[test]
    fn json_escapes_html_and_line_separators() {
        let c = CertInfo {
            organization: "A&B <C>\u{2028}\u{2029}".into(),
            ..ok()
        };
        assert!(
            render(&[c], Format::Json)
                .contains(r#""organization":"A\u0026B \u003cC\u003e\u2028\u2029""#)
        );
    }
}
