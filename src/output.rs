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
        out.push_str(&format!("CommonName:   {}\n", c.common_name));
        out.push_str(&format!("SANs:         {}\n", sans_list(c)));
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

fn render_md(certs: &[CertInfo]) -> String {
    let with_chain = certs
        .iter()
        .any(|c| c.chain.is_some() || c.chain_check.is_some());
    let mut out = String::from(
        "DomainName | IP | Port | Issuer | Validation | Organization | NotBefore | NotAfter | CN | SANs | Error",
    );
    let mut rule = String::from("--- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---");
    if with_chain {
        out.push_str(" | Chain | ChainCheck");
        rule.push_str(" | --- | ---");
    }
    out.push('\n');
    out.push_str(&rule);
    out.push('\n');
    for c in certs {
        let sans: String = c
            .sans
            .iter()
            .flatten()
            .map(|s| format!("{}<br/>", s.replace('*', "\\*")))
            .collect();
        out.push_str(&format!(
            "{} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {}\n",
            c.domain_name,
            c.ip,
            c.port,
            c.issuer,
            c.validation_type,
            c.organization,
            c.not_before,
            c.not_after,
            c.common_name,
            sans,
            c.error
        ));
        if with_chain {
            let chain: String = c
                .chain
                .iter()
                .flatten()
                .enumerate()
                .map(|(i, e)| format!("[{i}] {} (NotAfter: {})<br/>", e.subject, e.not_after))
                .collect();
            out.pop();
            out.push_str(&format!(
                " | {} | {}\n",
                chain,
                c.chain_check.as_deref().unwrap_or_default()
            ));
        }
    }
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::error_info;
    use crate::chain::ChainEntry;

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
            error: "".into(),
            chain: None,
            chain_check: None,
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
        error_info("bad.example", "boom")
    }
    fn entry(subject: &str, issuer: &str, serial: &str) -> ChainEntry {
        ChainEntry {
            subject: subject.into(),
            issuer: issuer.into(),
            not_before: "NB".into(),
            not_after: "NA".into(),
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
            ..dv()
        }
    }

    #[test]
    fn table() {
        assert_eq!(
            render(&[ok(), dv(), err()], Format::Table),
            "DomainName:   a.example.com\nIP:           192.0.2.1\nPort:         443\nIssuer:       Test CA\nValidation:   OV\nOrganization: Acme\nNotBefore:    NB\nNotAfter:     NA\nCommonName:   a.example.com\nSANs:         [a.example.com *.example.com]\nError:        \n\n\
DomainName:   a.example.com\nIP:           192.0.2.1\nPort:         443\nIssuer:       Test CA\nValidation:   DV\nNotBefore:    NB\nNotAfter:     NA\nCommonName:   a.example.com\nSANs:         [a.example.com *.example.com]\nError:        \n\n\
DomainName:   bad.example\nIP:           \nPort:         \nIssuer:       \nValidation:   \nNotBefore:    \nNotAfter:     \nCommonName:   \nSANs:         []\nError:        boom\n\n\n"
        );
    }

    #[test]
    fn table_with_chain() {
        assert_eq!(
            render(&[chained(), err()], Format::Table),
            "DomainName:   a.example.com\nIP:           192.0.2.1\nPort:         443\nIssuer:       Test CA\nValidation:   DV\nNotBefore:    NB\nNotAfter:     NA\nCommonName:   a.example.com\nSANs:         [a.example.com *.example.com]\nError:        \n\
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
DomainName:   bad.example\nIP:           \nPort:         \nIssuer:       \nValidation:   \nNotBefore:    \nNotAfter:     \nCommonName:   \nSANs:         []\nError:        boom\n\n\n"
        );
    }

    #[test]
    fn markdown_with_chain() {
        assert_eq!(
            render(&[chained(), err()], Format::Md),
            "DomainName | IP | Port | Issuer | Validation | Organization | NotBefore | NotAfter | CN | SANs | Error | Chain | ChainCheck\n--- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---\n\
a.example.com | 192.0.2.1 | 443 | Test CA | DV |  | NB | NA | a.example.com | a.example.com<br/>\\*.example.com<br/> |  | [0] CN=a.example.com (NotAfter: NA)<br/>[1] CN=Test CA (NotAfter: NA)<br/> | NG: [1] expired\n\
bad.example |  |  |  |  |  |  |  |  |  | boom |  | \n\n"
        );
    }

    #[test]
    fn json_with_chain() {
        assert_eq!(
            render(&[chained()], Format::Json),
            r#"[{"domainName":"a.example.com","ip":"192.0.2.1","port":"443","issuer":"Test CA","validationType":"DV","commonName":"a.example.com","sans":["a.example.com","*.example.com"],"notBefore":"NB","notAfter":"NA","error":"","chain":[{"subject":"CN=a.example.com","issuer":"CN=Test CA","notBefore":"NB","notAfter":"NA","serial":"0A1B","sha256":"AA:BB"},{"subject":"CN=Test CA","issuer":"CN=Test Root","notBefore":"NB","notAfter":"NA","serial":"01","sha256":"AA:BB"}],"chainCheck":"NG: [1] expired"}]"#
        );
    }

    #[test]
    fn markdown_escapes_star_only_here() {
        assert_eq!(
            render(&[ok(), err()], Format::Md),
            "DomainName | IP | Port | Issuer | Validation | Organization | NotBefore | NotAfter | CN | SANs | Error\n--- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---\n\
a.example.com | 192.0.2.1 | 443 | Test CA | OV | Acme | NB | NA | a.example.com | a.example.com<br/>\\*.example.com<br/> | \n\
bad.example |  |  |  |  |  |  |  |  |  | boom\n\n"
        );
    }

    #[test]
    fn json() {
        assert_eq!(
            render(&[dv(), err()], Format::Json),
            r#"[{"domainName":"a.example.com","ip":"192.0.2.1","port":"443","issuer":"Test CA","validationType":"DV","commonName":"a.example.com","sans":["a.example.com","*.example.com"],"notBefore":"NB","notAfter":"NA","error":""},{"domainName":"bad.example","ip":"","port":"","issuer":"","validationType":"","commonName":"","sans":null,"notBefore":"","notAfter":"","error":"boom"}]"#
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
