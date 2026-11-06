use std::net::IpAddr;

const DEFAULT_PORT: &str = "443";

/// `--resolve HOST:PORT:ADDR` で指定された名前解決の上書き。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolve {
    pub host: String,
    pub port: String,
    pub addr: IpAddr,
}

/// ホスト入力（`host`、`host:port`、`[v6]:port`、URL）を `(host, port)` に分解する。
pub fn split_host_port(input: &str) -> Result<(String, String), String> {
    // url クレートは authority を取り出すだけのために入れない
    let authority = match input.split_once("://") {
        Some((_, rest)) => rest.split(['/', '?', '#']).next().unwrap_or(""),
        None => input,
    };

    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| format!("missing ']' in address: {authority}"))?;
        let port = after
            .strip_prefix(':')
            .ok_or_else(|| format!("missing port in address: {authority}"))?;
        if port.contains(':') {
            return Err(format!("too many colons in address: {authority}"));
        }
        if host.contains(['[', ']']) || port.contains(['[', ']']) {
            return Err(format!("unexpected bracket in address: {authority}"));
        }
        (host, port)
    } else {
        if authority.matches(':').count() > 1 {
            return Err(format!("too many colons in address: {authority}"));
        }
        if authority.contains(['[', ']']) {
            return Err(format!("unexpected '[' in address: {authority}"));
        }
        authority.split_once(':').unwrap_or((authority, ""))
    };

    let port = if port.is_empty() { DEFAULT_PORT } else { port };
    Ok((host.to_string(), port.to_string()))
}

/// `HOST:PORT:ADDR` を解析する。ADDR が IPv6 のときは `[..]` で囲む。
pub fn parse_resolve(s: &str) -> Result<Resolve, String> {
    let bad = || format!("invalid resolve spec (expected HOST:PORT:ADDR): {s}");
    let (rest, addr) = if s.ends_with(']') {
        let i = s.rfind(":[").ok_or_else(bad)?;
        (&s[..i], &s[i + 1..])
    } else {
        s.rsplit_once(':').ok_or_else(bad)?
    };
    let (host, port) = rest.rsplit_once(':').ok_or_else(bad)?;
    let addr = addr
        .strip_prefix('[')
        .and_then(|a| a.strip_suffix(']'))
        .unwrap_or(addr);
    let addr: IpAddr = addr
        .parse()
        .map_err(|_| format!("invalid IP address in resolve spec: {s}"))?;
    Ok(Resolve {
        host: host.to_string(),
        port: port.to_string(),
        addr,
    })
}

pub fn lookup_resolve<'a>(list: &'a [Resolve], host: &str, port: &str) -> Option<IpAddr> {
    list.iter()
        .find(|r| r.host.eq_ignore_ascii_case(host) && r.port == port)
        .map(|r| r.addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_host_defaults_to_443() {
        assert_eq!(
            split_host_port("example.com").unwrap(),
            ("example.com".into(), "443".into())
        );
    }
    #[test]
    fn host_with_port() {
        assert_eq!(
            split_host_port("example.com:8443").unwrap(),
            ("example.com".into(), "8443".into())
        );
    }
    #[test]
    fn url_takes_host_and_port() {
        assert_eq!(
            split_host_port("https://example.com:8443/a/b?c=1").unwrap(),
            ("example.com".into(), "8443".into())
        );
    }
    #[test]
    fn url_without_port() {
        assert_eq!(
            split_host_port("https://example.com/path").unwrap(),
            ("example.com".into(), "443".into())
        );
    }
    #[test]
    fn ipv6_bracketed() {
        assert_eq!(
            split_host_port("[::1]:8443").unwrap(),
            ("::1".into(), "8443".into())
        );
    }
    #[test]
    fn bare_ipv6_is_error() {
        assert!(split_host_port("::1").is_err());
    }
    #[test]
    fn empty_port_defaults() {
        assert_eq!(split_host_port("example.com:").unwrap().1, "443");
    }

    #[test]
    fn resolve_v4() {
        let r = parse_resolve("db.example.com:443:192.0.2.10").unwrap();
        assert_eq!(
            (
                r.host.as_str(),
                r.port.as_str(),
                r.addr.to_string().as_str()
            ),
            ("db.example.com", "443", "192.0.2.10")
        );
    }
    #[test]
    fn resolve_v6() {
        assert_eq!(
            parse_resolve("h:443:[2001:db8::1]")
                .unwrap()
                .addr
                .to_string(),
            "2001:db8::1"
        );
    }
    #[test]
    fn resolve_bad() {
        assert!(parse_resolve("h:443").is_err());
        assert!(parse_resolve("h:443:not-an-ip").is_err());
    }
    #[test]
    fn resolve_lookup_case_insensitive() {
        let list = vec![parse_resolve("Example.COM:443:10.0.0.1").unwrap()];
        assert_eq!(
            lookup_resolve(&list, "example.com", "443")
                .unwrap()
                .to_string(),
            "10.0.0.1"
        );
        assert!(lookup_resolve(&list, "example.com", "8443").is_none());
    }

    #[test]
    fn bracketed_without_port_is_error() {
        assert!(split_host_port("[::1]").is_err());
    }

    #[test]
    fn bracketed_with_extra_colon_in_port_is_error() {
        assert!(split_host_port("[::1]:8:9").is_err());
    }

    #[test]
    fn stray_bracket_in_unbracketed_host_is_error() {
        assert!(split_host_port("a[b:1").is_err());
    }
}
