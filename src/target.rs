use std::fmt;
use std::net::IpAddr;

const DEFAULT_PORT: &str = "443";

/// A name resolution override given as `--resolve HOST:PORT:ADDR`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolve {
    pub host: String,
    pub port: String,
    pub addr: IpAddr,
}

impl fmt::Display for Resolve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.addr {
            IpAddr::V4(a) => write!(f, "{}:{}:{a}", self.host, self.port),
            IpAddr::V6(a) => write!(f, "{}:{}:[{a}]", self.host, self.port),
        }
    }
}

/// Splits a host argument (`host`, `host:port`, `[v6]:port` or a URL) into `(host, port)`.
pub fn split_host_port(input: &str) -> Result<(String, String), String> {
    // Not the url crate: pulling in a URL parser just to find the authority is overkill.
    // The scheme is ignored on purpose: http:// pasted from a browser still means
    // "check this host's certificate", so it gets 443 like https://.
    let authority = match input.split_once("://") {
        Some((_, rest)) => {
            let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
            authority
                .rsplit_once('@')
                .map_or(authority, |(_, host)| host)
        }
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

/// Parses `HOST:PORT:ADDR`; an IPv6 ADDR must be bracketed.
pub fn parse_resolve(s: &str) -> Result<Resolve, String> {
    let bad = || format!("invalid resolve spec (expected HOST:PORT:ADDR): {s}");
    let (rest, addr) = if s.ends_with(']') {
        let i = s.rfind(":[").ok_or_else(bad)?;
        (&s[..i], &s[i + 1..])
    } else {
        s.rsplit_once(':').ok_or_else(bad)?
    };
    let (host, port) = rest.rsplit_once(':').ok_or_else(bad)?;
    // u16's parser alone would accept "+443" and "0".
    if !port.bytes().all(|b| b.is_ascii_digit()) || !matches!(port.parse::<u16>(), Ok(1..)) {
        return Err(format!("invalid port in resolve spec: {s}"));
    }
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

impl Resolve {
    fn matches(&self, host: &str, port: &str) -> bool {
        self.host.eq_ignore_ascii_case(host) && self.port == port
    }
}

pub fn lookup_resolve(list: &[Resolve], host: &str, port: &str) -> Option<IpAddr> {
    list.iter().find(|r| r.matches(host, port)).map(|r| r.addr)
}

/// Returns the overrides that no `(host, port)` target uses.
pub fn unmatched_resolves<'a>(
    list: &'a [Resolve],
    targets: &[(String, String)],
) -> Vec<&'a Resolve> {
    list.iter()
        .filter(|r| !targets.iter().any(|(h, p)| r.matches(h, p)))
        .collect()
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
    fn http_url_still_defaults_to_443() {
        assert_eq!(
            split_host_port("http://example.com/").unwrap(),
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

    #[test]
    fn url_userinfo_is_dropped() {
        assert_eq!(
            split_host_port("https://u@example.com/x").unwrap(),
            ("example.com".into(), "443".into())
        );
        assert_eq!(
            split_host_port("https://u:p@w@example.com:8443").unwrap(),
            ("example.com".into(), "8443".into())
        );
    }

    #[test]
    fn resolve_port_must_be_1_to_65535() {
        for bad in [
            "h:0:192.0.2.1",
            "h:65536:192.0.2.1",
            "h:x:192.0.2.1",
            "h::192.0.2.1",
        ] {
            assert!(parse_resolve(bad).is_err(), "{bad}");
        }
        assert!(parse_resolve("h:65535:192.0.2.1").is_ok());
        assert!(parse_resolve("h:1:192.0.2.1").is_ok());
    }

    #[test]
    fn resolve_displays_as_spec() {
        for spec in [
            "example.com:443:192.0.2.10",
            "example.com:443:[2001:db8::1]",
        ] {
            assert_eq!(parse_resolve(spec).unwrap().to_string(), spec);
        }
    }

    #[test]
    fn unmatched_resolves_are_reported() {
        let list = vec![
            parse_resolve("Example.com:443:192.0.2.10").unwrap(),
            parse_resolve("example.com:8443:192.0.2.11").unwrap(),
            parse_resolve("example.org:443:192.0.2.12").unwrap(),
        ];
        let targets = vec![("example.com".to_string(), "443".to_string())];
        let unmatched: Vec<String> = unmatched_resolves(&list, &targets)
            .iter()
            .map(|r| r.to_string())
            .collect();
        assert_eq!(
            unmatched,
            ["example.com:8443:192.0.2.11", "example.org:443:192.0.2.12"]
        );
    }
}
