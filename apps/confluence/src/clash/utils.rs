use crate::error::ConfigError;
use addr::parse_domain_name;
use std::net::IpAddr;

#[derive(Debug, Hash, PartialOrd, Ord, PartialEq, Eq, Clone)]
pub enum ServerTld<'a> {
    Tld(&'a str),
    Ip(IpAddr),
}

pub fn parse_server_tld<'b>(
    config_name: &str,
    name: &'b str,
) -> Result<ServerTld<'b>, ConfigError> {
    if let Ok(addr) = IpAddr::parse_ascii(name.as_bytes()) {
        return Ok(ServerTld::Ip(addr));
    }

    let proxy_server = parse_domain_name(name);

    let proxy_server = proxy_server.map_err(|e| ConfigError::ProxyServerInvalid {
        config_name: config_name.to_string(),
        server: name.to_string(),
        source_kind: e.kind(),
    })?;

    let proxy_server_root = proxy_server
        .root()
        .ok_or_else(|| ConfigError::ProxyServerInvalid {
            config_name: config_name.to_string(),
            server: name.to_string(),
            source_kind: addr::error::Kind::EmptyName,
        })?;

    Ok(ServerTld::Tld(proxy_server_root))
}

#[cfg(test)]
mod tests {
    use super::{ServerTld, parse_server_tld};
    use crate::error::ConfigError;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn parse_server_tld_extracts_root_domain() {
        let tld = parse_server_tld("demo", "sub.example.com").expect("domain should parse");

        assert_eq!(tld, ServerTld::Tld("example.com"));
    }

    #[test]
    fn parse_server_tld_accepts_ipv4_and_ipv6() {
        let ipv4 = parse_server_tld("demo", "1.1.1.1").expect("ipv4 should parse");
        let ipv6 = parse_server_tld("demo", "2001:db8::1").expect("ipv6 should parse");

        assert_eq!(ipv4, ServerTld::Ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert_eq!(
            ipv6,
            ServerTld::Ip(IpAddr::V6(
                "2001:db8::1".parse::<Ipv6Addr>().expect("valid ipv6")
            ))
        );
    }

    #[test]
    fn parse_server_tld_rejects_invalid_server() {
        let err = parse_server_tld("demo", "not a valid host")
            .expect_err("invalid host should be rejected");

        assert!(matches!(
            err,
            ConfigError::ProxyServerInvalid {
                config_name,
                server,
                ..
            } if config_name == "demo" && server == "not a valid host"
        ));
    }
}
