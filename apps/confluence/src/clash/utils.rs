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
    let proxy_server = parse_domain_name(name);

    if let Err(err) = &proxy_server
        && err.kind() == addr::error::Kind::NumericTld
    {
        let addr = IpAddr::parse_ascii(name.as_bytes()).map_err(|e| {
            ConfigError::ProxyServerIpInvalid {
                config_name: config_name.to_string(),
                server: name.to_string(),
                source: e,
            }
        })?;

        return Ok(ServerTld::Ip(addr));
    }

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
