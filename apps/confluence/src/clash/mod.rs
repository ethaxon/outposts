pub mod http;
pub mod utils;

pub use http::parse_subscription_userinfo_in_header;
use monostate::MustBe;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::collections::HashMap;

pub fn hysteria_v2_flatten_deserialize_with<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let mut map: HashMap<String, Value> = HashMap::deserialize(deserializer)?;
    match (map.contains_key("password"), map.contains_key("auth")) {
        (true, false) => {
            map.insert("auth".to_string(), map.get("password").unwrap().clone());
        }
        (false, true) => {
            map.insert("password".to_string(), map.get("auth").unwrap().clone());
        }
        _ => {}
    }
    Ok(map)
}

pub fn hysteria_v1_flatten_deserialize_with<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let mut map: HashMap<String, Value> = HashMap::deserialize(deserializer)?;
    match (map.contains_key("auth-str"), map.contains_key("auth_str")) {
        (true, false) => {
            map.insert("auth_str".to_string(), map.get("auth-str").unwrap().clone());
        }
        (false, true) => {
            map.insert("auth-str".to_string(), map.get("auth_str").unwrap().clone());
        }
        _ => {}
    }
    Ok(map)
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct HysteriaV1Proxy {
    #[serde(rename = "type")]
    pub kind: MustBe!("hysteria"),
    pub name: String,
    pub server: String,
    #[serde(flatten, deserialize_with = "hysteria_v1_flatten_deserialize_with")]
    pub others: HashMap<String, Value>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct HysteriaV2Proxy {
    #[serde(rename = "type")]
    pub kind: MustBe!("hysteria2"),
    pub name: String,
    pub server: String,
    #[serde(flatten, deserialize_with = "hysteria_v2_flatten_deserialize_with")]
    pub others: HashMap<String, Value>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct OtherProxy {
    pub name: String,
    pub server: String,
    #[serde(flatten)]
    pub others: HashMap<String, Value>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum Proxy {
    HysteriaV1(HysteriaV1Proxy),
    HysteriaV2(HysteriaV2Proxy),
    OtherProxy(OtherProxy),
}

impl Proxy {
    pub fn name(&self) -> &str {
        match self {
            Proxy::HysteriaV2(proxy) => &proxy.name,
            Proxy::HysteriaV1(proxy) => &proxy.name,
            Proxy::OtherProxy(proxy) => &proxy.name,
        }
    }

    pub fn set_name(&mut self, name: String) {
        match self {
            Proxy::HysteriaV2(proxy) => proxy.name = name,
            Proxy::HysteriaV1(proxy) => proxy.name = name,
            Proxy::OtherProxy(proxy) => proxy.name = name,
        }
    }

    pub fn server(&self) -> &str {
        match self {
            Proxy::HysteriaV2(proxy) => &proxy.server,
            Proxy::HysteriaV1(proxy) => &proxy.server,
            Proxy::OtherProxy(proxy) => &proxy.server,
        }
    }
}

#[derive(
    serde_enum_str::Deserialize_enum_str,
    serde_enum_str::Serialize_enum_str,
    Debug,
    PartialEq,
    PartialOrd,
    Eq,
    Ord,
    Clone,
)]
#[serde(rename_all = "snake_case")]
pub enum ProxyGroupKind {
    Select,
    #[serde(other)]
    Other(String),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ProxyGroup {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: ProxyGroupKind,
    #[serde(flatten)]
    pub others: HashMap<String, Value>,
    pub proxies: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub struct Rule(pub String);

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ClashConfig {
    #[serde(flatten)]
    pub others: HashMap<String, Value>,
    pub proxies: Vec<Proxy>,
    #[serde(rename = "proxy-groups")]
    pub proxy_groups: Vec<ProxyGroup>,
    pub rules: Vec<Rule>,
}

#[cfg(test)]
mod tests {
    use super::{ClashConfig, Proxy};
    use std::assert_matches::assert_matches;

    #[test]
    fn test_model() -> anyhow::Result<()> {
        let tmpl = include_str!("../tests/tmpl.yaml");
        let config: ClashConfig = serde_yaml::from_str(tmpl)?;

        assert_eq!(config.rules.len(), 1usize);
        assert_eq!(config.proxy_groups.len(), 3usize);
        assert_eq!(config.proxies.len(), 0usize);
        assert_eq!(
            config.others.get("port"),
            Some(&serde_yaml::Value::Number(serde_yaml::Number::from(7890)))
        );

        Ok(())
    }

    #[test]
    fn test_hysteria_v1_auth_str_polyfill() {
        let proxy_str1 = r#"
            { name: "aaa", type: hysteria, server: "bbb", port: 4430, auth_str: "dddd", alpn: h3, protocol: udp, up: 70, down: 150, fast-open: true, disable_mtu_discovery: true, skip-cert-verify: true, ports: 5000-20000 }
        "#;

        let proxy_str2 = r#"
            { name: "aaa", type: hysteria, server: "bbb", port: 4430, auth-str: "dddd", alpn: h3, protocol: udp, up: 70, down: 150, fast-open: true, disable_mtu_discovery: true, skip-cert-verify: true, ports: 5000-20000 }
        "#;

        let proxy1: Proxy = serde_yaml::from_str(proxy_str1).expect("should parse proxy success");
        let proxy2: Proxy = serde_yaml::from_str(proxy_str2).expect("should parse proxy success");

        assert_eq!(proxy1, proxy2);

        assert_matches!(&proxy1, &Proxy::HysteriaV1(_));

        #[allow(irrefutable_let_patterns)]
        if let Proxy::HysteriaV1(proxy) = proxy1 {
            assert_eq!(
                proxy.others.get("auth_str").unwrap(),
                &serde_yaml::Value::String("dddd".to_string())
            );
            assert_eq!(
                proxy.others.get("auth-str").unwrap(),
                &serde_yaml::Value::String("dddd".to_string())
            );
        }
    }

    #[test]
    fn test_hysteria_v2_auth_polyfill() {
        let proxy_str1 = r#"
            { name: "aaa", type: hysteria2, server: "bbb", port: 4430, password: "dddd", alpn: h3, protocol: udp, up: 70, down: 150, fast-open: true, disable_mtu_discovery: true, skip-cert-verify: true, ports: 5000-20000 }
        "#;

        let proxy1: Proxy = serde_yaml::from_str(proxy_str1).expect("should parse proxy success");

        assert_matches!(&proxy1, &Proxy::HysteriaV2(_));

        #[allow(irrefutable_let_patterns)]
        if let Proxy::HysteriaV2(proxy) = &proxy1 {
            assert_eq!(
                proxy.others.get("password").unwrap(),
                &serde_yaml::Value::String("dddd".to_string())
            );
            assert_eq!(
                proxy.others.get("auth").unwrap(),
                &serde_yaml::Value::String("dddd".to_string())
            );
        }
    }
}
