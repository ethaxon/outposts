use std::collections::{BTreeMap, HashMap, HashSet};

use crate::clash::utils::{ServerTld, parse_server_tld};
use crate::clash::{
    ClashConfig, Proxy, ProxyGroup, ProxyGroupKind, ProxyServerNameserverPolicySource, Rule,
};
use crate::models::subscribe_source;
use fancy_regex::Regex;
use serde_yaml::Value;

const MUX_SLOT: &str = "<mux>";

/// Parse a regex slot from a string.
///
/// # Examples
///
/// ```ignore
/// let slot = "<proxy-regex:^CN|中国$>";
/// let regex = parse_regex_slot(slot);
/// assert_eq!(regex.unwrap().as_str(), "^CN|中国$");
/// ```
fn parse_regex_slot(slot: &str) -> Option<fancy_regex::Result<Regex>> {
    if slot.starts_with("<proxy-regex:") && slot.ends_with(">") {
        let regex_str = slot
            .trim_start_matches("<proxy-regex:")
            .trim_end_matches(">");
        Some(Regex::new(regex_str))
    } else {
        None
    }
}

use crate::error::ConfigError;

/// Resolve the [`ProxyServerNameserverPolicySource`] stored on a
/// [`subscribe_source::Model`].  Falls back to the enum default
/// (`Auto`) when the column is `None` or contains an unrecognised value.
fn resolve_policy_source(model: &subscribe_source::Model) -> ProxyServerNameserverPolicySource {
    model
        .proxy_server_nameserver_policy_source
        .as_deref()
        .and_then(|s| serde_json::from_value(serde_json::Value::String(s.to_string())).ok())
        .unwrap_or_default()
}

pub fn mux_configs(
    template_name: &str,
    template: &ClashConfig,
    sources: &[(&subscribe_source::Model, ClashConfig)],
) -> Result<ClashConfig, ConfigError> {
    let others = &template.others;
    let rules = &template.rules;
    let proxy_groups = &template.proxy_groups;
    let template_proxies = &template.proxies;
    let mut source_name_to_proxies_map = BTreeMap::<&str, Vec<Proxy>>::new();
    let mut proxy_servers_root_ltd = HashSet::<ServerTld<'_>>::new();

    let mut mux_proxy_groups = vec![];
    let mut mux_rules = vec![];

    // Merged DNS proxy-server-nameserver-policy from all sources.
    // Accumulate nameserver lists per TLD key so that sources sharing the
    // same root TLD get their nameservers merged and deduplicated.
    let mut merged_dns_ns_policy = HashMap::<String, Vec<String>>::new();

    {
        for p in template_proxies {
            {
                // resolve proxy server root domain
                let proxy_server_root = parse_server_tld(template_name, p.server())?;
                proxy_servers_root_ltd.insert(proxy_server_root);
            }

            {
                // group proxies by config name
                source_name_to_proxies_map
                    .entry(template_name)
                    .and_modify(|v| v.push(p.clone()))
                    .or_insert_with(|| vec![p.clone()]);
            }
        }
    }

    for (source_model, source_config) in sources {
        let source_name = source_model.name.as_str();
        let policy_source = resolve_policy_source(source_model);

        // Collect "per-source proxy server domain → nameserver" mappings.
        let nameservers: &[String] = source_config
            .dns
            .as_ref()
            .map(|dns| dns.nameservers_for_proxy_server_nameserver_policy(&policy_source))
            .unwrap_or(&[]);

        for p in &source_config.proxies {
            {
                // resolve proxy server root domain
                let proxy_server_root = parse_server_tld(source_name, p.server())?;

                // Build proxy-server-nameserver-policy entry when nameservers
                // are available for this source.
                if !nameservers.is_empty()
                    && let ServerTld::Tld(domain) = &proxy_server_root
                {
                    let key = format!("+.{domain}");
                    let entry = merged_dns_ns_policy.entry(key).or_default();
                    for ns in nameservers {
                        if !entry.contains(ns) {
                            entry.push(ns.clone());
                        }
                    }
                }

                proxy_servers_root_ltd.insert(proxy_server_root);
            }

            {
                // group proxies by config name
                source_name_to_proxies_map
                    .entry(source_name)
                    .and_modify(|v| v.push(p.clone()))
                    .or_insert_with(|| vec![p.clone()]);
            }
        }
    }

    let mut mux_proxies = vec![];

    {
        let source_names = sources
            .iter()
            .map(|(sm, _)| sm.name.to_string())
            .collect::<Vec<_>>();

        for g in proxy_groups {
            let mut n = g.clone();
            if let Some(index) = n.proxies.iter().position(|f| f.trim() == MUX_SLOT) {
                n.proxies.splice(index..index + 1, source_names.clone());
            }
            mux_proxy_groups.push(n);
        }

        for (source_name, proxies) in source_name_to_proxies_map {
            let new_proxies = proxies
                .into_iter()
                .map(|mut p| {
                    let proxy_name = p.name();
                    let new_proxy_name = format!("{} | {}", proxy_name, source_name);
                    p.set_name(new_proxy_name);
                    p
                })
                .collect::<Vec<Proxy>>();

            mux_proxy_groups.push(ProxyGroup {
                name: source_name.to_string(),
                kind: ProxyGroupKind::Select,
                proxies: new_proxies.iter().map(|s| s.name().to_string()).collect(),
                others: HashMap::new(),
            });

            mux_proxies.extend(new_proxies);
        }

        let mux_proxie_names = mux_proxies
            .iter()
            .map(|p| p.name().to_string())
            .collect::<Vec<_>>();

        for pg in &mut mux_proxy_groups {
            let mut index_and_regex_proxies: Option<(usize, Vec<String>)> = None;
            for (i, p) in pg.proxies.iter().enumerate() {
                if let Some(regex) = parse_regex_slot(p) {
                    let regex = regex.map_err(|e| ConfigError::Other {
                        message: e.to_string(),
                    })?;
                    let filtered_proxies = mux_proxie_names
                        .iter()
                        .filter(|pn| regex.is_match(pn as &str).is_ok_and(|b| b))
                        .map(|pn| pn.to_string())
                        .collect::<Vec<_>>();

                    index_and_regex_proxies = Some((i, filtered_proxies));
                }
            }

            if let Some((index, regex_proxies)) = index_and_regex_proxies {
                pg.proxies.splice(index..index + 1, regex_proxies);
            }
        }
    }

    {
        mux_rules.extend(proxy_servers_root_ltd.into_iter().map(|s| {
            Rule({
                match s {
                    ServerTld::Tld(domain) => format!("DOMAIN-SUFFIX,{},DIRECT", domain),
                    ServerTld::Ip(ip) => {
                        if ip.is_ipv6() {
                            format!("IP-CIDR6,{}/128,DIRECT", ip)
                        } else {
                            format!("IP-CIDR,{}/32,DIRECT", ip)
                        }
                    }
                }
            })
        }));
        mux_rules.extend_from_slice(rules);
    }

    // Merge DNS: start from the template DNS, inject collected nameserver
    // policy entries.  Template-defined entries take precedence.
    let mux_dns = if merged_dns_ns_policy.is_empty() {
        template.dns.clone()
    } else {
        let mut dns = template.dns.clone().unwrap_or_default();
        for (k, ns_list) in merged_dns_ns_policy {
            dns.proxy_server_nameserver_policy.entry(k).or_insert_with(|| {
                serde_yaml::to_value(&ns_list).unwrap_or(Value::Sequence(vec![]))
            });
        }
        Some(dns)
    };

    Ok(ClashConfig {
        others: others.clone(),
        dns: mux_dns,
        proxies: mux_proxies,
        proxy_groups: mux_proxy_groups,
        rules: mux_rules,
    })
}

#[cfg(test)]
mod tests {
    use crate::clash::ClashConfig;
    use crate::models::subscribe_source;
    use crate::mux::mux_configs;
    use sea_orm::prelude::DateTime;

    fn parse_config(yaml: &str) -> ClashConfig {
        serde_yaml::from_str(yaml).expect("config yaml should be valid")
    }

    /// Helper to build a minimal subscribe_source::Model for testing.
    fn stub_model(name: &str, policy_source: Option<&str>) -> subscribe_source::Model {
        subscribe_source::Model {
            id: 0,
            url: String::new(),
            created_at: DateTime::default(),
            updated_at: DateTime::default(),
            confluence_id: 0,
            name: name.to_string(),
            content: String::new(),
            sub_upload: None,
            sub_download: None,
            sub_total: None,
            sub_expire: None,
            passive_sync: None,
            proxy_server: None,
            proxy_auth: None,
            proxy_server_nameserver_policy_source: policy_source.map(String::from),
        }
    }

    #[test]
    fn test_mux_slot() -> Result<(), Box<dyn std::error::Error>> {
        let rules1 = include_str!("../tests/profile1.yaml");
        let rules2 = include_str!("../tests/profile2.yaml");
        let tmpl = include_str!("../tests/tmpl.yaml");

        let config1: ClashConfig = serde_yaml::from_str(rules1)?;
        let config2: ClashConfig = serde_yaml::from_str(rules2)?;
        let config_tmpl: ClashConfig = serde_yaml::from_str(tmpl)?;

        let m1 = stub_model("proxy1", None);
        let m2 = stub_model("proxy2", None);
        let sources = vec![(&m1, config1), (&m2, config2)];

        let config_res = mux_configs("test", &config_tmpl, &sources)?;

        let expected_proxies: Vec<String> = serde_yaml::from_str(
            r#"
- "SPEED"
- "QUANTITY"
- "DIRECT"
- "proxy1"
- "proxy2"
- "REJECT"
        "#,
        )?;

        assert!(&config_res.proxy_groups.iter().any(|p| p.name == "proxy1"));
        assert_eq!(
            &config_res
                .proxy_groups
                .iter()
                .find(|p| p.name == "PROXY")
                .unwrap()
                .proxies,
            &expected_proxies
        );

        Ok(())
    }

    #[test]
    fn test_proxy_regex_slot() -> Result<(), Box<dyn std::error::Error>> {
        let rules1 = include_str!("../tests/profile1.yaml");
        let rules2 = include_str!("../tests/profile2.yaml");
        let tmpl = include_str!("../tests/tmpl-regex.yaml");

        let config1: ClashConfig = serde_yaml::from_str(rules1)?;
        let config2: ClashConfig = serde_yaml::from_str(rules2)?;
        let config_tmpl: ClashConfig = serde_yaml::from_str(tmpl)?;

        let m1 = stub_model("proxy1", None);
        let m2 = stub_model("proxy2", None);
        let sources = vec![(&m1, config1), (&m2, config2)];

        let config_res = mux_configs("test", &config_tmpl, &sources)?;

        let expected_proxies: Vec<String> = serde_yaml::from_str(
            r#"
- "SPEED"
- "QUANTITY"
- "DIRECT"
- "A | proxy1"
- "C | proxy2"
- "REJECT"
        "#,
        )?;

        assert!(&config_res.proxy_groups.iter().any(|p| p.name == "proxy1"));
        assert_eq!(
            &config_res
                .proxy_groups
                .iter()
                .find(|p| p.name == "PROXY")
                .unwrap()
                .proxies,
            &expected_proxies
        );

        Ok(())
    }

    #[test]
    fn test_mux_generates_direct_rules_for_domain_and_ip_sources()
    -> Result<(), Box<dyn std::error::Error>> {
        let template = parse_config(
            r#"
port: 7890
proxies:
  - { name: "Template", type: "ss", server: "template.example.com", port: 443 }
proxy-groups:
  - { name: "PROXY", type: "select", proxies: ["<mux>"] }
rules:
  - "MATCH,PROXY"
"#,
        );
        let source_one = parse_config(
            r#"
proxies:
  - { name: "IPv4", type: "ss", server: "1.1.1.1", port: 443 }
proxy-groups: []
rules: []
"#,
        );
        let source_two = parse_config(
            r#"
proxies:
  - { name: "IPv6", type: "ss", server: "2001:db8::1", port: 443 }
proxy-groups: []
rules: []
"#,
        );

        let m1 = stub_model("source-one", None);
        let m2 = stub_model("source-two", None);
        let result = mux_configs(
            "template",
            &template,
            &[(&m1, source_one), (&m2, source_two)],
        )?;
        let rule_set = result
            .rules
            .iter()
            .map(|rule| rule.0.as_str())
            .collect::<Vec<_>>();

        assert!(rule_set.contains(&"DOMAIN-SUFFIX,example.com,DIRECT"));
        assert!(rule_set.contains(&"IP-CIDR,1.1.1.1/32,DIRECT"));
        assert!(rule_set.contains(&"IP-CIDR6,2001:db8::1/128,DIRECT"));
        assert!(rule_set.contains(&"MATCH,PROXY"));

        Ok(())
    }

    #[test]
    fn test_mux_rejects_invalid_proxy_regex_slot() {
        let template = parse_config(
            r#"
proxies: []
proxy-groups:
  - { name: "PROXY", type: "select", proxies: ["<proxy-regex:(invalid>"] }
rules: []
"#,
        );
        let source = parse_config(
            r#"
proxies:
  - { name: "A", type: "ss", server: "a.example.com", port: 443 }
proxy-groups: []
rules: []
"#,
        );

        let m = stub_model("source", None);
        assert!(
            mux_configs("template", &template, &[(&m, source)]).is_err(),
            "invalid regex should return an error"
        );
    }

    #[test]
    fn test_mux_dns_nameserver_policy_from_proxy_server_nameserver()
    -> Result<(), Box<dyn std::error::Error>> {
        let template = parse_config(
            r#"
proxies: []
proxy-groups:
  - { name: "PROXY", type: "select", proxies: ["<mux>"] }
rules: []
"#,
        );
        let source = parse_config(
            r#"
proxies:
  - { name: "A", type: "ss", server: "node1.example.com", port: 443 }
proxy-groups: []
rules: []
dns:
  proxy-server-nameserver:
    - https://doh.pub/dns-query
  nameserver:
    - https://dns.alidns.com/dns-query
"#,
        );

        // Default policy source = proxy_server_nameserver
        let m = stub_model("src", Some("proxy_server_nameserver"));
        let result = mux_configs("tmpl", &template, &[(&m, source)])?;
        let dns = result.dns.expect("dns should be present in mux output");
        let policy_entry = dns
            .proxy_server_nameserver_policy
            .get("+.example.com")
            .expect("policy entry for +.example.com should exist");

        // Should use proxy-server-nameserver, not nameserver
        let ns: Vec<String> = serde_yaml::from_value(policy_entry.clone())?;
        assert_eq!(ns, vec!["https://doh.pub/dns-query"]);

        Ok(())
    }

    #[test]
    fn test_mux_dns_nameserver_policy_from_nameserver() -> Result<(), Box<dyn std::error::Error>> {
        let template = parse_config(
            r#"
proxies: []
proxy-groups:
  - { name: "PROXY", type: "select", proxies: ["<mux>"] }
rules: []
"#,
        );
        let source = parse_config(
            r#"
proxies:
  - { name: "A", type: "ss", server: "node1.example.com", port: 443 }
proxy-groups: []
rules: []
dns:
  proxy-server-nameserver:
    - https://doh.pub/dns-query
  nameserver:
    - https://dns.alidns.com/dns-query
"#,
        );

        let m = stub_model("src", Some("nameserver"));
        let result = mux_configs("tmpl", &template, &[(&m, source)])?;
        let dns = result.dns.unwrap();
        let policy_entry = dns
            .proxy_server_nameserver_policy
            .get("+.example.com")
            .unwrap();
        let ns: Vec<String> = serde_yaml::from_value(policy_entry.clone())?;
        assert_eq!(ns, vec!["https://dns.alidns.com/dns-query"]);

        Ok(())
    }

    #[test]
    fn test_mux_dns_nameserver_policy_none() -> Result<(), Box<dyn std::error::Error>> {
        let template = parse_config(
            r#"
proxies: []
proxy-groups:
  - { name: "PROXY", type: "select", proxies: ["<mux>"] }
rules: []
"#,
        );
        let source = parse_config(
            r#"
proxies:
  - { name: "A", type: "ss", server: "node1.example.com", port: 443 }
proxy-groups: []
rules: []
dns:
  proxy-server-nameserver:
    - https://doh.pub/dns-query
"#,
        );

        let m = stub_model("src", Some("none"));
        let result = mux_configs("tmpl", &template, &[(&m, source)])?;
        // No DNS policy should be generated
        assert!(result.dns.is_none());

        Ok(())
    }

    /// Case 1: Two sources share the same root TLD (e.g. huaweiyun.com) but
    /// have different proxy-server-nameservers.  The nameserver lists must be
    /// merged and deduplicated.
    #[test]
    fn test_mux_same_tld_different_dns_merged() -> Result<(), Box<dyn std::error::Error>> {
        let template = parse_config(
            r#"
proxies: []
proxy-groups:
  - { name: "PROXY", type: "select", proxies: ["<mux>"] }
rules: []
"#,
        );
        let source_a = parse_config(
            r#"
proxies:
  - { name: "A", type: "ss", server: "groupa-xxx.huaweiyun.com", port: 443 }
proxy-groups: []
rules: []
dns:
  proxy-server-nameserver:
    - https://dns-a.example.com/dns-query
    - https://shared.example.com/dns-query
"#,
        );
        let source_b = parse_config(
            r#"
proxies:
  - { name: "B", type: "ss", server: "groupb-yyy.huaweiyun.com", port: 443 }
proxy-groups: []
rules: []
dns:
  proxy-server-nameserver:
    - https://dns-b.example.com/dns-query
    - https://shared.example.com/dns-query
"#,
        );

        let m_a = stub_model("src-a", Some("proxy_server_nameserver"));
        let m_b = stub_model("src-b", Some("proxy_server_nameserver"));
        let result = mux_configs("tmpl", &template, &[(&m_a, source_a), (&m_b, source_b)])?;

        let dns = result.dns.expect("dns should be present");
        let ns: Vec<String> = serde_yaml::from_value(
            dns.proxy_server_nameserver_policy
                .get("+.huaweiyun.com")
                .expect("policy for +.huaweiyun.com should exist")
                .clone(),
        )?;

        // Both sources' nameservers merged, shared one deduplicated
        assert_eq!(ns.len(), 3);
        assert!(ns.contains(&"https://dns-a.example.com/dns-query".to_string()));
        assert!(ns.contains(&"https://dns-b.example.com/dns-query".to_string()));
        assert!(ns.contains(&"https://shared.example.com/dns-query".to_string()));

        Ok(())
    }

    /// Case 2: Two sources with different root TLDs but identical nameservers.
    /// Each TLD should get its own independent policy entry.
    #[test]
    fn test_mux_different_tld_same_dns() -> Result<(), Box<dyn std::error::Error>> {
        let template = parse_config(
            r#"
proxies: []
proxy-groups:
  - { name: "PROXY", type: "select", proxies: ["<mux>"] }
rules: []
"#,
        );
        let source_a = parse_config(
            r#"
proxies:
  - { name: "A", type: "ss", server: "node.alpha.com", port: 443 }
proxy-groups: []
rules: []
dns:
  proxy-server-nameserver:
    - https://shared-dns.example.com/dns-query
"#,
        );
        let source_b = parse_config(
            r#"
proxies:
  - { name: "B", type: "ss", server: "node.beta.com", port: 443 }
proxy-groups: []
rules: []
dns:
  proxy-server-nameserver:
    - https://shared-dns.example.com/dns-query
"#,
        );

        let m_a = stub_model("src-a", Some("proxy_server_nameserver"));
        let m_b = stub_model("src-b", Some("proxy_server_nameserver"));
        let result = mux_configs("tmpl", &template, &[(&m_a, source_a), (&m_b, source_b)])?;
        let dns = result.dns.unwrap();

        let ns_alpha: Vec<String> = serde_yaml::from_value(
            dns.proxy_server_nameserver_policy.get("+.alpha.com").unwrap().clone(),
        )?;
        let ns_beta: Vec<String> = serde_yaml::from_value(
            dns.proxy_server_nameserver_policy.get("+.beta.com").unwrap().clone(),
        )?;

        assert_eq!(ns_alpha, vec!["https://shared-dns.example.com/dns-query"]);
        assert_eq!(ns_beta, vec!["https://shared-dns.example.com/dns-query"]);

        Ok(())
    }

    /// Case 3: Source has no DNS config at all — no policy entries should be
    /// generated and the template DNS should pass through unchanged.
    #[test]
    fn test_mux_source_without_dns_no_policy() -> Result<(), Box<dyn std::error::Error>> {
        let template = parse_config(
            r#"
proxies: []
proxy-groups:
  - { name: "PROXY", type: "select", proxies: ["<mux>"] }
rules: []
dns:
  enable: true
  nameserver:
    - https://template-dns.example.com/dns-query
"#,
        );
        let source = parse_config(
            r#"
proxies:
  - { name: "A", type: "ss", server: "node.example.com", port: 443 }
proxy-groups: []
rules: []
"#,
        );

        let m = stub_model("src", Some("proxy_server_nameserver"));
        let result = mux_configs("tmpl", &template, &[(&m, source)])?;

        // Template DNS preserved as-is, no extra policy entries
        let dns = result.dns.unwrap();
        assert!(dns.proxy_server_nameserver_policy.is_empty());
        // Template's own fields are kept
        assert_eq!(
            dns.others.get("enable"),
            Some(&serde_yaml::Value::Bool(true)),
        );

        Ok(())
    }

    /// Case 4: Template already defines a proxy-server-nameserver-policy entry
    /// for a TLD. The template's value should take precedence over the
    /// source-generated one.
    #[test]
    fn test_mux_template_policy_takes_precedence() -> Result<(), Box<dyn std::error::Error>> {
        let template = parse_config(
            r#"
proxies: []
proxy-groups:
  - { name: "PROXY", type: "select", proxies: ["<mux>"] }
rules: []
dns:
  proxy-server-nameserver-policy:
    '+.example.com': '114.114.114.114'
"#,
        );
        let source = parse_config(
            r#"
proxies:
  - { name: "A", type: "ss", server: "node.example.com", port: 443 }
proxy-groups: []
rules: []
dns:
  proxy-server-nameserver:
    - https://source-dns.example.com/dns-query
"#,
        );

        let m = stub_model("src", Some("proxy_server_nameserver"));
        let result = mux_configs("tmpl", &template, &[(&m, source)])?;
        let dns = result.dns.unwrap();

        // Template's existing entry must be preserved, not overwritten
        let policy_value = dns
            .proxy_server_nameserver_policy
            .get("+.example.com")
            .expect("policy for +.example.com should exist");
        assert_eq!(
            policy_value,
            &serde_yaml::Value::String("114.114.114.114".to_string()),
        );

        Ok(())
    }
}
