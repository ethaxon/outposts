use std::collections::{BTreeMap, HashMap, HashSet};

use crate::clash::utils::{ServerTld, parse_server_tld};
use crate::clash::{ClashConfig, Proxy, ProxyGroup, ProxyGroupKind, Rule};
use fancy_regex::Regex;

const MUX_SLOT: &str = "<mux>";

/// Parse a regex slot from a string.
///
/// # Examples
///
/// ```
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

pub fn mux_configs(
    template_name: &str,
    template: &ClashConfig,
    sources: &[(&str, ClashConfig)],
) -> anyhow::Result<ClashConfig> {
    let others = &template.others;
    let rules = &template.rules;
    let proxy_groups = &template.proxy_groups;
    let template_proxies = &template.proxies;
    let mut source_name_to_proxies_map = BTreeMap::<&str, Vec<Proxy>>::new();
    let mut proxy_servers_root_ltd = HashSet::<ServerTld<'_>>::new();

    let mut mux_proxy_groups = vec![];
    let mut mux_rules = vec![];

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

    for (source_name, source_config) in sources {
        for p in &source_config.proxies {
            {
                // resolve proxy server root domain
                let proxy_server_root = parse_server_tld(source_name, p.server())?;
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
            .map(|(source_name, _)| source_name.to_string())
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
                    let regex = regex?;
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

    Ok(ClashConfig {
        others: others.clone(),
        proxies: mux_proxies,
        proxy_groups: mux_proxy_groups,
        rules: mux_rules,
    })
}

#[cfg(test)]
mod tests {
    use crate::clash::ClashConfig;
    use crate::mux::mux_configs;

    #[test]
    fn test_mux_slot() -> anyhow::Result<()> {
        let rules1 = include_str!("../tests/profile1.yaml");

        let rules2 = include_str!("../tests/profile2.yaml");

        let tmpl = include_str!("../tests/tmpl.yaml");

        let config1: ClashConfig = serde_yaml::from_str(rules1)?;
        let config2: ClashConfig = serde_yaml::from_str(rules2)?;
        let config_tmpl: ClashConfig = serde_yaml::from_str(tmpl)?;
        let sources = vec![("proxy1", config1), ("proxy2", config2)];

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
    fn test_proxy_regex_slot() -> anyhow::Result<()> {
        let rules1 = include_str!("../tests/profile1.yaml");

        let rules2 = include_str!("../tests/profile2.yaml");

        let tmpl = include_str!("../tests/tmpl-regex.yaml");

        let config1: ClashConfig = serde_yaml::from_str(rules1)?;
        let config2: ClashConfig = serde_yaml::from_str(rules2)?;
        let config_tmpl: ClashConfig = serde_yaml::from_str(tmpl)?;
        let sources = vec![("proxy1", config1), ("proxy2", config2)];

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
}
