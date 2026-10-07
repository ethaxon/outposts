use std::collections::{BTreeMap, BTreeSet};

use base64::{Engine, engine::general_purpose::STANDARD};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use ts_rs::TS;

use crate::{error::AppError, subscription_encryption::encrypt_profile};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(deny_unknown_fields)]
pub struct VlanConfig {
    pub vlan_configs: Vec<VlanNetwork>,
    pub supplicant_configs: Vec<VlanSupplicant>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(deny_unknown_fields)]
pub struct VlanNetwork {
    pub id: String,
    pub enabled: bool,
    pub network: String,
    pub routes: Vec<String>,
    pub tunnels: Vec<VlanTunnel>,
    pub accept_supplicants: Vec<VlanGrant>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(deny_unknown_fields)]
pub struct VlanTunnel {
    pub id: String,
    pub name: String,
    pub config: WireGuardClientConfig,
    pub supplicant_ids: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(deny_unknown_fields)]
pub struct WireGuardClientConfig {
    pub addresses: Vec<String>,
    pub mtu: Option<u16>,
    pub persistent_keepalive: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub has_private_key: bool,
    pub peers: Vec<WireGuardPeer>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(deny_unknown_fields)]
pub struct WireGuardPeer {
    pub server: String,
    pub port: u16,
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub pre_shared_key: Option<String>,
    #[serde(default)]
    pub has_pre_shared_key: bool,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(deny_unknown_fields)]
pub struct VlanSupplicant {
    pub id: String,
    pub name: String,
    pub age_recipient: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(deny_unknown_fields)]
pub struct VlanGrant {
    pub supplicant_id: String,
}

fn bad(message: &str) -> AppError {
    AppError::BadRequest {
        message: message.into(),
    }
}

/// Names travel unescaped in `confluence/supplicants=<key>,…&vlans=<net>,…`,
/// whose separators survive percent-decoding, so escaping cannot protect them.
/// Restrict names to lowercase RFC 3986 unreserved characters so uppercasing
/// preserves their uniqueness in the generated Clash config.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'-' | b'_' | b'.' | b'~')
        })
}

fn wireguard_key(key: Option<&str>, message: &str) -> Result<[u8; 32], AppError> {
    STANDARD
        .decode(key.unwrap_or_default())
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| bad(message))
}

fn cidrs(routes: &[String]) -> Result<Vec<IpNet>, AppError> {
    routes
        .iter()
        .map(|value| {
            value
                .parse::<IpNet>()
                .map(|route| route.trunc())
                .map_err(|_| bad("Invalid VLAN route CIDR"))
        })
        .collect()
}

pub fn aggregate_routes(routes: &[String]) -> Result<Vec<String>, AppError> {
    Ok(IpNet::aggregate(&cidrs(routes)?)
        .iter()
        .map(ToString::to_string)
        .collect())
}

fn validate_coverage(allowed_ips: &[String], routes: &[IpNet]) -> Result<(), AppError> {
    if allowed_ips.is_empty() {
        return Err(bad("Tunnel AllowedIPs cannot be empty"));
    }
    for allowed in cidrs(allowed_ips)? {
        if !routes.iter().any(|route| route.contains(&allowed)) {
            return Err(bad("Tunnel AllowedIPs must be covered by the VLAN CIDRs"));
        }
    }
    Ok(())
}

fn validate_endpoint(server: &str, port: u16) -> Result<(), AppError> {
    if server.is_empty() || port == 0 {
        return Err(bad("A tunnel endpoint requires a server and port"));
    }
    Ok(())
}

impl VlanSupplicant {
    pub(crate) fn validate(&self) -> Result<(), AppError> {
        if !valid_name(&self.name)
            || self
                .age_recipient
                .parse::<age::x25519::Recipient>()
                .is_err()
        {
            return Err(bad("Invalid supplicant name or age recipient"));
        }
        Ok(())
    }
}

impl VlanNetwork {
    pub(crate) fn redact_keys(mut self) -> Self {
        for tunnel in &mut self.tunnels {
            let config = &mut tunnel.config;
            config.has_private_key = config.private_key.take().is_some();
            for peer in &mut config.peers {
                peer.has_pre_shared_key = peer.pre_shared_key.take().is_some();
            }
        }
        self
    }

    pub(crate) fn preserve_keys(&mut self, previous: &[VlanTunnel]) -> Result<(), AppError> {
        for tunnel in &mut self.tunnels {
            let old = previous.iter().find(|old| old.id == tunnel.id);
            if !tunnel.id.is_empty() && old.is_none() {
                return Err(bad("Tunnel ID does not belong to this VLAN"));
            }
            let config = &mut tunnel.config;
            if config.private_key.as_deref().is_none_or(str::is_empty) {
                config.private_key = old.and_then(|old| old.config.private_key.clone());
            }
            for peer in &mut config.peers {
                if peer.pre_shared_key.as_deref() == Some("") {
                    peer.pre_shared_key = None;
                } else if peer.pre_shared_key.is_none() {
                    peer.pre_shared_key = old.and_then(|old| {
                        old.config
                            .peers
                            .iter()
                            .find(|saved| saved.public_key == peer.public_key)
                            .and_then(|saved| saved.pre_shared_key.clone())
                    });
                }
            }
        }
        self.validate()
    }

    pub fn validate(&self) -> Result<(), AppError> {
        if !valid_name(&self.network) {
            return Err(bad("Invalid VLAN network"));
        }
        if self.enabled && self.routes.is_empty() {
            return Err(bad("Enabled VLAN requires destination CIDRs"));
        }
        let routes = IpNet::aggregate(&cidrs(&self.routes)?);
        let mut members = BTreeSet::new();
        for grant in &self.accept_supplicants {
            if !members.insert(grant.supplicant_id.as_str()) {
                return Err(bad("Duplicate VLAN supplicant grant"));
            }
        }
        let mut names = BTreeSet::new();
        let mut ids = BTreeSet::new();
        for tunnel in &self.tunnels {
            if !valid_name(&tunnel.name)
                || !names.insert(&tunnel.name)
                || (!tunnel.id.is_empty() && !ids.insert(&tunnel.id))
            {
                return Err(bad("Invalid or duplicate VLAN tunnel"));
            }
            tunnel.config.validate(&routes)?;
            let mut granted = BTreeSet::new();
            for id in &tunnel.supplicant_ids {
                if !members.contains(id.as_str()) || !granted.insert(id) {
                    return Err(bad("Tunnel grants require distinct VLAN supplicants"));
                }
            }
        }
        Ok(())
    }
}

impl WireGuardClientConfig {
    fn validate(&self, routes: &[IpNet]) -> Result<(), AppError> {
        wireguard_key(
            self.private_key.as_deref(),
            "Invalid WireGuard client private key",
        )?;
        let mut address_families = BTreeSet::new();
        for address in &self.addresses {
            let ip = address
                .parse::<IpNet>()
                .map_err(|_| bad("Invalid WireGuard client address"))?;
            if !address_families.insert(ip.addr().is_ipv4()) {
                return Err(bad(
                    "Mihomo supports one WireGuard client address per family",
                ));
            }
        }
        if address_families.is_empty() || self.peers.is_empty() {
            return Err(bad(
                "WireGuard requires a client address and at least one peer",
            ));
        }
        let mut allowed = BTreeSet::new();
        let mut peer_keys = BTreeSet::new();
        for peer in &self.peers {
            validate_endpoint(&peer.server, peer.port)?;
            let public_key =
                wireguard_key(Some(&peer.public_key), "Invalid WireGuard peer public key")?;
            if !peer_keys.insert(public_key) {
                return Err(bad("Duplicate WireGuard peer public key"));
            }
            if let Some(key) = &peer.pre_shared_key {
                wireguard_key(Some(key), "Invalid WireGuard pre-shared key")?;
            }
            validate_coverage(&peer.allowed_ips, routes)?;
            for prefix in cidrs(&peer.allowed_ips)? {
                if !allowed.insert(prefix) {
                    return Err(bad("WireGuard peers require distinct AllowedIPs prefixes"));
                }
            }
        }
        Ok(())
    }
}

const CONFLUENCE_MARKER: &str = "confluence/";
const UNSAFE_PRIVATE_KEY: &str = "_unsafe_supplicant_private";

#[derive(Debug, Default, PartialEq, Eq)]
enum Selection {
    #[default]
    All,
    Named(BTreeSet<String>),
}

#[derive(Default)]
pub(crate) struct SubscriptionRequest {
    supplicants: Selection,
    vlans: Selection,
    unsafe_identity: Option<age::x25519::Identity>,
}

fn confluence_parameters(word: &str) -> Option<&str> {
    let prefix = word.get(..CONFLUENCE_MARKER.len())?;
    prefix
        .eq_ignore_ascii_case(CONFLUENCE_MARKER)
        .then_some(&word[CONFLUENCE_MARKER.len()..])
}

pub(crate) fn redact_subscription_user_agent(ua: &str) -> std::borrow::Cow<'_, str> {
    let is_private = |query: &str| {
        url::form_urlencoded::parse(query.as_bytes()).any(|(key, _)| key == UNSAFE_PRIVATE_KEY)
    };
    if !ua
        .split_ascii_whitespace()
        .filter_map(confluence_parameters)
        .any(is_private)
    {
        return std::borrow::Cow::Borrowed(ua);
    }

    std::borrow::Cow::Owned(
        ua.split_ascii_whitespace()
            .map(|word| {
                let Some(params) = confluence_parameters(word).filter(|params| is_private(params))
                else {
                    return std::borrow::Cow::Borrowed(word);
                };
                let public = params
                    .split('&')
                    .filter(|field| !is_private(field))
                    .collect::<Vec<_>>()
                    .join("&");
                std::borrow::Cow::Owned(format!("{}{public}", &word[..CONFLUENCE_MARKER.len()]))
            })
            .collect::<Vec<_>>()
            .join(" "),
    )
}

pub(crate) fn parse_request(ua: &str, search: &str) -> Result<SubscriptionRequest, AppError> {
    #[derive(Default)]
    struct Parameters {
        supplicants: Option<Selection>,
        vlans: Option<Selection>,
        unsafe_identity: Option<age::x25519::Identity>,
    }

    fn selection(value: &str) -> Result<Selection, AppError> {
        if value == "*" {
            return Ok(Selection::All);
        }
        let mut names = BTreeSet::new();
        for name in value.split(',') {
            if !valid_name(name) {
                return Err(bad("Invalid name in subscription selector"));
            }
            if !names.insert(name.to_owned()) {
                return Err(bad("Duplicate name in subscription selector"));
            }
        }
        Ok(Selection::Named(names))
    }

    fn fields(encoded: &str, from_ua: bool) -> Result<Parameters, AppError> {
        let mut params = Parameters::default();
        for (key, value) in url::form_urlencoded::parse(encoded.as_bytes()) {
            let field = match key.as_ref() {
                "supplicants" => &mut params.supplicants,
                "vlans" => &mut params.vlans,
                "supplicant" => return Err(bad("Use the supplicants query parameter")),
                UNSAFE_PRIVATE_KEY => {
                    if !from_ua {
                        return Err(bad("Supply the unsafe age private key only in User-Agent"));
                    }
                    if params.unsafe_identity.is_some() {
                        return Err(bad("Duplicate Confluence request parameter"));
                    }
                    params.unsafe_identity = Some(
                        value
                            .parse()
                            .map_err(|_| bad("Invalid unsafe age private key"))?,
                    );
                    continue;
                }
                _ if from_ua => return Err(bad("Unknown Confluence request parameter")),
                _ => continue,
            };
            if field.is_some() {
                return Err(bad("Duplicate Confluence request parameter"));
            }
            *field = Some(selection(&value)?);
        }
        Ok(params)
    }

    fn merge(query: Option<Selection>, ua: Option<Selection>) -> Result<Selection, AppError> {
        if let (Some(query), Some(ua)) = (&query, &ua)
            && query != ua
        {
            return Err(bad("UA and URL subscription selectors disagree"));
        }
        Ok(query.or(ua).unwrap_or_default())
    }

    let query = fields(search, false)?;
    let mut markers = ua
        .split_ascii_whitespace()
        .filter_map(confluence_parameters);
    let ua = markers
        .next()
        .map(|marker| fields(marker, true))
        .transpose()?
        .unwrap_or_default();
    if markers.next().is_some() {
        return Err(bad("Duplicate Confluence UA marker"));
    }
    Ok(SubscriptionRequest {
        supplicants: merge(query.supplicants, ua.supplicants)?,
        vlans: merge(query.vlans, ua.vlans)?,
        unsafe_identity: ua.unsafe_identity,
    })
}

/// A subscription after VLAN injection, before the optional age encryption.
///
/// Kept separate so the owner-only preview can show both stages from the exact
/// pipeline the public endpoint serves.
pub(crate) struct PreparedSubscription {
    pub(crate) content: String,
    pub(crate) supplicants: Vec<VlanSupplicant>,
    pub(crate) vlans: Vec<String>,
    unsafe_plaintext: bool,
}

impl PreparedSubscription {
    pub(crate) fn recipients(&self) -> &[VlanSupplicant] {
        if self.unsafe_plaintext {
            &[]
        } else {
            &self.supplicants
        }
    }

    pub(crate) fn encrypt(&self) -> Result<Option<String>, AppError> {
        let recipients = self.recipients();
        if recipients.is_empty() {
            return Ok(None);
        }
        encrypt_profile(
            &self.content,
            recipients
                .iter()
                .map(|recipient| recipient.age_recipient.as_str()),
        )
        .map(Some)
    }

    pub(crate) fn into_served(self) -> Result<String, AppError> {
        Ok(self.encrypt()?.unwrap_or(self.content))
    }
}

pub(crate) fn prepare_subscription(
    content: &str,
    linked_vlans: &[VlanNetwork],
    profile_supplicants: &[VlanSupplicant],
    request: SubscriptionRequest,
    allow_unsafe_age_private_key: bool,
) -> Result<PreparedSubscription, AppError> {
    let mut profile_supplicants = profile_supplicants
        .iter()
        .map(|supplicant| (supplicant.name.as_str(), supplicant))
        .collect::<BTreeMap<_, _>>();
    if let Selection::Named(names) = request.supplicants {
        profile_supplicants.retain(|name, _| names.contains(*name));
        if profile_supplicants.len() != names.len() {
            return Err(bad("Supplicant is not accepted by this Profile"));
        }
    }
    let recipients = profile_supplicants
        .into_values()
        .cloned()
        .collect::<Vec<_>>();
    let unsafe_plaintext = request.unsafe_identity.is_some();
    if let Some(identity) = request.unsafe_identity {
        if !allow_unsafe_age_private_key {
            return Err(bad("Unsafe age compatibility is disabled for this Profile"));
        }
        let [supplicant] = recipients.as_slice() else {
            return Err(bad(
                "Unsafe age compatibility requires exactly one supplicant",
            ));
        };
        let recipient = supplicant
            .age_recipient
            .parse::<age::x25519::Recipient>()
            .map_err(|_| bad("Invalid supplicant age recipient"))?;
        if identity.to_public() != recipient {
            return Err(bad("Unsafe age private key does not match the supplicant"));
        }
    }

    let ids = recipients
        .iter()
        .map(|recipient| recipient.id.as_str())
        .collect::<Vec<_>>();
    let accepted = |network: &VlanNetwork| {
        !ids.is_empty()
            && ids.iter().all(|id| {
                network
                    .accept_supplicants
                    .iter()
                    .any(|grant| grant.supplicant_id == *id)
            })
    };
    let enabled = linked_vlans
        .iter()
        .filter(|network| network.enabled)
        .map(|network| (network.network.as_str(), network))
        .collect::<BTreeMap<_, _>>();
    let networks = match request.vlans {
        Selection::All => enabled
            .into_values()
            .filter(|network| accepted(network))
            .collect::<Vec<_>>(),
        Selection::Named(names) => names
            .iter()
            .map(|name| {
                let network = enabled
                    .get(name.as_str())
                    .copied()
                    .ok_or_else(|| bad("Unknown or disabled VLAN"))?;
                if !accepted(network) {
                    return Err(bad(
                        "Not all selected supplicants are accepted by this VLAN",
                    ));
                }
                Ok(network)
            })
            .collect::<Result<Vec<_>, _>>()?,
    };

    let yaml = if networks.is_empty() {
        content.to_owned()
    } else {
        let mut profile: Value = if content.trim().is_empty() {
            json!({})
        } else {
            serde_yaml::from_str(content).map_err(crate::error::ConfigError::from)?
        };
        if !profile.is_object() {
            return Err(bad("VLAN requires a YAML object"));
        }
        for network in &networks {
            network.validate()?;
            inject_network(&mut profile, network, &ids)?;
        }
        serde_yaml::to_string(&profile).map_err(crate::error::ConfigError::from)?
    };
    Ok(PreparedSubscription {
        content: yaml,
        supplicants: recipients,
        vlans: networks
            .into_iter()
            .map(|network| network.network.clone())
            .collect(),
        unsafe_plaintext,
    })
}

fn render_peer(server: &str, port: u16, public_key: &str, allowed_ips: &[String]) -> Value {
    json!({ "server": server, "port": port, "public-key": public_key, "allowed-ips": allowed_ips })
}

fn inject_network(
    profile: &mut Value,
    config: &VlanNetwork,
    supplicant_ids: &[&str],
) -> Result<(), AppError> {
    let group_name = format!("VLAN-{}", config.network.to_ascii_uppercase());
    // Names may contain hyphens, so use a separator outside their allowed alphabet.
    let proxy_prefix = format!("{group_name}::");
    let mut proxies = Vec::new();
    let mut proxy_names = Vec::new();
    for tunnel in &config.tunnels {
        if !supplicant_ids
            .iter()
            .all(|id| tunnel.supplicant_ids.iter().any(|grant| grant == id))
        {
            continue;
        }
        let name = format!("{proxy_prefix}{}-WG", tunnel.name.to_ascii_uppercase());
        let mut node = json!({ "name": name, "type": "wireguard", "udp": true });
        let config = &tunnel.config;
        node["private-key"] = json!(config.private_key);
        if let Some(mtu) = config.mtu {
            node["mtu"] = json!(mtu);
        }
        if let Some(keepalive) = config.persistent_keepalive {
            node["persistent-keepalive"] = json!(keepalive);
        }
        for address in &config.addresses {
            let ip = address
                .parse::<IpNet>()
                .map_err(|_| bad("Invalid WireGuard client address"))?
                .addr();
            node[if ip.is_ipv4() { "ip" } else { "ipv6" }] = json!(ip.to_string());
        }
        node["peers"] = json!(
            config
                .peers
                .iter()
                .map(|peer| {
                    let mut item =
                        render_peer(&peer.server, peer.port, &peer.public_key, &peer.allowed_ips);
                    if let Some(key) = &peer.pre_shared_key {
                        item["pre-shared-key"] = json!(key);
                    }
                    item
                })
                .collect::<Vec<_>>()
        );
        proxy_names.push(name);
        proxies.push(node);
    }
    let existing_proxies = profile
        .get("proxies")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    proxies.extend(existing_proxies.into_iter().filter(|proxy| {
        !proxy
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|name| name.starts_with(&proxy_prefix))
    }));
    profile["proxies"] = json!(proxies);
    proxy_names.push("REJECT".into());
    proxy_names.push("DIRECT".into());
    let mut groups = profile
        .get("proxy-groups")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    groups.retain(|group| {
        group
            .get("name")
            .and_then(Value::as_str)
            .is_none_or(|name| name != group_name)
    });
    groups.push(json!({ "name": group_name, "type": "select", "proxies": proxy_names }));
    profile["proxy-groups"] = json!(groups);
    let mut rules = config
        .routes
        .iter()
        .map(|route| {
            json!(format!(
                "{},{route},{group_name},no-resolve",
                if route.contains(':') {
                    "IP-CIDR6"
                } else {
                    "IP-CIDR"
                }
            ))
        })
        .collect::<Vec<_>>();
    rules.extend(
        profile
            .get("rules")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|rule| {
                !rule
                    .as_str()
                    .is_some_and(|rule| rule.ends_with(&format!(",{group_name},no-resolve")))
            }),
    );
    profile["rules"] = json!(rules);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn config(recipient: &str) -> VlanConfig {
        let identity = "00000000-0000-7000-8000-000000000001";
        let network = |name: &str| VlanNetwork {
            id: format!("new:{name}"),
            enabled: true,
            network: name.into(),
            routes: vec!["10.20.0.0/24".into(), "10.30.0.0/24".into()],
            tunnels: vec![VlanTunnel {
                id: format!("tunnel:{name}"),
                name: "wire".into(),
                config: WireGuardClientConfig {
                    addresses: vec!["10.42.0.2/24".into()],
                    mtu: None,
                    persistent_keepalive: Some(25),
                    private_key: Some(STANDARD.encode([5; 32])),
                    has_private_key: true,
                    peers: vec![WireGuardPeer {
                        server: "192.0.2.1".into(),
                        port: 51820,
                        public_key: STANDARD.encode([1; 32]),
                        allowed_ips: vec!["10.20.0.0/24".into()],
                        pre_shared_key: None,
                        has_pre_shared_key: false,
                    }],
                },
                supplicant_ids: vec![identity.into()],
            }],
            accept_supplicants: vec![VlanGrant {
                supplicant_id: identity.into(),
            }],
        };
        VlanConfig {
            supplicant_configs: vec![VlanSupplicant {
                id: identity.into(),
                name: "owner".into(),
                age_recipient: recipient.into(),
            }],
            vlan_configs: vec![network("home"), network("office")],
        }
    }

    fn render_test_subscription(
        content: &str,
        stored: &VlanConfig,
        ua: &str,
        query: &str,
    ) -> Result<String, AppError> {
        prepare_subscription(
            content,
            &stored.vlan_configs,
            &stored.supplicant_configs,
            parse_request(ua, query)?,
            false,
        )?
        .into_served()
    }

    fn decrypt_profile(identity: &age::x25519::Identity, encrypted: &str) -> Value {
        let request =
            age::Decryptor::new(age::armor::ArmoredReader::new(encrypted.as_bytes())).unwrap();
        let mut reader = request
            .decrypt(std::iter::once(identity as &dyn age::Identity))
            .unwrap();
        let mut content = String::new();
        reader.read_to_string(&mut content).unwrap();
        serde_yaml::from_str(&content).unwrap()
    }

    #[test]
    fn tunnel_shares_one_configuration_with_multiple_authorized_supplicants() {
        let identity = age::x25519::Identity::generate();
        let mut stored = config(&identity.to_public().to_string());
        let owner_id = stored.supplicant_configs[0].id.clone();
        let second = age::x25519::Identity::generate();
        let second_id = "00000000-0000-7000-8000-000000000002".to_string();
        stored.supplicant_configs.push(VlanSupplicant {
            id: second_id.clone(),
            name: "second".into(),
            age_recipient: second.to_public().to_string(),
        });
        let home = &mut stored.vlan_configs[0];
        home.routes = vec![
            "10.20.0.0/25".into(),
            "10.20.0.128/25".into(),
            "10.30.0.0/24".into(),
        ];
        let peers = ["10.20.0.0/25", "10.30.0.0/25"]
            .into_iter()
            .enumerate()
            .map(|(i, cidr)| WireGuardPeer {
                server: format!("192.0.2.{}", i + 2),
                port: 51820,
                public_key: STANDARD.encode([i as u8 + 1; 32]),
                allowed_ips: vec![cidr.into()],
                pre_shared_key: Some(STANDARD.encode([4; 32])),
                has_pre_shared_key: true,
            })
            .collect();
        home.tunnels[0].config.peers = peers;
        home.tunnels[0].supplicant_ids.clear();
        home.accept_supplicants.push(VlanGrant {
            supplicant_id: second_id.clone(),
        });
        assert_eq!(
            serde_json::from_value::<VlanNetwork>(serde_json::to_value(&*home).unwrap()).unwrap(),
            *home
        );
        let redacted = serde_json::to_string(&home.clone().redact_keys()).unwrap();
        assert!(!redacted.contains(&STANDARD.encode([4; 32])));
        assert!(!redacted.contains(&STANDARD.encode([5; 32])));
        assert_eq!(
            aggregate_routes(&home.routes).unwrap(),
            vec!["10.20.0.0/24", "10.30.0.0/24"]
        );
        home.validate().unwrap();
        let request = "supplicants=owner&vlans=home";
        let unassigned = decrypt_profile(
            &identity,
            &render_test_subscription("{}", &stored, "", request).unwrap(),
        );
        assert_eq!(
            unassigned["proxy-groups"][0]["proxies"],
            json!(["REJECT", "DIRECT"])
        );

        let home = &mut stored.vlan_configs[0];
        let mut assigned = home.clone().redact_keys();
        assigned.tunnels[0].supplicant_ids = vec![owner_id, second_id];
        assigned.preserve_keys(&home.tunnels).unwrap();
        *home = assigned;
        let mut restricted = home.tunnels[0].clone();
        restricted.id = "private".into();
        restricted.name = "private".into();
        restricted.supplicant_ids.pop();
        restricted.config.private_key = Some(STANDARD.encode([6; 32]));
        home.tunnels.push(restricted);
        let explicitly_shared = "supplicants=second,owner&vlans=home";
        for query in [
            "",
            "supplicants=*&vlans=*",
            "supplicants=second,owner",
            explicitly_shared,
        ] {
            let encrypted = render_test_subscription("{}", &stored, "", query).unwrap();
            let profile = decrypt_profile(&identity, &encrypted);
            assert_eq!(decrypt_profile(&second, &encrypted), profile);
            assert_eq!(profile["proxy-groups"].as_array().unwrap().len(), 1);
            assert_eq!(profile["proxies"].as_array().unwrap().len(), 1);
            let wireguard = &profile["proxies"][0];
            assert_eq!(wireguard["name"], "VLAN-HOME::WIRE-WG");
            assert_eq!(wireguard["peers"].as_array().unwrap().len(), 2);
            assert_eq!(wireguard["ip"], "10.42.0.2");
            assert_eq!(wireguard["private-key"], STANDARD.encode([5; 32]));
            assert_eq!(
                wireguard["peers"][0]["pre-shared-key"],
                STANDARD.encode([4; 32])
            );
            assert_eq!(profile["rules"].as_array().unwrap().len(), 3);
        }
        let solo = render_test_subscription("{}", &stored, "", request).unwrap();
        assert_eq!(
            decrypt_profile(&identity, &solo)["proxies"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert!(render_test_subscription("{}", &stored, "", "vlans=office").is_err());
        stored.vlan_configs[0].routes.pop();
        assert!(stored.vlan_configs[0].validate().is_err());
    }

    #[test]
    fn shared_identity_encrypts_multiple_vlans_with_independent_tunnel_permissions() {
        let identity = age::x25519::Identity::generate();
        let stored = config(&identity.to_public().to_string());
        let content = "proxies: []\nrules: [\"MATCH,DIRECT\"]";
        let request = "supplicants=owner&vlans=home,office";
        let encrypted = render_test_subscription(content, &stored, "", request).unwrap();
        let decryptor =
            age::Decryptor::new(age::armor::ArmoredReader::new(encrypted.as_bytes())).unwrap();
        let mut reader = decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .unwrap();
        let mut plaintext = String::new();
        reader.read_to_string(&mut plaintext).unwrap();
        let profile: Value = serde_yaml::from_str(&plaintext).unwrap();
        assert_eq!(profile["proxies"].as_array().unwrap().len(), 2);
        let mut stored = stored;
        stored.vlan_configs[0].tunnels[0].supplicant_ids.clear();
        let empty = decrypt_profile(
            &identity,
            &render_test_subscription(content, &stored, "", "supplicants=owner&vlans=home")
                .unwrap(),
        );
        assert_eq!(
            empty["proxy-groups"][0]["proxies"],
            json!(["REJECT", "DIRECT"])
        );
        assert!(
            render_test_subscription(content, &stored, "", &request.replace("owner", "missing"))
                .is_err()
        );
    }

    #[test]
    fn clash_names_keep_hyphenated_vlans_and_tunnels_distinct() {
        let identity = age::x25519::Identity::generate();
        let mut stored = config(&identity.to_public().to_string());
        stored.vlan_configs[0].network = "lab".into();
        stored.vlan_configs[0].tunnels[0].name = "west-wire".into();
        let west = &mut stored.vlan_configs[1];
        west.network = "lab-west".into();
        west.routes = vec!["10.40.0.0/24".into()];
        west.tunnels[0].config.peers[0].allowed_ips = west.routes.clone();

        let encrypted = render_test_subscription("{}", &stored, "", "vlans=lab,lab-west").unwrap();
        let profile = decrypt_profile(&identity, &encrypted);
        assert_eq!(
            profile["proxy-groups"],
            json!([
                { "name": "VLAN-LAB", "type": "select", "proxies": ["VLAN-LAB::WEST-WIRE-WG", "REJECT", "DIRECT"] },
                { "name": "VLAN-LAB-WEST", "type": "select", "proxies": ["VLAN-LAB-WEST::WIRE-WG", "REJECT", "DIRECT"] }
            ])
        );
        let proxies = profile["proxies"].as_array().unwrap();
        assert_eq!(proxies.len(), 2);
        assert_eq!(proxies[0]["name"], "VLAN-LAB-WEST::WIRE-WG");
        assert_eq!(proxies[1]["name"], "VLAN-LAB::WEST-WIRE-WG");
        assert_eq!(
            profile["rules"],
            json!([
                "IP-CIDR,10.40.0.0/24,VLAN-LAB-WEST,no-resolve",
                "IP-CIDR,10.20.0.0/24,VLAN-LAB,no-resolve",
                "IP-CIDR,10.30.0.0/24,VLAN-LAB,no-resolve"
            ])
        );
    }

    #[test]
    fn prepared_stage_is_what_the_served_ciphertext_decrypts_to() {
        let identity = age::x25519::Identity::generate();
        let stored = config(&identity.to_public().to_string());
        let owner = stored.supplicant_configs[0].clone();
        let content = "proxies: []\nrules: [\"MATCH,DIRECT\"]";

        // VLAN request: injected plaintext, encrypted only to the requesting supplicant.
        let prepared = prepare_subscription(
            content,
            &stored.vlan_configs,
            &stored.supplicant_configs,
            parse_request("", "supplicants=owner&vlans=home").unwrap(),
            false,
        )
        .unwrap();
        assert_eq!(prepared.recipients(), std::slice::from_ref(&owner));
        let encrypted = prepared.encrypt().unwrap().unwrap();
        assert_eq!(
            decrypt_profile(&identity, &encrypted),
            serde_yaml::from_str::<Value>(&prepared.content).unwrap()
        );

        // No request: content untouched, encrypted to every profile recipient.
        let prepared = prepare_subscription(
            content,
            &[],
            std::slice::from_ref(&owner),
            SubscriptionRequest::default(),
            false,
        )
        .unwrap();
        assert_eq!(prepared.content, content);
        assert_eq!(prepared.recipients(), std::slice::from_ref(&owner));

        // Unsafe-key compatibility serves plaintext, so there is nothing to encrypt.
        let ua = format!(
            "confluence/supplicants=owner&_unsafe_supplicant_private={}",
            age::secrecy::ExposeSecret::expose_secret(&identity.to_string())
        );
        let prepared = prepare_subscription(
            content,
            &stored.vlan_configs,
            std::slice::from_ref(&owner),
            parse_request(&ua, "").unwrap(),
            true,
        )
        .unwrap();
        assert!(prepared.recipients().is_empty());
        assert_eq!(prepared.encrypt().unwrap(), None);
        assert_eq!(prepared.supplicants, std::slice::from_ref(&owner));
        assert!(prepared.into_served().unwrap().contains("VLAN-HOME"));
    }

    #[test]
    fn request_sources_are_canonical_and_conflicts_fail_closed() {
        let request = "supplicants=owner,second&vlans=home,office";
        let ua = format!("Client/1 confluence/{request}");
        assert!(parse_request(&ua, "vlans=office,home&supplicants=second,owner").is_ok());
        assert!(parse_request(&ua, &request.replace("home", "elsewhere")).is_err());
        assert!(
            parse_request("Client/1 confluence/supplicants=owner", "vlans=home,office").is_ok()
        );
        for invalid in [
            "supplicant=owner",
            "supplicants=owner&vlans=home:010",
            "supplicants=owner&vlans=home,home",
            "supplicants=owner&vlans=home&vlans=office",
            "supplicants=owner,owner",
            "supplicants=*,owner",
            "supplicants=owner,",
            "vlans=",
        ] {
            assert!(parse_request("", invalid).is_err(), "{invalid}");
        }
        let defaults = parse_request("Client/1", "").unwrap();
        assert_eq!(defaults.vlans, Selection::All);
        assert_eq!(defaults.supplicants, Selection::All);
    }

    #[test]
    fn names_allow_unreserved_lowercase_characters_only() {
        for valid in [
            "home",
            "home-lan",
            "home_lan",
            "home.lan",
            "~edge",
            "a",
            &"a".repeat(64),
        ] {
            assert!(valid_name(valid), "{valid}");
        }
        for invalid in [
            "",
            "Home",
            "home lan",
            "home,lan",
            "home:lan",
            "home&lan",
            "home=lan",
            "home%2c",
            "home/lan",
            "家",
            &"a".repeat(65),
        ] {
            assert!(!valid_name(invalid), "{invalid}");
        }
        let request = parse_request("", "supplicants=owner.v2&vlans=home.lan,~edge").unwrap();
        assert_eq!(
            request.supplicants,
            Selection::Named(BTreeSet::from(["owner.v2".into()]))
        );
        assert_eq!(
            request.vlans,
            Selection::Named(BTreeSet::from(["home.lan".into(), "~edge".into()]))
        );
    }

    #[test]
    fn tunnel_grants_require_distinct_vlan_members_and_redacted_keys_are_preserved() {
        let identity = age::x25519::Identity::generate();
        let mut config = config(&identity.to_public().to_string());
        config.vlan_configs[0].validate().unwrap();
        let mut redacted = config.vlan_configs[0].clone().redact_keys();
        redacted.network = "renamed".into();
        redacted
            .preserve_keys(&config.vlan_configs[0].tunnels)
            .unwrap();
        assert!(redacted.tunnels[0].config.private_key.is_some());
        let tunnel = &mut redacted.tunnels[0];
        tunnel.supplicant_ids.push(tunnel.supplicant_ids[0].clone());
        assert!(redacted.validate().is_err());
        config.vlan_configs[0].accept_supplicants[0].supplicant_id = "unknown".into();
        assert!(config.vlan_configs[0].validate().is_err());
    }
}
