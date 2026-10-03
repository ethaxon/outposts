use std::collections::{BTreeMap, BTreeSet};

use base64::{Engine, engine::general_purpose::STANDARD};
use hkdf::Hkdf;
use ipnet::{IpNet, Ipv4Net};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use ts_rs::TS;
use x25519_dalek::{PublicKey, StaticSecret};

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
    pub gateways: Vec<VlanGateway>,
    pub accept_supplicants: Vec<VlanGrant>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(deny_unknown_fields)]
pub struct VlanGateway {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub subnet: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub has_private_key: bool,
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
    pub slots: String,
}

fn bad(message: &str) -> AppError {
    AppError::BadRequest {
        message: message.into(),
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
}

fn master_key(gateway: &VlanGateway) -> Result<[u8; 32], AppError> {
    STANDARD
        .decode(gateway.private_key.as_deref().unwrap_or_default())
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| {
            bad("Each VLAN gateway requires a base64-encoded 32-byte Portal private key")
        })
}

impl VlanConfig {
    pub fn validate(&self) -> Result<(), AppError> {
        let mut identities = BTreeSet::new();
        let mut slugs = BTreeSet::new();
        for supplicant in &self.supplicant_configs {
            supplicant.validate()?;
            if !identities.insert(&supplicant.id) || !slugs.insert(&supplicant.name) {
                return Err(bad("Duplicate supplicant identity"));
            }
        }
        let mut names = BTreeSet::new();
        for network in &self.vlan_configs {
            if !names.insert(&network.network) {
                return Err(bad("Duplicate VLAN network"));
            }
            network.validate()?;
            if network
                .accept_supplicants
                .iter()
                .any(|grant| !identities.contains(&grant.supplicant_id))
            {
                return Err(bad("Unknown supplicant reference"));
            }
        }
        Ok(())
    }
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
        for gateway in &mut self.gateways {
            gateway.has_private_key = gateway.private_key.take().is_some();
        }
        self
    }

    pub(crate) fn preserve_keys(&mut self, previous: &[VlanGateway]) -> Result<(), AppError> {
        for gateway in &mut self.gateways {
            if gateway.private_key.as_deref().is_none_or(str::is_empty) {
                gateway.private_key = previous
                    .iter()
                    .find(|old| old.name == gateway.name)
                    .and_then(|old| old.private_key.clone());
            }
        }
        self.validate()
    }

    pub fn validate(&self) -> Result<(), AppError> {
        if !valid_name(&self.network) {
            return Err(bad("Invalid VLAN network"));
        }
        if self.enabled
            && (self.gateways.is_empty()
                || self.accept_supplicants.is_empty()
                || self.routes.is_empty())
        {
            return Err(bad(
                "Enabled VLAN requires gateways, supplicants and routes",
            ));
        }
        let mut gateway_names = BTreeSet::new();
        let mut subnets = BTreeSet::new();
        for gateway in &self.gateways {
            if !valid_name(&gateway.name)
                || !gateway_names.insert(&gateway.name)
                || gateway.server.trim().is_empty()
                || gateway.port == 0
            {
                return Err(bad("Invalid or duplicate VLAN gateway"));
            }
            let subnet = gateway
                .subnet
                .parse::<Ipv4Net>()
                .map_err(|_| bad("Invalid Portal subnet"))?;
            if subnet.prefix_len() != 24
                || subnet.addr() != subnet.network()
                || !subnets.insert(subnet)
            {
                return Err(bad(
                    "Portal gateways require distinct canonical IPv4 /24 subnets",
                ));
            }
            master_key(gateway)?;
        }
        let mut supplicants = BTreeSet::new();
        for grant in &self.accept_supplicants {
            parse_slots(&grant.slots)?;
            if !supplicants.insert(&grant.supplicant_id) {
                return Err(bad("Duplicate VLAN supplicant grant"));
            }
        }
        for route in &self.routes {
            if route.parse::<IpNet>().is_err() {
                return Err(bad("Invalid VLAN route CIDR"));
            }
        }
        Ok(())
    }
}

fn parse_slots(expression: &str) -> Result<BTreeSet<u8>, AppError> {
    let mut slots = BTreeSet::new();
    fn number(value: &str) -> Result<u8, AppError> {
        let value = value.trim();
        let number = value
            .parse::<u8>()
            .map_err(|_| bad("Invalid slot number"))?;
        if !(2..=254).contains(&number) || number.to_string() != value {
            return Err(bad("Slots must be decimal numbers from 2 to 254"));
        }
        Ok(number)
    }
    for part in expression.split(',') {
        let (start, end) = match part.trim().split_once('-') {
            Some((start, end)) => (number(start)?, number(end)?),
            None => {
                let slot = number(part)?;
                (slot, slot)
            }
        };
        if start > end {
            return Err(bad("Slot range must be ascending"));
        }
        slots.extend(start..=end);
    }
    Ok(slots)
}

#[derive(PartialEq, Eq)]
struct VlanRequest {
    supplicant: String,
    vlans: BTreeMap<String, u8>,
}

fn parse_request(ua: &str, search: &str) -> Result<Option<VlanRequest>, AppError> {
    fn fields(encoded: &str, strict: bool) -> Result<Option<VlanRequest>, AppError> {
        let mut values = BTreeMap::new();
        for (key, value) in url::form_urlencoded::parse(encoded.as_bytes()) {
            if key != "supplicant" && key != "vlans" {
                if strict {
                    return Err(bad("Unknown Confluence request parameter"));
                }
                continue;
            }
            if values
                .insert(key.into_owned(), value.into_owned())
                .is_some()
            {
                return Err(bad("Duplicate Confluence request parameter"));
            }
        }
        if values.is_empty() && !strict {
            return Ok(None);
        }
        let supplicant = values
            .get("supplicant")
            .filter(|v| valid_name(v))
            .ok_or_else(|| bad("Missing or invalid supplicant"))?
            .clone();
        let list = values
            .get("vlans")
            .ok_or_else(|| bad("Missing VLAN list"))?;
        let mut vlans = BTreeMap::new();
        for entry in list.split(',') {
            let (network, slot) = entry
                .split_once(':')
                .ok_or_else(|| bad("Expected VLAN key:slot"))?;
            let value = slot.parse::<u8>().map_err(|_| bad("Invalid VLAN slot"))?;
            if !valid_name(network) || !(2..=254).contains(&value) || value.to_string() != slot {
                return Err(bad("Invalid VLAN key or slot"));
            }
            if vlans.insert(network.into(), value).is_some() {
                return Err(bad("Duplicate VLAN in request"));
            }
        }
        Ok(Some(VlanRequest { supplicant, vlans }))
    }
    let mut markers = ua
        .split_ascii_whitespace()
        .filter(|v| v.to_ascii_lowercase().starts_with("confluence/"));
    let from_ua = markers
        .next()
        .map(|marker| fields(&marker["confluence/".len()..], true))
        .transpose()?
        .flatten();
    if markers.next().is_some() {
        return Err(bad("Duplicate Confluence UA marker"));
    }
    let from_query = fields(search, false)?;
    match (from_ua, from_query) {
        (Some(a), Some(b)) if a != b => Err(bad("UA and URL VLAN requests disagree")),
        (Some(a), _) | (_, Some(a)) => Ok(Some(a)),
        _ => Ok(None),
    }
}

fn derive_client_key(master: &[u8; 32], slot: u8) -> [u8; 32] {
    let name = format!("subscription-slot-{slot}");
    let mut context = Vec::new();
    for label in [b"wireguard-client".as_slice(), name.as_bytes()] {
        context.extend_from_slice(&(label.len() as u32).to_be_bytes());
        context.extend_from_slice(label);
    }
    let mut output = [0; 32];
    Hkdf::<Sha256>::new(Some(b"easytier/wireguard-portal/v1"), master)
        .expand(&context, &mut output)
        .expect("32-byte HKDF output is valid");
    output
}

pub fn apply_vlan_subscription(
    content: &str,
    stored: Option<&VlanConfig>,
    ua: &str,
    search: &str,
) -> Result<String, AppError> {
    let Some(request) = parse_request(ua, search)? else {
        return Ok(content.into());
    };
    let config = stored.ok_or_else(|| bad("VLAN is not configured"))?;
    config.validate()?;
    let supplicant = config
        .supplicant_configs
        .iter()
        .find(|s| s.name == request.supplicant)
        .ok_or_else(|| bad("Unknown supplicant"))?;
    let mut profile =
        serde_yaml::from_str::<Value>(content).map_err(crate::error::ConfigError::from)?;
    if !profile.is_object() {
        return Err(bad("VLAN requires a YAML object"));
    }
    for (key, slot) in request.vlans {
        let network = config
            .vlan_configs
            .iter()
            .find(|v| v.enabled && v.network == key)
            .ok_or_else(|| bad("Unknown or disabled VLAN"))?;
        let grant = network
            .accept_supplicants
            .iter()
            .find(|g| g.supplicant_id == supplicant.id)
            .ok_or_else(|| bad("Supplicant is not accepted by this VLAN"))?;
        if !parse_slots(&grant.slots)?.contains(&slot) {
            return Err(bad("Slot is not permitted for this supplicant"));
        }
        inject_network(&mut profile, network, slot)?;
    }
    let yaml = serde_yaml::to_string(&profile).map_err(crate::error::ConfigError::from)?;
    encrypt_profile(&yaml, std::slice::from_ref(&supplicant.age_recipient))
}

fn inject_network(profile: &mut Value, config: &VlanNetwork, slot: u8) -> Result<(), AppError> {
    let group_name = format!("VLAN-{}", config.network);
    let proxy_prefix = format!("{group_name}-");
    let mut proxies = Vec::new();
    let mut proxy_names = Vec::new();
    let mut routes: BTreeSet<String> = config.routes.iter().cloned().collect();
    for gateway in &config.gateways {
        let master = master_key(gateway)?;
        let subnet = gateway
            .subnet
            .parse::<Ipv4Net>()
            .map_err(|_| bad("Invalid Portal subnet"))?;
        let ip = std::net::Ipv4Addr::from(u32::from(subnet.network()) + u32::from(slot));
        let name = format!("{proxy_prefix}{}-WG", gateway.name.to_ascii_uppercase());
        proxy_names.push(name.clone());
        routes.insert(gateway.subnet.clone());
        proxies.push(json!({ "name": name, "type": "wireguard", "server": gateway.server,
            "port": gateway.port, "ip": ip.to_string(), "udp": true,
            "private-key": STANDARD.encode(derive_client_key(&master, slot)),
            "public-key": STANDARD.encode(PublicKey::from(&StaticSecret::from(master)).as_bytes()) }));
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
    let mut rules = routes
        .into_iter()
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
        let network = |name: &str, slots: &str| VlanNetwork {
            id: format!("new:{name}"),
            enabled: true,
            network: name.into(),
            routes: vec!["10.20.0.0/24".into()],
            gateways: vec![VlanGateway {
                name: "portal".into(),
                server: "192.0.2.1".into(),
                port: 24,
                subnet: "10.30.0.0/24".into(),
                private_key: Some(STANDARD.encode([7; 32])),
                has_private_key: false,
            }],
            accept_supplicants: vec![VlanGrant {
                supplicant_id: identity.into(),
                slots: slots.into(),
            }],
        };
        VlanConfig {
            supplicant_configs: vec![VlanSupplicant {
                id: identity.into(),
                name: "owner".into(),
                age_recipient: recipient.into(),
            }],
            vlan_configs: vec![network("home", "2,4,10-100"), network("office", "20-30")],
        }
    }

    #[test]
    fn shared_identity_encrypts_multiple_vlans_with_independent_slot_permissions() {
        let identity = age::x25519::Identity::generate();
        let stored = config(&identity.to_public().to_string());
        let content = "proxies: []\nrules: [\"MATCH,DIRECT\"]";
        let request = "supplicant=owner&vlans=home:10,office:20";
        let encrypted = apply_vlan_subscription(content, Some(&stored), "", request).unwrap();
        let decryptor =
            age::Decryptor::new(age::armor::ArmoredReader::new(encrypted.as_bytes())).unwrap();
        let mut reader = decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .unwrap();
        let mut plaintext = String::new();
        reader.read_to_string(&mut plaintext).unwrap();
        let profile: Value = serde_yaml::from_str(&plaintext).unwrap();
        assert_eq!(profile["proxies"].as_array().unwrap().len(), 2);
        assert!(!plaintext.contains(&STANDARD.encode([7; 32])));
        for invalid in [
            request.replace("home:10", "home:3"),
            request.replace("office:20", "office:31"),
            request.replace("owner", "missing"),
        ] {
            assert!(apply_vlan_subscription(content, Some(&stored), "", &invalid).is_err());
        }
    }

    #[test]
    fn request_sources_are_canonical_and_conflicts_fail_closed() {
        let request = "supplicant=owner&vlans=home:10,office:20";
        let ua = format!("Client/1 confluence/{request}");
        assert!(parse_request(&ua, "vlans=office:20,home:10&supplicant=owner").is_ok());
        assert!(parse_request(&ua, &request.replace("home:10", "home:11")).is_err());
        for invalid in [
            "supplicant=owner&vlans=home:010",
            "supplicant=owner&vlans=home:2,home:4",
            "supplicant=owner&vlans=home:2&vlans=office:4",
            "supplicant=owner",
            "vlans=home:10",
        ] {
            assert!(parse_request("", invalid).is_err(), "{invalid}");
        }
        assert!(parse_request("Client/1", "").unwrap().is_none());
    }

    #[test]
    fn global_identity_references_and_slot_expressions_are_validated() {
        let identity = age::x25519::Identity::generate();
        let mut config = config(&identity.to_public().to_string());
        config.validate().unwrap();
        let mut redacted = config.vlan_configs[0].clone().redact_keys();
        redacted.network = "renamed".into();
        redacted
            .preserve_keys(&config.vlan_configs[0].gateways)
            .unwrap();
        assert!(redacted.gateways[0].private_key.is_some());
        config.vlan_configs[0].accept_supplicants[0].supplicant_id = "unknown".into();
        assert!(config.validate().is_err());
        assert_eq!(
            parse_slots("2,4,10-12").unwrap(),
            BTreeSet::from([2, 4, 10, 11, 12])
        );
        for invalid in ["", "1", "255", "10-2", "02", "2,,4"] {
            assert!(parse_slots(invalid).is_err());
        }
    }
}
