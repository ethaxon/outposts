use std::collections::{BTreeMap, BTreeSet};

use base64::{Engine, engine::general_purpose::STANDARD};
use hkdf::Hkdf;
use ipnet::{IpNet, Ipv4Net};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use ts_rs::TS;
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{error::AppError, scalars::UuidV7, subscription_encryption::encrypt_profile};

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
pub struct VlanTunnel {
    pub id: String,
    pub name: String,
    #[serde(flatten)]
    pub source: VlanTunnelSource,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(tag = "type", rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub enum VlanTunnelSource {
    EasytierGateway {
        server: String,
        port: u16,
        subnet: String,
        allowed_ips: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        private_key: Option<String>,
        #[serde(default)]
        has_private_key: bool,
        grants: Vec<EasyTierTunnelGrant>,
    },
    WireguardCompatible {
        configs: Vec<WireGuardClientConfig>,
        grants: Vec<WireGuardTunnelGrant>,
    },
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(deny_unknown_fields)]
pub struct EasyTierTunnelGrant {
    pub supplicant_id: String,
    pub slots: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(deny_unknown_fields)]
pub struct WireGuardTunnelGrant {
    pub supplicant_id: String,
    #[ts(as = "UuidV7")]
    pub config_id: Uuid,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(deny_unknown_fields)]
pub struct WireGuardClientConfig {
    #[ts(as = "UuidV7")]
    pub id: Uuid,
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

/// Names travel unescaped in `confluence/supplicant=<key>&vlans=<net>:<slot>,…`,
/// whose separators survive percent-decoding, so escaping cannot protect them.
/// Allow only RFC 3986 unreserved characters, lowercase so gateway names stay
/// unique after being uppercased into Clash proxy names.
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
        for tunnel in &mut self.tunnels {
            match &mut tunnel.source {
                VlanTunnelSource::EasytierGateway {
                    private_key,
                    has_private_key,
                    ..
                } => {
                    *has_private_key = private_key.take().is_some();
                }
                VlanTunnelSource::WireguardCompatible { configs, .. } => {
                    for config in configs {
                        config.has_private_key = config.private_key.take().is_some();
                        for peer in &mut config.peers {
                            peer.has_pre_shared_key = peer.pre_shared_key.take().is_some();
                        }
                    }
                }
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
            match (&mut tunnel.source, old.map(|old| &old.source)) {
                (
                    VlanTunnelSource::EasytierGateway { private_key, .. },
                    Some(VlanTunnelSource::EasytierGateway {
                        private_key: saved, ..
                    }),
                ) if private_key.as_deref().is_none_or(str::is_empty) => {
                    private_key.clone_from(saved);
                }
                (VlanTunnelSource::WireguardCompatible { configs, .. }, old) => {
                    let saved = match old {
                        Some(VlanTunnelSource::WireguardCompatible { configs, .. }) => {
                            configs.as_slice()
                        }
                        _ => &[],
                    };
                    for config in configs {
                        let old = saved.iter().find(|old| old.id == config.id);
                        if config.private_key.as_deref().is_none_or(str::is_empty) {
                            config.private_key = old.and_then(|old| old.private_key.clone());
                        }
                        for peer in &mut config.peers {
                            if peer.pre_shared_key.as_deref() == Some("") {
                                peer.pre_shared_key = None;
                            } else if peer.pre_shared_key.is_none() {
                                peer.pre_shared_key = old.and_then(|old| {
                                    old.peers
                                        .iter()
                                        .find(|saved| saved.public_key == peer.public_key)
                                        .and_then(|saved| saved.pre_shared_key.clone())
                                });
                            }
                        }
                    }
                }
                _ => {}
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
        let mut subnets = BTreeSet::new();
        for tunnel in &self.tunnels {
            if !valid_name(&tunnel.name)
                || !names.insert(&tunnel.name)
                || (!tunnel.id.is_empty() && !ids.insert(&tunnel.id))
            {
                return Err(bad("Invalid or duplicate VLAN tunnel"));
            }
            let mut granted = BTreeSet::new();
            let mut check_grant = |id: &'_ str| {
                if !members.contains(id) || !granted.insert(id.to_owned()) {
                    return Err(bad("Tunnel grants require distinct VLAN supplicants"));
                }
                Ok(())
            };
            match &tunnel.source {
                VlanTunnelSource::EasytierGateway {
                    server,
                    port,
                    subnet,
                    allowed_ips,
                    private_key,
                    grants,
                    ..
                } => {
                    validate_endpoint(server, *port)?;
                    let subnet = subnet
                        .parse::<Ipv4Net>()
                        .map_err(|_| bad("Invalid Portal subnet"))?;
                    if subnet.prefix_len() != 24
                        || subnet.addr() != subnet.network()
                        || !subnets.insert(subnet)
                    {
                        return Err(bad(
                            "Portal tunnels require distinct canonical IPv4 /24 subnets",
                        ));
                    }
                    wireguard_key(private_key.as_deref(), "Invalid Portal server private key")?;
                    validate_coverage(allowed_ips, &routes)?;
                    for grant in grants {
                        check_grant(&grant.supplicant_id)?;
                        parse_slots(&grant.slots)?;
                    }
                }
                VlanTunnelSource::WireguardCompatible { configs, grants } => {
                    let mut config_ids = BTreeSet::new();
                    for config in configs {
                        if !config_ids.insert(config.id) {
                            return Err(bad("Duplicate WireGuard config"));
                        }
                        config.validate(&routes)?;
                    }
                    for grant in grants {
                        check_grant(&grant.supplicant_id)?;
                        if !config_ids.remove(&grant.config_id) {
                            return Err(bad(
                                "WireGuard grants require distinct configs from this tunnel",
                            ));
                        }
                    }
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

const CONFLUENCE_MARKER: &str = "confluence/";
const UNSAFE_PRIVATE_KEY: &str = "_unsafe_supplicant_private";

pub(crate) struct SubscriptionRequest {
    supplicant: String,
    vlans: BTreeMap<String, Option<u8>>,
    unsafe_identity: Option<age::x25519::Identity>,
}

impl SubscriptionRequest {
    pub(crate) fn uses_unsafe_key(&self) -> bool {
        self.unsafe_identity.is_some()
    }
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

pub(crate) fn parse_request(
    ua: &str,
    search: &str,
) -> Result<Option<SubscriptionRequest>, AppError> {
    fn fields(encoded: &str, from_ua: bool) -> Result<Option<SubscriptionRequest>, AppError> {
        let mut values = BTreeMap::new();
        for (key, value) in url::form_urlencoded::parse(encoded.as_bytes()) {
            match key.as_ref() {
                UNSAFE_PRIVATE_KEY if !from_ua => {
                    return Err(bad("Supply the unsafe age private key only in User-Agent"));
                }
                "supplicant" | "vlans" | UNSAFE_PRIVATE_KEY => {}
                _ if from_ua => return Err(bad("Unknown Confluence request parameter")),
                _ => continue,
            }
            if values.insert(key, value).is_some() {
                return Err(bad("Duplicate Confluence request parameter"));
            }
        }
        if values.is_empty() && !from_ua {
            return Ok(None);
        }
        let supplicant = values
            .remove("supplicant")
            .filter(|value| valid_name(value))
            .ok_or_else(|| bad("Missing or invalid supplicant"))?
            .into_owned();
        let unsafe_identity = values
            .remove(UNSAFE_PRIVATE_KEY)
            .map(|value| {
                value
                    .parse()
                    .map_err(|_| bad("Invalid unsafe age private key"))
            })
            .transpose()?;

        let mut vlans = BTreeMap::new();
        if let Some(list) = values.get("vlans") {
            for entry in list.split(',') {
                let (network, slot) = entry
                    .split_once(':')
                    .map_or((entry, None), |(network, slot)| (network, Some(slot)));
                if !valid_name(network) {
                    return Err(bad("Invalid VLAN key"));
                }
                let slot = slot
                    .map(|slot| {
                        let value = slot.parse::<u8>().map_err(|_| bad("Invalid VLAN slot"))?;
                        if !(2..=254).contains(&value) || value.to_string() != slot {
                            return Err(bad("Invalid VLAN slot"));
                        }
                        Ok(value)
                    })
                    .transpose()?;
                if vlans.insert(network.into(), slot).is_some() {
                    return Err(bad("Duplicate VLAN in request"));
                }
            }
        } else if unsafe_identity.is_none() {
            return Err(bad("Missing VLAN list"));
        }

        Ok(Some(SubscriptionRequest {
            supplicant,
            vlans,
            unsafe_identity,
        }))
    }

    let from_query = fields(search, false)?;
    let mut markers = ua
        .split_ascii_whitespace()
        .filter_map(confluence_parameters);
    let from_ua = markers
        .next()
        .map(|marker| fields(marker, true))
        .transpose()?
        .flatten();
    if markers.next().is_some() {
        return Err(bad("Duplicate Confluence UA marker"));
    }
    match (from_ua, from_query) {
        (Some(a), Some(b)) if a.supplicant != b.supplicant || a.vlans != b.vlans => {
            Err(bad("UA and URL VLAN requests disagree"))
        }
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

pub(crate) fn render_subscription(
    content: &str,
    stored: Option<&VlanConfig>,
    profile_supplicants: &[VlanSupplicant],
    request: Option<SubscriptionRequest>,
    allow_unsafe_age_private_key: bool,
) -> Result<String, AppError> {
    let Some(request) = request else {
        return if profile_supplicants.is_empty() {
            Ok(content.into())
        } else {
            encrypt_profile(
                content,
                profile_supplicants
                    .iter()
                    .map(|supplicant| supplicant.age_recipient.as_str()),
            )
        };
    };
    if request.uses_unsafe_key() && !allow_unsafe_age_private_key {
        return Err(bad("Unsafe age compatibility is disabled for this Profile"));
    }

    let config = if request.vlans.is_empty() {
        None
    } else {
        let config = stored.ok_or_else(|| bad("VLAN is not configured"))?;
        config.validate()?;
        Some(config)
    };
    let supplicant = config
        .map(|config| config.supplicant_configs.as_slice())
        .unwrap_or(profile_supplicants)
        .iter()
        .find(|s| s.name == request.supplicant)
        .ok_or_else(|| bad("Unknown supplicant"))?;
    if !profile_supplicants.is_empty()
        && !profile_supplicants
            .iter()
            .any(|recipient| recipient.id == supplicant.id)
    {
        return Err(bad("Supplicant is not accepted by this Profile"));
    }

    let uses_unsafe_key = request.uses_unsafe_key();
    if let Some(identity) = request.unsafe_identity {
        let recipient = supplicant
            .age_recipient
            .parse::<age::x25519::Recipient>()
            .map_err(|_| bad("Invalid supplicant age recipient"))?;
        if identity.to_public() != recipient {
            return Err(bad("Unsafe age private key does not match the supplicant"));
        }
    }

    let yaml = match config {
        Some(config) => {
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
                if !network
                    .accept_supplicants
                    .iter()
                    .any(|g| g.supplicant_id == supplicant.id)
                {
                    return Err(bad("Supplicant is not accepted by this VLAN"));
                }
                inject_network(&mut profile, network, &supplicant.id, slot)?;
            }
            serde_yaml::to_string(&profile).map_err(crate::error::ConfigError::from)?
        }
        None => content.into(),
    };
    if uses_unsafe_key {
        Ok(yaml)
    } else {
        encrypt_profile(&yaml, std::iter::once(supplicant.age_recipient.as_str()))
    }
}

fn render_peer(server: &str, port: u16, public_key: &str, allowed_ips: &[String]) -> Value {
    json!({ "server": server, "port": port, "public-key": public_key, "allowed-ips": allowed_ips })
}

fn inject_network(
    profile: &mut Value,
    config: &VlanNetwork,
    supplicant: &str,
    slot: Option<u8>,
) -> Result<(), AppError> {
    let group_name = format!("VLAN-{}", config.network);
    let proxy_prefix = format!("{group_name}-");
    let mut proxies = Vec::new();
    let mut proxy_names = Vec::new();
    for tunnel in &config.tunnels {
        let name = format!("{proxy_prefix}{}-WG", tunnel.name.to_ascii_uppercase());
        let mut node = json!({ "name": name, "type": "wireguard", "udp": true });
        match &tunnel.source {
            VlanTunnelSource::EasytierGateway {
                server,
                port,
                subnet,
                allowed_ips,
                private_key,
                grants,
                ..
            } => {
                let Some(slot) = slot else { continue };
                let Some(grant) = grants
                    .iter()
                    .find(|grant| grant.supplicant_id == supplicant)
                else {
                    continue;
                };
                if !parse_slots(&grant.slots)?.contains(&slot) {
                    continue;
                }
                let master =
                    wireguard_key(private_key.as_deref(), "Invalid Portal server private key")?;
                let subnet = subnet
                    .parse::<Ipv4Net>()
                    .map_err(|_| bad("Invalid Portal subnet"))?;
                let ip = std::net::Ipv4Addr::from(u32::from(subnet.network()) + u32::from(slot));
                let public_key =
                    STANDARD.encode(PublicKey::from(&StaticSecret::from(master)).as_bytes());
                node["ip"] = json!(ip.to_string());
                node["private-key"] = json!(STANDARD.encode(derive_client_key(&master, slot)));
                node["peers"] = json!([render_peer(server, *port, &public_key, allowed_ips)]);
            }
            VlanTunnelSource::WireguardCompatible { configs, grants } => {
                let Some(config) = grants
                    .iter()
                    .find(|grant| grant.supplicant_id == supplicant)
                    .and_then(|grant| configs.iter().find(|config| config.id == grant.config_id))
                else {
                    continue;
                };
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
                            let mut item = render_peer(
                                &peer.server,
                                peer.port,
                                &peer.public_key,
                                &peer.allowed_ips,
                            );
                            if let Some(key) = &peer.pre_shared_key {
                                item["pre-shared-key"] = json!(key);
                            }
                            item
                        })
                        .collect::<Vec<_>>()
                );
            }
        }
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
        let network = |name: &str, slots: &str| VlanNetwork {
            id: format!("new:{name}"),
            enabled: true,
            network: name.into(),
            routes: vec!["10.20.0.0/24".into(), "10.30.0.0/24".into()],
            tunnels: vec![VlanTunnel {
                id: format!("tunnel:{name}"),
                name: "portal".into(),
                source: VlanTunnelSource::EasytierGateway {
                    server: "192.0.2.1".into(),
                    port: 24,
                    subnet: "10.30.0.0/24".into(),
                    allowed_ips: vec!["10.20.0.0/24".into()],
                    private_key: Some(STANDARD.encode([7; 32])),
                    has_private_key: false,
                    grants: vec![EasyTierTunnelGrant {
                        supplicant_id: identity.into(),
                        slots: slots.into(),
                    }],
                },
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
            vlan_configs: vec![network("home", "2,4,10-100"), network("office", "20-30")],
        }
    }

    fn render_test_subscription(
        content: &str,
        stored: Option<&VlanConfig>,
        recipients: &[VlanSupplicant],
        ua: &str,
        query: &str,
    ) -> Result<String, AppError> {
        render_subscription(
            content,
            stored,
            recipients,
            parse_request(ua, query)?,
            false,
        )
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
    fn mixed_tunnels_filter_grants_and_emit_peers_without_changing_vlan_routes() {
        let identity = age::x25519::Identity::generate();
        let mut stored = config(&identity.to_public().to_string());
        let supplicant_id = stored.supplicant_configs[0].id.clone();
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
        let config_id = Uuid::parse_str("00000000-0000-7000-8000-000000000001").unwrap();
        home.tunnels.push(VlanTunnel {
            id: "wire".into(),
            name: "wire".into(),
            source: VlanTunnelSource::WireguardCompatible {
                grants: vec![],
                configs: vec![WireGuardClientConfig {
                    id: config_id,
                    addresses: vec!["10.42.0.2/24".into()],
                    mtu: None,
                    persistent_keepalive: Some(25),
                    private_key: Some(STANDARD.encode([5; 32])),
                    has_private_key: true,
                    peers,
                }],
            },
        });
        // A tagged request DTO must round-trip without losing its source or rejecting its common fields.
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
        stored.validate().unwrap();
        let request = "supplicant=owner&vlans=home";
        let unassigned = decrypt_profile(
            &identity,
            &render_test_subscription("{}", Some(&stored), &[], "", request).unwrap(),
        );
        assert_eq!(
            unassigned["proxy-groups"][0]["proxies"],
            json!(["REJECT", "DIRECT"])
        );

        let home = &mut stored.vlan_configs[0];
        let mut assigned = home.clone().redact_keys();
        let VlanTunnelSource::WireguardCompatible { grants, .. } = &mut assigned.tunnels[1].source
        else {
            unreachable!()
        };
        grants.push(WireGuardTunnelGrant {
            supplicant_id,
            config_id,
        });
        assigned.preserve_keys(&home.tunnels).unwrap();
        *home = assigned;
        for (suffix, expected) in [("", 1), (":3", 1), (":10", 2)] {
            let encrypted = render_test_subscription(
                "{}",
                Some(&stored),
                &[],
                "",
                &format!("supplicant=owner&vlans=home{suffix}"),
            )
            .unwrap();
            let profile = decrypt_profile(&identity, &encrypted);
            let proxies = profile["proxies"].as_array().unwrap();
            assert_eq!(proxies.len(), expected);
            let wireguard = proxies
                .iter()
                .find(|proxy| proxy["name"] == "VLAN-home-WIRE-WG")
                .unwrap();
            assert_eq!(wireguard["peers"].as_array().unwrap().len(), 2);
            assert_eq!(wireguard["ip"], "10.42.0.2");
            assert_eq!(wireguard["private-key"], STANDARD.encode([5; 32]));
            assert_eq!(
                wireguard["peers"][0]["pre-shared-key"],
                STANDARD.encode([4; 32])
            );
            assert_eq!(profile["rules"].as_array().unwrap().len(), 3);
        }
        stored.vlan_configs[0].routes.pop();
        assert!(stored.validate().is_err());
    }

    #[test]
    fn shared_identity_encrypts_multiple_vlans_with_independent_slot_permissions() {
        let identity = age::x25519::Identity::generate();
        let stored = config(&identity.to_public().to_string());
        let content = "proxies: []\nrules: [\"MATCH,DIRECT\"]";
        let request = "supplicant=owner&vlans=home:10,office:20";
        let encrypted = render_test_subscription(content, Some(&stored), &[], "", request).unwrap();
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
        let empty = decrypt_profile(
            &identity,
            &render_test_subscription(
                content,
                Some(&stored),
                &[],
                "",
                "supplicant=owner&vlans=home:3",
            )
            .unwrap(),
        );
        assert_eq!(
            empty["proxy-groups"][0]["proxies"],
            json!(["REJECT", "DIRECT"])
        );
        assert!(
            render_test_subscription(
                content,
                Some(&stored),
                &[],
                "",
                &request.replace("owner", "missing")
            )
            .is_err()
        );
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
        let request = parse_request("", "supplicant=owner.v2&vlans=home.lan:10,~edge:2")
            .unwrap()
            .unwrap();
        assert_eq!(request.supplicant, "owner.v2");
        assert_eq!(
            request.vlans,
            BTreeMap::from([("home.lan".into(), Some(10)), ("~edge".into(), Some(2))])
        );
    }

    #[test]
    fn global_identity_references_and_slot_expressions_are_validated() {
        let identity = age::x25519::Identity::generate();
        let mut config = config(&identity.to_public().to_string());
        config.validate().unwrap();
        let mut redacted = config.vlan_configs[0].clone().redact_keys();
        redacted.network = "renamed".into();
        redacted
            .preserve_keys(&config.vlan_configs[0].tunnels)
            .unwrap();
        assert!(matches!(
            &redacted.tunnels[0].source,
            VlanTunnelSource::EasytierGateway {
                private_key: Some(_),
                ..
            }
        ));
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
