import type { WireGuardClientConfig } from "../bindings/WireGuardClientConfig";
import { parseCidr } from "./cidr";

const HOST_LABEL = /^[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?$/i;
const WIREGUARD_KEY = /^[a-z\d+/]{43}=$/i;
type ImportError = "format" | "endpoint" | "allowedIps" | "keepalive" | "fields";
type ImportResult<T> = ({ ok: true } & T) | { ok: false; error: ImportError };

function readSections(config: string) {
  let interfaceFields: Map<string, string> | undefined;
  const peers: Map<string, string>[] = [];
  let fields: Map<string, string> | undefined;
  for (const rawLine of config.split(/\r?\n/)) {
    const line = rawLine.split("#", 1)[0].trim();
    if (!line) continue;
    if (/^\[interface\]$/i.test(line)) {
      if (interfaceFields || peers.length) return;
      fields = interfaceFields = new Map();
    } else if (/^\[peer\]$/i.test(line)) {
      if (!interfaceFields) return;
      fields = new Map();
      peers.push(fields);
    } else {
      const entry = /^(\w+)\s*=\s*(.*)$/.exec(line);
      if (!entry || !fields) return;
      const key = entry[1].toLowerCase();
      if (fields.has(key)) return;
      fields.set(key, entry[2]);
    }
  }
  return interfaceFields && peers.length ? { interfaceFields, peers } : undefined;
}

function parseEndpoint(endpoint: string) {
  const match = /^(\[[^\]\s]+\]|[^:\s]+):(\d{1,5})$/.exec(endpoint);
  if (!match) return;
  const port = Number(match[2]);
  if (port < 1 || port > 65535) return;
  let server = match[1];
  if (server.startsWith("[")) {
    server = server.slice(1, -1);
    const address = parseCidr(server, { family: 6, prefix: 128 });
    if (!address.ok || server.includes("/")) return;
    if (address.cidr === "::/128") server = "";
  } else {
    const hostname = server.replace(/\.$/, "");
    const valid = /^[\d.]+$/.test(server)
      ? parseCidr(server).ok
      : hostname.length <= 253 && hostname.split(".").every((label) => HOST_LABEL.test(label));
    if (!valid) return;
    if (server === "0.0.0.0") server = "";
  }
  return { server, port };
}

function parseRoutes(value: string) {
  const routes = new Set<string>();
  for (const item of value.split(",")) {
    const route = parseCidr(item);
    if (!route.ok) return;
    routes.add(route.cidr);
  }
  return [...routes];
}

export function parseWireGuardImport(config: string): ImportResult<{
  server: string;
  port: number;
  routes: string[];
  suggestedSubnet: string;
}> {
  const result = readSections(config);
  if (!result || result.peers.length !== 1) return { ok: false, error: "format" };
  const peer = result.peers[0];
  const endpoint = parseEndpoint(peer.get("endpoint") ?? "");
  if (!endpoint) return { ok: false, error: "endpoint" };
  const routes = parseRoutes(peer.get("allowedips") ?? "");
  if (!routes) return { ok: false, error: "allowedIps" };

  const client = parseCidr(result.interfaceFields.get("address") ?? "", { family: 4, prefix: 32 });
  const subnet = client.ok ? parseCidr(client.cidr.split("/")[0], { family: 4, prefix: 24 }) : null;
  return { ok: true, ...endpoint, routes, suggestedSubnet: subnet?.ok ? subnet.cidr : "" };
}

export function parseWireGuardClient(
  config: string,
): ImportResult<{ settings: Omit<WireGuardClientConfig, "id"> }> {
  const result = readSections(config);
  if (!result) return { ok: false, error: "format" };
  const { interfaceFields, peers } = result;
  if (
    [...interfaceFields.keys()].some((key) => !["address", "privatekey", "mtu"].includes(key)) ||
    peers.some((peer) =>
      [...peer.keys()].some(
        (key) =>
          !["endpoint", "allowedips", "publickey", "presharedkey", "persistentkeepalive"].includes(
            key,
          ),
      ),
    )
  )
    return { ok: false, error: "fields" };
  const privateKey = interfaceFields.get("privatekey") ?? "";
  const mtuText = interfaceFields.get("mtu");
  const mtu = mtuText === undefined ? null : Number(mtuText);
  if (
    !WIREGUARD_KEY.test(privateKey) ||
    (mtu !== null && (!/^\d+$/.test(mtuText!) || mtu < 1 || mtu > 65535))
  )
    return { ok: false, error: "fields" };
  const addresses: string[] = [];
  const families = new Set<number>();
  for (const entry of (interfaceFields.get("address") ?? "").split(",")) {
    const address = entry.trim();
    const parsed = parseCidr(address);
    if (!parsed.ok || !address.includes("/") || families.has(parsed.family))
      return { ok: false, error: "fields" };
    families.add(parsed.family);
    addresses.push(address);
  }

  const peerSettings: WireGuardClientConfig["peers"] = [];
  const keepalives = new Set<number>();
  for (const peer of peers) {
    const endpoint = parseEndpoint(peer.get("endpoint") ?? "");
    if (!endpoint?.server) return { ok: false, error: "endpoint" };
    const routes = parseRoutes(peer.get("allowedips") ?? "");
    if (!routes) return { ok: false, error: "allowedIps" };
    const publicKey = peer.get("publickey") ?? "";
    const PSK = peer.get("presharedkey");
    if (!WIREGUARD_KEY.test(publicKey) || (PSK !== undefined && !WIREGUARD_KEY.test(PSK)))
      return { ok: false, error: "fields" };
    const keepalive = peer.get("persistentkeepalive") ?? "0";
    if (!/^\d+$/.test(keepalive) || Number(keepalive) > 65535)
      return { ok: false, error: "keepalive" };
    keepalives.add(Number(keepalive));
    peerSettings.push({
      ...endpoint,
      public_key: publicKey,
      allowed_ips: routes,
      pre_shared_key: PSK ?? "",
      has_pre_shared_key: false,
    });
  }
  if (keepalives.size !== 1) return { ok: false, error: "keepalive" };
  return {
    ok: true,
    settings: {
      private_key: privateKey,
      has_private_key: false,
      addresses,
      mtu,
      persistent_keepalive: [...keepalives][0],
      peers: peerSettings,
    },
  };
}
