/* eslint-disable */
/**
 * Compact Clash/Mihomo type hints for profile transform scripts.
 *
 * This file intentionally follows the coarse-grained MetaCubeXD API model
 * instead of expanding the full JSON schema. Unknown and evolving fields are
 * represented by index signatures so scripts get useful hints without noisy
 * generated helper types.
 */

export type LogLevel = "debug" | "info" | "warning" | "error" | "silent" | string;

export type ConnectionsTableAccessorKey =
  | "close"
  | "ID"
  | "metadata"
  | "chains"
  | "download"
  | "upload"
  | "rule"
  | "rulePayload"
  | "process"
  | "sourceIP"
  | "sourcePort"
  | "destinationIP"
  | "destinationPort"
  | "host"
  | "network"
  | "type"
  | "start"
  | string;

export type UnknownRecord = Record<string, unknown>;
export type StringArray = string[];
export type RuleLine = string;

export type ProxyType =
  | "direct"
  | "reject"
  | "reject-drop"
  | "pass"
  | "dns"
  | "ss"
  | "ssr"
  | "snell"
  | "socks5"
  | "http"
  | "vmess"
  | "vless"
  | "trojan"
  | "hysteria"
  | "hysteria2"
  | "wireguard"
  | "tuic"
  | "ssh"
  | "mieru"
  | "anytls"
  | "sudoku"
  | "masque"
  | "trust-tunnel"
  | string;

export type ProxyGroupType =
  | "select"
  | "url-test"
  | "fallback"
  | "load-balance"
  | "relay"
  | "smart"
  | string;

export type RuleProviderBehavior = "domain" | "ipcidr" | "classical" | string;
export type ProviderVehicleType = "HTTP" | "File" | "Compatible" | string;

export interface Proxy {
  name: string;
  type: string;
  all?: string[];
  icon?: string;
  extra: UnknownRecord;
  history: {
    time: string;
    delay: number;
  }[];
  hidden: boolean;
  udp: boolean;
  xudp: boolean;
  tfo: boolean;
  now: string;
  testUrl?: string;
  timeout?: number;
}

export interface ProxyNode {
  alive: boolean;
  type: string;
  name: string;
  tfo: boolean;
  udp: boolean;
  xudp: boolean;
  now: string;
  id: string;
  extra: UnknownRecord;
  history: {
    time: string;
    delay: number;
  }[];
}

export interface SubscriptionInfo {
  Download?: number;
  Upload?: number;
  Total?: number;
  Expire?: number;
}

export interface ProxyProvider {
  subscriptionInfo?: SubscriptionInfo;
  name: string;
  proxies: ProxyNode[];
  testUrl: string;
  timeout?: number;
  updatedAt: string;
  vehicleType: string;
}

export interface RuleExtra {
  disabled?: boolean;
  hitCount?: number;
  hitAt?: string;
  missCount?: number;
  missAt?: string;
}

export interface Rule {
  index: number;
  type: string;
  payload: string;
  proxy: string;
  size: number;
  extra?: RuleExtra;
}

export interface RuleProvider {
  behavior: string;
  format: string;
  name: string;
  ruleCount: number;
  type: string;
  updatedAt: string;
  vehicleType: string;
}

export interface ConnectionRawMessage {
  id: string;
  download: number;
  upload: number;
  chains: string[];
  rule: string;
  rulePayload: string;
  start: string;
  metadata: {
    network: string;
    type: string;
    destinationIP: string;
    destinationPort: string;
    dnsMode: string;
    host: string;
    inboundIP: string;
    inboundName: string;
    inboundPort: string;
    inboundUser: string;
    process: string;
    processPath: string;
    remoteDestination: string;
    sniffHost: string;
    sourceIP: string;
    sourcePort: string;
    specialProxy: string;
    specialRules: string;
    uid: number;
  };
}

export type Connection = ConnectionRawMessage & {
  downloadSpeed: number;
  uploadSpeed: number;
};

export interface Log {
  type: LogLevel;
  payload: string;
}

export type LogWithSeq = Log & { seq: number };

export interface Config {
  mode: string;
  "mode-list": string[];
  modes?: string[];
  port: number;
  "socks-port": number;
  "redir-port": number;
  "tproxy-port": number;
  "mixed-port": number;
  tun: {
    enable: boolean;
    device: string;
    stack: string;
    "dns-hijack": null | string[];
    "auto-route": boolean;
    "auto-detect-interface": boolean;
    "file-descriptor": number;
    [key: string]: unknown;
  };
  "tuic-server": {
    enable: boolean;
    listen: string;
    certificate: string;
    "private-key": string;
    [key: string]: unknown;
  };
  "ss-config": string;
  "vmess-config": string;
  authentication: null | string[];
  "allow-lan": boolean;
  "bind-address": string;
  "inbound-tfo": boolean;
  UnifiedDelay: boolean;
  "unified-delay"?: boolean;
  "log-level": string;
  ipv6: boolean;
  "interface-name": string;
  "geodata-mode": boolean;
  "geodata-loader": string;
  "tcp-concurrent": boolean;
  "find-process-mode": string;
  sniffing: boolean;
  "global-client-fingerprint": boolean | string;
  [key: string]: unknown;
}

export interface DNSQuery {
  AD: boolean;
  CD: boolean;
  RA: boolean;
  RD: boolean;
  TC: boolean;
  status: number;
  Question: {
    Name: string;
    Qtype: number;
    Qclass: number;
  }[];
  Answer?: {
    TTL: number;
    data: string;
    name: string;
    type: number;
  }[];
}

export interface BackendVersion {
  meta: boolean;
  version: string;
}

export type ConnectionsTableColumnVisibility = Partial<
  Record<ConnectionsTableAccessorKey, boolean>
>;
export type ConnectionsTableColumnOrder = ConnectionsTableAccessorKey[];

export type DataUsageType = "sourceIP" | "host" | "process" | "outbound";

export interface DataUsageEntry {
  type: DataUsageType;
  label: string;
  upload: number;
  download: number;
  total: number;
  firstSeen: number;
  lastSeen: number;
}

export interface TrafficData {
  up: number;
  down: number;
}

export interface MemoryData {
  inuse: number;
}

export type WsMsg = {
  connections?: ConnectionRawMessage[];
  uploadTotal: number;
  downloadTotal: number;
} | null;

export type ChartDataPoint = [number, number];

export interface Endpoint {
  id: string;
  url: string;
  secret: string;
}

export type ProxyWithProvider = Proxy & { provider?: string };
export type ProxyNodeWithProvider = ProxyNode & { provider?: string };

export interface ReleaseInfo {
  version: string;
  changelog: string;
  publishedAt: string;
  isCurrent: boolean;
}

export interface ProxyConfig extends UnknownRecord {
  name: string;
  type: ProxyType;
  server?: string;
  port?: number | string;
  udp?: boolean;
  xudp?: boolean;
  tfo?: boolean;
  mptcp?: boolean;
  "skip-cert-verify"?: boolean;
  sni?: string;
  password?: string;
  username?: string;
  uuid?: string;
  cipher?: string;
  network?: string;
}

export interface ProxyGroup extends UnknownRecord {
  name: string;
  type: ProxyGroupType;
  proxies?: string[];
  use?: string[];
  url?: string;
  interval?: number;
  tolerance?: number;
  filter?: string;
  "exclude-filter"?: string;
  "exclude-type"?: string;
  "include-all"?: boolean;
  "include-all-proxies"?: boolean;
  "include-all-providers"?: boolean;
  hidden?: boolean;
  icon?: string;
}

export interface ProviderConfig extends UnknownRecord {
  type?: string;
  path?: string;
  url?: string;
  interval?: number;
  behavior?: RuleProviderBehavior;
  format?: string;
  "health-check"?: {
    enable?: boolean;
    url?: string;
    interval?: number;
    timeout?: number;
    lazy?: boolean;
    "expected-status"?: string | number | "*";
    [key: string]: unknown;
  };
}

export interface DNSConfig extends UnknownRecord {
  enable?: boolean;
  ipv6?: boolean;
  listen?: string;
  "enhanced-mode"?: "fake-ip" | "redir-host" | string;
  "fake-ip-range"?: string;
  "fake-ip-filter"?: string[];
  nameserver?: string[];
  fallback?: string[];
  "default-nameserver"?: string[];
  "proxy-server-nameserver"?: string[];
  "nameserver-policy"?: Record<string, string | string[]>;
  "proxy-server-nameserver-policy"?: Record<string, string | string[]>;
  "fallback-filter"?: UnknownRecord;
}

export interface TunConfig extends UnknownRecord {
  enable?: boolean;
  device?: string;
  stack?: string;
  "dns-hijack"?: string[];
  "auto-route"?: boolean;
  "auto-detect-interface"?: boolean;
  "strict-route"?: boolean;
  mtu?: number;
}

export interface SnifferConfig extends UnknownRecord {
  enable?: boolean;
  "override-destination"?: boolean;
  "force-domain"?: string[];
  "skip-domain"?: string[];
  sniff?: UnknownRecord;
}

export type ClashMetaConfig = Partial<Config> & {
  proxies?: ProxyConfig[];
  "proxy-groups"?: ProxyGroup[];
  rules?: RuleLine[];
  "proxy-providers"?: Record<string, ProviderConfig>;
  "rule-providers"?: Record<string, ProviderConfig>;
  "sub-rules"?: Record<string, RuleLine[]>;
  dns?: DNSConfig;
  tun?: TunConfig;
  sniffer?: SnifferConfig;
  hosts?: Record<string, string | string[]>;
  profile?: UnknownRecord;
  experimental?: UnknownRecord;
  ntp?: UnknownRecord;
  [key: string]: unknown;
};
