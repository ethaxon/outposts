import { describe, expect, it } from "vitest";
import { parseWireGuardClient, parseWireGuardImport } from "./wireguard-import";

describe("EasyTier WireGuard import", () => {
  function config(endpoint: string, routes = "10.0.1.7/24, 10.0.1.0/24, 2001:db8::/64") {
    return [
      "[Interface]",
      "Address = 192.0.2.2/32",
      "",
      "[Peer]",
      `AllowedIPs = ${routes}`,
      `Endpoint = ${endpoint} # replace wildcard with the public address`,
    ].join("\r\n");
  }

  it("normalizes routes and accepts bracketed IPv6 endpoints", () => {
    expect(parseWireGuardImport(config("[2001:db8::1]:11013"))).toEqual({
      ok: true,
      server: "2001:db8::1",
      port: 11013,
      suggestedSubnet: "192.0.2.0/24",
      routes: ["10.0.1.0/24", "2001:db8::/64"],
    });
  });

  it.each(["0.0.0.0:24", "[::]:24"])("leaves a wildcard server blank for %s", (endpoint) => {
    expect(parseWireGuardImport(config(endpoint))).toMatchObject({
      ok: true,
      server: "",
      port: 24,
    });
  });

  it.each(["example.test:65536", "https://example.test:24", "192.0.2.300:24", "[::1/128]:24"])(
    "rejects invalid endpoint %s",
    (endpoint) => {
      expect(parseWireGuardImport(config(endpoint))).toEqual({ ok: false, error: "endpoint" });
    },
  );

  it("rejects an invalid route or multiple peers", () => {
    expect(parseWireGuardImport(config("example.test:24", "10.0.1.0/24, invalid"))).toEqual({
      ok: false,
      error: "allowedIps",
    });
    expect(
      parseWireGuardImport(`${config("example.test:24")}\n[Peer]\nEndpoint = other.test:24`),
    ).toEqual({ ok: false, error: "format" });
  });

  it("leaves the subnet blank when the interface address is ambiguous", () => {
    const text = config("example.test:24").replace("192.0.2.2/32", "192.0.2.2/32, 192.0.2.3/32");
    expect(parseWireGuardImport(text)).toMatchObject({ ok: true, suggestedSubnet: "" });
  });
});

describe("WireGuard client import", () => {
  const client = `${"A".repeat(43)}=`;
  const peer = (key: string, ip: string, keepalive: number) =>
    `[Peer]\nEndpoint = example.test:24\nPublicKey = ${key.repeat(43)}=\nAllowedIPs = ${ip}\nPersistentKeepalive = ${keepalive}`;
  const conf = (keepalive = 25) =>
    [
      `[Interface]\nPrivateKey = ${client}\nAddress = 192.0.2.2/24, 2001:db8::2/64\nMTU = 1420`,
      peer("B", "10.0.0.0/24", 25),
      peer("C", "2001:db8::/64", keepalive),
    ].join("\n\n");

  it("keeps the client addresses and each peer's AllowedIPs", () => {
    const result = parseWireGuardClient(conf());
    expect(result).toMatchObject({
      ok: true,
      settings: {
        addresses: ["192.0.2.2/24", "2001:db8::2/64"],
        private_key: client,
        mtu: 1420,
        persistent_keepalive: 25,
        peers: [{ allowed_ips: ["10.0.0.0/24"] }, { allowed_ips: ["2001:db8::/64"] }],
      },
    });
  });

  it("rejects different peer keepalive values and unrepresentable directives", () => {
    expect(parseWireGuardClient(conf(15))).toEqual({ ok: false, error: "keepalive" });
    expect(parseWireGuardClient(conf().replace("MTU =", "PreUp = anything\nMTU ="))).toEqual({
      ok: false,
      error: "fields",
    });
  });
});
