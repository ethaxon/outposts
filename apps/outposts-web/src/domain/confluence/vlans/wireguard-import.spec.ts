import { describe, expect, it } from "vitest";
import { parseWireGuardClient } from "./wireguard-import";

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

  it.each([
    "0.0.0.0:24",
    "[::]:24",
    "example.test:65536",
    "https://example.test:24",
    "192.0.2.300:24",
    "[::1/128]:24",
  ])("rejects an unreachable or invalid endpoint %s", (endpoint) => {
    expect(parseWireGuardClient(conf().replace("example.test:24", endpoint))).toEqual({
      ok: false,
      error: "endpoint",
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
