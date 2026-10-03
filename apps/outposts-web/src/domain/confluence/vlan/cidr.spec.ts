import { describe, expect, it } from "vitest";
import { CidrError, parseCidr, splitCidrTokens } from "./cidr";

const canonical = (input: string, constraints?: Parameters<typeof parseCidr>[1]) => {
  const result = parseCidr(input, constraints);
  return result.ok ? result.cidr : result.reason;
};

describe("parseCidr", () => {
  it.each([
    ["10.20.0.0/24", "10.20.0.0/24"],
    [" 10.20.0.0/24 ", "10.20.0.0/24"],
    ["0.0.0.0/0", "0.0.0.0/0"],
    ["10.20.0.9/24", "10.20.0.0/24"],
    ["192.168.1.1", "192.168.1.1/32"],
    ["172.16.255.255/12", "172.16.0.0/12"],
  ])("canonicalizes IPv4 %s", (input, expected) => {
    expect(canonical(input)).toBe(expected);
  });

  it.each([
    ["fd00::/64", "fd00::/64"],
    ["FD00:0:0:0:0:0:0:1/64", "fd00::/64"],
    ["2001:db8::1", "2001:db8::1/128"],
    ["::/0", "::/0"],
    ["2001:db8:0:0:1:0:0:1/128", "2001:db8::1:0:0:1/128"],
    ["::ffff:10.0.0.1/128", "::ffff:a00:1/128"],
    ["2001:0db8:0001:0000:0000:0000:0000:0000/48", "2001:db8:1::/48"],
  ])("canonicalizes IPv6 %s", (input, expected) => {
    expect(canonical(input)).toBe(expected);
  });

  it.each([
    "",
    "10.20.0/24",
    "10.20.0.256/24",
    "10.020.0.0/24",
    "10.20.0.0/33",
    "10.20.0.0/",
    "10.20.0.0/+8",
    "fd00::1::/64",
    "fd00:0:0:0:0:0:0:0:1/64",
    "2001:db8::/129",
    "gggg::/16",
    "example.com/24",
    "0xa.0.0.1/8",
    "fe80::1%eth0/64",
  ])("rejects %j", (input) => {
    expect(canonical(input)).toBe(CidrError.Syntax);
  });

  it("flags only real normalization as adjusted", () => {
    expect(parseCidr("10.20.0.0/24")).toMatchObject({ ok: true, adjusted: false });
    expect(parseCidr("10.20.0.1/24")).toMatchObject({ ok: true, adjusted: true });
  });

  it("applies family and prefix constraints", () => {
    const portal = { family: 4, prefix: 24 } as const;
    expect(canonical("10.30.0.7/24", portal)).toBe("10.30.0.0/24");
    expect(canonical("10.30.0.0", portal)).toBe("10.30.0.0/24");
    expect(canonical("10.30.0.0/16", portal)).toBe(CidrError.Prefix);
    expect(canonical("fd00::/24", portal)).toBe(CidrError.Family);
  });
});

describe("splitCidrTokens", () => {
  it("splits on newlines, whitespace, commas and semicolons", () => {
    expect(splitCidrTokens("10.0.0.0/8,\r\n fd00::/8;; 192.168.0.0/16\t")).toEqual([
      "10.0.0.0/8",
      "fd00::/8",
      "192.168.0.0/16",
    ]);
  });
});
