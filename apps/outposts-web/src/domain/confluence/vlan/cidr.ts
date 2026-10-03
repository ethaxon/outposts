import ipaddr from "ipaddr.js";

export type IpFamily = 4 | 6;

export interface CidrConstraints {
  /** Restrict to one address family. */
  family?: IpFamily;
  /** Require an exact prefix length. */
  prefix?: number;
}

export type CidrParseResult =
  | {
      ok: true;
      /** Canonical network form, e.g. `10.0.0.0/24` or `2001:db8::/32`. */
      cidr: string;
      family: IpFamily;
      prefix: number;
      /** True when the stored form differs from what was typed. */
      adjusted: boolean;
    }
  | { ok: false; reason: CidrError };

export const CidrError = {
  Syntax: "syntax",
  Family: "family",
  Prefix: "prefix",
} as const;

export type CidrError = (typeof CidrError)[keyof typeof CidrError];

/**
 * Parses an IPv4/IPv6 CIDR (or bare address) into its canonical network form.
 *
 * ipaddr.js is more lenient than the backend's Rust `ipnet` parser, so forms it
 * would reject are filtered here: non dotted-decimal IPv4 (`0xa.1`, `10.020.0.0`)
 * and IPv6 zone IDs (`fe80::1%eth0`).
 */
export function parseCidr(input: string, constraints: CidrConstraints = {}): CidrParseResult {
  const text = input.trim();
  const slash = text.indexOf("/");
  const address = slash === -1 ? text : text.slice(0, slash);
  const family: IpFamily = address.includes(":") ? 6 : 4;
  // A bare address takes the required prefix when one is fixed, else a host route.
  const withPrefix =
    slash === -1 ? `${text}/${constraints.prefix ?? (family === 4 ? 32 : 128)}` : text;

  if (family === 4 ? !ipaddr.IPv4.isValidFourPartDecimal(address) : address.includes("%")) {
    return { ok: false, reason: CidrError.Syntax };
  }

  let prefix: number;
  let network: string;
  try {
    if (family === 4) {
      prefix = ipaddr.IPv4.parseCIDR(withPrefix)[1];
      network = ipaddr.IPv4.networkAddressFromCIDR(withPrefix).toString();
    } else {
      prefix = ipaddr.IPv6.parseCIDR(withPrefix)[1];
      network = ipaddr.IPv6.networkAddressFromCIDR(withPrefix).toRFC5952String();
    }
  } catch {
    return { ok: false, reason: CidrError.Syntax };
  }

  if (constraints.family && constraints.family !== family) {
    return { ok: false, reason: CidrError.Family };
  }
  if (constraints.prefix !== undefined && constraints.prefix !== prefix) {
    return { ok: false, reason: CidrError.Prefix };
  }

  const cidr = `${network}/${prefix}`;
  return { ok: true, cidr, family, prefix, adjusted: cidr !== text };
}

/** Splits pasted or typed text into candidate CIDR tokens. */
export function splitCidrTokens(text: string): string[] {
  return text
    .split(/[\s,;]+/)
    .map((token) => token.trim())
    .filter(Boolean);
}
