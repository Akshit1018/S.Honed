import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

const ALLOWED_PORTS = new Set(["", "80", "443"]);

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const v = Number(p);
    if (v > 255) return null;
    n = (n << 8) + v;
  }
  return n >>> 0;
}

function inCidr(ip: string, cidr: string): boolean {
  const [base, bitsRaw] = cidr.split("/");
  const bits = Number(bitsRaw);
  const ipN = ipv4ToInt(ip);
  const baseN = ipv4ToInt(base ?? "");
  if (ipN === null || baseN === null || Number.isNaN(bits)) return false;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipN & mask) === (baseN & mask);
}

const PRIVATE_V4 = [
  "0.0.0.0/8",
  "10.0.0.0/8",
  "100.64.0.0/10",
  "127.0.0.0/8",
  "169.254.0.0/16",
  "172.16.0.0/12",
  "192.0.0.0/24",
  "192.0.2.0/24",
  "192.168.0.0/16",
  "198.18.0.0/15",
  "198.51.100.0/24",
  "203.0.113.0/24",
  "224.0.0.0/4",
  "240.0.0.0/4",
];

export function isBlockedIp(ip: string): boolean {
  const raw = ip.trim().toLowerCase();
  if (!raw) return true;
  if (raw === "::" || raw === "::1" || raw === "0.0.0.0") return true;
  if (raw.startsWith("fe80:") || raw.startsWith("fc") || raw.startsWith("fd")) {
    return true;
  }
  if (raw.startsWith("::ffff:")) {
    return isBlockedIp(raw.slice(7));
  }
  if (isIP(raw) === 4) {
    return PRIVATE_V4.some((c) => inCidr(raw, c));
  }
  if (isIP(raw) === 6) {
    if (raw === "::1") return true;
    if (raw.startsWith("2001:db8:")) return true;
  }
  return false;
}

export async function assertPublicHttpUrl(raw: string): Promise<URL> {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("That does not look like a valid URL.");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("Only http and https targets are allowed.");
  }
  if (!ALLOWED_PORTS.has(url.port)) {
    throw new Error("Only default web ports (80 / 443) are allowed.");
  }
  if (url.username || url.password) {
    throw new Error("URLs with credentials are not allowed.");
  }
  const host = url.hostname.replace(/^\[|\]$/g, "");
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host.endsWith(".internal")
  ) {
    throw new Error("Local hosts cannot be inspected.");
  }
  if (isIP(host)) {
    if (isBlockedIp(host)) throw new Error("Private or reserved addresses are blocked.");
    return url;
  }
  let addrs: { address: string }[];
  try {
    addrs = await lookup(host, { all: true });
  } catch {
    throw new Error("Could not resolve that host.");
  }
  if (!addrs.length) throw new Error("Could not resolve that host.");
  if (addrs.some((a) => isBlockedIp(a.address))) {
    throw new Error("That host resolves to a private address.");
  }
  return url;
}
