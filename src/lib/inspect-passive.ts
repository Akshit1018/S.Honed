import type { CookieCheck, Finding, Vendor } from "@/lib/report";

export type FindingDraft = Omit<Finding, "id">;

const SESSION_RE = /^(session|sess|sid|token|auth|jwt|csrf|remember|connect\.sid|__session|ssid)$/i;

const CATEGORY: [RegExp, string][] = [
  [/googletagmanager|gtag\/js|google-analytics|analytics\.google/, "analytics"],
  [/mixpanel|amplitude|segment\.(com|io)|plausible|fathom|hotjar|fullstory|heap-/, "analytics"],
  [/doubleclick|googlesyndication|adservice|adsystem|taboola|outbrain|criteo/, "ads"],
  [/facebook\.com\/tr|connect\.facebook|fbevents|pixel/, "ads"],
  [/fonts\.googleapis|fonts\.gstatic|typekit|use\.typekit|fonts\.adobe/, "fonts"],
  [/jsdelivr|unpkg|cdnjs|cloudflare|fastly|akamai|cloudfront/, "cdn"],
  [/js\.stripe|paypal|checkout\.shopify|paddle/, "payments"],
  [/twitter\.com|platform\.twitter|linkedin|instagram|tiktok/, "social"],
  [/sentry|bugsnag|datadog|newrelic|honeybadger/, "observability"],
];

function categoryFor(host: string, href: string): string {
  const blob = `${host} ${href}`.toLowerCase();
  for (const [re, name] of CATEGORY) if (re.test(blob)) return name;
  return "other";
}

function pickAttr(tag: string, name: string): string | undefined {
  const re = new RegExp(`${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, "i");
  const m = tag.match(re);
  return m?.[2] ?? m?.[3] ?? m?.[4];
}

function allTags(html: string, tag: string): string[] {
  return html.match(new RegExp(`<${tag}\\b[^>]*>`, "gi")) ?? [];
}

export function parseCookies(setCookies: string[]): CookieCheck[] {
  return setCookies
    .map((raw) => {
      const parts = raw.split(";").map((s) => s.trim()).filter(Boolean);
      const nv = parts[0] ?? "";
      const name = nv.split("=")[0]?.trim() || "cookie";
      const attrs = parts.slice(1).map((a) => a.toLowerCase());
      const secure = attrs.some((a) => a === "secure");
      const httpOnly = attrs.some((a) => a === "httponly");
      const same = attrs.find((a) => a.startsWith("samesite"));
      const sameSite = same?.split("=")[1]?.trim() ?? "";
      const sessionish = SESSION_RE.test(name);
      const issues: string[] = [];
      if (!secure) issues.push("missing Secure");
      if (sessionish && !httpOnly) issues.push("missing HttpOnly");
      if (!sameSite) issues.push("missing SameSite");
      if (sameSite === "none" && !secure) issues.push("SameSite=None without Secure");
      return { name: name.slice(0, 64), secure, httpOnly, sameSite, issues };
    })
    .slice(0, 24);
}

export function cookieFindings(cookies: CookieCheck[], https: boolean): FindingDraft[] {
  if (!cookies.length) return [];
  const out: FindingDraft[] = [];
  const weak = cookies.filter((c) => c.issues.length > 0);
  if (weak.length) {
    const sessionWeak = weak.filter((c) => SESSION_RE.test(c.name));
    out.push({
      kind: "security",
      severity: sessionWeak.length ? "high" : "medium",
      title:
        sessionWeak.length > 0
          ? "Session cookies are missing Secure / HttpOnly / SameSite"
          : `${weak.length} cookie${weak.length === 1 ? "" : "s"} missing security flags`,
      summary: "A stolen or leaked cookie is usable from HTTP, JavaScript, or a cross-site request.",
      detail:
        "Set Secure, HttpOnly (for session tokens), and SameSite=Lax or Strict. SameSite=None is only for true cross-site embeds and still requires Secure.",
      cwe: "CWE-614",
      location: "Set-Cookie",
      evidence: weak.map((c) => `${c.name}: ${c.issues.join(", ")}`).join("\n"),
      effort: "low",
      fixTitle: "Lock the cookie",
      fix: "Set-Cookie: session=…; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=1209600",
    });
  }
  if (!https && cookies.length) {
    out.push({
      kind: "security",
      severity: "critical",
      title: "Cookies set on an HTTP origin",
      summary: "Any network observer can read these cookies.",
      detail: "Move the origin to HTTPS before the flags even matter.",
      cwe: "CWE-614",
      location: "Set-Cookie",
      effort: "low",
      fixTitle: "Serve cookies only on HTTPS",
      fix: "Redirect HTTP → HTTPS, then set Secure on every cookie.",
    });
  }
  return out;
}

export function cspQualityFindings(csp: string): FindingDraft[] {
  if (!csp) return [];
  const out: FindingDraft[] = [];
  const lower = csp.toLowerCase();
  const scriptSrc = lower.match(/script-src[^;]*/)?.[0] ?? "";
  const defaultSrc = lower.match(/default-src[^;]*/)?.[0] ?? "";
  const objectSrc = lower.match(/object-src[^;]*/)?.[0] ?? "";
  if (/unsafe-eval/.test(scriptSrc) || (/unsafe-eval/.test(defaultSrc) && !scriptSrc)) {
    out.push({
      kind: "security",
      severity: "medium",
      title: "CSP allows unsafe-eval",
      summary: "eval() and similar are still permitted, so a successful XSS can compile new code.",
      detail: "Remove 'unsafe-eval'. If a library needs it, replace the library.",
      cwe: "CWE-1021",
      location: "Content-Security-Policy",
      evidence: csp.slice(0, 400),
      effort: "medium",
      fixTitle: "Drop unsafe-eval",
      fix: "Remove 'unsafe-eval' from script-src. Prefer nonces or hashes over broad keywords.",
    });
  }
  if (/unsafe-inline/.test(scriptSrc) || (/unsafe-inline/.test(defaultSrc) && !/script-src/.test(lower))) {
    out.push({
      kind: "security",
      severity: "medium",
      title: "CSP allows unsafe-inline scripts",
      summary: "A policy that still permits inline scripts will not contain XSS.",
      detail: "Move to nonces or hashes. 'unsafe-inline' on style-src is a later problem.",
      cwe: "CWE-1021",
      location: "Content-Security-Policy",
      evidence: csp.slice(0, 400),
      effort: "medium",
      fixTitle: "Nonce the scripts",
      fix: "Content-Security-Policy: script-src 'self' 'nonce-{random}'; object-src 'none'; base-uri 'self';",
    });
  }
  if (/\bscript-src[^;]*\*/.test(lower) || (!scriptSrc && /\bdefault-src[^;]*\*/.test(lower))) {
    out.push({
      kind: "security",
      severity: "high",
      title: "CSP script-src is a wildcard",
      summary: "Any host can supply script. The policy is theatre.",
      detail: "Name the CDNs you actually use.",
      cwe: "CWE-1021",
      location: "Content-Security-Policy",
      evidence: csp.slice(0, 400),
      effort: "medium",
      fixTitle: "Name the hosts",
      fix: "script-src 'self' https://js.stripe.com; object-src 'none';",
    });
  }
  if (!objectSrc) {
    out.push({
      kind: "security",
      severity: "low",
      title: "CSP is missing object-src",
      summary: "Flash/PDF plugins are not explicitly denied.",
      detail: "object-src 'none' is a one-token close.",
      location: "Content-Security-Policy",
      effort: "low",
      fixTitle: "Deny plugins",
      fix: "Content-Security-Policy: object-src 'none';",
    });
  }
  return out;
}

export function hstsQualityFindings(hsts: string): FindingDraft[] {
  if (!hsts) return [];
  const out: FindingDraft[] = [];
  const max = Number(/max-age\s*=\s*(\d+)/i.exec(hsts)?.[1] ?? 0);
  if (max < 15_552_000) {
    out.push({
      kind: "security",
      severity: max < 86_400 ? "medium" : "low",
      title: "HSTS max-age is too short",
      summary: `Browsers will forget HTTPS after ${max || 0} seconds.`,
      detail: "Six months (15552000) is the floor. Two years is the preload requirement.",
      cwe: "CWE-319",
      location: "Strict-Transport-Security",
      evidence: hsts,
      effort: "low",
      fixTitle: "Raise max-age",
      fix: "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
    });
  }
  if (!/includesubdomains/i.test(hsts)) {
    out.push({
      kind: "security",
      severity: "info",
      title: "HSTS does not cover subdomains",
      summary: "www is locked; api. and staging. can still be downgraded.",
      detail: "Add includeSubDomains once every hostname on the zone speaks HTTPS.",
      location: "Strict-Transport-Security",
      evidence: hsts,
      effort: "low",
      fixTitle: "Cover the zone",
      fix: "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
    });
  }
  return out;
}

export function isolationFindings(headers: Record<string, string>): FindingDraft[] {
  const out: FindingDraft[] = [];
  if (!headers["cross-origin-opener-policy"]) {
    out.push({
      kind: "security",
      severity: "low",
      title: "Cross-Origin-Opener-Policy is unset",
      summary: "This document can be opened as a popup and share a browsing context group.",
      detail: "COOP: same-origin isolates window.opener attacks and enables a tighter process.",
      cwe: "CWE-1021",
      location: "response headers",
      effort: "low",
      fixTitle: "Set COOP",
      fix: "Cross-Origin-Opener-Policy: same-origin",
    });
  }
  if (!headers["cross-origin-resource-policy"]) {
    out.push({
      kind: "security",
      severity: "info",
      title: "Cross-Origin-Resource-Policy is unset",
      summary: "Other sites can embed this response as a no-cors resource.",
      detail: "CORP: same-origin (or same-site) is the modern default for HTML documents.",
      location: "response headers",
      effort: "low",
      fixTitle: "Set CORP",
      fix: "Cross-Origin-Resource-Policy: same-origin",
    });
  }
  return out;
}

export function collectVendors(html: string, pageUrl: string): Vendor[] {
  let originHost = "";
  try {
    originHost = new URL(pageUrl).host;
  } catch {
    return [];
  }
  const seen = new Map<string, Vendor>();
  const add = (href: string | undefined, kind: Vendor["kind"], sri: boolean) => {
    if (!href) return;
    try {
      const abs = new URL(href, pageUrl);
      if (abs.host === originHost) return;
      if (!/^https?:$/i.test(abs.protocol)) return;
      const key = `${abs.host}|${kind}`;
      if (seen.has(key)) return;
      seen.set(key, {
        host: abs.host,
        kind,
        category: categoryFor(abs.host, abs.href),
        sri,
        sample: abs.href.slice(0, 180),
      });
    } catch {
      /* ignore */
    }
  };

  for (const tag of allTags(html, "script")) {
    add(pickAttr(tag, "src"), "script", Boolean(pickAttr(tag, "integrity")));
  }
  for (const tag of allTags(html, "link")) {
    const rel = (pickAttr(tag, "rel") ?? "").toLowerCase();
    const href = pickAttr(tag, "href");
    if (rel.includes("stylesheet")) add(href, "style", Boolean(pickAttr(tag, "integrity")));
    else if (rel.includes("preconnect") || rel.includes("dns-prefetch")) add(href, "connect", true);
    else if (rel.includes("font")) add(href, "font", Boolean(pickAttr(tag, "integrity")));
  }
  for (const tag of allTags(html, "iframe")) add(pickAttr(tag, "src"), "iframe", false);
  for (const tag of allTags(html, "img")) {
    const src = pickAttr(tag, "src") ?? "";
    if (/pixel|collect|track|facebook\.com\/tr|google-analytics/i.test(src)) {
      add(src, "pixel", false);
    }
  }
  return [...seen.values()].slice(0, 40);
}

export function vendorFindings(vendors: Vendor[]): FindingDraft[] {
  if (!vendors.length) return [];
  const out: FindingDraft[] = [];
  const trackers = vendors.filter((v) => v.category === "ads" || v.category === "analytics");
  if (trackers.length >= 4) {
    out.push({
      kind: "polish",
      severity: "medium",
      title: "Tracker load is heavy",
      summary: `${trackers.length} analytics or ad hosts on the first document.`,
      detail: "Each extra pixel is consent, performance, and a new XSS surface. Keep one analytics host unless you can name why the second exists.",
      location: "third-party hosts",
      evidence: trackers.map((v) => `${v.host} (${v.category})`).join("\n"),
      effort: "medium",
      fixTitle: "Cut to one analytics host",
      fix: "Keep first-party or one privacy-respecting analytics tag. Load the rest after consent, if at all.",
    });
  }
  const noSriScripts = vendors.filter((v) => v.kind === "script" && !v.sri);
  if (noSriScripts.length > 0 && noSriScripts.length <= 3) {
    // SRI on many scripts is already covered by the HTML inspector; skip duplicate when crowded.
  }
  return out;
}

export function collectPassive(
  url: string,
  headers: Record<string, string>,
  html: string,
  setCookies: string[],
): { cookies: CookieCheck[]; vendors: Vendor[]; findings: FindingDraft[] } {
  const https = url.startsWith("https://");
  const cookies = parseCookies(setCookies);
  const vendors = collectVendors(html, url);
  return {
    cookies,
    vendors,
    findings: [
      ...cookieFindings(cookies, https),
      ...cspQualityFindings(headers["content-security-policy"] ?? ""),
      ...hstsQualityFindings(headers["strict-transport-security"] ?? ""),
      ...isolationFindings(headers),
      ...vendorFindings(vendors),
    ],
  };
}
