import { assertPublicHttpUrl } from "@/lib/ssrf";
import {
  type CookieCheck,
  type DnsCheck,
  type Finding,
  type Report,
  type SurfaceCheck,
  type TargetType,
  type Vendor,
  gradeFromScore,
} from "@/lib/report";
import { finalizeReport } from "@/lib/report-extra";
import { collectPassive } from "@/lib/inspect-passive";
import { gatherSiteExtras } from "@/lib/probe-extra";

const MAX_BODY = 220_000;
const FETCH_MS = 9000;

type HeaderMap = Record<string, string>;

async function probeSurface(origin: string): Promise<SurfaceCheck[]> {
  const checks: { id: string; label: string; path: string; hint: string }[] = [
    { id: "security-txt", label: "security.txt", path: "/.well-known/security.txt", hint: "Where researchers report a hole." },
    { id: "robots", label: "robots.txt", path: "/robots.txt", hint: "What you ask crawlers to skip." },
    { id: "sitemap", label: "sitemap.xml", path: "/sitemap.xml", hint: "The map search engines expect." },
    { id: "humans", label: "humans.txt", path: "/humans.txt", hint: "Who made this." },
    { id: "manifest", label: "manifest", path: "/manifest.json", hint: "Installable app metadata." },
    { id: "ads", label: "ads.txt", path: "/ads.txt", hint: "Who may sell your inventory." },
    { id: "change-password", label: "change-password", path: "/.well-known/change-password", hint: "Where password managers send people." },
  ];
  return Promise.all(
    checks.map(async (c) => {
      try {
        const url = await assertPublicHttpUrl(`${origin}${c.path}`);
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 4000);
        const res = await fetch(url.toString(), {
          method: "GET",
          redirect: "manual",
          signal: ctrl.signal,
          headers: { "User-Agent": "HonedBrief/1.0", Accept: "text/plain,application/xml,*/*" },
        }).finally(() => clearTimeout(timer));
        return {
          id: c.id,
          label: c.label,
          status: res.ok ? ("found" as const) : ("missing" as const),
          detail: res.ok ? `HTTP ${res.status}. ${c.hint}` : `Not published. ${c.hint}`,
        };
      } catch {
        return { id: c.id, label: c.label, status: "missing" as const, detail: `Unreachable. ${c.hint}` };
      }
    }),
  );
}

function h(headers: HeaderMap, name: string): string {
  return headers[name.toLowerCase()] ?? "";
}

function decodeEntities(s: string): string {
  return s
    .replace(/&/g, "&")
    .replace(/</g, "<")
    .replace(/>/g, ">")
    .replace(/"/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, " ");
}

function pickAttr(tag: string, name: string): string | undefined {
  const re = new RegExp(`${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, "i");
  const m = tag.match(re);
  return m?.[2] ?? m?.[3] ?? m?.[4];
}

function allTags(html: string, tag: string): string[] {
  return html.match(new RegExp(`<${tag}\\b[^>]*>`, "gi")) ?? [];
}

function textBetween(html: string, tag: string): string[] {
  const re = new RegExp(`<${tag}\\b[^>]*>([\\s\\S]*?)</${tag}>`, "gi");
  const out: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(html))) {
    out.push(decodeEntities(m[1].replace(/<[^>]+>/g, "").trim()));
  }
  return out;
}

function metaContent(html: string, key: string): string | undefined {
  const re = new RegExp(`<meta\\b[^>]*(?:name|property)\\s*=\\s*["']${key}["'][^>]*>`, "i");
  const tag = html.match(re)?.[0];
  if (!tag) {
    const re2 = new RegExp(
      `<meta\\b[^>]*content\\s*=\\s*["'][^"']+["'][^>]*(?:name|property)\\s*=\\s*["']${key}["'][^>]*>`,
      "i",
    );
    const t2 = html.match(re2)?.[0];
    return t2 ? pickAttr(t2, "content") : undefined;
  }
  return pickAttr(tag, "content");
}

function detectTech(html: string, headers: HeaderMap, scripts: string[]): string[] {
  const tech = new Set<string>();
  const gen = metaContent(html, "generator") ?? "";
  const powered = h(headers, "x-powered-by");
  const server = h(headers, "server");
  const blob = `${html.slice(0, 80_000)}\n${powered}\n${server}\n${scripts.join("\n")}`.toLowerCase();
  const checks: [string, RegExp][] = [
    ["Next.js", /_next\/|__next|next\.js/],
    ["React", /react(?:-dom)?[.-]|data-reactroot|__next/],
    ["Vite", /@vite|vite\/client/],
    ["WordPress", /wp-content|wordpress/],
    ["Shopify", /cdn\.shopify|myshopify/],
    ["Webflow", /webflow/],
    ["Cloudflare", /cloudflare|cf-ray/],
    ["Vercel", /x-vercel|vercel/],
    ["Netlify", /netlify/],
    ["Google Analytics", /gtag\/js|google-analytics|googletagmanager/],
    ["Stripe", /js\.stripe\.com/],
    ["Tailwind", /tailwindcss|cdn\.tailwindcss/],
  ];
  for (const [name, re] of checks) if (re.test(blob)) tech.add(name);
  if (gen) tech.add(gen.split(/[,\s]/)[0] ?? gen);
  if (/php/i.test(powered)) tech.add("PHP");
  if (/express/i.test(powered)) tech.add("Express");
  return [...tech].slice(0, 8);
}

function fid(partial: Omit<Finding, "id"> & { id?: string }, n: { i: number }): Finding {
  n.i += 1;
  return { id: partial.id ?? `F-${String(n.i).padStart(2, "0")}`, ...partial };
}

function classifyTarget(raw: string): { type: TargetType; url?: string; notes?: string } {
  const t = raw.trim();
  if (/^https?:\/\//i.test(t)) {
    try {
      const u = new URL(t);
      if (/(^|\.)github\.com$/i.test(u.hostname)) return { type: "github", url: t };
      return { type: "url", url: t };
    } catch {
      return { type: "notes", notes: t };
    }
  }
  if (/^github\.com\//i.test(t)) return { type: "github", url: `https://${t}` };
  if (/^[a-z0-9.-]+\.[a-z]{2,}([/:].*)?$/i.test(t) && !/\s/.test(t)) {
    return { type: "url", url: `https://${t}` };
  }
  return { type: "notes", notes: t };
}

async function safeGet(raw: string): Promise<{ url: string; status: number; headers: HeaderMap; body: string; cookies: string[] }> {
  let current = await assertPublicHttpUrl(raw);
  for (let hop = 0; hop < 5; hop += 1) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), FETCH_MS);
    let res: Response;
    try {
      res = await fetch(current.toString(), {
        method: "GET",
        redirect: "manual",
        signal: ctrl.signal,
        headers: {
          Accept: "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
          "User-Agent": "HonedBrief/1.0 (+https://honed.app; passive inspector)",
        },
      });
    } catch (err) {
      clearTimeout(timer);
      throw new Error((err as Error).name === "AbortError" ? "The target timed out." : "Could not reach that target.");
    }
    clearTimeout(timer);
    const headers: HeaderMap = {};
    res.headers.forEach((v, k) => {
      headers[k.toLowerCase()] = v;
    });
    const cookies =
      typeof res.headers.getSetCookie === "function" ? res.headers.getSetCookie() : [];
    if (res.status >= 300 && res.status < 400) {
      const loc = headers.location;
      if (!loc) break;
      current = await assertPublicHttpUrl(new URL(loc, current).toString());
      continue;
    }
    const buf = new Uint8Array(await res.arrayBuffer());
    const slice = buf.byteLength > MAX_BODY ? buf.slice(0, MAX_BODY) : buf;
    return { url: current.toString(), status: res.status, headers, body: new TextDecoder("utf-8", { fatal: false }).decode(slice), cookies };
  }
  throw new Error("Too many redirects.");
}

function scoreFindings(findings: Finding[]): number {
  let score = 100;
  const cost: Record<Finding["severity"], number> = { critical: 18, high: 10, medium: 5, low: 2, info: 0 };
  for (const f of findings) if (f.kind !== "solution") score -= cost[f.severity];
  return Math.max(12, Math.min(99, score));
}

function buildSummary(name: string, context: string, findings: Finding[]): string {
  const real = findings.filter((f) => f.kind !== "solution");
  const crit = real.filter((f) => f.severity === "critical" || f.severity === "high");
  if (!real.length) return `${name} is in unusually good shape on a first pass. ${context} Keep the headers and the craft this tight.`;
  if (crit.length) return `${name} has ${crit.length} high-priority item${crit.length === 1 ? "" : "s"} that should move before polish. ${context}`;
  return `${name} is structurally sound. The work is in craft: ${real[0]?.title.toLowerCase() ?? "small gaps"}. ${context}`;
}

function defaultAgents(kind: TargetType): Report["agents"] {
  return [
    { name: "Scout", role: "Recon", note: kind === "notes" ? "Read the brief and mapped implied surfaces." : "Resolved the host and fetched the public surface." },
    { name: "Auditor", role: "Security", note: "Checked transport, headers, disclosure paths, and obvious exposure." },
    { name: "Editor", role: "Polish", note: "Read structure, language, and first-impression craft." },
    { name: "Smith", role: "Solutions", note: "Ranked fixes by effort and drafted the first patch for each." },
  ];
}

function push(
  findings: Finding[],
  n: { i: number },
  partial: Omit<Finding, "id">,
) {
  findings.push(fid(partial, n));
}

function inspectHtml(
  url: string,
  status: number,
  headers: HeaderMap,
  html: string,
  surface: SurfaceCheck[] = [],
  setCookies: string[] = [],
  extras: { dns?: DnsCheck[]; extraFindings?: Omit<Finding, "id">[] } = {},
): Report {
  const n = { i: 0 };
  const findings: Finding[] = [];
  const title = textBetween(html, "title")[0] || metaContent(html, "og:title") || new URL(url).hostname;
  const desc = metaContent(html, "description") || metaContent(html, "og:description") || "";
  const viewport = metaContent(html, "viewport") || "";
  const lang = html.match(/<html\b[^>]*lang=["']([^"']+)/i)?.[1];
  const imgs = allTags(html, "img");
  const missingAlt = imgs.filter((t) => pickAttr(t, "alt") === undefined).length;
  const h1s = textBetween(html, "h1");
  const scriptTags = allTags(html, "script");
  const scripts = scriptTags.map((t) => pickAttr(t, "src") ?? "").filter(Boolean);
  const forms = allTags(html, "form");
  const passwordFields = allTags(html, "input").filter((t) => /type=["']password["']/i.test(t));
  const blanks = allTags(html, "a").filter((t) => /target=["']_blank["']/i.test(t));
  const unsafeBlank = blanks.filter((t) => !/rel=["'][^"']*noopener/i.test(t)).length;
  const https = url.startsWith("https://");

  if (!https) {
    push(findings, n, { kind: "security", severity: "critical", title: "Site is served over HTTP", summary: "The origin is not encrypted. Credentials, cookies, and tokens travel in the clear.", detail: "Modern browsers mark this as Not Secure.", cwe: "CWE-319", cvss: 7.5, location: url, effort: "low", fixTitle: "Force HTTPS", fix: "Terminate TLS and redirect every http request.\n\nStrict-Transport-Security: max-age=63072000; includeSubDomains; preload" });
  }
  if (https && !h(headers, "strict-transport-security")) {
    push(findings, n, { kind: "security", severity: "medium", title: "HSTS is not set", summary: "Browsers are not told to stay on HTTPS, so a first visit can still be downgraded.", detail: "HSTS is a one-line header and the cheapest way to lock in TLS.", cwe: "CWE-319", cvss: 4.3, location: "response headers", effort: "low", fixTitle: "Send HSTS", fix: "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload" });
  }
  if (!h(headers, "content-security-policy")) {
    push(findings, n, { kind: "security", severity: "high", title: "No Content-Security-Policy", summary: "A successful XSS has no containment.", detail: "Start with a report-only policy, then lock default-src to self.", cwe: "CWE-1021", cvss: 6.1, location: "response headers", effort: "medium", fixTitle: "Start with a tight CSP", fix: "Content-Security-Policy: default-src 'self'; img-src 'self' data: https:; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';" });
  }
  if (!h(headers, "x-frame-options") && !/frame-ancestors/i.test(h(headers, "content-security-policy"))) {
    push(findings, n, { kind: "security", severity: "medium", title: "Clickjacking controls are missing", summary: "The page can be framed by any origin.", detail: "Prefer CSP frame-ancestors over X-Frame-Options.", cwe: "CWE-1021", cvss: 4.3, location: "response headers", effort: "low", fixTitle: "Disallow foreign frames", fix: "Content-Security-Policy: frame-ancestors 'none';\nX-Frame-Options: DENY" });
  }
  if (!/nosniff/i.test(h(headers, "x-content-type-options"))) {
    push(findings, n, { kind: "security", severity: "low", title: "MIME sniffing is allowed", summary: "X-Content-Type-Options: nosniff is absent.", detail: "Browsers may interpret a downloaded file as HTML/JS.", cwe: "CWE-16", location: "response headers", effort: "low", fixTitle: "Disable sniffing", fix: "X-Content-Type-Options: nosniff" });
  }
  if (!h(headers, "referrer-policy")) {
    push(findings, n, { kind: "security", severity: "low", title: "Referrer-Policy is unset", summary: "Full URLs may leak to third parties.", detail: "strict-origin-when-cross-origin is the modern default.", location: "response headers", effort: "low", fixTitle: "Set a referrer policy", fix: "Referrer-Policy: strict-origin-when-cross-origin" });
  }
  if (!h(headers, "permissions-policy")) {
    push(findings, n, { kind: "security", severity: "info", title: "Permissions-Policy is unset", summary: "Camera, mic, and geo are left to browser defaults.", detail: "Lock unused device APIs on a marketing or docs site.", location: "response headers", effort: "low", fixTitle: "Lock unused device APIs", fix: "Permissions-Policy: camera=(), microphone=(), geolocation=()" });
  }
  if (h(headers, "access-control-allow-origin") === "*") {
    push(findings, n, { kind: "security", severity: "medium", title: "CORS is wide open", summary: "Access-Control-Allow-Origin is *.", detail: "Fine for a cookieless public API. Dangerous if this origin serves authenticated JSON.", cwe: "CWE-942", location: "response headers", evidence: "Access-Control-Allow-Origin: *", effort: "medium", fixTitle: "Allowlist origins", fix: "Access-Control-Allow-Origin: https://app.your-domain.tld" });
  }
  const server = h(headers, "server");
  const powered = h(headers, "x-powered-by");
  if (/\d+\.\d+/.test(server) || powered) {
    push(findings, n, { kind: "security", severity: "low", title: "Stack version is advertised", summary: [server && `Server: ${server}`, powered && `X-Powered-By: ${powered}`].filter(Boolean).join(" · "), detail: "Version banners help scanners pick exploits.", evidence: `${server} ${powered}`.trim(), location: "response headers", effort: "low", fixTitle: "Strip version banners", fix: "Remove X-Powered-By. Send a generic Server token or none." });
  }
  if (!desc) {
    push(findings, n, { kind: "polish", severity: "medium", title: "No meta description", summary: "Search and chat unfurls have nothing to quote.", detail: "Write one sentence (140–160 characters).", location: "<head>", effort: "low", fixTitle: "Add a description", fix: `<meta name="description" content="One sentence: who it's for, what it does, why now." />` });
  }
  if (!metaContent(html, "og:image") && !metaContent(html, "twitter:image")) {
    push(findings, n, { kind: "polish", severity: "medium", title: "No share card image", summary: "Links will unfurl as a bland title.", detail: "A 1200×630 image with the product name in the middle of the frame.", location: "<head>", effort: "low", fixTitle: "Add an og:image", fix: `<meta property="og:image" content="https://your-domain/og.jpg" />` });
  }
  if (!viewport) {
    push(findings, n, { kind: "polish", severity: "high", title: "No mobile viewport", summary: "Phones will pinch-zoom a desktop layout.", detail: "The most common reason a site looks broken on a phone.", location: "<head>", effort: "low", fixTitle: "Set the viewport", fix: `<meta name="viewport" content="width=device-width, initial-scale=1" />` });
  }
  if (!lang) {
    push(findings, n, { kind: "polish", severity: "low", title: "html lang is missing", summary: "Screen readers guess the language.", detail: "One attribute.", location: "<html>", effort: "low", fixTitle: "Declare the language", fix: `<html lang="en">` });
  }
  if (h1s.length === 0) {
    push(findings, n, { kind: "polish", severity: "medium", title: "No H1 on the page", summary: "The document has no primary heading.", detail: "One clear H1. Make it the thing you would say out loud.", location: "document outline", effort: "low", fixTitle: "Add a single H1", fix: `<h1>${title}</h1>` });
  } else if (h1s.length > 2) {
    push(findings, n, { kind: "polish", severity: "low", title: "Heading outline is noisy", summary: `${h1s.length} H1s on one page.`, detail: `Seen: ${h1s.slice(0, 4).map((s) => `“${s.slice(0, 48)}”`).join(", ")}.`, location: "document outline", effort: "low", fixTitle: "Collapse to one H1", fix: "Leave the page title as H1. Demote the rest." });
  }
  if (missingAlt > 0) {
    push(findings, n, { kind: "polish", severity: missingAlt > 5 ? "medium" : "low", title: `${missingAlt} image${missingAlt === 1 ? "" : "s"} missing alt text`, summary: "Screen readers announce the filename.", detail: "Decorative images get alt=\"\". Meaningful ones get a short phrase.", location: "<img>", effort: "low", fixTitle: "Write the alts", fix: `<img src="…" alt="What the picture is doing." />` });
  }
  if (unsafeBlank > 0) {
    push(findings, n, { kind: "security", severity: "low", title: "target=_blank without rel=noopener", summary: `${unsafeBlank} outbound link${unsafeBlank === 1 ? "" : "s"} can access window.opener.`, detail: "Always pair _blank with noopener noreferrer.", cwe: "CWE-1022", location: "<a target=_blank>", effort: "low", fixTitle: "Close the opener", fix: `<a href="…" target="_blank" rel="noopener noreferrer">` });
  }
  const originHost = new URL(url).host;
  const noSri = scriptTags.filter((tag) => {
    const src = pickAttr(tag, "src");
    if (!src) return false;
    try {
      return new URL(src, url).host !== originHost && !pickAttr(tag, "integrity");
    } catch {
      return false;
    }
  });
  if (noSri.length > 0) {
    push(findings, n, { kind: "security", severity: noSri.length > 3 ? "medium" : "low", title: `${noSri.length} third-party script${noSri.length === 1 ? "" : "s"} without SRI`, summary: "A compromised CDN can run anything it likes on this origin.", detail: "Subresource Integrity pins the bytes you meant to load.", cwe: "CWE-353", location: "<script src>", evidence: noSri.slice(0, 4).map((t) => pickAttr(t, "src") ?? "").join("\n"), effort: "medium", fixTitle: "Pin the bytes", fix: `<script src="https://cdn.example/lib.js" integrity="sha384-…" crossorigin="anonymous"></script>` });
  }
  if (https) {
    const mixed = html.match(/(?:src|href)=["']http:\/\//gi)?.length ?? 0;
    if (mixed > 0) {
      push(findings, n, { kind: "security", severity: "high", title: "Mixed content on an HTTPS page", summary: `${mixed} http:// resource${mixed === 1 ? "" : "s"} loaded from a TLS document.`, detail: "Promote every src/href to https.", cwe: "CWE-311", location: "document", effort: "low", fixTitle: "Upgrade the URLs", fix: "Rewrite http:// assets to https://. Add Content-Security-Policy: upgrade-insecure-requests." });
    }
  }
  if (!/rel=["']canonical["']/i.test(html)) {
    push(findings, n, { kind: "polish", severity: "low", title: "No canonical URL", summary: "Search may treat query variants as separate pages.", detail: "One link tag tells crawlers which URL is the real one.", location: "<head>", effort: "low", fixTitle: "Add a canonical", fix: `<link rel="canonical" href="${url.split("?")[0]}" />` });
  }
  if (!/application\/ld\+json/i.test(html)) {
    push(findings, n, { kind: "polish", severity: "info", title: "No structured data", summary: "Nothing for search to parse as a WebSite.", detail: "A small JSON-LD block makes the product name unambiguous.", location: "<head>", effort: "low", fixTitle: "Add JSON-LD", fix: `<script type="application/ld+json">{"@context":"https://schema.org","@type":"WebSite","name":"${title.replace(/"/g, "")}","url":"${url}"}</script>` });
  }
  const undim = imgs.filter((t) => !pickAttr(t, "width") && !pickAttr(t, "height")).length;
  if (undim > 2) {
    push(findings, n, { kind: "polish", severity: "low", title: `${undim} images have no width or height`, summary: "The layout will jump as pictures arrive.", detail: "Set width and height so the browser can reserve space.", location: "<img>", effort: "low", fixTitle: "Reserve the box", fix: `<img src="…" width="1200" height="630" alt="…" />` });
  }
  const secTxt = surface.find((s) => s.id === "security-txt");
  if (secTxt && secTxt.status === "missing") {
    push(findings, n, { kind: "security", severity: "low", title: "No security.txt", summary: "Researchers have no published mailbox.", detail: "RFC 9116 is a single file at /.well-known/security.txt.", cwe: "CWE-1059", location: "/.well-known/security.txt", effort: "low", fixTitle: "Publish security.txt", fix: "Contact: mailto:security@your-domain\nExpires: 2027-12-31T00:00:00.000Z\nPreferred-Languages: en" });
  }
  if (passwordFields.length && forms.some((f) => /^http:/i.test(pickAttr(f, "action") ?? ""))) {
    push(findings, n, { kind: "security", severity: "critical", title: "Password form posts over HTTP", summary: "A login form action is a cleartext URL.", detail: "Move the action to HTTPS.", cwe: "CWE-319", cvss: 8.1, location: "<form>", effort: "low", fixTitle: "Post over TLS", fix: `<form method="post" action="https://your-domain/login">` });
  }
  const thirdParty = scripts.filter((src) => {
    try { return new URL(src, url).origin !== new URL(url).origin; } catch { return false; }
  });
  if (thirdParty.length > 8) {
    push(findings, n, { kind: "polish", severity: "medium", title: "Script surface is crowded", summary: `${thirdParty.length} third-party scripts on the first document.`, detail: "Keep analytics + payments; defer the rest.", evidence: thirdParty.slice(0, 6).join("\n"), location: "<script src>", effort: "medium", fixTitle: "Cut the tag manager down", fix: "Load first-party JS only in <head>. Defer vendors." });
  }
  if (!html.includes('rel="icon"') && !html.includes("rel='icon'")) {
    push(findings, n, { kind: "polish", severity: "info", title: "No favicon declared", summary: "Browser tabs will show a generic document glyph.", detail: "A 32×32 SVG is enough.", location: "<head>", effort: "low", fixTitle: "Add a favicon", fix: `<link rel="icon" type="image/svg+xml" href="/favicon.svg" />` });
  }
  const passive = collectPassive(url, headers, html, setCookies);
  for (const f of passive.findings) push(findings, n, f);
  for (const f of extras.extraFindings ?? []) push(findings, n, f);
  const cookies: CookieCheck[] = passive.cookies;
  const vendors: Vendor[] = passive.vendors;
  push(findings, n, { kind: "solution", severity: "info", title: "Edge header pack (copy onto the origin)", summary: "A complete, boring, correct header set for a public site.", detail: "Apply at the CDN so every HTML response inherits it.", effort: "low", fixTitle: "Vercel / nginx / Caddy snippet", fix: `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
X-Frame-Options: DENY
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy: default-src 'self'; img-src 'self' data: https:; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';` });

  const score = scoreFindings(findings);
  return finalizeReport({
    target: url,
    targetType: "url",
    finalUrl: url,
    statusCode: status,
    pageTitle: title,
    tech: detectTech(html, headers, scripts),
    score,
    grade: gradeFromScore(score),
    summary: buildSummary(title, `HTTP ${status} · ${new URL(url).hostname}.`, findings),
    findings,
    agents: defaultAgents("url"),
    inspectedAt: new Date().toISOString(),
    headerNames: Object.keys(headers).sort(),
    surface,
    cookies,
    vendors,
    dns: extras.dns,
    enriched: false,
  });
}

async function inspectGithub(url: string): Promise<Report> {
  let owner = "";
  let repo = "";
  try {
    const parts = new URL(url).pathname.split("/").filter(Boolean);
    owner = parts[0] ?? "";
    repo = (parts[1] ?? "").replace(/\.git$/, "");
  } catch { /* ignore */ }
  if (!owner || !repo) return inspectUrl(url);
  const api = `https://api.github.com/repos/${owner}/${repo}`;
  await assertPublicHttpUrl(api);
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_MS);
  const res = await fetch(api, {
    headers: { Accept: "application/vnd.github+json", "User-Agent": "HonedBrief/1.0" },
    signal: ctrl.signal,
  }).finally(() => clearTimeout(timer));
  if (res.status === 404) throw new Error("That GitHub repository was not found.");
  if (!res.ok) throw new Error("GitHub would not return that repository.");
  const data = (await res.json()) as {
    full_name: string; description: string | null; language: string | null;
    license: { spdx_id: string } | null; stargazers_count: number; open_issues_count: number;
    archived: boolean; html_url: string; homepage: string | null; pushed_at: string; topics?: string[];
  };
  let readme = "";
  try {
    const rm = await fetch(`${api}/readme`, { headers: { Accept: "application/vnd.github.raw", "User-Agent": "HonedBrief/1.0" } });
    if (rm.ok) readme = (await rm.text()).slice(0, 12_000);
  } catch { /* optional */ }
  const n = { i: 0 };
  const findings: Finding[] = [];
  const lower = readme.toLowerCase();
  if (!data.license || data.license.spdx_id === "NOASSERTION") {
    push(findings, n, { kind: "polish", severity: "medium", title: "No OSI license on the repository", summary: "Visitors cannot tell how they may use this software.", detail: "A missing license is legal fog and a trust signal.", location: "repository root", effort: "low", fixTitle: "Add a LICENSE", fix: "Add an SPDX license at the repo root and set it in GitHub settings." });
  }
  if (!/security\.md|reporting a vulnerability|# security/.test(lower)) {
    push(findings, n, { kind: "security", severity: "medium", title: "No public vulnerability reporting path", summary: "There is no SECURITY.md or documented disclosure channel.", detail: "A short policy with an email or GHSA path closes that gap.", cwe: "CWE-1059", location: "SECURITY.md", effort: "low", fixTitle: "Add SECURITY.md", fix: "# Security Policy\n\nEmail security@your-domain. Acknowledge within 2 business days." });
  }
  if (!readme) {
    push(findings, n, { kind: "polish", severity: "high", title: "README is empty or missing", summary: "The repository has no readable introduction.", detail: "State what it is, who it is for, how to run it.", effort: "medium", fixTitle: "Write a one-screen README", fix: "# Name\nWhat it does.\n\n## Quick start\n```bash\n# install + run\n```" });
  } else if (readme.length < 400) {
    push(findings, n, { kind: "polish", severity: "medium", title: "README is too thin to onboard anyone", summary: "The introduction is shorter than a landing-page hero.", detail: "Add purpose, install, and a who-this-is-for line.", effort: "low", fixTitle: "Expand the README", fix: "Add: problem statement, install, one happy-path command." });
  }
  if (data.archived) {
    push(findings, n, { kind: "polish", severity: "info", title: "Repository is archived", summary: "GitHub marks this project as read-only.", detail: "Banner that at the top of the README.", effort: "low", fixTitle: "Banner the archive", fix: "> This project is archived." });
  }
  if (!data.homepage) {
    push(findings, n, { kind: "polish", severity: "info", title: "No project homepage set", summary: "The GitHub About panel has no website.", detail: "Set it if a docs site or demo exists.", effort: "low", fixTitle: "Set the homepage", fix: "Repository → Settings → Homepage." });
  }
  push(findings, n, { kind: "solution", severity: "info", title: "Ship a 48-hour hardening pack", summary: "Three changes that move a public repo from interesting to trustworthy.", detail: "License, SECURITY.md, and a README that states scope.", effort: "low", fixTitle: "Order of operations", fix: "1. LICENSE\n2. SECURITY.md\n3. README\n4. Enable Dependabot" });
  const score = scoreFindings(findings);
  return finalizeReport({
    target: data.html_url,
    targetType: "github",
    finalUrl: data.html_url,
    statusCode: 200,
    pageTitle: data.full_name,
    tech: [data.language, ...(data.topics ?? [])].filter(Boolean).slice(0, 8) as string[],
    score,
    grade: gradeFromScore(score),
    summary: buildSummary(data.full_name, `${data.description ?? "No description."} · ${data.stargazers_count} stars · pushed ${data.pushed_at.slice(0, 10)}.`, findings),
    findings,
    agents: defaultAgents("github"),
    inspectedAt: new Date().toISOString(),
    enriched: false,
  });
}

function inspectNotes(notes: string): Report {
  const n = { i: 0 };
  const findings: Finding[] = [];
  const text = notes.toLowerCase();
  const title = notes.split(/[\n.]/)[0]?.slice(0, 80) || "Software brief";
  const hasAuth = /auth|login|oauth|jwt|session|sso/.test(text);
  const hasPay = /pay|stripe|billing|checkout|invoice/.test(text);
  const hasUpload = /upload|s3|file|image|pdf/.test(text);
  const hasApi = /api|graphql|rest|webhook/.test(text);
  const hasMulti = /tenant|org|workspace|team/.test(text);
  push(findings, n, { kind: "security", severity: hasAuth ? "high" : "medium", title: hasAuth ? "Authentication is in scope — threat-model it on paper" : "No auth story is written down", summary: hasAuth ? "Login is mentioned. Session theft, reset, and enumeration need explicit answers." : "Write who is allowed to do what before writing more features.", detail: "A one-page threat model prevents half of later pentest findings.", effort: "medium", fixTitle: "Write a one-page threat model", fix: "## Assets\n## Actors\n## Entry points\n## What a stolen session can do" });
  if (hasPay) push(findings, n, { kind: "security", severity: "critical", title: "Payment surface needs an idempotency and replay plan", summary: "Billing is mentioned. Race conditions and webhook replay are the usual holes.", detail: "Every charge and webhook must be idempotent. Never trust a client-sent price.", cwe: "CWE-841", cvss: 8.6, effort: "high", fixTitle: "Harden checkout", fix: "- Price computed server-side\n- Webhook signatures verified\n- Idempotency-Key on charges" });
  if (hasUpload) push(findings, n, { kind: "security", severity: "high", title: "Uploads are a malware and XSS pipe", summary: "File intake is mentioned without a described allowlist.", detail: "Serve user files from a separate origin.", cwe: "CWE-434", effort: "medium", fixTitle: "Lock the upload path", fix: "- Allowlist MIME + magic bytes\n- Separate cookie-less CDN origin" });
  if (hasApi) push(findings, n, { kind: "security", severity: "high", title: "API authorization is the usual IDOR factory", summary: "An API is implied. Object-level auth is where most SaaS breaks.", detail: "Every GET/PATCH/DELETE of /resource/:id must check ownership.", cwe: "CWE-639", cvss: 7.7, effort: "high", fixTitle: "Object-level checks", fix: "Load the row, compare org_id to the session, 404 on mismatch." });
  if (hasMulti) push(findings, n, { kind: "security", severity: "high", title: "Tenant isolation needs a failing test", summary: "Workspaces / orgs are mentioned.", detail: "Write a test that user A cannot read org 2's invoices.", cwe: "CWE-284", effort: "medium", fixTitle: "Cross-tenant test", fix: "it('cannot read another org invoice') → 404" });
  push(findings, n, { kind: "polish", severity: "medium", title: "First-run empty states are missing from the brief", summary: "New products die on the empty screen.", detail: "Write the empty state for the primary object.", effort: "low", fixTitle: "Design the empty state", fix: "Headline + one sentence + one CTA." });
  push(findings, n, { kind: "solution", severity: "info", title: "A 5-day polish + harden sequence", summary: "Do these in order. Stop when the week ends.", detail: "Sequence beats a backlog.", effort: "medium", fixTitle: "Week plan", fix: "Day 1 — threat model\nDay 2 — object-level auth tests\nDay 3 — headers and cookies\nDay 4 — empty states\nDay 5 — re-run this brief" });
  const score = scoreFindings(findings);
  return finalizeReport({
    target: notes.slice(0, 240),
    targetType: "notes",
    pageTitle: title,
    tech: [],
    score,
    grade: gradeFromScore(score),
    summary: buildSummary(title, "Reviewed from the written brief — no live origin was fetched.", findings),
    findings,
    agents: defaultAgents("notes"),
    inspectedAt: new Date().toISOString(),
    enriched: false,
  });
}

async function inspectUrl(url: string): Promise<Report> {
  const got = await safeGet(url);
  let surface: SurfaceCheck[] = [];
  try { surface = await probeSurface(new URL(got.url).origin); } catch { surface = []; }
  let extras: { dns?: DnsCheck[]; extraFindings?: Omit<Finding, "id">[] } = {};
  try {
    const more = await gatherSiteExtras(got.url);
    surface = [...surface, ...more.surface];
    extras = { dns: more.dns, extraFindings: more.findings };
  } catch {
    extras = {};
  }
  const looksHtml = /<html|<head|<body|<!doctype html/i.test(got.body);
  if (!looksHtml) {
    const headerReport = inspectHtml(
      got.url,
      got.status,
      got.headers,
      `<html lang="en"><head><title>${got.url}</title></head><body></body></html>`,
      surface,
      got.cookies,
      extras,
    );
    return finalizeReport({
      ...headerReport,
      pageTitle: new URL(got.url).hostname,
      summary: `Non-HTML response from ${new URL(got.url).hostname} (HTTP ${got.status}). Header review still applies.`,
      findings: headerReport.findings.filter((f) => f.location === "response headers" || f.kind === "solution" || f.location === "Set-Cookie"),
      surface,
      dns: extras.dns,
    });
  }
  return inspectHtml(got.url, got.status, got.headers, got.body, surface, got.cookies, extras);
}

export async function runInspection(raw: string): Promise<Report> {
  const classified = classifyTarget(raw);
  if (classified.type === "notes" || !classified.url) return inspectNotes(classified.notes ?? raw);
  if (classified.type === "github") return inspectGithub(classified.url);
  return inspectUrl(classified.url);
}

export function classifyInput(raw: string): TargetType {
  return classifyTarget(raw).type;
}
