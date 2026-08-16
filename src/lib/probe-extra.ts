import { resolveCaa, resolveTxt } from "node:dns/promises";
import { assertPublicHttpUrl } from "@/lib/ssrf";
import type { DnsCheck, Finding, SurfaceCheck } from "@/lib/report";

export type FindingDraft = Omit<Finding, "id">;

const FETCH_MS = 4000;
const PLATFORM =
  /\.(vercel\.app|netlify\.app|github\.io|pages\.dev|web\.app|herokuapp\.com|cloudfront\.net|azurewebsites\.net|workers\.dev)$/i;

function timeout<T>(ms: number, fallback: T): Promise<T> {
  return new Promise((resolve) => setTimeout(() => resolve(fallback), ms));
}

async function txtOf(name: string): Promise<string[]> {
  try {
    const rows = await Promise.race([resolveTxt(name), timeout(FETCH_MS, [] as string[][])]);
    return rows.map((parts) => parts.join(""));
  } catch {
    return [];
  }
}

function apexOf(host: string): string {
  if (host.toLowerCase().startsWith("www.")) return host.slice(4);
  return host;
}

export async function probeHttpRedirect(httpsUrl: string): Promise<{
  check: SurfaceCheck;
  finding?: FindingDraft;
}> {
  let host = "";
  try {
    const u = new URL(httpsUrl);
    host = u.hostname;
    if (u.protocol !== "https:") {
      return {
        check: {
          id: "https-redirect",
          label: "HTTP → HTTPS",
          status: "n/a",
          detail: "Origin is not HTTPS, so there is nothing to upgrade.",
        },
      };
    }
  } catch {
    return {
      check: {
        id: "https-redirect",
        label: "HTTP → HTTPS",
        status: "n/a",
        detail: "Could not parse the origin.",
      },
    };
  }

  try {
    const httpUrl = await assertPublicHttpUrl(`http://${host}/`);
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), FETCH_MS);
    const res = await fetch(httpUrl.toString(), {
      method: "GET",
      redirect: "manual",
      signal: ctrl.signal,
      headers: { "User-Agent": "HonedBrief/1.0", Accept: "text/html,*/*" },
    }).finally(() => clearTimeout(timer));
    const loc = res.headers.get("location") ?? "";
    const upgraded =
      res.status >= 300 && res.status < 400 && /^https:\/\//i.test(loc);
    if (upgraded) {
      return {
        check: {
          id: "https-redirect",
          label: "HTTP → HTTPS",
          status: "found",
          detail: `HTTP ${res.status} to ${loc.slice(0, 80)}. First visits are upgraded.`,
        },
      };
    }
    return {
      check: {
        id: "https-redirect",
        label: "HTTP → HTTPS",
        status: "missing",
        detail: `HTTP still answers ${res.status} without sending people to HTTPS.`,
      },
      finding: {
        kind: "security",
        severity: "medium",
        title: "HTTP is not redirected to HTTPS",
        summary: "A first visit over port 80 can stay in the clear.",
        detail: "Send a 301 from every http URL to its https twin before the body.",
        cwe: "CWE-319",
        location: `http://${host}/`,
        effort: "low",
        fixTitle: "Force the upgrade",
        fix: "return 301 https://$host$request_uri;",
      },
    };
  } catch {
    return {
      check: {
        id: "https-redirect",
        label: "HTTP → HTTPS",
        status: "n/a",
        detail: "HTTP was unreachable. Many hosts simply do not listen on 80.",
      },
    };
  }
}

export async function probeDns(hostname: string): Promise<{
  dns: DnsCheck[];
  findings: FindingDraft[];
}> {
  if (!hostname || PLATFORM.test(hostname)) {
    return {
      dns: [
        {
          id: "spf",
          label: "SPF",
          status: "n/a",
          detail: "Platform hostnames do not own their mail.",
        },
        {
          id: "dmarc",
          label: "DMARC",
          status: "n/a",
          detail: "Skip email posture on a PaaS subdomain.",
        },
        {
          id: "caa",
          label: "CAA",
          status: "n/a",
          detail: "Certificate authority restrictions live on the apex you control.",
        },
      ],
      findings: [],
    };
  }

  const apex = apexOf(hostname);
  const [apexTxt, dmarcTxt, caa] = await Promise.all([
    txtOf(apex),
    txtOf(`_dmarc.${apex}`),
    (async () => {
      try {
        return await Promise.race([
          resolveCaa(apex),
          timeout(FETCH_MS, [] as { issue?: string; critical: number }[]),
        ]);
      } catch {
        return [] as { issue?: string; critical: number }[];
      }
    })(),
  ]);

  const spf = apexTxt.find((t) => /v=spf1/i.test(t));
  const dmarc = dmarcTxt.find((t) => /v=dmarc1/i.test(t));
  const findings: FindingDraft[] = [];

  const dns: DnsCheck[] = [
    {
      id: "spf",
      label: "SPF",
      status: spf ? "found" : "missing",
      detail: spf ? spf.slice(0, 180) : `No v=spf1 TXT on ${apex}. Anyone can spoof mail from this zone.`,
    },
    {
      id: "dmarc",
      label: "DMARC",
      status: dmarc ? "found" : "missing",
      detail: dmarc
        ? dmarc.slice(0, 180)
        : `No _dmarc.${apex}. Receivers have no policy for forged mail.`,
    },
    {
      id: "caa",
      label: "CAA",
      status: caa.length ? "found" : "missing",
      detail: caa.length
        ? caa.map((c) => c.issue ?? "record").slice(0, 4).join(", ")
        : `No CAA on ${apex}. Any public CA may issue a certificate.`,
    },
  ];

  if (!spf) {
    findings.push({
      kind: "security",
      severity: "low",
      title: "No SPF record on the apex",
      summary: "Receivers cannot tell who is allowed to send mail as this domain.",
      detail: "A single TXT record at the apex is enough to start. Include only the providers you actually use.",
      location: apex,
      effort: "low",
      fixTitle: "Publish SPF",
      fix: `v=spf1 include:_spf.google.com -all`,
    });
  }
  if (!dmarc) {
    findings.push({
      kind: "security",
      severity: "medium",
      title: "No DMARC policy",
      summary: "Forged mail from this domain has no published handling rule.",
      detail: "Start with p=none and a rua mailbox, then move to quarantine once the reports look clean.",
      location: `_dmarc.${apex}`,
      effort: "low",
      fixTitle: "Publish DMARC",
      fix: "v=DMARC1; p=none; rua=mailto:dmarc@your-domain; adkim=s; aspf=s",
    });
  } else if (/p\s*=\s*none/i.test(dmarc)) {
    dns[1] = { ...dns[1], status: "warn", detail: `${dmarc.slice(0, 160)} — monitor-only.` };
    findings.push({
      kind: "security",
      severity: "info",
      title: "DMARC is monitor-only",
      summary: "p=none records what happens; it does not stop the forged mail.",
      detail: "When reports look clean, raise the policy to quarantine, then reject.",
      location: `_dmarc.${apex}`,
      evidence: dmarc,
      effort: "low",
      fixTitle: "Raise the policy",
      fix: "v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@your-domain",
    });
  }
  if (!caa.length) {
    findings.push({
      kind: "security",
      severity: "info",
      title: "No CAA record",
      summary: "Any public certificate authority may issue for this name.",
      detail: "CAA is a cheap extra lock once you know which CA you actually use.",
      location: apex,
      effort: "low",
      fixTitle: "Pin the CA",
      fix: "example.com. CAA 0 issue \"letsencrypt.org\"\nexample.com. CAA 0 issuewild \"letsencrypt.org\"",
    });
  }

  return { dns, findings };
}

export async function gatherSiteExtras(finalUrl: string): Promise<{
  surface: SurfaceCheck[];
  dns: DnsCheck[];
  findings: FindingDraft[];
}> {
  let host = "";
  try {
    host = new URL(finalUrl).hostname;
  } catch {
    return { surface: [], dns: [], findings: [] };
  }
  const [redirect, dns] = await Promise.all([probeHttpRedirect(finalUrl), probeDns(host)]);
  return {
    surface: [redirect.check],
    dns: dns.dns,
    findings: [...(redirect.finding ? [redirect.finding] : []), ...dns.findings],
  };
}
