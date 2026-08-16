import {
  type Finding,
  type HeaderCheck,
  type Report,
  type SurfaceCheck,
  severityRank,
} from "@/lib/report";

const OWASP_BY_CWE: Record<string, string> = {
  "CWE-639": "A01 Broken Access Control",
  "CWE-284": "A01 Broken Access Control",
  "CWE-918": "A10 SSRF",
  "CWE-89": "A03 Injection",
  "CWE-79": "A03 Injection",
  "CWE-434": "A04 Insecure Design",
  "CWE-841": "A04 Insecure Design",
  "CWE-319": "A02 Cryptographic Failures",
  "CWE-614": "A07 Auth Failures",
  "CWE-1021": "A05 Security Misconfiguration",
  "CWE-16": "A05 Security Misconfiguration",
  "CWE-942": "A05 Security Misconfiguration",
  "CWE-1022": "A05 Security Misconfiguration",
  "CWE-1059": "A09 Logging Failures",
  "CWE-353": "A08 Integrity Failures",
  "CWE-311": "A02 Cryptographic Failures",
};

export function tagOwasp(finding: Finding): Finding {
  if (finding.owasp) return finding;
  if (finding.cwe && OWASP_BY_CWE[finding.cwe]) {
    return { ...finding, owasp: OWASP_BY_CWE[finding.cwe] };
  }
  if (finding.kind === "security" && /header|csp|hsts|cookie|cors|mime|coop|corp/i.test(finding.title)) {
    return { ...finding, owasp: "A05 Security Misconfiguration" };
  }
  return finding;
}

export function buildHeaderScorecard(report: Report): HeaderCheck[] {
  const names = new Set((report.headerNames ?? []).map((n) => n.toLowerCase()));
  const titles = report.findings.map((f) => f.title.toLowerCase());
  const has = (key: string, missingPhrase: string) =>
    names.has(key) && !titles.some((t) => t.includes(missingPhrase));

  return [
    {
      name: "HSTS",
      present: has("strict-transport-security", "hsts"),
      note: "Stay on HTTPS after the first visit.",
    },
    {
      name: "CSP",
      present: has("content-security-policy", "content-security-policy"),
      note: "Contain a successful XSS.",
    },
    {
      name: "Frame",
      present:
        has("x-frame-options", "clickjacking") || titles.some((t) => t.includes("frame-ancestors")),
      note: "Stop foreign pages from framing you.",
    },
    {
      name: "nosniff",
      present: has("x-content-type-options", "mime sniffing"),
      note: "Do not let the browser guess a type.",
    },
    {
      name: "Referrer",
      present: has("referrer-policy", "referrer-policy"),
      note: "Stop tokens leaking in the Referer.",
    },
    {
      name: "Permissions",
      present: has("permissions-policy", "permissions-policy"),
      note: "Lock camera, mic, and geo if unused.",
    },
    {
      name: "COOP",
      present: has("cross-origin-opener-policy", "cross-origin-opener"),
      note: "Isolate this document from foreign popups.",
    },
    {
      name: "CORP",
      present: has("cross-origin-resource-policy", "cross-origin-resource"),
      note: "Stop other sites embedding this as a resource.",
    },
  ];
}

export function buildPlaybook(findings: Finding[]): string[] {
  return findings
    .filter((f) => f.kind !== "solution")
    .slice()
    .sort((a, b) => {
      const sev = severityRank(a.severity) - severityRank(b.severity);
      if (sev !== 0) return sev;
      return { low: 0, medium: 1, high: 2 }[a.effort] - { low: 0, medium: 1, high: 2 }[b.effort];
    })
    .map((f) => f.id);
}

export function finalizeReport(report: Report): Report {
  const findings = report.findings.map(tagOwasp);
  return {
    ...report,
    findings,
    headers: report.headers?.length ? report.headers : buildHeaderScorecard({ ...report, findings }),
    playbook: report.playbook?.length ? report.playbook : buildPlaybook(findings),
  };
}

export function compareReports(prev: Report, next: Report): NonNullable<Report["compare"]> {
  const prevTitles = new Set(
    prev.findings.filter((f) => f.kind !== "solution").map((f) => f.title),
  );
  const nextTitles = new Set(
    next.findings.filter((f) => f.kind !== "solution").map((f) => f.title),
  );
  return {
    previousScore: prev.score,
    previousGrade: prev.grade,
    delta: next.score - prev.score,
    added: [...nextTitles].filter((t) => !prevTitles.has(t)).slice(0, 12),
    resolved: [...prevTitles].filter((t) => !nextTitles.has(t)).slice(0, 12),
  };
}

export function reportToMarkdown(report: Report): string {
  const lines: string[] = [
    `# ${report.pageTitle || report.target}`,
    "",
    `> Score **${report.score}** · Grade **${report.grade}** · ${new Date(report.inspectedAt).toISOString().slice(0, 10)}`,
    "",
    report.finalUrl || report.target,
    "",
    report.summary,
    "",
  ];
  if (report.compare) {
    const sign = report.compare.delta >= 0 ? "+" : "";
    lines.push(
      `Compared with the last brief: ${report.compare.previousScore} → ${report.score} (${sign}${report.compare.delta}).`,
      "",
    );
    if (report.compare.resolved?.length) {
      lines.push("Resolved:", ...report.compare.resolved.map((t) => `- ${t}`), "");
    }
    if (report.compare.added?.length) {
      lines.push("New:", ...report.compare.added.map((t) => `- ${t}`), "");
    }
  }
  if (report.cookies?.length) {
    lines.push("## Cookies", "");
    for (const c of report.cookies) {
      const flags = [
        c.secure ? "Secure" : "no-Secure",
        c.httpOnly ? "HttpOnly" : "no-HttpOnly",
        c.sameSite ? `SameSite=${c.sameSite}` : "no-SameSite",
      ].join(", ");
      lines.push(`- \`${c.name}\` — ${flags}${c.issues.length ? ` (${c.issues.join("; ")})` : ""}`);
    }
    lines.push("");
  }
  if (report.vendors?.length) {
    lines.push("## Third-party hosts", "");
    for (const v of report.vendors) {
      lines.push(`- ${v.host} · ${v.kind} · ${v.category}${v.sri ? " · SRI" : ""}`);
    }
    lines.push("");
  }
  if (report.dns?.length) {
    lines.push("## DNS", "");
    for (const d of report.dns) {
      lines.push(`- **${d.label}** (${d.status}) — ${d.detail}`);
    }
    lines.push("");
  }
  lines.push("## Playbook", "");
  const byId = new Map(report.findings.map((f) => [f.id, f]));
  for (const id of report.playbook ?? []) {
    const f = byId.get(id);
    if (!f) continue;
    lines.push(`- [ ] **${f.title}** (${f.severity}, ${f.effort} effort)`);
  }
  lines.push("", "## Findings", "");
  for (const f of report.findings) {
    lines.push(
      `### ${f.title}`,
      "",
      `${f.severity} · ${f.kind}${f.cwe ? ` · ${f.cwe}` : ""}${f.owasp ? ` · ${f.owasp}` : ""}`,
      "",
      f.summary,
      "",
      f.detail,
      "",
      `**${f.fixTitle}**`,
      "",
      "```",
      f.fix,
      "```",
      "",
    );
  }
  return lines.join("\n");
}

export function reportToJson(report: Report): string {
  return JSON.stringify(report, null, 2);
}

export function findingToGithubIssue(finding: Finding, target: string): string {
  const labels = [finding.severity, finding.kind, finding.effort ? `effort:${finding.effort}` : ""]
    .filter(Boolean)
    .join(", ");
  return [
    `## ${finding.title}`,
    "",
    `**Target:** ${target}`,
    `**Severity:** ${finding.severity} · **Kind:** ${finding.kind} · **Effort:** ${finding.effort}`,
    finding.cwe ? `**${finding.cwe}**` : "",
    finding.owasp ? `**${finding.owasp}**` : "",
    "",
    finding.summary,
    "",
    "### Why it matters",
    "",
    finding.detail,
    finding.location ? `\n\`${finding.location}\`\n` : "",
    finding.evidence ? `\n\`\`\`\n${finding.evidence}\n\`\`\`\n` : "",
    "### Fix",
    "",
    `**${finding.fixTitle}**`,
    "",
    "```",
    finding.fix,
    "```",
    "",
    `<!-- labels: ${labels} -->`,
    "",
  ]
    .filter((line) => line !== "")
    .join("\n");
}

export function headerPackText(): string {
  return `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
X-Frame-Options: DENY
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy: default-src 'self'; img-src 'self' data: https:; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';
`;
}

export function cookiePackText(): string {
  return `Set-Cookie: session=…; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=1209600
Set-Cookie: csrf=…; Path=/; Secure; SameSite=Strict
`;
}

export type { SurfaceCheck };
