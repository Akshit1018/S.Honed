import type { Finding, Report } from "@/lib/report";

type AiShape = {
  summary?: string;
  extraFindings?: Array<{
    kind?: Finding["kind"];
    severity?: Finding["severity"];
    title?: string;
    summary?: string;
    detail?: string;
    effort?: Finding["effort"];
    fixTitle?: string;
    fix?: string;
    cwe?: string;
  }>;
};

function extractJson(text: string): AiShape | null {
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  const raw = fenced?.[1] ?? text;
  const start = raw.indexOf("{");
  const end = raw.lastIndexOf("}");
  if (start < 0 || end <= start) return null;
  try {
    return JSON.parse(raw.slice(start, end + 1)) as AiShape;
  } catch {
    return null;
  }
}

export async function enrichReport(report: Report): Promise<Report> {
  const apiKey = process.env.XAI_API_KEY;
  if (!apiKey) return report;

  const compact = {
    target: report.target,
    type: report.targetType,
    title: report.pageTitle,
    tech: report.tech,
    score: report.score,
    findings: report.findings
      .filter((f) => f.kind !== "solution")
      .slice(0, 14)
      .map((f) => ({
        kind: f.kind,
        severity: f.severity,
        title: f.title,
        summary: f.summary,
      })),
  };

  const res = await fetch("https://api.x.ai/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model: "grok-4.5",
      temperature: 0.3,
      max_tokens: 1400,
      response_format: { type: "json_object" },
      messages: [
        {
          role: "system",
          content:
            "You are Honed, an editorial security-and-craft reviewer. Write like a precise partner, never like a scanner. Return JSON only.",
        },
        {
          role: "user",
          content: `A passive inspection produced this evidence. Write:
1) "summary": 2–3 sentences, specific to THIS target (no generic filler).
2) "extraFindings": 2–4 items this pass would not have seen — polish, product craft, or a sharper solution. Each item: kind (security|polish|solution), severity (critical|high|medium|low|info), title, summary, detail, effort (low|medium|high), fixTitle, fix (concrete steps or a snippet), optional cwe.

Do not invent vulnerabilities that require exploitation. Stay inside what a careful reviewer can claim from a public page or repo brief.

EVIDENCE:
${JSON.stringify(compact)}`,
        },
      ],
    }),
  });

  if (!res.ok) return report;
  const body = (await res.json()) as {
    choices?: { message?: { content?: string } }[];
  };
  const parsed = extractJson(body.choices?.[0]?.message?.content ?? "");
  if (!parsed) return report;

  const extras: Finding[] = [];
  let i = report.findings.length;
  for (const item of parsed.extraFindings ?? []) {
    if (!item.title || !item.summary) continue;
    i += 1;
    extras.push({
      id: `AI-${String(i).padStart(2, "0")}`,
      kind: item.kind === "security" || item.kind === "solution" ? item.kind : "polish",
      severity: item.severity ?? "low",
      title: item.title.slice(0, 140),
      summary: item.summary.slice(0, 280),
      detail: (item.detail ?? item.summary).slice(0, 800),
      effort: item.effort ?? "low",
      fixTitle: (item.fixTitle ?? "What to do").slice(0, 80),
      fix: (item.fix ?? "Review this with the team and ship a small, testable change.").slice(
        0,
        1200,
      ),
      cwe: item.cwe,
    });
  }

  return {
    ...report,
    summary: parsed.summary?.trim() || report.summary,
    findings: [...report.findings, ...extras],
    enriched: true,
  };
}

export async function askAboutFinding(input: {
  question: string;
  title: string;
  summary: string;
  detail: string;
  fix: string;
  target: string;
}): Promise<{ ok: true; text: string } | { ok: false; error: string }> {
  const apiKey = process.env.XAI_API_KEY;
  if (!apiKey) return { ok: false, error: "AI is not available in this environment." };

  const res = await fetch("https://api.x.ai/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model: "grok-4.5",
      temperature: 0.2,
      max_tokens: 500,
      messages: [
        {
          role: "system",
          content:
            "You are Honed. Answer in 2–5 short paragraphs or a tight checklist. Stay inside what a passive review can claim. No exploits.",
        },
        {
          role: "user",
          content: `Target: ${input.target}\nFinding: ${input.title}\n${input.summary}\n${input.detail}\nSuggested fix:\n${input.fix}\n\nQuestion: ${input.question}`,
        },
      ],
    }),
  });
  if (!res.ok) return { ok: false, error: `xAI API error ${res.status}` };
  const body = (await res.json()) as { choices?: { message?: { content?: string } }[] };
  const text = body.choices?.[0]?.message?.content?.trim();
  if (!text) return { ok: false, error: "Empty answer." };
  return { ok: true, text };
}
