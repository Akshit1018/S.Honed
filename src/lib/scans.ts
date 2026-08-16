import { createServerFn } from "@tanstack/react-start";
import { authMiddleware } from "@/lib/auth/middleware";
import { getSql } from "@/lib/db";
import { classifyInput, runInspection } from "@/lib/analyze";
import { askAboutFinding as askModel, enrichReport } from "@/lib/ai-report";
import { type Report, type ScanSummary, type WorkStatus, parseReport } from "@/lib/report";
import { compareReports } from "@/lib/report-extra";

function asSummary(row: {
  id: string;
  target: string;
  target_type: string;
  status: string;
  score: number | null;
  grade: string | null;
  summary: string | null;
  report_json: string;
  created_at: string;
  completed_at: string | null;
}): ScanSummary {
  const report = parseReport(row.report_json);
  const real = report?.findings.filter((f) => f.kind !== "solution") ?? [];
  return {
    id: row.id,
    target: row.target,
    targetType: row.target_type as ScanSummary["targetType"],
    status: row.status as ScanSummary["status"],
    score: row.score,
    grade: row.grade,
    summary: row.summary,
    findingCount: real.length,
    criticalCount: real.filter((f) => f.severity === "critical").length,
    highCount: real.filter((f) => f.severity === "high").length,
    createdAt: row.created_at,
    completedAt: row.completed_at,
  };
}

async function persistComplete(
  sql: Awaited<ReturnType<typeof getSql>>,
  userId: string,
  target: string,
  report: Report,
  id: string,
) {
  const prev = await sql<{ id: string; score: number | null; grade: string | null; report_json: string }>`
    select id, score, grade, report_json from scans
    where user_id = ${userId} and target = ${target} and status = ${"complete"} and id <> ${id}
    order by created_at desc
    limit 1
  `;
  const last = prev[0];
  if (last && typeof last.score === "number") {
    const previous = parseReport(last.report_json);
    report = {
      ...report,
      compare: previous
        ? compareReports(previous, report)
        : {
            previousScore: last.score,
            previousGrade: last.grade ?? "",
            delta: report.score - last.score,
          },
    };
  }
  const json = JSON.stringify(report);
  await sql`
    update scans
    set status = ${"complete"},
        score = ${report.score},
        grade = ${report.grade},
        summary = ${report.summary},
        report_json = ${json},
        completed_at = now()
    where id = ${id} and user_id = ${userId}
  `;
  return report;
}

async function runAndStore(userId: string, target: string) {
  const sql = await getSql();
  const id = crypto.randomUUID();
  const targetType = classifyInput(target);
  await sql`
    insert into scans (id, user_id, target, target_type, mode, status)
    values (${id}, ${userId}, ${target}, ${targetType}, ${"standard"}, ${"running"})
  `;
  try {
    const base = await runInspection(target);
    let report: Report = base;
    try {
      report = await enrichReport(base);
    } catch {
      report = base;
    }
    report = await persistComplete(sql, userId, target, report, id);
    return { id, report };
  } catch (err) {
    const message = err instanceof Error ? err.message : "Inspection failed.";
    await sql`
      update scans
      set status = ${"failed"}, error = ${message}, completed_at = now()
      where id = ${id} and user_id = ${userId}
    `;
    throw new Error(message);
  }
}

export const inspectTarget = createServerFn({ method: "POST" })
  .validator((input: { target: string }) => {
    const target = String(input.target ?? "").trim();
    if (!target) throw new Error("Paste a site, a GitHub repo, or a short brief.");
    if (target.length > 4000) throw new Error("Keep the brief under 4,000 characters.");
    return { target };
  })
  .handler(async ({ data }) => runInspection(data.target));

export const createScan = createServerFn({ method: "POST" })
  .middleware([authMiddleware])
  .validator((input: { target: string }) => {
    const target = String(input.target ?? "").trim();
    if (!target) throw new Error("Paste a site, a GitHub repo, or a short brief.");
    if (target.length > 4000) throw new Error("Keep the brief under 4,000 characters.");
    return { target };
  })
  .handler(async ({ context, data }) => runAndStore(context.userId, data.target));

export const rescanScan = createServerFn({ method: "POST" })
  .middleware([authMiddleware])
  .validator((input: { id: string }) => {
    const id = String(input.id ?? "");
    if (!id) throw new Error("Missing brief.");
    return { id };
  })
  .handler(async ({ context, data }) => {
    const sql = await getSql();
    const rows = await sql<{ target: string }>`
      select target from scans where id = ${data.id} and user_id = ${context.userId} limit 1
    `;
    const target = rows[0]?.target;
    if (!target) throw new Error("Brief not found.");
    return runAndStore(context.userId, target);
  });

export const listScans = createServerFn({ method: "GET" })
  .middleware([authMiddleware])
  .handler(async ({ context }) => {
    const sql = await getSql();
    const rows = await sql<{
      id: string;
      target: string;
      target_type: string;
      status: string;
      score: number | null;
      grade: string | null;
      summary: string | null;
      report_json: string;
      created_at: string;
      completed_at: string | null;
    }>`
      select id, target, target_type, status, score, grade, summary, report_json, created_at, completed_at
      from scans
      where user_id = ${context.userId}
      order by created_at desc
      limit 40
    `;
    return rows.map(asSummary);
  });

export const getScan = createServerFn({ method: "GET" })
  .middleware([authMiddleware])
  .validator((input: { id: string }) => {
    const id = String(input.id ?? "");
    if (!id) throw new Error("Missing brief.");
    return { id };
  })
  .handler(async ({ context, data }) => {
    const sql = await getSql();
    const rows = await sql<{
      id: string;
      target: string;
      target_type: string;
      status: string;
      score: number | null;
      grade: string | null;
      summary: string | null;
      report_json: string;
      error: string | null;
      created_at: string;
      completed_at: string | null;
    }>`
      select id, target, target_type, status, score, grade, summary, report_json, error, created_at, completed_at
      from scans
      where id = ${data.id} and user_id = ${context.userId}
      limit 1
    `;
    const row = rows[0];
    if (!row) throw new Error("Brief not found.");
    return {
      ...asSummary(row),
      error: row.error,
      report: row.status === "complete" ? parseReport(row.report_json) : null,
    };
  });

export const saveGuestReport = createServerFn({ method: "POST" })
  .middleware([authMiddleware])
  .validator((input: { report: Report }) => {
    if (!input?.report?.target) throw new Error("Nothing to save.");
    return { report: input.report };
  })
  .handler(async ({ context, data }) => {
    const sql = await getSql();
    const id = crypto.randomUUID();
    let report = data.report;
    if (!report.enriched) {
      try {
        report = await enrichReport(report);
      } catch {
        /* keep */
      }
    }
    await sql`
      insert into scans (id, user_id, target, target_type, mode, status)
      values (${id}, ${context.userId}, ${report.target}, ${report.targetType}, ${"standard"}, ${"running"})
    `;
    report = await persistComplete(sql, context.userId, report.target, report, id);
    return { id, report };
  });

export const listFindingStatuses = createServerFn({ method: "GET" })
  .middleware([authMiddleware])
  .validator((input: { scanId: string }) => ({ scanId: String(input.scanId ?? "") }))
  .handler(async ({ context, data }) => {
    if (!data.scanId) return [] as { findingId: string; status: WorkStatus }[];
    const sql = await getSql();
    return sql<{ findingId: string; status: WorkStatus }>`
      select finding_id as "findingId", status from finding_status
      where user_id = ${context.userId} and scan_id = ${data.scanId}
    `;
  });

export const setFindingStatus = createServerFn({ method: "POST" })
  .middleware([authMiddleware])
  .validator((input: { scanId: string; findingId: string; status: WorkStatus }) => {
    const status = input.status;
    if (status !== "open" && status !== "doing" && status !== "done") {
      throw new Error("Bad status.");
    }
    return {
      scanId: String(input.scanId ?? ""),
      findingId: String(input.findingId ?? ""),
      status,
    };
  })
  .handler(async ({ context, data }) => {
    const sql = await getSql();
    const owned = await sql<{ id: string }>`
      select id from scans where id = ${data.scanId} and user_id = ${context.userId} limit 1
    `;
    if (!owned[0]) throw new Error("Brief not found.");
    await sql`
      insert into finding_status (user_id, scan_id, finding_id, status, updated_at)
      values (${context.userId}, ${data.scanId}, ${data.findingId}, ${data.status}, now())
      on conflict (user_id, scan_id, finding_id)
      do update set status = excluded.status, updated_at = now()
    `;
    return { ok: true as const };
  });

export const askFinding = createServerFn({ method: "POST" })
  .middleware([authMiddleware])
  .validator((input: {
    question: string;
    title: string;
    summary: string;
    detail: string;
    fix: string;
    target: string;
  }) => {
    const question = String(input.question ?? "").trim();
    if (!question) throw new Error("Ask a question.");
    if (question.length > 400) throw new Error("Keep the question short.");
    return {
      question,
      title: String(input.title ?? "").slice(0, 160),
      summary: String(input.summary ?? "").slice(0, 400),
      detail: String(input.detail ?? "").slice(0, 800),
      fix: String(input.fix ?? "").slice(0, 800),
      target: String(input.target ?? "").slice(0, 240),
    };
  })
  .handler(async ({ data }) => askModel(data));
