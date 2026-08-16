import { createServerFn } from "@tanstack/react-start";
import { authMiddleware } from "@/lib/auth/middleware";
import { getSql } from "@/lib/db";
import { askAboutFinding as askModel } from "@/lib/ai-report";
import type { WorkStatus } from "@/lib/report";

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
